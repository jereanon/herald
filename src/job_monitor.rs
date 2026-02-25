use std::sync::Arc;

use orra::cron::service::CronService;
use orra::cron::types::CronJobStatus;
use orra::message::Message;
use orra::namespace::Namespace;
use orra::store::SessionStore;
use tokio::sync::broadcast;

use crate::hlog;

/// Background monitor that detects stuck cron jobs (no progress for
/// N minutes), resets their concurrent-run counter, and notifies the
/// user so the job can fire again on the next schedule.
pub struct JobMonitor {
    cron_service: Arc<CronService>,
    store: Arc<dyn SessionStore>,
    events_tx: broadcast::Sender<String>,
    /// Max minutes a running job can go without a session update before
    /// being considered stuck.
    stuck_threshold_mins: u64,
}

impl JobMonitor {
    pub fn new(
        cron_service: Arc<CronService>,
        store: Arc<dyn SessionStore>,
        events_tx: broadcast::Sender<String>,
        stuck_threshold_mins: u64,
    ) -> Self {
        Self {
            cron_service,
            store,
            events_tx,
            stuck_threshold_mins,
        }
    }

    /// Spawn the background monitor loop. Checks every 2 minutes.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(120));
            // Skip the immediate first tick
            interval.tick().await;

            loop {
                interval.tick().await;
                self.check_stuck_jobs().await;
            }
        })
    }

    async fn check_stuck_jobs(&self) {
        let jobs = match self.cron_service.list_jobs().await {
            Ok(j) => j,
            Err(_) => return,
        };

        let now = chrono::Utc::now();

        for job in &jobs {
            if job.status != CronJobStatus::Active {
                continue;
            }

            // Only check jobs that are currently "running" (concurrent count > 0)
            let running = self.cron_service.running_count(&job.id).await;
            if running == 0 {
                continue;
            }

            // Resolve the namespace for this job
            let ns = if job.namespace.starts_with("web:") {
                Namespace::parse(&job.namespace)
            } else if job.namespace == "web" {
                Namespace::parse(&format!("web:cron-{}", job.id))
            } else {
                Namespace::parse(&format!("cron:{}", job.namespace))
            };

            // Check if the session has been updated recently
            if let Ok(Some(session)) = self.store.load(&ns).await {
                let mins_since_update = (now - session.updated_at).num_minutes();
                if mins_since_update >= self.stuck_threshold_mins as i64 {
                    hlog!(
                        "[monitor] Job '{}' stuck (no update for {} min, running={}). Releasing lock.",
                        job.name,
                        mins_since_update,
                        running
                    );

                    // Reset the running counter so the job can fire again
                    for _ in 0..running {
                        self.cron_service.decrement_running(&job.id).await;
                    }

                    // Append a notice to the session
                    let mut session = session;
                    session.push_message(Message::assistant(&format!(
                        "This task was detected as stuck after {} minutes with no progress. \
                         The lock has been released so it can run again on the next schedule.",
                        mins_since_update
                    )));
                    let _ = self.store.save(&session).await;

                    // Notify WS clients
                    let ns_key = ns.key();
                    if ns_key.starts_with("web:") {
                        let _ = self.events_tx.send(ns_key);
                    }
                }
            }
        }
    }
}
