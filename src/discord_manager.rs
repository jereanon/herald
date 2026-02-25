//! Manages the Discord bot connection lifecycle, allowing the bot to be
//! stopped and restarted at runtime (e.g., when the token is changed via
//! the web UI).

use crate::config::DiscordFilter;
use crate::hlog;
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use orra::channels::discord::{DiscordChannel, DiscordChannelConfig, MessageFilter};
use orra::channels::ChannelAdapter;
use orra::context::CharEstimator;
use orra::routing::{Router, RoutingRule};
use orra::runtime::Runtime;
use orra::tools::discord::DiscordConfig;

/// Current state of the Discord connection.
#[derive(Debug, Clone)]
pub struct DiscordState {
    pub connected: bool,
    pub token_hint: String,
    pub filter: DiscordFilter,
    pub allowed_users: Vec<String>,
    pub namespace_prefix: String,
}

/// Manages the Discord bot connection, supporting hot-restart.
pub struct DiscordManager {
    runtime: Arc<Runtime<CharEstimator>>,
    /// Named agent runtimes for multi-agent routing via `@AgentName`.
    agent_runtimes: Arc<RwLock<HashMap<String, Arc<Runtime<CharEstimator>>>>>,
    /// Default agent name (lowercase) for fallback routing.
    default_agent: Arc<RwLock<String>>,
    state: RwLock<DiscordState>,
    /// The currently running channel (if any) — used to signal shutdown.
    active_channel: RwLock<Option<Arc<DiscordChannel>>>,
    /// The background task running ChannelAdapter::run.
    task_handle: RwLock<Option<JoinHandle<()>>>,
}

impl DiscordManager {
    /// Create a new manager (not yet connected).
    pub fn new(
        runtime: Arc<Runtime<CharEstimator>>,
        agent_runtimes: Arc<RwLock<HashMap<String, Arc<Runtime<CharEstimator>>>>>,
        default_agent: Arc<RwLock<String>>,
    ) -> Self {
        Self {
            runtime,
            agent_runtimes,
            default_agent,
            state: RwLock::new(DiscordState {
                connected: false,
                token_hint: String::new(),
                filter: DiscordFilter::Mentions,
                allowed_users: Vec::new(),
                namespace_prefix: "discord".into(),
            }),
            active_channel: RwLock::new(None),
            task_handle: RwLock::new(None),
        }
    }

    /// Get the current state.
    pub async fn state(&self) -> DiscordState {
        self.state.read().await.clone()
    }

    /// Connect to Discord with the given token and settings.
    /// If already connected, shuts down the existing connection first.
    pub async fn connect(
        &self,
        token: &str,
        discord_filter: DiscordFilter,
        allowed_users: Vec<String>,
        namespace_prefix: &str,
    ) -> Result<(), String> {
        // Stop any existing connection
        self.disconnect().await;

        let dc = DiscordConfig::new(token);
        let filter = match discord_filter {
            DiscordFilter::All => MessageFilter::All,
            DiscordFilter::Dm => MessageFilter::DirectMessagesFrom(allowed_users.clone()),
            DiscordFilter::Mentions => MessageFilter::MentionsOnly,
        };

        // Gather agent names for @mention routing
        let agent_names: Vec<String> = self
            .agent_runtimes
            .read()
            .await
            .keys()
            .map(|k| k.clone())
            .collect();

        let channel_config = DiscordChannelConfig::new(dc)
            .with_filter(filter)
            .with_namespace_prefix(namespace_prefix)
            .with_agent_names(agent_names.clone());

        let channel = Arc::new(DiscordChannel::new(channel_config));

        // Connect to Discord gateway
        channel
            .connect()
            .await
            .map_err(|e| format!("Discord connection failed: {}", e))?;

        // Update state
        let hint = if token.len() >= 4 {
            format!("****{}", &token[token.len() - 4..])
        } else {
            "****".into()
        };

        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.token_hint = hint;
            state.filter = discord_filter;
            state.allowed_users = allowed_users;
            state.namespace_prefix = namespace_prefix.to_string();
        }

        // Spawn the channel adapter loop.
        // If we have agent runtimes, use the Router with MetadataKey("agent")
        // routing so @AgentName mentions dispatch to the correct runtime.
        // Otherwise, use the simple ChannelAdapter.
        let channel_for_task = channel.clone();
        let runtime = self.runtime.clone();
        let runtimes_snapshot = self.agent_runtimes.read().await.clone();
        let default_agent_name = self.default_agent.read().await.clone();
        let has_agents = !runtimes_snapshot.is_empty();

        let handle = tokio::spawn(async move {
            if has_agents {
                let mut router = Router::new(RoutingRule::MetadataKey("agent".into()));
                router.add_channel(
                    "discord",
                    channel_for_task as Arc<dyn orra::channels::Channel>,
                );
                let default_key = default_agent_name.to_lowercase();
                if let Err(e) = router.run(&runtimes_snapshot, Some(&default_key)).await {
                    hlog!("[discord] Router error: {}", e);
                }
            } else {
                if let Err(e) = ChannelAdapter::run(channel_for_task.as_ref(), &runtime).await {
                    hlog!("[discord] Channel adapter error: {}", e);
                }
            }
            hlog!("[discord] Channel adapter stopped");
        });

        *self.active_channel.write().await = Some(channel);
        *self.task_handle.write().await = Some(handle);

        hlog!("[discord] Connected successfully");
        Ok(())
    }

    /// Disconnect from Discord gracefully.
    pub async fn disconnect(&self) {
        // Signal shutdown to the active channel
        if let Some(channel) = self.active_channel.write().await.take() {
            channel.shutdown();
            hlog!("[discord] Shutdown signal sent");
        }

        // Wait for the task to finish (with timeout)
        if let Some(handle) = self.task_handle.write().await.take() {
            let _ = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await;
        }

        {
            let mut state = self.state.write().await;
            state.connected = false;
        }
    }

    /// Fully reset state after bot removal (disconnect + clear token hint etc).
    pub async fn clear_state(&self) {
        self.disconnect().await;
        let mut state = self.state.write().await;
        state.token_hint = String::new();
        state.filter = DiscordFilter::Mentions;
        state.allowed_users = Vec::new();
    }
}
