mod config;
mod discord_manager;
mod federation;
mod hooks;
mod identity;
mod logging;
mod provider_wrapper;
mod refreshable_provider;
mod tools;
mod update;
mod web;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use clap::Parser;

use orra::channels::gateway::{GatewayChannel, GatewayConfig as LibGatewayConfig};
use orra::context::{CharEstimator, ContextBudget};
use orra::cron::service::CronService;
use orra::cron::store::FileCronStore;
use orra::cron::types::CronPayload;
use orra::hook::HookRegistry;
use orra::message::Message;
use orra::metrics::MetricsCollector;
use orra::namespace::Namespace;
use orra::policy::PolicyRegistry;
use orra::provider::Provider;
use orra::providers::claude::ClaudeProvider;
use orra::providers::openai::OpenAIProvider;
use orra::runtime::{Runtime, RuntimeConfig, RuntimeError};
use orra::scheduler::Scheduler;
use orra::store::InMemoryStore;
use orra::stores::file::FileStore;
use orra::tool::ToolRegistry;

use crate::config::Config;
use crate::provider_wrapper::DynamicProvider;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "herald")]
#[command(about = "A self-hostable AI assistant built on orra")]
#[command(version)]
struct Cli {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "assistant.toml")]
    config: PathBuf,

    /// Validate configuration and exit without starting.
    #[arg(long)]
    check: bool,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load config
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // --- File logging ---
    logging::init(&config.data_dir);

    if cli.check {
        eprintln!("Configuration is valid.");
        eprintln!("  Agent: {}", config.agent.name);
        eprintln!(
            "  Provider: {} ({})",
            config.provider.provider_type, config.provider.model
        );
        eprintln!(
            "  Provider key: {}",
            if config.has_provider_key() {
                "configured"
            } else {
                "not set (use web UI)"
            }
        );
        eprintln!(
            "  Discord: {}",
            if config.has_discord_token() {
                format!("enabled (filter: {})", config.discord.filter)
            } else {
                "disabled (no token)".into()
            }
        );
        eprintln!("  Session store: {}", config.sessions.store);
        eprintln!(
            "  Memory: {}",
            if config.memory.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        eprintln!(
            "  Gateway: {}",
            if config.gateway.enabled {
                format!("{}:{}", config.gateway.host, config.gateway.port)
            } else {
                "disabled".into()
            }
        );
        eprintln!(
            "  Scheduler: {}",
            if config.scheduler.enabled {
                format!("{} jobs", config.scheduler.jobs.len())
            } else {
                "disabled".into()
            }
        );
        eprintln!("  Tools: {}", enabled_tools_summary(&config));
        eprintln!(
            "  MCP servers: {}",
            if config.mcp.servers.is_empty() {
                "(none)".into()
            } else {
                config
                    .mcp
                    .servers
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        return;
    }

    // --- Provider (may be a placeholder if no API key) ---
    // Track how the provider was authenticated for the settings UI.
    let mut auth_source = "none".to_string();

    // Build the OAuth refresh callback (reused by AppState for handler swaps).
    let refresh_callback: Option<refreshable_provider::RefreshFn> = {
        let model = config.provider.model.clone();
        let api_url = config.provider.api_url.clone();
        Some(Arc::new(move || {
            let model = model.clone();
            let api_url = api_url.clone();
            Box::pin(async move {
                let model = model.clone();
                let api_url = api_url.clone();
                tokio::task::spawn_blocking(move || {
                    config::read_claude_cli_credentials().map(|token| {
                        let mut p = ClaudeProvider::new(&token, &model);
                        if let Some(ref url) = api_url {
                            p = p.with_api_url(url);
                        }
                        Arc::new(p) as Arc<dyn Provider>
                    })
                })
                .await
                .ok()
                .flatten()
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Option<Arc<dyn Provider>>> + Send>>
        }))
    };

    let dynamic_provider = if config.has_provider_key() {
        let api_key = config.provider.api_key.as_deref().unwrap();

        // Determine the auth source based on how the key was obtained.
        // The key was set during Config::load() in this priority:
        //   1) TOML file (has api_key literally in the file)
        //   2) ANTHROPIC_API_KEY env var
        //   3) Claude CLI keychain credentials
        // We detect which one by checking in reverse (CLI tokens start with sk-ant-oat).
        if api_key.starts_with("sk-ant-oat") {
            auth_source = "cli".to_string();
        } else if std::env::var("ANTHROPIC_API_KEY")
            .map(|k| k == api_key)
            .unwrap_or(false)
        {
            auth_source = "env".to_string();
        } else {
            auth_source = "config".to_string();
        }

        let real_provider: Arc<dyn Provider> = match config.provider.provider_type.as_str() {
            "openai" => {
                let mut p = OpenAIProvider::new(api_key, &config.provider.model);
                if let Some(ref url) = config.provider.api_url {
                    p = p.with_api_url(url);
                }
                hlog!(
                    "[init] provider: openai ({}) [source: {}]",
                    config.provider.model, auth_source
                );
                Arc::new(p)
            }
            _ => {
                hlog!(
                    "[init] provider: claude ({}) [source: {}]",
                    config.provider.model, auth_source
                );
                Arc::new(ClaudeProvider::new(api_key, &config.provider.model))
            }
        };

        // Wrap in RefreshableProvider for automatic OAuth token refresh.
        // Only attach the refresh callback for CLI-sourced OAuth tokens.
        let refresh = if auth_source == "cli" {
            refresh_callback.clone()
        } else {
            None
        };
        let refreshable: Arc<dyn Provider> =
            Arc::new(refreshable_provider::RefreshableProvider::new(real_provider, refresh));

        Arc::new(DynamicProvider::with_provider(refreshable))
    } else {
        hlog!("[init] provider: not configured (use web UI to set API key)");
        Arc::new(DynamicProvider::placeholder())
    };

    // --- Data directory ---
    let sessions_path = config.sessions_path();
    let cron_path = config.cron_path();
    hlog!("[init] data directory: {}", config.data_dir.display());

    // --- Session store ---
    let store: Arc<dyn orra::store::SessionStore> = match config.sessions.store.as_str() {
        "file" => {
            hlog!(
                "[init] session store: file ({})",
                sessions_path.display()
            );
            Arc::new(FileStore::new(&sessions_path))
        }
        _ => {
            hlog!("[init] session store: in-memory");
            Arc::new(InMemoryStore::new())
        }
    };

    // --- Cron service ---
    let cron_service = if config.cron.enabled {
        let cron_store = Arc::new(FileCronStore::new(&cron_path));
        if let Err(e) = cron_store.load_from_disk().await {
            hlog!("[init] cron: failed to load jobs: {}", e);
        }
        let svc = Arc::new(CronService::new(cron_store));
        hlog!("[init] cron: enabled ({})", cron_path.display());
        Some(svc)
    } else {
        None
    };

    // --- Tools ---
    let mut tool_registry = ToolRegistry::new();
    // Pass the DynamicProvider as an Arc<dyn Provider> to tools
    let provider_for_tools: Arc<dyn Provider> = dynamic_provider.clone() as Arc<dyn Provider>;
    tools::register_all(
        &mut tool_registry,
        &config,
        &provider_for_tools,
        cron_service.as_ref(),
    );

    // --- MCP servers ---
    let mut _mcp_clients = Vec::new();
    for server in &config.mcp.servers {
        let args: Vec<&str> = server.args.iter().map(|s| s.as_str()).collect();
        let env: Vec<(&str, &str)> = server
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        match orra::mcp::transport::StdioTransport::spawn_with_env(&server.command, &args, &env)
            .await
        {
            Ok(transport) => {
                let transport = std::sync::Arc::new(transport);
                match orra::mcp::register_mcp_tools(&mut tool_registry, transport).await {
                    Ok(client) => {
                        hlog!("[init] mcp server '{}': connected", server.name);
                        _mcp_clients.push(client);
                    }
                    Err(e) => {
                        hlog!(
                            "[init] mcp server '{}': handshake failed: {}",
                            server.name, e
                        );
                    }
                }
            }
            Err(e) => {
                hlog!(
                    "[init] mcp server '{}': failed to start: {}",
                    server.name, e
                );
            }
        }
    }

    hlog!("[init] registered {} tools", tool_registry.len());

    // --- Policies ---
    let policies = PolicyRegistry::default();

    // --- Approval channel (shared between ApprovalHook and WS handler) ---
    let (approval_tx, approval_rx) =
        tokio::sync::mpsc::channel::<hooks::approval::ApprovalRequest>(32);

    // --- Discord config for approval routing ---
    let discord_approval_config = config
        .discord
        .token
        .as_ref()
        .filter(|t| !t.is_empty() && !t.starts_with("${"))
        .map(|t| orra::tools::discord::DiscordConfig::new(t));

    // --- Session event broadcast (for pushing updates to WebSocket clients) ---
    // Created early so hooks can reference the sender.
    let (session_events_tx, _) = tokio::sync::broadcast::channel::<String>(64);

    // --- Hooks ---
    let mut hook_registry = HookRegistry::new();
    hook_registry.register(Arc::new(hooks::file_logging::FileLoggingHook::new()));
    hook_registry.register(Arc::new(
        hooks::working_directory::WorkingDirectoryHook::new(),
    ));
    let approval_hook = hooks::approval::ApprovalHook::new(approval_tx.clone());
    let approval_hook = if let Some(ref dc) = discord_approval_config {
        approval_hook.with_discord(dc.clone())
    } else {
        approval_hook
    };
    hook_registry.register(Arc::new(approval_hook));
    hook_registry.register(Arc::new(
        hooks::session_notify::SessionNotifyHook::new(session_events_tx.clone()),
    ));

    // --- Metrics ---
    let _metrics = if config.metrics.enabled {
        let mut collector = MetricsCollector::new();
        if config.metrics.log_metrics {
            collector.add_sink(Arc::new(orra::metrics::LoggingSink));
        }
        hlog!("[init] metrics: enabled");
        Some(Arc::new(collector))
    } else {
        None
    };

    // --- System prompt ---
    let system_prompt = identity::build_system_prompt(&config);

    // --- Runtime config ---
    let runtime_config = RuntimeConfig {
        system_prompt: Some(system_prompt),
        max_turns: 10,
        max_tokens: Some(config.provider.max_tokens),
        temperature: Some(config.provider.temperature),
        context_budget: ContextBudget {
            max_tokens: config.context.max_tokens,
            reserved_for_output: config.context.reserved_for_output,
            ..ContextBudget::default()
        },
        parallel_tool_execution: true,
    };

    // --- Assemble runtime ---
    // The DynamicProvider implements Provider, so the runtime uses it directly.
    // When the provider is hot-swapped via the web UI, all subsequent runtime
    // calls will use the new provider automatically.
    let provider_for_runtime: Arc<dyn Provider> = dynamic_provider.clone() as Arc<dyn Provider>;
    let mut runtime = Runtime::new(
        provider_for_runtime,
        store.clone(),
        tool_registry,
        policies,
        CharEstimator::default(),
        runtime_config,
    );
    runtime.set_hooks(hook_registry);

    let runtime = Arc::new(runtime);

    // --- Multi-agent runtimes ---
    let agents = config.resolved_agents();
    let default_agent_name = agents
        .first()
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "Atlas".into());
    let mut runtimes_map: std::collections::HashMap<String, Arc<Runtime<CharEstimator>>> =
        std::collections::HashMap::new();

    // Create the shared runtimes Arc upfront so the DelegateToAgentTool can
    // reference it even before the map is populated.
    let runtimes = Arc::new(tokio::sync::RwLock::new(runtimes_map.clone()));

    // --- Federation manager (created before agent build so tools can reference it) ---
    let federation_manager = Arc::new(federation::manager::FederationManager::new(
        runtimes.clone(),
        store.clone(),
    ));

    // Auto-enable delegation when multiple agents are configured
    let enable_delegation = config.tools.delegation || agents.len() > 1;
    let enable_federation_tool = config.federation.enabled;

    if agents.len() > 1 {
        hlog!("[init] multi-agent mode: {} agents", agents.len());

        // Collect all agent names for the system prompt
        let all_agent_names: Vec<String> = agents.iter().map(|a| a.name.clone()).collect();

        // If federation is enabled, include a hint about remote agents in the system prompt.
        // Actual remote agent names are discovered at runtime, so we just describe the capability.
        let federation_remote_agents: Vec<identity::RemoteAgentDesc> =
            if config.federation.enabled {
                // At startup, static peers are seeded but not yet discovered.
                // We pass an empty list — the tool description handles discovery.
                // If we have static peer names, include a placeholder.
                config
                    .federation
                    .peers
                    .iter()
                    .map(|p| identity::RemoteAgentDesc {
                        name: format!("(agents on {})", p.name),
                        instance: p.name.clone(),
                    })
                    .collect()
            } else {
                vec![]
            };

        for agent_profile in &agents {
            let agent_prompt = identity::build_agent_system_prompt_full(
                agent_profile,
                &config,
                &all_agent_names,
                &federation_remote_agents,
            );
            let agent_runtime_config = RuntimeConfig {
                system_prompt: Some(agent_prompt),
                max_turns: 10,
                max_tokens: Some(config.provider.max_tokens),
                temperature: Some(config.provider.temperature),
                context_budget: ContextBudget {
                    max_tokens: config.context.max_tokens,
                    reserved_for_output: config.context.reserved_for_output,
                    ..ContextBudget::default()
                },
                parallel_tool_execution: true,
            };

            // Each agent shares the same provider, store, tools, and policies
            let provider_for_agent: Arc<dyn Provider> =
                dynamic_provider.clone() as Arc<dyn Provider>;
            let mut agent_tool_registry = ToolRegistry::new();
            let provider_for_agent_tools: Arc<dyn Provider> =
                dynamic_provider.clone() as Arc<dyn Provider>;
            tools::register_all(
                &mut agent_tool_registry,
                &config,
                &provider_for_agent_tools,
                cron_service.as_ref(),
            );

            // Register inter-agent delegation tool
            if enable_delegation {
                agent_tool_registry.register(Box::new(
                    orra::tools::delegation::DelegateToAgentTool::new(
                        runtimes.clone(),
                        agent_profile.name.clone(),
                    ),
                ));
            }

            // Register remote delegation tool (federation)
            if enable_federation_tool {
                agent_tool_registry.register(Box::new(
                    federation::tool::DelegateToRemoteAgentTool::new(
                        federation_manager.clone(),
                        agent_profile.name.clone(),
                    ),
                ));
            }

            let agent_policies = PolicyRegistry::default();
            let mut agent_hook_registry = HookRegistry::new();
            agent_hook_registry.register(Arc::new(hooks::file_logging::FileLoggingHook::new()));
            agent_hook_registry.register(Arc::new(
                hooks::working_directory::WorkingDirectoryHook::new(),
            ));
            let agent_approval_hook = hooks::approval::ApprovalHook::new(approval_tx.clone());
            let agent_approval_hook = if let Some(ref dc) = discord_approval_config {
                agent_approval_hook.with_discord(dc.clone())
            } else {
                agent_approval_hook
            };
            agent_hook_registry.register(Arc::new(agent_approval_hook));
            agent_hook_registry.register(Arc::new(
                hooks::session_notify::SessionNotifyHook::new(session_events_tx.clone()),
            ));

            let mut agent_rt = Runtime::new(
                provider_for_agent,
                store.clone(),
                agent_tool_registry,
                agent_policies,
                CharEstimator::default(),
                agent_runtime_config,
            );
            agent_rt.set_hooks(agent_hook_registry);

            let key = agent_profile.name.to_lowercase();
            hlog!("[init]   agent '{}' registered", agent_profile.name);
            runtimes_map.insert(key, Arc::new(agent_rt));
        }
        // Populate the shared runtimes map now that all agents are built
        *runtimes.write().await = runtimes_map;
    } else {
        // Single agent — register the default runtime under its name
        let key = default_agent_name.to_lowercase();
        runtimes_map.insert(key, runtime.clone());
        *runtimes.write().await = runtimes_map;
    }

    let agent_profiles = Arc::new(tokio::sync::RwLock::new(agents.clone()));
    let default_agent = Arc::new(tokio::sync::RwLock::new(default_agent_name.clone()));

    // --- Federation startup ---
    if config.federation.enabled {
        let local_agents: Vec<federation::LocalAgentInfo> = agents
            .iter()
            .map(|a| federation::LocalAgentInfo {
                name: a.name.clone(),
                personality: a.personality.clone(),
                model: config.provider.model.clone(),
            })
            .collect();

        if let Err(e) = federation_manager
            .start(config.federation.clone(), local_agents, config.gateway.port)
            .await
        {
            hlog!("[init] federation: failed to start: {e}");
        } else {
            hlog!(
                "[init] federation: enabled (instance: '{}', {} static peers)",
                config.federation.instance_name,
                config.federation.peers.len(),
            );
        }
    }

    // --- Scheduler ---
    let _scheduler_handle = if config.scheduler.enabled && !config.scheduler.jobs.is_empty() {
        let scheduler = Scheduler::new();
        for job in &config.scheduler.jobs {
            let msg = job.message.clone();
            let cb: orra::scheduler::JobCallback = Arc::new(move || {
                let m = msg.clone();
                tokio::spawn(async move {
                    hlog!("[scheduler] triggered: {}", m);
                })
            });
            match scheduler.add_job(&job.name, &job.schedule, cb).await {
                Ok(_) => hlog!("[init] scheduled job: {} ({})", job.name, job.schedule),
                Err(e) => hlog!("[init] failed to schedule {}: {}", job.name, e),
            }
        }
        Some(scheduler.start())
    } else {
        None
    };

    // --- Interactive-request counter (shared with cron callback) ---
    let interactive_count = Arc::new(AtomicUsize::new(0));

    // --- Cron service tick loop ---
    let _cron_handle = if let Some(ref svc) = cron_service {
        let jobs = svc.list_jobs().await.unwrap_or_default();
        if !jobs.is_empty() {
            hlog!("[init] cron: loaded {} jobs", jobs.len());
        }

        // Wire up the callback that runs when a cron job fires
        let cron_runtimes = runtimes.clone();
        let cron_fallback_rt = runtime.clone();
        let cron_default_agent = default_agent.clone();
        let events_tx = session_events_tx.clone();
        let cron_interactive = interactive_count.clone();
        let cron_store = store.clone();
        let cron_callback: orra::cron::service::CronCallback = Arc::new(move |job| {
            let rts = cron_runtimes.clone();
            let fallback_rt = cron_fallback_rt.clone();
            let default_agent = cron_default_agent.clone();
            let events_tx = events_tx.clone();
            let interactive = cron_interactive.clone();
            let store = cron_store.clone();
            tokio::spawn(async move {
                let raw_prompt = match &job.payload {
                    CronPayload::AgentTurn { prompt } => prompt.clone(),
                    CronPayload::SystemEvent { message } => message.clone(),
                };
                // Resolve the namespace for this job:
                //   - "web:<uuid>"  → write into that existing web session
                //   - "web"         → create a dedicated web session for this
                //                     job so it appears in the sidebar
                //   - anything else → prefix with cron: for a background session
                let ns = if job.namespace.starts_with("web:") {
                    Namespace::parse(&job.namespace)
                } else if job.namespace == "web" {
                    // Use a stable namespace derived from the job ID so the
                    // same job always reuses the same session.
                    Namespace::parse(&format!("web:cron-{}", job.id))
                } else {
                    Namespace::parse(&format!("cron:{}", job.namespace))
                };
                let is_web = ns.key().starts_with("web:");

                // For web sessions, tell the LLM to respond with text
                // instead of trying to use Discord's send_message tool.
                let prompt = format!(
                    "[scheduled task: {}] {}\n\n\
                         (This is a scheduled task. Respond with text directly — \
                         do not use send_message or any Discord tools.)",
                    job.name, raw_prompt
                );

                // Defer if an interactive chat is in-flight to avoid
                // saturating the shared API key.
                let mut deferred = false;
                for _ in 0..30 {
                    if interactive.load(Ordering::Relaxed) == 0 {
                        break;
                    }
                    if !deferred {
                        hlog!(
                            "[cron] Deferring job '{}' — interactive chat active",
                            job.name
                        );
                        deferred = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }

                // Resolve the agent runtime (same approach as WS handler)
                let rt = {
                    let rts_guard = rts.read().await;
                    if rts_guard.is_empty() {
                        fallback_rt.clone()
                    } else {
                        let key = default_agent.read().await.to_lowercase();
                        rts_guard.get(&key).cloned().unwrap_or(fallback_rt.clone())
                    }
                };

                // Ensure the session exists with a friendly name (so it
                // appears in the sidebar) and set chaos_mode if auto_approve.
                {
                    let mut session = match store.load(&ns).await {
                        Ok(Some(s)) => s,
                        _ => orra::store::Session::new(ns.clone()),
                    };
                    // Give it the job name so the sidebar shows something useful
                    session.metadata.entry("name".into())
                        .or_insert_with(|| serde_json::json!(format!("Task: {}", job.name)));
                    if job.auto_approve.unwrap_or(false) {
                        session.metadata.insert(
                            "chaos_mode".into(),
                            serde_json::json!(true),
                        );
                    }
                    let _ = store.save(&session).await;
                }

                hlog!(
                    "[cron] Running job '{}' in namespace {}",
                    job.name,
                    ns.key()
                );
                let ns_key = ns.key();
                let model = job.model.clone();
                let max_turns = job.max_turns;
                let is_lightweight = job.lightweight.unwrap_or(false);

                let run_result = if is_lightweight {
                    hlog!("[cron] Running job '{}' in lightweight mode", job.name);
                    rt.run_lightweight(&ns, Message::user(&prompt), model).await
                } else {
                    rt.run_with_model(&ns, Message::user(&prompt), model, max_turns).await
                };
                match run_result {
                    Ok(result) => {
                        hlog!(
                            "[cron] Job '{}' completed ({} turns)",
                            job.name,
                            result.turns.len()
                        );
                        // WS notification is handled automatically by the
                        // SessionNotifyHook which fires on every session save
                        // (including the final save at the end of run_with_model).
                    }
                    Err(e) => {
                        let error_msg = if let RuntimeError::MaxTurnsExceeded(n) = &e {
                            format!(
                                "Scheduled task '{}' ran out of turns ({} max). \
                                 You can increase the limit in the task settings.",
                                job.name, n
                            )
                        } else {
                            format!(
                                "Error while running scheduled task '{}': {}",
                                job.name, e
                            )
                        };
                        hlog!("[cron] {}", error_msg);

                        // Append the error as an assistant message so it appears
                        // in the chat session (the runtime already saved partial
                        // progress, so we load → push → save).
                        if let Ok(Some(mut session)) = store.load(&ns).await {
                            session.push_message(Message::assistant(&error_msg));
                            let _ = store.save(&session).await;
                        }

                        // Notify WS clients so the error shows up immediately
                        if ns_key.starts_with("web:") || ns_key.starts_with("cron:web") {
                            let _ = events_tx.send(ns_key);
                        }
                    }
                }
            })
        });
        svc.set_callback(cron_callback).await;

        Some(svc.start())
    } else {
        None
    };

    // --- Discord manager ---
    let discord_manager = Arc::new(discord_manager::DiscordManager::new(
        runtime.clone(),
        runtimes.clone(),
        default_agent.clone(),
    ));

    // Connect to Discord if a token is configured
    if config.has_discord_token() {
        let discord_token = config.discord.token.as_deref().unwrap();
        hlog!("Connecting to Discord...");
        match discord_manager
            .connect(
                discord_token,
                &config.discord.filter,
                config.discord.allowed_users.clone(),
                &config.discord.namespace_prefix,
            )
            .await
        {
            Ok(()) => hlog!("Connected! Listening for messages..."),
            Err(e) => {
                hlog!("Failed to connect to Discord: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --- Web UI (gateway) ---
    if !config.gateway.enabled {
        if !config.has_discord_token() {
            hlog!("No Discord token and gateway is disabled. Nothing to run.");
            hlog!("Enable the gateway or provide a Discord token in your config.");
            std::process::exit(1);
        }
        // Discord-only mode: wait for Ctrl+C
        hlog!();
        hlog!(
            "=== {} — herald v{} ===",
            default_agent_name,
            env!("CARGO_PKG_VERSION")
        );
        hlog!("Press Ctrl+C to stop.");
        hlog!();
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
        hlog!("\n[shutdown] Goodbye!");
        discord_manager.disconnect().await;
        return;
    }

    let gw_config_obj = LibGatewayConfig {
        host: config.gateway.host.clone(),
        port: config.gateway.port,
        api_key: config.gateway.api_key.clone(),
        ..LibGatewayConfig::default()
    };

    let gateway = Arc::new(GatewayChannel::new(gw_config_obj));

    let discord_api = Arc::new(tokio::sync::RwLock::new(
        config
            .discord
            .token
            .as_ref()
            .filter(|t| !t.is_empty() && !t.starts_with("${"))
            .map(|t| orra::tools::discord::DiscordConfig::new(t)),
    ));

    // --- Update checker ---
    let update_checker = Arc::new(update::UpdateChecker::new());
    // Check for updates every 6 hours (21600 seconds)
    update_checker.start_background_check(6 * 60 * 60);

    let app_state = web::AppState {
        gateway: gateway.clone(),
        runtime: runtime.clone(),
        store: store.clone(),
        dynamic_provider: dynamic_provider.clone(),
        config_provider_type: config.provider.provider_type.clone(),
        config_model: config.provider.model.clone(),
        config_api_url: config.provider.api_url.clone(),
        auth_source: Arc::new(tokio::sync::RwLock::new(auth_source.clone())),
        config_path: cli.config.clone(),
        discord_manager: discord_manager.clone(),
        cron_service: cron_service.clone(),
        discord_api: discord_api.clone(),
        session_events: session_events_tx.clone(),
        runtimes: runtimes.clone(),
        default_agent: default_agent.clone(),
        agent_profiles: agent_profiles.clone(),
        approval_rx: Arc::new(tokio::sync::Mutex::new(approval_rx)),
        federation_manager: federation_manager.clone(),
        gateway_port: config.gateway.port,
        update_checker,
        data_dir: config.data_dir.clone(),
        interactive_count: interactive_count.clone(),
        refresh_callback: refresh_callback.clone(),
    };

    // --- Start ---
    hlog!();
    hlog!(
        "=== {} — herald v{} ===",
        default_agent_name,
        env!("CARGO_PKG_VERSION")
    );
    hlog!(
        "[init] web UI: http://{}:{}",
        config.gateway.host, config.gateway.port
    );

    if !dynamic_provider.is_configured() {
        hlog!("[init] Provider not configured — will retry credential detection in background.");
    }

    // --- Background credential recovery ---
    // Periodically attempt to re-detect CLI credentials if the provider is
    // unconfigured (or was unconfigured at startup). This handles the case
    // where the OAuth token expires while Herald is stopped, the refresh
    // fails at startup, but Claude CLI later refreshes the token externally.
    {
        let dp = dynamic_provider.clone();
        let model = config.provider.model.clone();
        let api_url = config.provider.api_url.clone();
        let auth_src = app_state.auth_source.clone();
        let rcb = refresh_callback.clone();
        tokio::spawn(async move {
            // Check every 5 minutes
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.tick().await; // skip immediate tick
            loop {
                interval.tick().await;
                // Only attempt recovery if provider is unconfigured
                if dp.is_configured() {
                    continue;
                }
                hlog!("[auth] provider unconfigured, attempting credential recovery...");
                let model = model.clone();
                let api_url = api_url.clone();
                let token = tokio::task::spawn_blocking(move || {
                    config::read_claude_cli_credentials()
                })
                .await
                .ok()
                .flatten();
                if let Some(token) = token {
                    let raw: Arc<dyn Provider> = Arc::new(ClaudeProvider::new(&token, &model));
                    let refreshable: Arc<dyn Provider> = Arc::new(
                        refreshable_provider::RefreshableProvider::new(raw, rcb.clone()),
                    );
                    dp.swap(refreshable).await;
                    *auth_src.write().await = "cli".to_string();
                    hlog!("[auth] credential recovery successful — provider is now configured");
                }
            }
        });
    }
    if config.gateway.api_key.is_none() {
        hlog!("[init] \u{26a0} Gateway has no API key — all endpoints are unauthenticated.");
        hlog!("       Set [gateway] api_key in your config for production use.");
    }
    hlog!(
        "Web UI available at http://{}:{}",
        config.gateway.host, config.gateway.port
    );
    hlog!("Press Ctrl+C to stop.");
    hlog!();

    // Set up graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
        hlog!("\n[shutdown] Received Ctrl+C, shutting down...");
        let _ = shutdown_tx.send(());
    });

    tokio::select! {
        result = web::serve(app_state, &config.gateway) => {
            if let Err(e) = result {
                hlog!("[error] Web server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = &mut shutdown_rx => {
            discord_manager.disconnect().await;
            hlog!("[shutdown] Goodbye!");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn enabled_tools_summary(config: &Config) -> String {
    let mut enabled = Vec::new();
    if config.tools.discord {
        enabled.push("discord");
    }
    if config.tools.web_fetch {
        enabled.push("web_fetch");
    }
    if config.tools.web_search {
        enabled.push("web_search");
    }
    if config.tools.exec {
        enabled.push("exec");
    }
    if config.tools.documents {
        enabled.push("documents");
    }
    if config.tools.browser {
        enabled.push("browser");
    }
    if config.tools.image_gen {
        enabled.push("image_gen");
    }
    if config.tools.delegation {
        enabled.push("delegation");
    }
    if config.tools.claude_code {
        enabled.push("claude_code");
    }
    if config.memory.enabled {
        enabled.push("memory");
    }
    if config.cron.enabled {
        enabled.push("cron");
    }
    if enabled.is_empty() {
        "(none)".into()
    } else {
        enabled.join(", ")
    }
}
