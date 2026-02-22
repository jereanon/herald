mod config;
mod discord_manager;
mod hooks;
mod identity;
mod provider_wrapper;
mod tools;
mod web;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use agentic_rs::channels::gateway::{GatewayChannel, GatewayConfig as LibGatewayConfig};
use agentic_rs::context::{CharEstimator, ContextBudget};
use agentic_rs::cron::service::CronService;
use agentic_rs::cron::store::FileCronStore;
use agentic_rs::cron::types::CronPayload;
use agentic_rs::message::Message;
use agentic_rs::namespace::Namespace;
use agentic_rs::hook::HookRegistry;
use agentic_rs::metrics::MetricsCollector;
use agentic_rs::policy::PolicyRegistry;
use agentic_rs::provider::Provider;
use agentic_rs::providers::claude::ClaudeProvider;
use agentic_rs::providers::openai::OpenAIProvider;
use agentic_rs::runtime::{Runtime, RuntimeConfig};
use agentic_rs::scheduler::Scheduler;
use agentic_rs::store::InMemoryStore;
use agentic_rs::stores::file::FileStore;
use agentic_rs::tool::ToolRegistry;

use crate::config::Config;
use crate::provider_wrapper::DynamicProvider;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "agentic-assistant")]
#[command(about = "A Discord AI assistant built on the agentic library")]
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

    if cli.check {
        eprintln!("Configuration is valid.");
        eprintln!("  Agent: {}", config.agent.name);
        eprintln!("  Provider: {} ({})", config.provider.provider_type, config.provider.model);
        eprintln!("  Provider key: {}", if config.has_provider_key() { "configured" } else { "not set (use web UI)" });
        eprintln!("  Discord: {}", if config.has_discord_token() {
            format!("enabled (filter: {})", config.discord.filter)
        } else {
            "disabled (no token)".into()
        });
        eprintln!("  Session store: {}", config.sessions.store);
        eprintln!("  Memory: {}", if config.memory.enabled { "enabled" } else { "disabled" });
        eprintln!("  Gateway: {}", if config.gateway.enabled {
            format!("{}:{}", config.gateway.host, config.gateway.port)
        } else {
            "disabled".into()
        });
        eprintln!("  Scheduler: {}", if config.scheduler.enabled {
            format!("{} jobs", config.scheduler.jobs.len())
        } else {
            "disabled".into()
        });
        eprintln!(
            "  Tools: {}",
            enabled_tools_summary(&config)
        );
        eprintln!("  MCP servers: {}", if config.mcp.servers.is_empty() {
            "(none)".into()
        } else {
            config.mcp.servers.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
        });
        return;
    }

    // --- Provider (may be a placeholder if no API key) ---
    // Track how the provider was authenticated for the settings UI.
    let mut auth_source = "none".to_string();

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
        } else if std::env::var("ANTHROPIC_API_KEY").map(|k| k == api_key).unwrap_or(false) {
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
                eprintln!("[init] provider: openai ({}) [source: {}]", config.provider.model, auth_source);
                Arc::new(p)
            }
            _ => {
                eprintln!("[init] provider: claude ({}) [source: {}]", config.provider.model, auth_source);
                Arc::new(ClaudeProvider::new(api_key, &config.provider.model))
            }
        };
        Arc::new(DynamicProvider::with_provider(real_provider))
    } else {
        eprintln!("[init] provider: not configured (use web UI to set API key)");
        Arc::new(DynamicProvider::placeholder())
    };

    // --- Session store ---
    let store: Arc<dyn agentic_rs::store::SessionStore> = match config.sessions.store.as_str() {
        "file" => {
            eprintln!("[init] session store: file ({})", config.sessions.path.display());
            Arc::new(FileStore::new(&config.sessions.path))
        }
        _ => {
            eprintln!("[init] session store: in-memory");
            Arc::new(InMemoryStore::new())
        }
    };

    // --- Cron service ---
    let cron_service = if config.cron.enabled {
        let cron_store = Arc::new(FileCronStore::new(&config.cron.path));
        if let Err(e) = cron_store.load_from_disk().await {
            eprintln!("[init] cron: failed to load jobs: {}", e);
        }
        let svc = Arc::new(CronService::new(cron_store));
        eprintln!("[init] cron: enabled ({})", config.cron.path.display());
        Some(svc)
    } else {
        None
    };

    // --- Tools ---
    let mut tool_registry = ToolRegistry::new();
    // Pass the DynamicProvider as an Arc<dyn Provider> to tools
    let provider_for_tools: Arc<dyn Provider> = dynamic_provider.clone() as Arc<dyn Provider>;
    tools::register_all(&mut tool_registry, &config, &provider_for_tools, cron_service.as_ref());

    // --- MCP servers ---
    let mut _mcp_clients = Vec::new();
    for server in &config.mcp.servers {
        let args: Vec<&str> = server.args.iter().map(|s| s.as_str()).collect();
        let env: Vec<(&str, &str)> = server.env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        match agentic_rs::mcp::transport::StdioTransport::spawn_with_env(
            &server.command,
            &args,
            &env,
        ).await {
            Ok(transport) => {
                let transport = std::sync::Arc::new(transport);
                match agentic_rs::mcp::register_mcp_tools(&mut tool_registry, transport).await {
                    Ok(client) => {
                        eprintln!("[init] mcp server '{}': connected", server.name);
                        _mcp_clients.push(client);
                    }
                    Err(e) => {
                        eprintln!("[init] mcp server '{}': handshake failed: {}", server.name, e);
                    }
                }
            }
            Err(e) => {
                eprintln!("[init] mcp server '{}': failed to start: {}", server.name, e);
            }
        }
    }

    eprintln!("[init] registered {} tools", tool_registry.len());

    // --- Policies ---
    let policies = PolicyRegistry::default();

    // --- Approval channel (shared between ApprovalHook and WS handler) ---
    let (approval_tx, approval_rx) = tokio::sync::mpsc::channel::<hooks::approval::ApprovalRequest>(32);

    // --- Discord config for approval routing ---
    let discord_approval_config = config.discord.token.as_ref()
        .filter(|t| !t.is_empty() && !t.starts_with("${"))
        .map(|t| agentic_rs::tools::discord::DiscordConfig::new(t));

    // --- Hooks ---
    let mut hook_registry = HookRegistry::new();
    hook_registry.register(Arc::new(hooks::logging::LoggingHook::new()));
    hook_registry.register(Arc::new(hooks::working_directory::WorkingDirectoryHook::new()));
    let approval_hook = hooks::approval::ApprovalHook::new(approval_tx.clone());
    let approval_hook = if let Some(ref dc) = discord_approval_config {
        approval_hook.with_discord(dc.clone())
    } else {
        approval_hook
    };
    hook_registry.register(Arc::new(approval_hook));

    // --- Metrics ---
    let _metrics = if config.metrics.enabled {
        let mut collector = MetricsCollector::new();
        if config.metrics.log_metrics {
            collector.add_sink(Arc::new(agentic_rs::metrics::LoggingSink));
        }
        eprintln!("[init] metrics: enabled");
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
    let default_agent_name = agents.first().map(|a| a.name.clone()).unwrap_or_else(|| "Atlas".into());
    let mut runtimes_map: std::collections::HashMap<String, Arc<Runtime<CharEstimator>>> = std::collections::HashMap::new();

    // Create the shared runtimes Arc upfront so the DelegateToAgentTool can
    // reference it even before the map is populated.
    let runtimes = Arc::new(tokio::sync::RwLock::new(runtimes_map.clone()));

    // Auto-enable delegation when multiple agents are configured
    let enable_delegation = config.tools.delegation || agents.len() > 1;

    if agents.len() > 1 {
        eprintln!("[init] multi-agent mode: {} agents", agents.len());

        // Collect all agent names for the system prompt
        let all_agent_names: Vec<String> = agents.iter().map(|a| a.name.clone()).collect();

        for agent_profile in &agents {
            let agent_prompt = identity::build_agent_system_prompt(agent_profile, &config, &all_agent_names);
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
            let provider_for_agent: Arc<dyn Provider> = dynamic_provider.clone() as Arc<dyn Provider>;
            let mut agent_tool_registry = ToolRegistry::new();
            let provider_for_agent_tools: Arc<dyn Provider> = dynamic_provider.clone() as Arc<dyn Provider>;
            tools::register_all(&mut agent_tool_registry, &config, &provider_for_agent_tools, cron_service.as_ref());

            // Register inter-agent delegation tool
            if enable_delegation {
                agent_tool_registry.register(Box::new(
                    agentic_rs::tools::delegation::DelegateToAgentTool::new(
                        runtimes.clone(),
                        agent_profile.name.clone(),
                    ),
                ));
            }

            let agent_policies = PolicyRegistry::default();
            let mut agent_hook_registry = HookRegistry::new();
            agent_hook_registry.register(Arc::new(hooks::logging::LoggingHook::new()));
            agent_hook_registry.register(Arc::new(hooks::working_directory::WorkingDirectoryHook::new()));
            let agent_approval_hook = hooks::approval::ApprovalHook::new(approval_tx.clone());
            let agent_approval_hook = if let Some(ref dc) = discord_approval_config {
                agent_approval_hook.with_discord(dc.clone())
            } else {
                agent_approval_hook
            };
            agent_hook_registry.register(Arc::new(agent_approval_hook));

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
            eprintln!("[init]   agent '{}' registered", agent_profile.name);
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

    // --- Scheduler ---
    let _scheduler_handle = if config.scheduler.enabled && !config.scheduler.jobs.is_empty() {
        let scheduler = Scheduler::new();
        for job in &config.scheduler.jobs {
            let msg = job.message.clone();
            let cb: agentic_rs::scheduler::JobCallback = Arc::new(move || {
                let m = msg.clone();
                tokio::spawn(async move {
                    eprintln!("[scheduler] triggered: {}", m);
                })
            });
            match scheduler.add_job(&job.name, &job.schedule, cb).await {
                Ok(_) => eprintln!("[init] scheduled job: {} ({})", job.name, job.schedule),
                Err(e) => eprintln!("[init] failed to schedule {}: {}", job.name, e),
            }
        }
        Some(scheduler.start())
    } else {
        None
    };

    // --- Session event broadcast (for pushing cron results to WebSocket clients) ---
    let (session_events_tx, _) = tokio::sync::broadcast::channel::<String>(64);

    // --- Cron service tick loop ---
    let _cron_handle = if let Some(ref svc) = cron_service {
        let jobs = svc.list_jobs().await.unwrap_or_default();
        if !jobs.is_empty() {
            eprintln!("[init] cron: loaded {} jobs", jobs.len());
        }

        // Wire up the callback that runs when a cron job fires
        let rt = runtime.clone();
        let events_tx = session_events_tx.clone();
        let cron_callback: agentic_rs::cron::service::CronCallback =
            Arc::new(move |job| {
                let rt = rt.clone();
                let events_tx = events_tx.clone();
                tokio::spawn(async move {
                    let raw_prompt = match &job.payload {
                        CronPayload::AgentTurn { prompt } => prompt.clone(),
                        CronPayload::SystemEvent { message } => message.clone(),
                    };
                    // If the job targets an existing session (e.g. web:uuid),
                    // use that namespace directly so messages appear in the
                    // user's session. Otherwise prefix with cron: to create
                    // a dedicated cron session.
                    let is_web = job.namespace.starts_with("web:");
                    let ns = if is_web {
                        Namespace::parse(&job.namespace)
                    } else {
                        Namespace::parse(&format!("cron:{}", job.namespace))
                    };
                    // For web sessions, tell the LLM to just respond with text
                    // instead of trying to use Discord's send_message tool.
                    // Prefix with [cron] marker so the UI can style/hide it.
                    let prompt = if is_web {
                        format!(
                            "[cron:{}] {}\n\n\
                             (This is a scheduled task running in a web chat session. \
                             Respond with text directly — do not use send_message \
                             or any Discord tools.)",
                            job.name, raw_prompt
                        )
                    } else {
                        raw_prompt
                    };
                    eprintln!(
                        "[cron] Running job '{}' in namespace {}",
                        job.name,
                        ns.key()
                    );
                    let ns_key = ns.key();
                    let model = job.model.clone();
                    match rt.run_with_model(&ns, Message::user(&prompt), model).await {
                        Ok(result) => {
                            eprintln!(
                                "[cron] Job '{}' completed ({} turns)",
                                job.name,
                                result.turns.len()
                            );
                            // Notify WebSocket clients that this session was updated
                            if ns_key.starts_with("web:") {
                                let _ = events_tx.send(ns_key);
                            }
                        }
                        Err(e) => {
                            eprintln!("[cron] Job '{}' failed: {}", job.name, e);
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
        eprintln!("Connecting to Discord...");
        match discord_manager
            .connect(
                discord_token,
                &config.discord.filter,
                config.discord.allowed_users.clone(),
                &config.discord.namespace_prefix,
            )
            .await
        {
            Ok(()) => eprintln!("Connected! Listening for messages..."),
            Err(e) => {
                eprintln!("Failed to connect to Discord: {}", e);
                std::process::exit(1);
            }
        }
    }

    // --- Web UI (gateway) ---
    if !config.gateway.enabled {
        if !config.has_discord_token() {
            eprintln!("No Discord token and gateway is disabled. Nothing to run.");
            eprintln!("Enable the gateway or provide a Discord token in your config.");
            std::process::exit(1);
        }
        // Discord-only mode: wait for Ctrl+C
        eprintln!();
        eprintln!("=== {} — agentic-assistant v{} ===", default_agent_name, env!("CARGO_PKG_VERSION"));
        eprintln!("Press Ctrl+C to stop.");
        eprintln!();
        tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");
        eprintln!("\n[shutdown] Goodbye!");
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
        config.discord.token.as_ref()
            .filter(|t| !t.is_empty() && !t.starts_with("${"))
            .map(|t| agentic_rs::tools::discord::DiscordConfig::new(t)),
    ));

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
    };

    // --- Start ---
    eprintln!();
    eprintln!("=== {} — agentic-assistant v{} ===", default_agent_name, env!("CARGO_PKG_VERSION"));
    eprintln!("[init] web UI: http://{}:{}", config.gateway.host, config.gateway.port);

    if !dynamic_provider.is_configured() {
        eprintln!("[init] Provider not configured — visit the web UI to set your API key.");
    }
    if config.gateway.api_key.is_none() {
        eprintln!("[init] \u{26a0} Gateway has no API key — all endpoints are unauthenticated.");
        eprintln!("       Set [gateway] api_key in your config for production use.");
    }
    eprintln!("Web UI available at http://{}:{}", config.gateway.host, config.gateway.port);
    eprintln!("Press Ctrl+C to stop.");
    eprintln!();

    // Set up graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
        eprintln!("\n[shutdown] Received Ctrl+C, shutting down...");
        let _ = shutdown_tx.send(());
    });

    tokio::select! {
        result = web::serve(app_state, &config.gateway) => {
            if let Err(e) = result {
                eprintln!("[error] Web server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = &mut shutdown_rx => {
            discord_manager.disconnect().await;
            eprintln!("[shutdown] Goodbye!");
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
