pub mod claude_code;

// Re-export from the agentic library (used in delegation sub-agent setup).
use agentic_rs::tools::web_fetch;

use std::sync::Arc;

use agentic_rs::cron::CronService;
use agentic_rs::memory::{InMemoryMemoryStore, MemoryManager};
use agentic_rs::provider::Provider;
use agentic_rs::tool::ToolRegistry;
use agentic_rs::tools::browser::BrowserTool;
use agentic_rs::tools::delegation::{self, SubAgentConfig};
use agentic_rs::tools::discord::DiscordConfig;
use agentic_rs::tools::image_gen::DallEProvider;

use crate::config::Config;

/// Register all enabled tools into the registry based on config.
pub fn register_all(
    registry: &mut ToolRegistry,
    config: &Config,
    provider: &Arc<dyn Provider>,
    cron_service: Option<&Arc<CronService>>,
) {
    // Discord tools (from agentic-rs) — only if a token is configured
    if config.tools.discord {
        if let Some(ref token) = config.discord.token {
            if !token.is_empty() && !token.starts_with("${") {
                let dc = DiscordConfig::new(token);
                agentic_rs::tools::discord::register_tools(registry, &dc);
            }
        }
    }

    // Web fetch (from agentic-rs)
    if config.tools.web_fetch {
        agentic_rs::tools::web_fetch::register_tool(registry);
    }

    // Web search (from agentic-rs)
    if config.tools.web_search {
        if let Some(ref api_key) = config.tools.web_search_api_key {
            agentic_rs::tools::web_search::register_tool(registry, api_key);
        }
    }

    // Command execution (from agentic-rs)
    if config.tools.exec {
        agentic_rs::tools::exec::register_tool(
            registry,
            config.tools.exec_allowed_commands.clone(),
            config.tools.exec_timeout_secs,
        );
    }

    // Browser/readability tool (from agentic-rs)
    if config.tools.browser {
        agentic_rs::tools::browser::register_tool(registry);
    }

    // Document knowledge tools (from agentic-rs)
    if config.tools.documents {
        let doc_store = Arc::new(agentic_rs::tools::documents::InMemoryDocumentStore::new());
        agentic_rs::tools::documents::register_tools(registry, doc_store);
    }

    // Memory tools (remember/recall/forget)
    if config.memory.enabled {
        let store = Arc::new(InMemoryMemoryStore::new());
        let manager = Arc::new(MemoryManager::new(store));
        agentic_rs::tools::memory::register_tools(registry, &manager);
    }

    // Cron tool (AI-managed scheduled tasks)
    if config.cron.enabled {
        if let Some(svc) = cron_service {
            agentic_rs::tools::cron::register_tool(registry, svc);
        }
    }

    // Image generation
    if config.tools.image_gen {
        if let Some(ref api_key) = config.tools.image_gen_api_key {
            let img_provider = Arc::new(DallEProvider::new(api_key));
            agentic_rs::tools::image_gen::register_tool(registry, img_provider);
        }
    }

    // Sub-agent delegation
    if config.tools.delegation {
        // Give the sub-agent a limited tool set (no recursion, no exec)
        let sub_tools = {
            let mut sub = ToolRegistry::new();
            if config.tools.web_fetch {
                sub.register(Box::new(web_fetch::WebFetchTool::new()));
            }
            if config.tools.browser {
                sub.register(Box::new(BrowserTool::new()));
            }
            sub
        };

        let runner = delegation::create_runner(
            provider.clone(),
            Arc::new(sub_tools),
            SubAgentConfig {
                max_turns: 5,
                ..Default::default()
            },
        );
        delegation::register_tool(registry, &runner);
    }

    // Claude code delegation (local CLI, from agentic-rs)
    if config.tools.claude_code {
        let cc_config = agentic_rs::tools::claude_code::ClaudeCodeConfig {
            allowed_tools: config.tools.claude_code_allowed_tools.clone(),
            max_turns: config.tools.claude_code_max_turns,
            timeout_secs: config.tools.claude_code_timeout_secs,
            skip_permissions: config.tools.claude_code_skip_permissions,
            working_directory: config.tools.claude_code_working_directory
                .as_ref()
                .map(std::path::PathBuf::from),
        };
        agentic_rs::tools::claude_code::register_tools(registry, cc_config);
    }
}
