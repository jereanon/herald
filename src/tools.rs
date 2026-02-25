pub mod claude_code;

// Re-export from the agentic library (used in delegation sub-agent setup).
use orra::tools::web_fetch;

use std::sync::Arc;

use orra::cron::CronService;
use orra::memory::{InMemoryMemoryStore, MemoryManager};
use orra::provider::Provider;
use orra::tool::ToolRegistry;
use orra::tools::browser::BrowserTool;
use orra::tools::delegation::{self, SubAgentConfig};
use orra::tools::discord::DiscordConfig;
use orra::tools::image_gen::DallEProvider;

use crate::config::Config;

/// Register all enabled tools into the registry based on config.
pub fn register_all(
    registry: &mut ToolRegistry,
    config: &Config,
    provider: &Arc<dyn Provider>,
    cron_service: Option<&Arc<CronService>>,
) {
    // Discord tools (from orra) — only if a token is configured
    if config.tools.discord {
        if let Some(ref token) = config.discord.token {
            if !token.is_empty() && !token.starts_with("${") {
                let dc = DiscordConfig::new(token);
                orra::tools::discord::register_tools(registry, &dc);
            }
        }
    }

    // Web fetch (from orra)
    if config.tools.web_fetch {
        orra::tools::web_fetch::register_tool(registry);
    }

    // Web search (from orra)
    if config.tools.web_search {
        if let Some(ref api_key) = config.tools.web_search_api_key {
            orra::tools::web_search::register_tool(registry, api_key);
        }
    }

    // Command execution (from orra)
    if config.tools.exec {
        orra::tools::exec::register_tool(
            registry,
            config.tools.exec_allowed_commands.clone(),
            config.tools.exec_timeout_secs,
        );
    }

    // Filesystem tools (from orra)
    if config.tools.filesystem {
        let fs_config = orra::tools::filesystem::FilesystemConfig {
            base_dir: config
                .tools
                .filesystem_base_dir
                .as_ref()
                .map(std::path::PathBuf::from),
            max_read_size: config.tools.filesystem_max_read_size,
            max_write_size: config.tools.filesystem_max_write_size,
            protected_paths: config.tools.filesystem_protected_paths.clone(),
            ..Default::default()
        };
        orra::tools::filesystem::register_tools(registry, fs_config);
    }

    // Browser/readability tool (from orra)
    if config.tools.browser {
        orra::tools::browser::register_tool(registry);
    }

    // Document knowledge tools (from orra)
    if config.tools.documents {
        let doc_store = Arc::new(orra::tools::documents::InMemoryDocumentStore::new());
        orra::tools::documents::register_tools(registry, doc_store);
    }

    // Memory tools (remember/recall/forget)
    if config.memory.enabled {
        let store = Arc::new(InMemoryMemoryStore::new());
        let manager = Arc::new(MemoryManager::new(store));
        orra::tools::memory::register_tools(registry, &manager);
    }

    // Cron tool (AI-managed scheduled tasks)
    if config.cron.enabled {
        if let Some(svc) = cron_service {
            orra::tools::cron::register_tool(registry, svc);
        }
    }

    // Image generation
    if config.tools.image_gen {
        if let Some(ref api_key) = config.tools.image_gen_api_key {
            let img_provider = Arc::new(DallEProvider::new(api_key));
            orra::tools::image_gen::register_tool(registry, img_provider);
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

    // Claude code delegation (local CLI, from orra)
    if config.tools.claude_code {
        let cc_config = orra::tools::claude_code::ClaudeCodeConfig {
            allowed_tools: config.tools.claude_code_allowed_tools.clone(),
            max_turns: config.tools.claude_code_max_turns,
            timeout_secs: config.tools.claude_code_timeout_secs,
            skip_permissions: config.tools.claude_code_skip_permissions,
            working_directory: config
                .tools
                .claude_code_working_directory
                .as_ref()
                .map(std::path::PathBuf::from),
        };
        orra::tools::claude_code::register_tools(registry, cc_config);
    }
}
