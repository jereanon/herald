use orra::agent::AgentProfile;

use crate::config::Config;

/// Build the system prompt from the agent config.
///
/// If `agent.system_prompt` is explicitly set, that's used verbatim.
/// Otherwise, a prompt is auto-generated from the agent's name and personality,
/// plus contextual info about available tools.
pub fn build_system_prompt(config: &Config) -> String {
    let mut profile =
        AgentProfile::new(&config.agent.name).with_personality(&config.agent.personality);
    if let Some(ref prompt) = config.agent.system_prompt {
        profile = profile.with_system_prompt(prompt);
    }
    build_agent_system_prompt(&profile, config, &[])
}

/// Description of a remote agent for the system prompt.
pub struct RemoteAgentDesc {
    pub name: String,
    pub instance: String,
}

/// Build a system prompt for a specific agent profile.
///
/// `all_agent_names` should contain the names of all agents in the system,
/// used to inform this agent about its peers for delegation.
pub fn build_agent_system_prompt(
    agent: &AgentProfile,
    config: &Config,
    all_agent_names: &[String],
) -> String {
    build_agent_system_prompt_full(agent, config, all_agent_names, &[])
}

/// Build a system prompt with optional remote agent info (federation).
pub fn build_agent_system_prompt_full(
    agent: &AgentProfile,
    config: &Config,
    all_agent_names: &[String],
    remote_agents: &[RemoteAgentDesc],
) -> String {
    if let Some(ref custom) = agent.system_prompt {
        if !custom.is_empty() {
            return custom.clone();
        }
    }

    let name = &agent.name;
    let personality = &agent.personality;
    let now = chrono::Local::now().format("%A, %B %d, %Y");

    let mut tool_descriptions: Vec<&str> = Vec::new();
    let mut owned_descriptions: Vec<String> = Vec::new();

    if config.tools.discord {
        tool_descriptions.push(
            "Discord tools: You can list channels, read messages, send messages, \
             reply to messages, and get server info using the Discord tools.",
        );
    }

    if config.tools.web_fetch {
        tool_descriptions
            .push("Web fetch: You can fetch and read the content of any web page URL.");
    }

    if config.tools.browser {
        tool_descriptions.push(
            "Browser: You can read web pages and extract their main content, \
             stripping out navigation and ads for clean text.",
        );
    }

    if config.tools.web_search {
        tool_descriptions.push("Web search: You can search the web to find current information.");
    }

    if config.tools.exec {
        tool_descriptions.push(
            "Command execution: You can run shell commands to perform tasks. \
             Only whitelisted commands are available.",
        );
    }

    if config.tools.documents {
        tool_descriptions.push(
            "Document knowledge: You can search, read, and list documents \
             from the knowledge store.",
        );
    }

    if config.memory.enabled {
        tool_descriptions.push(
            "Memory: You can remember information for later, recall stored \
             memories by searching, and forget things that are no longer needed. \
             Use this to maintain context across conversations.",
        );
    }

    if config.tools.image_gen {
        tool_descriptions.push(
            "Image generation: You can create images from text descriptions \
             using DALL-E.",
        );
    }

    if config.tools.delegation {
        tool_descriptions.push(
            "Sub-agent delegation: You can spawn a sub-agent to handle complex \
             subtasks independently, then use its results in your response.",
        );
    }

    // Add peer agent delegation info for multi-agent setups
    {
        let peers: Vec<&String> = all_agent_names
            .iter()
            .filter(|n| !n.eq_ignore_ascii_case(&agent.name))
            .collect();
        if !peers.is_empty() {
            let peer_list = peers
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            owned_descriptions.push(format!(
                "Inter-agent delegation: You can delegate tasks to other agents using \
                 the delegate_to_agent tool. Available agents: {}. Use this when \
                 another agent is better suited for a task.",
                peer_list
            ));
        }
    }

    if config.tools.claude_code {
        tool_descriptions.push(
            "Claude Code: You can delegate coding tasks to a locally installed \
             Claude CLI agent that can read, edit, and test code autonomously. \
             Use claude_code for new tasks and claude_code_resume to continue \
             previous sessions using the returned session_id.",
        );
    }

    if config.cron.enabled {
        tool_descriptions.push(
            "Cron/Scheduling: You can create, manage, and delete scheduled tasks using the \
             cron tool. Users can ask you to set reminders, recurring checks, or scheduled \
             reports. You decide the appropriate schedule type:\n\
             - \"at\" for one-time tasks at a specific time (ISO-8601 datetime)\n\
             - \"every\" for repeating intervals (in milliseconds)\n\
             - \"cron\" for standard cron expressions (minute hour dom month dow)\n\
             Convert natural language time references (e.g. 'tomorrow at 6am', 'every weekday \
             at 9am') into the appropriate schedule. Use agent_turn payload for tasks that \
             need AI processing, and system_event for simple notifications.",
        );
    }

    if !config.mcp.servers.is_empty() {
        let names: Vec<&str> = config.mcp.servers.iter().map(|s| s.name.as_str()).collect();
        owned_descriptions.push(format!(
            "MCP integrations: You have tools provided by external MCP servers ({}). \
             Use them as you would any other tool.",
            names.join(", ")
        ));
    }

    // Federation: remote agents on peer instances
    if !remote_agents.is_empty() {
        // Group by instance
        let mut by_instance: std::collections::HashMap<&str, Vec<&str>> =
            std::collections::HashMap::new();
        for ra in remote_agents {
            by_instance
                .entry(ra.instance.as_str())
                .or_default()
                .push(ra.name.as_str());
        }
        let mut instance_descs: Vec<String> = by_instance
            .iter()
            .map(|(inst, names)| format!("{}: {}", inst, names.join(", ")))
            .collect();
        instance_descs.sort();

        owned_descriptions.push(format!(
            "Federation (remote agents): You can delegate tasks to agents on federated \
             herald instances using the delegate_to_remote_agent tool. Remote agents: {}. \
             Use 'peer:agent' for a specific instance or just the agent name to auto-route.",
            instance_descs.join("; ")
        ));
    }

    let tools_section = if tool_descriptions.is_empty() && owned_descriptions.is_empty() {
        String::new()
    } else {
        let mut all: Vec<&str> = tool_descriptions;
        for desc in &owned_descriptions {
            all.push(desc.as_str());
        }
        format!(
            "\n\nYou have access to the following capabilities:\n- {}",
            all.join("\n- ")
        )
    };

    format!(
        "You are {name}, a Discord assistant. Your personality is: {personality}.\n\
         Today is {now}.\n\
         \n\
         You are chatting in a Discord server. Keep your responses concise and \
         conversational — you're chatting, not writing essays. Use Discord \
         markdown formatting when appropriate (bold, italic, code blocks, etc.).\n\
         \n\
         When a user asks you something, respond directly. If you need more \
         information, use your tools to look it up before answering. If you're \
         unsure about something, say so rather than making things up.{tools_section}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn minimal_config() -> Config {
        Config {
            data_dir: std::path::PathBuf::from("./data"),
            agent: AgentConfig::default(),
            agents: Vec::new(),
            discord: DiscordConfig {
                token: Some("tok".into()),
                filter: crate::config::DiscordFilter::Mentions,
                namespace_prefix: "discord".into(),
                allowed_users: Vec::new(),
            },
            provider: ProviderConfig {
                api_key: Some("key".into()),
                model: "claude-opus-4-6".into(),
                max_tokens: 4096,
                temperature: 0.7,
                provider_type: crate::config::ProviderType::Claude,
                api_url: None,
                cheap_model: None,
            },
            tools: ToolsConfig::default(),
            sessions: SessionsConfig::default(),
            context: ContextConfig::default(),
            logging: LoggingConfig::default(),
            memory: MemoryConfig::default(),
            scheduler: SchedulerConfig::default(),
            gateway: GatewayConfig::default(),
            metrics: MetricsConfig::default(),
            mcp: McpConfig::default(),
            cron: CronConfig::default(),
            federation: FederationConfig::default(),
        }
    }

    #[test]
    fn auto_prompt_includes_name_and_personality() {
        let config = minimal_config();
        let prompt = build_system_prompt(&config);
        assert!(prompt.contains("Atlas"));
        assert!(prompt.contains("friendly, helpful, and concise"));
    }

    #[test]
    fn auto_prompt_includes_tool_descriptions() {
        let config = minimal_config();
        let prompt = build_system_prompt(&config);
        assert!(prompt.contains("Web fetch"));
        assert!(prompt.contains("Discord tools"));
        assert!(prompt.contains("Browser"));
        assert!(prompt.contains("Memory"));
        assert!(!prompt.contains("Command execution"));
        assert!(!prompt.contains("Web search"));
    }

    #[test]
    fn custom_system_prompt_overrides() {
        let mut config = minimal_config();
        config.agent.system_prompt = Some("You are a pirate.".into());
        let prompt = build_system_prompt(&config);
        assert_eq!(prompt, "You are a pirate.");
    }

    #[test]
    fn empty_custom_prompt_falls_back_to_auto() {
        let mut config = minimal_config();
        config.agent.system_prompt = Some(String::new());
        let prompt = build_system_prompt(&config);
        assert!(prompt.contains("Atlas"));
    }

    #[test]
    fn delegation_mentioned_when_enabled() {
        let mut config = minimal_config();
        config.tools.delegation = true;
        let prompt = build_system_prompt(&config);
        assert!(prompt.contains("Sub-agent delegation"));
    }

    #[test]
    fn claude_code_mentioned_when_enabled() {
        let mut config = minimal_config();
        config.tools.claude_code = true;
        let prompt = build_system_prompt(&config);
        assert!(prompt.contains("Claude Code"));
        assert!(prompt.contains("claude_code_resume"));
    }
}
