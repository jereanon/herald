use crate::hlog;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Re-export AgentProfile from the library as AgentProfileConfig for
/// backward compatibility within this crate.
pub use orra::agent::AgentProfile as AgentProfileConfig;

// ---------------------------------------------------------------------------
// Typed enums for config values (replaces raw strings)
// ---------------------------------------------------------------------------

/// LLM provider backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    Claude,
    #[serde(alias = "openai")]
    OpenAI,
}

impl Default for ProviderType {
    fn default() -> Self {
        Self::Claude
    }
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Claude => write!(f, "claude"),
            Self::OpenAI => write!(f, "openai"),
        }
    }
}

/// Discord message filter mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscordFilter {
    Mentions,
    All,
    Dm,
}

impl Default for DiscordFilter {
    fn default() -> Self {
        Self::Mentions
    }
}

impl fmt::Display for DiscordFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mentions => write!(f, "mentions"),
            Self::All => write!(f, "all"),
            Self::Dm => write!(f, "dm"),
        }
    }
}

/// Session persistence backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStoreType {
    File,
    Memory,
}

impl Default for SessionStoreType {
    fn default() -> Self {
        Self::File
    }
}

impl fmt::Display for SessionStoreType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => write!(f, "file"),
            Self::Memory => write!(f, "memory"),
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Base data directory for all persistent data (sessions, cron, etc.).
    /// Session and cron paths are resolved relative to this directory
    /// unless they are absolute paths.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Legacy single-agent config (backward compat). Prefer `agents`.
    #[serde(default)]
    pub agent: AgentConfig,
    /// Multi-agent profiles. If empty, falls back to `agent`.
    #[serde(default)]
    pub agents: Vec<AgentProfileConfig>,
    #[serde(default)]
    pub discord: DiscordConfig,
    #[serde(default)]
    pub provider: ProviderConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub sessions: SessionsConfig,
    #[serde(default)]
    pub context: ContextConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub cron: CronConfig,
    #[serde(default)]
    pub federation: FederationConfig,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

impl Config {
    /// Resolve the sessions path. If `sessions.path` is relative, it's
    /// resolved against `data_dir`. If absolute, used as-is.
    pub fn sessions_path(&self) -> PathBuf {
        if self.sessions.path.is_absolute() {
            self.sessions.path.clone()
        } else {
            self.data_dir.join(&self.sessions.path)
        }
    }

    /// Resolve the cron store path. If `cron.path` is relative, it's
    /// resolved against `data_dir`. If absolute, used as-is.
    pub fn cron_path(&self) -> PathBuf {
        if self.cron.path.is_absolute() {
            self.cron.path.clone()
        } else {
            self.data_dir.join(&self.cron.path)
        }
    }

    /// Returns true if a Discord token is configured and usable.
    pub fn has_discord_token(&self) -> bool {
        self.discord
            .token
            .as_ref()
            .map(|t| !t.is_empty() && !t.starts_with("${"))
            .unwrap_or(false)
    }

    /// Returns the resolved list of agent profiles.
    /// If `agents` is populated, use it. Otherwise, convert the legacy
    /// single `agent` config into one profile.
    pub fn resolved_agents(&self) -> Vec<AgentProfileConfig> {
        orra::agent::resolve_agents(
            &self.agents,
            Some(&self.agent.name),
            Some(&self.agent.personality),
            self.agent.system_prompt.as_deref(),
        )
    }

    /// Returns true if a provider API key is configured and usable.
    pub fn has_provider_key(&self) -> bool {
        self.provider
            .api_key
            .as_ref()
            .map(|k| !k.is_empty() && !k.starts_with("${"))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Section configs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_agent_name")]
    pub name: String,
    #[serde(default = "default_personality")]
    pub personality: String,
    /// If set, overrides the auto-generated system prompt entirely.
    pub system_prompt: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: default_agent_name(),
            personality: default_personality(),
            system_prompt: None,
        }
    }
}

fn default_agent_name() -> String {
    "Atlas".into()
}

fn default_personality() -> String {
    "friendly, helpful, and concise".into()
}

#[derive(Debug, Deserialize)]
pub struct DiscordConfig {
    /// Discord bot token. Optional — if not set, Discord is disabled and
    /// the web UI will be auto-enabled.
    pub token: Option<String>,
    #[serde(default)]
    pub filter: DiscordFilter,
    #[serde(default = "default_namespace_prefix")]
    pub namespace_prefix: String,
    /// List of Discord usernames allowed to DM the bot (used with filter = "dm").
    #[serde(default)]
    pub allowed_users: Vec<String>,
}

impl Default for DiscordConfig {
    fn default() -> Self {
        Self {
            token: None,
            filter: DiscordFilter::default(),
            namespace_prefix: default_namespace_prefix(),
            allowed_users: Vec::new(),
        }
    }
}

fn default_namespace_prefix() -> String {
    "discord".into()
}

#[derive(Debug, Deserialize)]
pub struct ProviderConfig {
    /// LLM provider API key. Optional — can be configured at runtime via
    /// the web UI's POST /api/config endpoint.
    pub api_key: Option<String>,
    #[serde(default = "default_model")]
    pub model: String,
    /// Optional cheap/fast model for lightweight tasks (e.g. cron triage).
    /// Falls back to `model` if not set.
    pub cheap_model: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    /// Provider backend: Claude (default) or OpenAI
    #[serde(default)]
    pub provider_type: ProviderType,
    /// Custom API URL (for OpenAI-compatible endpoints)
    pub api_url: Option<String>,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            model: default_model(),
            cheap_model: None,
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
            provider_type: ProviderType::default(),
            api_url: None,
        }
    }
}

fn default_model() -> String {
    "claude-opus-4-6".into()
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_temperature() -> f32 {
    0.7
}

#[derive(Debug, Deserialize)]
pub struct ToolsConfig {
    #[serde(default = "bool_true")]
    pub web_fetch: bool,
    #[serde(default)]
    pub web_search: bool,
    pub web_search_api_key: Option<String>,
    #[serde(default)]
    pub exec: bool,
    #[serde(default)]
    pub exec_allowed_commands: Vec<String>,
    #[serde(default = "default_exec_timeout")]
    pub exec_timeout_secs: u64,
    /// Enable filesystem tools (read_file, write_file, edit_file, list_dir)
    #[serde(default)]
    pub filesystem: bool,
    /// Base directory for filesystem sandboxing (if set, all paths confined here)
    pub filesystem_base_dir: Option<String>,
    /// Maximum file read size in bytes (default: 1 MB)
    #[serde(default = "default_fs_max_read")]
    pub filesystem_max_read_size: u64,
    /// Maximum file write size in bytes (default: 5 MB)
    #[serde(default = "default_fs_max_write")]
    pub filesystem_max_write_size: usize,
    /// Paths that cannot be written to
    #[serde(default)]
    pub filesystem_protected_paths: Vec<String>,
    #[serde(default = "bool_true")]
    pub discord: bool,
    #[serde(default)]
    pub documents: bool,
    /// Enable the read_url tool (HTML content extraction)
    #[serde(default = "bool_true")]
    pub browser: bool,
    /// Enable the image generation tool
    #[serde(default)]
    pub image_gen: bool,
    /// API key for image generation (OpenAI DALL-E key)
    pub image_gen_api_key: Option<String>,
    /// Enable the spawn_agent delegation tool
    #[serde(default)]
    pub delegation: bool,
    /// Enable claude code delegation (requires `claude` CLI installed)
    #[serde(default)]
    pub claude_code: bool,
    /// Tools allowed for claude code tasks
    #[serde(default = "default_claude_code_allowed_tools")]
    pub claude_code_allowed_tools: Vec<String>,
    /// Max agentic turns per claude code invocation
    #[serde(default = "default_claude_code_max_turns")]
    pub claude_code_max_turns: u32,
    /// Timeout in seconds for claude code tasks
    #[serde(default = "default_claude_code_timeout")]
    pub claude_code_timeout_secs: u64,
    /// Skip all permission checks (fully autonomous, use with caution)
    #[serde(default)]
    pub claude_code_skip_permissions: bool,
    /// Working directory for claude code tasks
    pub claude_code_working_directory: Option<String>,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            web_fetch: true,
            web_search: false,
            web_search_api_key: None,
            exec: false,
            exec_allowed_commands: Vec::new(),
            exec_timeout_secs: default_exec_timeout(),
            filesystem: false,
            filesystem_base_dir: None,
            filesystem_max_read_size: default_fs_max_read(),
            filesystem_max_write_size: default_fs_max_write(),
            filesystem_protected_paths: Vec::new(),
            discord: true,
            documents: false,
            browser: true,
            image_gen: false,
            image_gen_api_key: None,
            delegation: false,
            claude_code: false,
            claude_code_allowed_tools: default_claude_code_allowed_tools(),
            claude_code_max_turns: default_claude_code_max_turns(),
            claude_code_timeout_secs: default_claude_code_timeout(),
            claude_code_skip_permissions: false,
            claude_code_working_directory: None,
        }
    }
}

fn bool_true() -> bool {
    true
}

fn default_exec_timeout() -> u64 {
    30
}

fn default_fs_max_read() -> u64 {
    1_048_576
}

fn default_fs_max_write() -> usize {
    5_242_880
}

fn default_claude_code_allowed_tools() -> Vec<String> {
    vec!["Read".into(), "Edit".into(), "Bash".into()]
}

fn default_claude_code_max_turns() -> u32 {
    10
}

fn default_claude_code_timeout() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
pub struct SessionsConfig {
    #[serde(default)]
    pub store: SessionStoreType,
    #[serde(default = "default_sessions_path")]
    pub path: PathBuf,
}

impl Default for SessionsConfig {
    fn default() -> Self {
        Self {
            store: SessionStoreType::default(),
            path: default_sessions_path(),
        }
    }
}

fn default_sessions_path() -> PathBuf {
    PathBuf::from("sessions")
}

#[derive(Debug, Deserialize)]
pub struct ContextConfig {
    #[serde(default = "default_context_max_tokens")]
    pub max_tokens: usize,
    #[serde(default = "default_reserved_for_output")]
    pub reserved_for_output: usize,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            max_tokens: default_context_max_tokens(),
            reserved_for_output: default_reserved_for_output(),
        }
    }
}

fn default_context_max_tokens() -> usize {
    200_000
}

fn default_reserved_for_output() -> usize {
    4096
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Deserialize)]
pub struct MemoryConfig {
    /// Enable the memory tools (remember/recall/forget)
    #[serde(default = "bool_true")]
    pub enabled: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize)]
pub struct SchedulerConfig {
    /// Enable the cron-based task scheduler
    #[serde(default)]
    pub enabled: bool,
    /// Scheduled jobs in cron format
    #[serde(default)]
    pub jobs: Vec<ScheduledJobConfig>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jobs: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScheduledJobConfig {
    pub name: String,
    pub schedule: String,
    pub channel: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Enable the HTTP/WebSocket gateway
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gateway_host")]
    pub host: String,
    #[serde(default = "default_gateway_port")]
    pub port: u16,
    /// Optional API key for gateway authentication
    pub api_key: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_gateway_host(),
            port: default_gateway_port(),
            api_key: None,
        }
    }
}

fn default_gateway_host() -> String {
    "0.0.0.0".into()
}

fn default_gateway_port() -> u16 {
    8080
}

#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default)]
    pub enabled: bool,
    /// Log metrics to stderr periodically
    #[serde(default)]
    pub log_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_metrics: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CronConfig {
    /// Enable the AI-managed cron job system
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Path to store cron jobs (JSON file)
    #[serde(default = "default_cron_path")]
    pub path: PathBuf,
}

impl Default for CronConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_cron_path(),
        }
    }
}

fn default_cron_path() -> PathBuf {
    PathBuf::from("cron_jobs.json")
}

#[derive(Debug, Deserialize)]
pub struct McpConfig {
    /// MCP servers to connect to at startup.
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct McpServerConfig {
    /// Display name for this MCP server.
    pub name: String,
    /// Command to run the server (e.g. "npx", "python").
    pub command: String,
    /// Arguments to pass to the command.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to set for the server process.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

/// Federation config for connecting multiple herald instances.
///
/// When enabled, herald instances discover each other's agents and can route
/// requests to the best-suited instance. Peers communicate via:
/// - `GET /api/federation/agents` — discover remote agents
/// - `POST /api/federation/relay` — forward messages to remote agents
/// - `GET /api/federation/health` — health checks
///
/// Authentication uses a shared secret (bearer token). Discovery can be
/// automatic via mDNS on the local network, or manual via static peer config.
#[derive(Debug, Clone, Deserialize)]
pub struct FederationConfig {
    /// Enable federation with other instances.
    #[serde(default)]
    pub enabled: bool,

    /// Human-readable name for this instance. Appears in session labels and
    /// peer discovery. Defaults to the machine hostname.
    #[serde(default = "default_instance_name")]
    pub instance_name: String,

    /// Global shared secret for federation authentication. Required when
    /// federation is enabled (unless every peer has its own `shared_secret`).
    pub shared_secret: Option<String>,

    /// Port for the federation HTTP API. Defaults to `gateway.port + 1`.
    /// Only used when federation is enabled.
    pub port: Option<u16>,

    /// Enable mDNS discovery on the local network (`_herald._tcp.local.`).
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,

    /// Agent names to expose to peers. Empty list = expose all agents.
    #[serde(default)]
    pub exposed_agents: Vec<String>,

    /// Remote peer instances to connect to (static configuration).
    #[serde(default)]
    pub peers: Vec<FederationPeerConfig>,
}

fn default_instance_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "herald".into())
}

fn default_true() -> bool {
    true
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            instance_name: default_instance_name(),
            shared_secret: None,
            port: None,
            mdns_enabled: true,
            exposed_agents: Vec::new(),
            peers: Vec::new(),
        }
    }
}

impl FederationConfig {
    /// Resolve the federation port. Falls back to `gateway_port + 1`.
    pub fn resolve_port(&self, gateway_port: u16) -> u16 {
        self.port.unwrap_or(gateway_port + 1)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct FederationPeerConfig {
    /// Display name for this peer.
    pub name: String,
    /// URL of the remote instance (e.g. "http://other-machine:8081").
    pub url: String,
    /// Per-peer shared secret. Overrides the global `shared_secret` when
    /// communicating with this specific peer.
    pub shared_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("validation error: {0}")]
    Validation(String),
}

impl Config {
    /// Load a config from a TOML file, performing environment variable substitution.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;

        let expanded = substitute_env_vars(&raw);
        let mut config: Config = toml::from_str(&expanded)?;
        config.validate()?;

        // Allow HERALD_DATA_DIR env var to override the config file's data_dir.
        // This is used by the NixOS/nix-darwin modules to control where state
        // is written without editing the TOML.
        if let Ok(dir) = std::env::var("HERALD_DATA_DIR") {
            if !dir.is_empty() {
                config.data_dir = PathBuf::from(dir);
            }
        }

        // Auto-detect provider API key if none is configured.
        // Priority: 1) ANTHROPIC_API_KEY env var, 2) Claude CLI credentials
        if !config.has_provider_key() {
            if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
                if !key.is_empty() {
                    hlog!("[config] Auto-detected ANTHROPIC_API_KEY from environment");
                    config.provider.api_key = Some(key);
                }
            }
        }
        if !config.has_provider_key() {
            if let Some(key) = read_claude_cli_credentials() {
                hlog!("[config] Auto-detected API key from Claude CLI credentials");
                config.provider.api_key = Some(key);
            }
        }

        // Always auto-enable the web UI gateway so users can interact via
        // the browser regardless of whether Discord is also configured.
        if !config.gateway.enabled {
            config.gateway.enabled = true;
            hlog!(
                "[config] Auto-enabling web UI on {}:{}",
                config.gateway.host, config.gateway.port
            );
        }

        Ok(config)
    }

    /// Validate the loaded config.
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate optional tool keys only when their tools are enabled
        if self.tools.web_search {
            let key = self.tools.web_search_api_key.as_deref().unwrap_or("");
            if key.is_empty() || key.starts_with("${") {
                return Err(ConfigError::Validation(
                    "tools.web_search_api_key is required when web_search is enabled (set BRAVE_API_KEY env var)".into(),
                ));
            }
        }

        if self.tools.image_gen {
            let key = self.tools.image_gen_api_key.as_deref().unwrap_or("");
            if key.is_empty() || key.starts_with("${") {
                return Err(ConfigError::Validation(
                    "tools.image_gen_api_key is required when image_gen is enabled".into(),
                ));
            }
        }

        // Discord filter: "dm" requires allowed_users
        if self.discord.filter == DiscordFilter::Dm && self.discord.allowed_users.is_empty() {
            return Err(ConfigError::Validation(
                "discord.allowed_users must not be empty when filter is \"dm\"".into(),
            ));
        }

        // provider_type and sessions.store are now enums — serde rejects
        // invalid values at parse time, so no manual validation needed.

        // Federation: require a shared secret when enabled
        if self.federation.enabled {
            let has_global = self
                .federation
                .shared_secret
                .as_deref()
                .is_some_and(|s| !s.is_empty() && !s.starts_with("${"));

            let all_peers_have_secret = !self.federation.peers.is_empty()
                && self.federation.peers.iter().all(|p| {
                    p.shared_secret
                        .as_deref()
                        .is_some_and(|s| !s.is_empty() && !s.starts_with("${"))
                });

            if !has_global && !all_peers_have_secret {
                return Err(ConfigError::Validation(
                    "federation.shared_secret is required when federation is enabled \
                     (or each peer must have its own shared_secret)"
                        .into(),
                ));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Environment variable substitution
// ---------------------------------------------------------------------------

fn substitute_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut var_name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                var_name.push(c);
            }
            match std::env::var(&var_name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    result.push_str(&format!("${{{}}}", var_name));
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Claude CLI credential detection
// ---------------------------------------------------------------------------

/// Claude Code OAuth client ID (public, used for PKCE flow).
const CLAUDE_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

/// Attempt to read an API key from the locally installed Claude CLI.
///
/// Credential sources (tried in order):
/// 1. macOS keychain (`security find-generic-password` for "Claude Code-credentials")
/// 2. `~/.claude/.credentials.json` (Linux / fallback on any platform)
///
/// The access token (`sk-ant-oat01-...`) works as a Bearer token against the
/// Anthropic API. If the token is expired, we attempt a refresh and persist
/// the updated credentials back to the original store.
pub(crate) fn read_claude_cli_credentials() -> Option<String> {
    // Try macOS keychain first (only compiled on macOS)
    #[cfg(target_os = "macos")]
    {
        if let Some(token) = read_claude_cli_credentials_macos() {
            return Some(token);
        }
    }

    // Fall back to the credentials file (works on all platforms)
    read_claude_cli_credentials_file()
}

// ---- Credentials file backend (Linux / universal fallback) ----------------

/// Read Claude CLI credentials from a JSON file.
///
/// Checks the following locations in order:
/// 1. `CLAUDE_CREDENTIALS_FILE` env var (explicit path override)
/// 2. `~/.claude/.credentials.json` (default Claude CLI location on Linux)
///
/// On Linux (and Windows), Claude Code writes OAuth tokens to this JSON file
/// instead of using a system keychain. The format is identical to the macOS
/// keychain entry:
/// ```json
/// {"claudeAiOauth":{"accessToken":"sk-ant-oat01-...","refreshToken":"...","expiresAt":...}}
/// ```
fn read_claude_cli_credentials_file() -> Option<String> {
    let creds_path = if let Ok(explicit) = std::env::var("CLAUDE_CREDENTIALS_FILE") {
        PathBuf::from(explicit)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        PathBuf::from(&home).join(".claude").join(".credentials.json")
    };

    let json_str = match std::fs::read_to_string(&creds_path) {
        Ok(s) => s,
        Err(e) => {
            hlog!("[config] cannot read {}: {}", creds_path.display(), e);
            return None;
        }
    };
    let json_str = json_str.trim();

    if json_str.is_empty() {
        hlog!("[config] credentials file is empty: {}", creds_path.display());
        return None;
    }

    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            hlog!("[config] credentials file parse error: {}", e);
            return None;
        }
    };
    extract_oauth_token(&parsed, &CredentialStore::File(creds_path))
}

// ---- macOS keychain backend -----------------------------------------------

#[cfg(target_os = "macos")]
fn read_claude_cli_credentials_macos() -> Option<String> {
    // Claude Code stores OAuth credentials in the macOS keychain under the
    // service "Claude Code-credentials". The account name varies by version:
    //   - Newer versions use the user's account name (e.g. "jeremy")
    //   - Older versions use "Claude Code"
    // We try the current OS username first, then fall back to "Claude Code".
    let accounts_to_try: Vec<String> = {
        let mut v = Vec::new();
        if let Ok(user) = std::env::var("USER") {
            v.push(user);
        }
        v.push("Claude Code".to_string());
        v
    };

    for account in &accounts_to_try {
        if let Some(token) = try_keychain_account(account) {
            return Some(token);
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn try_keychain_account(account: &str) -> Option<String> {
    let output = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-a",
            account,
            "-w",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let json_str = String::from_utf8(output.stdout).ok()?;
    let json_str = json_str.trim();

    if json_str.is_empty() {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    extract_oauth_token(
        &parsed,
        &CredentialStore::Keychain(account.to_string()),
    )
}

// ---- Shared token extraction & refresh ------------------------------------

/// Where the credentials came from, so we can write refreshed tokens back.
enum CredentialStore {
    /// `~/.claude/.credentials.json`
    File(PathBuf),
    /// macOS keychain account name
    #[cfg(target_os = "macos")]
    Keychain(String),
}

/// Extract the OAuth access token from parsed credentials JSON. Handles
/// expiry checking and automatic refresh regardless of the backing store.
fn extract_oauth_token(
    parsed: &serde_json::Value,
    store: &CredentialStore,
) -> Option<String> {
    let oauth = match parsed.get("claudeAiOauth") {
        Some(v) => v,
        None => {
            hlog!("[config] credentials missing 'claudeAiOauth' key");
            return None;
        }
    };
    let token = match oauth.get("accessToken").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            hlog!("[config] credentials missing 'accessToken'");
            return None;
        }
    };

    if token.is_empty() {
        hlog!("[config] credentials accessToken is empty");
        return None;
    }

    // Check if the token is expired (or about to expire within 5 minutes)
    if let Some(expires_at) = oauth.get("expiresAt").and_then(|v| v.as_u64()) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let buffer_ms = 5 * 60 * 1000; // 5 minutes

        if now_ms + buffer_ms > expires_at {
            let expired_ago = (now_ms.saturating_sub(expires_at)) / 1000 / 60;
            hlog!("[config] OAuth token expired {}m ago, attempting refresh...", expired_ago);

            // Token is expired or expiring soon — try to refresh
            if let Some(refresh_token) = oauth.get("refreshToken").and_then(|v| v.as_str()) {
                if let Some(new_token) = refresh_oauth_token(store, refresh_token, parsed) {
                    return Some(new_token);
                }
                hlog!("[config] OAuth token refresh failed — see errors above");
                return None;
            }
            hlog!("[config] no refreshToken in credentials, cannot refresh");
            return None;
        }
    }

    Some(token.to_string())
}

/// Refresh an expired OAuth token and persist the updated credentials.
fn refresh_oauth_token(
    store: &CredentialStore,
    refresh_token: &str,
    current_creds: &serde_json::Value,
) -> Option<String> {
    // POST to Anthropic's OAuth token endpoint using reqwest (no curl dependency)
    let body = format!(
        "grant_type=refresh_token&refresh_token={}&client_id={}",
        refresh_token, CLAUDE_OAUTH_CLIENT_ID
    );

    let client = reqwest::blocking::Client::new();
    let http_resp = match client
        .post("https://console.anthropic.com/v1/oauth/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            hlog!("[config] OAuth refresh HTTP request failed: {}", e);
            return None;
        }
    };

    let status = http_resp.status();
    let resp_str = match http_resp.text() {
        Ok(t) => t,
        Err(e) => {
            hlog!("[config] failed to read refresh response body: {}", e);
            return None;
        }
    };

    if !status.is_success() {
        hlog!(
            "[config] OAuth refresh returned HTTP {}: {}",
            status,
            &resp_str[..resp_str.len().min(200)]
        );
    }

    let resp: serde_json::Value = match serde_json::from_str(resp_str.trim()) {
        Ok(v) => v,
        Err(e) => {
            hlog!("[config] refresh response parse error: {}", e);
            hlog!("[config] raw response: {}", &resp_str[..resp_str.len().min(200)]);
            return None;
        }
    };

    // Check for OAuth error response (HTTP 200 with error body)
    if let Some(error) = resp.get("error").and_then(|v| v.as_str()) {
        let desc = resp
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("(no description)");
        hlog!("[config] OAuth refresh error: {} — {}", error, desc);
        return None;
    }

    let new_access = match resp.get("access_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            hlog!("[config] refresh response missing 'access_token'");
            return None;
        }
    };
    let new_refresh = match resp.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            hlog!("[config] refresh response missing 'refresh_token'");
            return None;
        }
    };
    let expires_in = resp
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(28800);

    // Calculate new expiry
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let new_expires_at = now_ms + (expires_in * 1000);

    // Update the credentials JSON
    let mut updated = current_creds.clone();
    if let Some(oauth) = updated.get_mut("claudeAiOauth") {
        oauth["accessToken"] = serde_json::Value::String(new_access.to_string());
        oauth["refreshToken"] = serde_json::Value::String(new_refresh.to_string());
        oauth["expiresAt"] = serde_json::Value::Number(serde_json::Number::from(new_expires_at));
    }

    // Persist updated credentials back to the original store
    let persisted = persist_credentials(store, &updated);

    if persisted {
        hlog!(
            "[config] OAuth token refreshed successfully (expires in {}h)",
            expires_in / 3600
        );
    } else {
        hlog!("[config] OAuth token refreshed but credential store update failed");
    }

    // Return the new token regardless of whether persistence succeeded —
    // it's still valid for this process's lifetime.
    Some(new_access.to_string())
}

/// Write updated credentials back to the backing store.
fn persist_credentials(store: &CredentialStore, creds: &serde_json::Value) -> bool {
    match store {
        CredentialStore::File(path) => {
            let json = match serde_json::to_string_pretty(creds) {
                Ok(j) => j,
                Err(_) => return false,
            };
            std::fs::write(path, json).is_ok()
        }
        #[cfg(target_os = "macos")]
        CredentialStore::Keychain(account) => {
            let json = match serde_json::to_string(creds) {
                Ok(j) => j,
                Err(_) => return false,
            };
            // Delete old entry, then add new one
            let _ = std::process::Command::new("security")
                .args([
                    "delete-generic-password",
                    "-s",
                    "Claude Code-credentials",
                    "-a",
                    account,
                ])
                .output();

            std::process::Command::new("security")
                .args([
                    "add-generic-password",
                    "-s",
                    "Claude Code-credentials",
                    "-a",
                    account,
                    "-w",
                    &json,
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Config file persistence
// ---------------------------------------------------------------------------

/// Save a Discord token to the TOML config file.
///
/// Uses simple string manipulation to avoid needing a TOML serializer
/// (which would lose comments and formatting).
pub(crate) fn save_discord_token(path: &Path, token: &str) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let new_line = format!("token = \"{}\"", token);
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut in_discord_section = false;
    let mut token_replaced = false;
    let mut discord_section_end = None;

    for (i, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();

        // Track which section we're in
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if trimmed == "[discord]" {
                in_discord_section = true;
                continue;
            } else if in_discord_section {
                // We've left the discord section
                discord_section_end = Some(i);
                in_discord_section = false;
            }
        }

        if in_discord_section {
            // Replace existing token line (commented or not)
            if trimmed.starts_with("token") || trimmed.starts_with("# token") {
                *line = new_line.clone();
                token_replaced = true;
                break;
            }
        }
    }

    // Still in discord section at EOF
    if in_discord_section && !token_replaced {
        lines.push(new_line.clone());
        token_replaced = true;
    }

    // If token wasn't found in an existing discord section, insert it
    if !token_replaced {
        if let Some(end) = discord_section_end {
            lines.insert(end, new_line.clone());
        } else {
            // No [discord] section exists — add one
            lines.push(String::new());
            lines.push("[discord]".to_string());
            lines.push(new_line);
        }
    }

    let result = lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Remove (comment out) the Discord token from the TOML config file.
pub(crate) fn remove_discord_token(path: &Path) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut in_discord_section = false;

    for line in lines.iter_mut() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            in_discord_section = trimmed == "[discord]";
            continue;
        }

        if in_discord_section && trimmed.starts_with("token") {
            *line = format!("# {}", trimmed);
            break;
        }
    }

    let result = lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Save Discord filter and allowed_users to the TOML config file.
pub(crate) fn save_discord_settings(
    path: &Path,
    filter: &str,
    allowed_users: &[String],
) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut in_discord_section = false;
    let mut filter_replaced = false;
    let mut users_replaced = false;
    let mut discord_section_end = None;

    for i in 0..lines.len() {
        let trimmed = lines[i].trim().to_string();

        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if trimmed == "[discord]" {
                in_discord_section = true;
                continue;
            } else if in_discord_section {
                discord_section_end = Some(i);
                in_discord_section = false;
            }
        }

        if in_discord_section {
            if trimmed.starts_with("filter") || trimmed.starts_with("# filter") {
                lines[i] = format!("filter = \"{}\"", filter);
                filter_replaced = true;
            }
            if trimmed.starts_with("allowed_users") || trimmed.starts_with("# allowed_users") {
                let users_toml: Vec<String> =
                    allowed_users.iter().map(|u| format!("\"{}\"", u)).collect();
                lines[i] = format!("allowed_users = [{}]", users_toml.join(", "));
                users_replaced = true;
            }
        }
    }

    // Insert missing keys at the end of the discord section (or at EOF)
    let insert_pos = if in_discord_section {
        // Still in discord section at EOF
        lines.len()
    } else {
        discord_section_end.unwrap_or(lines.len())
    };

    let mut insertions = Vec::new();
    if !users_replaced {
        let users_toml: Vec<String> = allowed_users.iter().map(|u| format!("\"{}\"", u)).collect();
        insertions.push(format!("allowed_users = [{}]", users_toml.join(", ")));
    }
    if !filter_replaced {
        insertions.push(format!("filter = \"{}\"", filter));
    }

    for (offset, line) in insertions.into_iter().enumerate() {
        lines.insert(insert_pos + offset, line);
    }

    let result = lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Save agent profiles to the TOML config file.
///
/// Replaces any existing `[[agents]]` array (and the legacy `[agent]` section)
/// with the new list of agents.
pub(crate) fn save_agents(path: &Path, agents: &[AgentProfileConfig]) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut result_lines: Vec<String> = Vec::new();
    let mut skip_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect section headers
        if trimmed.starts_with('[') {
            if trimmed == "[agent]" || trimmed == "[[agents]]" {
                skip_section = true;
                continue;
            } else {
                skip_section = false;
            }
        }

        if skip_section {
            continue;
        }

        result_lines.push(line.to_string());
    }

    // Remove trailing blank lines
    while result_lines
        .last()
        .map(|l| l.trim().is_empty())
        .unwrap_or(false)
    {
        result_lines.pop();
    }

    // Append new agent profiles
    for agent in agents {
        result_lines.push(String::new());
        result_lines.push("[[agents]]".to_string());
        result_lines.push(format!("name = \"{}\"", agent.name));
        result_lines.push(format!(
            "personality = \"{}\"",
            agent.personality.replace('"', "\\\"")
        ));
        if let Some(ref prompt) = agent.system_prompt {
            // Use triple-quoted string for multi-line prompts
            if prompt.contains('\n') {
                result_lines.push(format!("system_prompt = \"\"\"{}\"\"\"", prompt));
            } else {
                result_lines.push(format!(
                    "system_prompt = \"{}\"",
                    prompt.replace('"', "\\\"")
                ));
            }
        }
        if let Some(ref model) = agent.model {
            result_lines.push(format!("model = \"{}\"", model));
        }
    }

    result_lines.push(String::new());
    let result = result_lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Federation config persistence
// ---------------------------------------------------------------------------

/// Settings that can be saved to the `[federation]` section of the TOML config.
pub(crate) struct FederationSettingsUpdate {
    pub enabled: bool,
    pub instance_name: Option<String>,
    /// `None` = don't change existing secret; `Some("")` would clear it.
    pub shared_secret: Option<String>,
    pub mdns_enabled: bool,
    pub port: Option<u16>,
    pub exposed_agents: Vec<String>,
}

/// Save federation settings to the `[federation]` section, preserving file
/// structure and comments on unrelated lines.
pub(crate) fn save_federation_settings(
    path: &Path,
    settings: &FederationSettingsUpdate,
) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut in_federation_section = false;
    let mut federation_section_start = None;
    let mut federation_section_end = None;

    // Track which fields we've replaced
    let mut enabled_replaced = false;
    let mut instance_name_replaced = false;
    let mut secret_replaced = false;
    let mut mdns_replaced = false;
    let mut port_replaced = false;
    let mut exposed_replaced = false;

    for i in 0..lines.len() {
        let trimmed = lines[i].trim().to_string();

        if trimmed.starts_with('[') {
            if trimmed == "[federation]" {
                in_federation_section = true;
                federation_section_start = Some(i);
                continue;
            } else if trimmed.starts_with("[[federation.") {
                // Sub-array like [[federation.peers]] — end of main section
                if in_federation_section {
                    federation_section_end = Some(i);
                    in_federation_section = false;
                }
                continue;
            } else if in_federation_section {
                federation_section_end = Some(i);
                in_federation_section = false;
            }
        }

        if in_federation_section {
            if trimmed.starts_with("enabled") || trimmed.starts_with("# enabled") {
                lines[i] = format!("enabled = {}", settings.enabled);
                enabled_replaced = true;
            } else if trimmed.starts_with("instance_name") || trimmed.starts_with("# instance_name")
            {
                if let Some(ref name) = settings.instance_name {
                    lines[i] = format!("instance_name = \"{}\"", name);
                }
                instance_name_replaced = true;
            } else if trimmed.starts_with("shared_secret")
                || trimmed.starts_with("# shared_secret")
            {
                if let Some(ref secret) = settings.shared_secret {
                    lines[i] = format!("shared_secret = \"{}\"", secret);
                }
                secret_replaced = true;
            } else if trimmed.starts_with("mdns_enabled") || trimmed.starts_with("# mdns_enabled")
            {
                lines[i] = format!("mdns_enabled = {}", settings.mdns_enabled);
                mdns_replaced = true;
            } else if trimmed.starts_with("port") || trimmed.starts_with("# port") {
                match settings.port {
                    Some(p) => lines[i] = format!("port = {}", p),
                    None => lines[i] = "# port = 8081".to_string(),
                }
                port_replaced = true;
            } else if trimmed.starts_with("exposed_agents")
                || trimmed.starts_with("# exposed_agents")
            {
                if settings.exposed_agents.is_empty() {
                    lines[i] = "exposed_agents = []".to_string();
                } else {
                    let agents: Vec<String> = settings
                        .exposed_agents
                        .iter()
                        .map(|a| format!("\"{}\"", a))
                        .collect();
                    lines[i] = format!("exposed_agents = [{}]", agents.join(", "));
                }
                exposed_replaced = true;
            }
        }
    }

    // If we were still in the section at EOF
    if in_federation_section {
        federation_section_end = Some(lines.len());
    }

    // Insert any missing fields at the end of the federation section
    let insert_pos = federation_section_end.unwrap_or(lines.len());

    let mut insertions = Vec::new();
    if !exposed_replaced {
        if settings.exposed_agents.is_empty() {
            insertions.push("exposed_agents = []".to_string());
        } else {
            let agents: Vec<String> = settings
                .exposed_agents
                .iter()
                .map(|a| format!("\"{}\"", a))
                .collect();
            insertions.push(format!("exposed_agents = [{}]", agents.join(", ")));
        }
    }
    if !port_replaced {
        if let Some(p) = settings.port {
            insertions.push(format!("port = {}", p));
        }
    }
    if !mdns_replaced {
        insertions.push(format!("mdns_enabled = {}", settings.mdns_enabled));
    }
    if !secret_replaced {
        if let Some(ref secret) = settings.shared_secret {
            insertions.push(format!("shared_secret = \"{}\"", secret));
        }
    }
    if !instance_name_replaced {
        if let Some(ref name) = settings.instance_name {
            insertions.push(format!("instance_name = \"{}\"", name));
        }
    }
    if !enabled_replaced {
        insertions.push(format!("enabled = {}", settings.enabled));
    }

    if federation_section_start.is_none() {
        // No [federation] section exists — create one
        lines.push(String::new());
        lines.push("[federation]".to_string());
        lines.push(format!("enabled = {}", settings.enabled));
        if let Some(ref name) = settings.instance_name {
            lines.push(format!("instance_name = \"{}\"", name));
        }
        if let Some(ref secret) = settings.shared_secret {
            lines.push(format!("shared_secret = \"{}\"", secret));
        }
        lines.push(format!("mdns_enabled = {}", settings.mdns_enabled));
        if let Some(p) = settings.port {
            lines.push(format!("port = {}", p));
        }
        if !settings.exposed_agents.is_empty() {
            let agents: Vec<String> = settings
                .exposed_agents
                .iter()
                .map(|a| format!("\"{}\"", a))
                .collect();
            lines.push(format!("exposed_agents = [{}]", agents.join(", ")));
        }
    } else {
        for (offset, line) in insertions.into_iter().enumerate() {
            lines.insert(insert_pos + offset, line);
        }
    }

    let result = lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Save federation peer list to the config file. Removes all existing
/// `[[federation.peers]]` entries and rewrites them.
pub(crate) fn save_federation_peers(
    path: &Path,
    peers: &[FederationPeerConfig],
) -> Result<(), ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut result_lines: Vec<String> = Vec::new();
    let mut skip_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            if trimmed == "[[federation.peers]]" {
                skip_section = true;
                continue;
            } else {
                skip_section = false;
            }
        }

        if skip_section {
            continue;
        }

        result_lines.push(line.to_string());
    }

    // Remove trailing blank lines
    while result_lines
        .last()
        .map(|l| l.trim().is_empty())
        .unwrap_or(false)
    {
        result_lines.pop();
    }

    // Append new peer entries
    for peer in peers {
        result_lines.push(String::new());
        result_lines.push("[[federation.peers]]".to_string());
        result_lines.push(format!("name = \"{}\"", peer.name));
        result_lines.push(format!("url = \"{}\"", peer.url));
        if let Some(ref secret) = peer.shared_secret {
            if !secret.is_empty() {
                result_lines.push(format!("shared_secret = \"{}\"", secret));
            }
        }
    }

    result_lines.push(String::new());
    let result = result_lines.join("\n");
    std::fs::write(path, &result).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Read federation settings from the TOML config file (for pre-filling the UI
/// form even when federation is not currently running).
pub(crate) fn read_federation_settings(path: &Path) -> Result<FederationConfig, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let expanded = substitute_env_vars(&content);
    let config: Config = toml::from_str(&expanded)?;
    Ok(config.federation)
}

/// Read the Discord token from the TOML config file (without full Config::load).
pub(crate) fn read_discord_token(path: &Path) -> Result<Option<String>, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;

    let expanded = substitute_env_vars(&content);
    let config: Config = toml::from_str(&expanded)?;
    Ok(config
        .discord
        .token
        .filter(|t| !t.is_empty() && !t.starts_with("${")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_substitution() {
        std::env::set_var("TEST_AGENTIC_VAR", "hello");
        let input = "key = \"${TEST_AGENTIC_VAR}\"";
        let result = substitute_env_vars(input);
        assert_eq!(result, "key = \"hello\"");
        std::env::remove_var("TEST_AGENTIC_VAR");
    }

    #[test]
    fn env_var_missing_left_as_placeholder() {
        let input = "key = \"${DEFINITELY_NOT_SET_XYZ}\"";
        let result = substitute_env_vars(input);
        assert_eq!(result, "key = \"${DEFINITELY_NOT_SET_XYZ}\"");
    }

    #[test]
    fn no_env_vars_untouched() {
        let input = "key = \"plain value\"";
        let result = substitute_env_vars(input);
        assert_eq!(result, input);
    }

    #[test]
    fn default_values_populated() {
        let toml_str = r#"
[discord]
token = "test-token"

[provider]
api_key = "test-key"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.agent.name, "Atlas");
        assert_eq!(config.discord.filter, DiscordFilter::Mentions);
        assert_eq!(config.provider.model, "claude-opus-4-6");
        assert_eq!(config.provider.provider_type, ProviderType::Claude);
        assert_eq!(config.provider.max_tokens, 4096);
        assert!(config.tools.web_fetch);
        assert!(config.tools.browser);
        assert!(!config.tools.exec);
        assert!(!config.tools.image_gen);
        assert!(config.memory.enabled);
        assert!(!config.scheduler.enabled);
        assert!(!config.gateway.enabled);
        assert_eq!(config.sessions.store, SessionStoreType::File);
    }

    #[test]
    fn empty_config_is_valid() {
        // Minimal config with no credentials — should parse and validate OK
        let toml_str = "";
        let config: Config = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();
        assert!(!config.has_discord_token());
        assert!(!config.has_provider_key());
    }

    #[test]
    fn has_discord_token_checks() {
        let toml_str = r#"
[discord]
token = "valid-token"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.has_discord_token());

        // Unresolved env var
        let toml_str2 = r#"
[discord]
token = "${UNSET_VAR}"
"#;
        let config2: Config = toml::from_str(toml_str2).unwrap();
        assert!(!config2.has_discord_token());
    }

    #[test]
    fn has_provider_key_checks() {
        let toml_str = r#"
[provider]
api_key = "sk-test"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.has_provider_key());

        let empty: Config = toml::from_str("").unwrap();
        assert!(!empty.has_provider_key());
    }

    #[test]
    fn serde_rejects_invalid_provider_type() {
        let toml_str = r#"
[provider]
api_key = "key"
provider_type = "gpt-local"
"#;
        // Invalid enum variant is caught at parse time, not validation
        assert!(toml::from_str::<Config>(toml_str).is_err());
    }

    #[test]
    fn enum_display_formats() {
        assert_eq!(ProviderType::Claude.to_string(), "claude");
        assert_eq!(ProviderType::OpenAI.to_string(), "openai");
        assert_eq!(DiscordFilter::Mentions.to_string(), "mentions");
        assert_eq!(DiscordFilter::All.to_string(), "all");
        assert_eq!(DiscordFilter::Dm.to_string(), "dm");
        assert_eq!(SessionStoreType::File.to_string(), "file");
        assert_eq!(SessionStoreType::Memory.to_string(), "memory");
    }
}
