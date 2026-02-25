pub mod handlers;
pub mod ws;

use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use axum::http::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use rust_embed::Embed;
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;

use orra::channels::gateway::GatewayChannel;
use orra::context::CharEstimator;
use orra::cron::CronService;
use orra::runtime::Runtime;
use orra::store::SessionStore;
use orra::tools::discord::DiscordConfig as DiscordApiConfig;

use crate::config::{AgentProfileConfig, GatewayConfig};
use crate::discord_manager::DiscordManager;
use crate::federation::manager::FederationManager;
use crate::provider_wrapper::DynamicProvider;
use crate::update::UpdateChecker;

// ---------------------------------------------------------------------------
// Embedded static files
// ---------------------------------------------------------------------------

#[derive(Embed)]
#[folder = "src/web/static/"]
struct StaticAssets;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<GatewayChannel>,
    pub runtime: Arc<Runtime<CharEstimator>>,
    pub store: Arc<dyn SessionStore>,
    /// The dynamic provider, allowing hot-swap at runtime via POST /api/config.
    pub dynamic_provider: Arc<DynamicProvider>,
    /// Default provider type from config (used when creating providers at runtime).
    pub config_provider_type: crate::config::ProviderType,
    /// Default model from config.
    pub config_model: String,
    /// Custom API URL from config (for OpenAI-compatible endpoints).
    pub config_api_url: Option<String>,
    /// How the provider was authenticated (cli/env/config/web_ui/none).
    pub auth_source: Arc<RwLock<String>>,
    /// Path to the config file for persistence.
    pub config_path: PathBuf,
    /// Manages the Discord bot connection lifecycle (connect/disconnect/reconnect).
    pub discord_manager: Arc<DiscordManager>,
    /// The cron service for scheduled jobs (None if disabled).
    pub cron_service: Option<Arc<CronService>>,
    /// Discord API config for channel listing (None if not configured).
    pub discord_api: Arc<RwLock<Option<DiscordApiConfig>>>,
    /// Broadcast channel for session update notifications (e.g. from cron jobs).
    /// Carries the namespace key of the session that was updated.
    pub session_events: broadcast::Sender<String>,
    /// Named agent runtimes. Key is lowercase agent name, value is the runtime.
    /// If empty, only `runtime` is used (single-agent mode).
    pub runtimes: Arc<RwLock<std::collections::HashMap<String, Arc<Runtime<CharEstimator>>>>>,
    /// The name of the default agent (first in the list).
    pub default_agent: Arc<RwLock<String>>,
    /// Agent profiles for the CRUD API.
    pub agent_profiles: Arc<RwLock<Vec<AgentProfileConfig>>>,
    /// Receiver for tool approval requests from the ApprovalHook.
    /// The WebSocket handler takes this to relay approval requests to the client.
    pub approval_rx: Arc<
        tokio::sync::Mutex<tokio::sync::mpsc::Receiver<crate::hooks::approval::ApprovalRequest>>,
    >,
    /// Federation manager — handles hot-reload of federation settings.
    pub federation_manager: Arc<FederationManager>,
    /// The gateway port (needed for federation port computation on hot-reload).
    pub gateway_port: u16,
    /// Background update checker for version monitoring.
    pub update_checker: Arc<UpdateChecker>,
    /// Data directory for staging update downloads.
    pub data_dir: PathBuf,
    /// Count of active interactive chat requests.
    /// Used by the cron callback to defer execution when chat is active.
    pub interactive_count: Arc<AtomicUsize>,
    /// OAuth token refresh callback (if CLI credentials are in use).
    /// Shared with handlers so newly swapped providers can also auto-refresh.
    pub refresh_callback: Option<crate::refreshable_provider::RefreshFn>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_origin(Any);

    let api_routes = Router::new()
        .route("/chat", post(handlers::chat))
        .route("/sessions", get(handlers::list_sessions))
        .route("/sessions/{id}", get(handlers::get_session))
        .route("/sessions/{id}", delete(handlers::delete_session))
        .route("/sessions/{id}/name", put(handlers::rename_session))
        .route(
            "/sessions/{id}/directory",
            put(handlers::set_session_directory),
        )
        .route("/sessions/{id}/chaos-mode", put(handlers::set_chaos_mode))
        .route("/fs/directories", get(handlers::list_directories))
        .route("/config", post(handlers::configure_provider))
        .route("/status", get(handlers::status))
        .route("/settings", get(handlers::get_settings))
        .route("/settings/provider", put(handlers::update_provider))
        .route("/settings/discord", put(handlers::update_discord).delete(handlers::remove_discord))
        .route("/settings/discord/disconnect", post(handlers::disconnect_discord))
        .route("/settings/discord/connect", post(handlers::reconnect_discord))
        .route("/settings/federation", put(handlers::update_federation))
        .route("/settings/provider/detect", post(handlers::detect_provider))
        .route("/channels", get(handlers::list_channels))
        .route("/cron", get(handlers::list_cron_jobs))
        .route("/cron", post(handlers::create_cron_job))
        .route("/cron/{id}", get(handlers::get_cron_job))
        .route("/cron/{id}", put(handlers::update_cron_job))
        .route("/cron/{id}", delete(handlers::delete_cron_job))
        .route("/cron/{id}/pause", post(handlers::pause_cron_job))
        .route("/cron/{id}/resume", post(handlers::resume_cron_job))
        .route("/agents", get(handlers::list_agents))
        .route("/agents", post(handlers::create_agent))
        .route("/agents/{name}", put(handlers::update_agent))
        .route("/agents/{name}", delete(handlers::delete_agent))
        .route("/version", get(handlers::get_version))
        .route("/update/check", post(handlers::check_update))
        .route("/update/install", post(handlers::install_update));

    Router::new()
        .route("/health", get(handlers::health))
        .route("/ws", get(ws::ws_handler))
        .nest("/api", api_routes)
        .fallback(serve_static)
        .layer(cors)
        // Security response headers
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------

async fn serve_static(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Serve index.html for root or unknown paths (SPA routing)
    let path = if path.is_empty() { "index.html" } else { path };

    match StaticAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => {
            // For SPA routes, serve index.html
            match StaticAssets::get("index.html") {
                Some(content) => Html(std::str::from_utf8(&content.data).unwrap_or("").to_string())
                    .into_response(),
                None => (StatusCode::NOT_FOUND, "Not found").into_response(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

pub async fn serve(
    state: AppState,
    config: &GatewayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = create_router(state);

    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    eprintln!("[web] Listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
