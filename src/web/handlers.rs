use crate::hlog;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use orra::channels::gateway::{ChatRequest, ErrorResponse};
use orra::cron::types::*;
use orra::namespace::Namespace;
use orra::provider::Provider;
use orra::providers::claude::ClaudeProvider;
use orra::providers::openai::OpenAIProvider;

use crate::config;

use super::AppState;

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), impl IntoResponse> {
    if !state.gateway.authenticate(extract_bearer(headers)) {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".into(),
                code: "unauthorized".into(),
            }),
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// GET /api/status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct StatusResponse {
    pub provider_configured: bool,
    pub provider_type: String,
    pub model: String,
}

pub async fn status(State(state): State<AppState>) -> impl IntoResponse {
    Json(StatusResponse {
        provider_configured: state.dynamic_provider.is_configured(),
        provider_type: state.config_provider_type.clone(),
        model: state.config_model.clone(),
    })
}

// ---------------------------------------------------------------------------
// POST /api/config
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ConfigureProviderRequest {
    pub api_key: String,
    /// "claude" or "openai" — defaults to the config file setting.
    pub provider_type: Option<String>,
    /// Model name — defaults to the config file setting.
    pub model: Option<String>,
    /// Custom API URL (for OpenAI-compatible endpoints).
    pub api_url: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigureProviderResponse {
    pub success: bool,
    pub provider_type: String,
    pub model: String,
}

pub async fn configure_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ConfigureProviderRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    if request.api_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "api_key is required".into(),
                code: "bad_request".into(),
            }),
        )
            .into_response();
    }

    let provider_type = request
        .provider_type
        .as_deref()
        .unwrap_or(&state.config_provider_type);

    let model = request.model.as_deref().unwrap_or(&state.config_model);

    let api_url = request
        .api_url
        .as_deref()
        .or(state.config_api_url.as_deref());

    let raw_provider: Arc<dyn Provider> = match provider_type {
        "openai" => {
            let mut p = OpenAIProvider::new(&request.api_key, model);
            if let Some(url) = api_url {
                p = p.with_api_url(url);
            }
            Arc::new(p)
        }
        _ => Arc::new(ClaudeProvider::new(&request.api_key, model)),
    };

    // Wrap in RefreshableProvider for automatic OAuth token refresh
    let refresh = if request.api_key.starts_with("sk-ant-oat") {
        state.refresh_callback.clone()
    } else {
        None
    };
    let new_provider: Arc<dyn Provider> = Arc::new(
        crate::refreshable_provider::RefreshableProvider::new(raw_provider, refresh),
    );

    // Hot-swap the provider
    state.dynamic_provider.swap(new_provider).await;

    hlog!(
        "[config] Provider configured via web UI: {} ({})",
        provider_type, model
    );

    (
        StatusCode::OK,
        Json(ConfigureProviderResponse {
            success: true,
            provider_type: provider_type.to_string(),
            model: model.to_string(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/chat
// ---------------------------------------------------------------------------

pub async fn chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ChatRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    match state.gateway.submit_and_wait(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "runtime_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/sessions
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SessionInfo {
    pub namespace: String,
    pub name: Option<String>,
    pub message_count: usize,
    pub created_at: String,
    pub updated_at: String,
    pub working_directory: Option<String>,
    pub chaos_mode: bool,
    /// Instance name (populated when federation is enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// True when this session lives on a remote peer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub remote: bool,
}

fn is_false(v: &bool) -> bool {
    !v
}

pub async fn list_sessions(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // List all web sessions
    let prefix = Namespace::new("web");
    match state.store.list(Some(&prefix)).await {
        Ok(namespaces) => {
            let mut sessions = Vec::new();
            for ns in namespaces {
                if let Ok(Some(session)) = state.store.load(&ns).await {
                    let name = session
                        .metadata
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let working_directory = session
                        .metadata
                        .get("working_directory")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let chaos_mode = session
                        .metadata
                        .get("chaos_mode")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let fed_service = state.federation_manager.service().await;
                    let instance = fed_service
                        .as_ref()
                        .map(|f| f.instance_name().to_string());

                    sessions.push(SessionInfo {
                        namespace: ns.key(),
                        name,
                        message_count: session.message_count(),
                        created_at: session.created_at.to_rfc3339(),
                        updated_at: session.updated_at.to_rfc3339(),
                        working_directory,
                        chaos_mode,
                        instance,
                        remote: false,
                    });
                }
            }

            // Aggregate remote sessions from federated peers
            let fed_svc = state.federation_manager.service().await;
            if let Some(ref fed) = fed_svc {
                let peers = fed.registry().list_peers().await;
                let healthy_peers: Vec<_> = peers
                    .into_iter()
                    .filter(|p| p.health == crate::federation::PeerHealth::Healthy)
                    .collect();

                if !healthy_peers.is_empty() {
                    let mut handles = Vec::new();
                    for peer in healthy_peers {
                        let url = peer.url.clone();
                        let secret = peer.shared_secret.clone();
                        let name = peer.name.clone();
                        handles.push(tokio::spawn(async move {
                            let result = tokio::time::timeout(
                                std::time::Duration::from_secs(3),
                                crate::federation::client::PeerClient::list_sessions(&url, &secret),
                            )
                            .await;
                            (name, result)
                        }));
                    }

                    for handle in handles {
                        if let Ok((_peer_name, Ok(Ok(remote_sessions)))) = handle.await {
                            for rs in remote_sessions {
                                sessions.push(SessionInfo {
                                    namespace: rs.namespace,
                                    name: rs.name,
                                    message_count: rs.message_count,
                                    created_at: rs.created_at,
                                    updated_at: rs.updated_at,
                                    working_directory: None,
                                    chaos_mode: false,
                                    instance: Some(rs.instance),
                                    remote: true,
                                });
                            }
                        } else {
                            // Timeout or error — skip this peer silently
                        }
                    }
                }
            }

            // Sort by most recently updated
            sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            (StatusCode::OK, Json(sessions)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/sessions/:id
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SessionDetail {
    pub namespace: String,
    pub messages: Vec<MessageInfo>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct MessageInfo {
    pub role: String,
    pub content: String,
    /// ISO-8601 timestamp for when this message was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct GetSessionQuery {
    /// When set, proxy the request to the named remote instance.
    pub instance: Option<String>,
}

pub async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<GetSessionQuery>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // If an instance is specified and it doesn't match local, proxy to the remote peer
    if let Some(ref remote_instance) = query.instance {
        let fed_svc = state.federation_manager.service().await;
        let is_local = fed_svc
            .as_ref()
            .map(|f| f.instance_name() == remote_instance.as_str())
            .unwrap_or(false);

        if !is_local {
            if let Some(ref fed) = fed_svc {
                let peers = fed.registry().list_peers().await;
                if let Some(peer) = peers.iter().find(|p| p.name == *remote_instance) {
                    match crate::federation::client::PeerClient::get_session(
                        &peer.url,
                        &peer.shared_secret,
                        &id,
                    )
                    .await
                    {
                        Ok(remote_detail) => {
                            let detail = SessionDetail {
                                namespace: remote_detail.namespace,
                                messages: remote_detail
                                    .messages
                                    .into_iter()
                                    .map(|m| MessageInfo {
                                        role: m.role,
                                        content: m.content,
                                        timestamp: None,
                                    })
                                    .collect(),
                                created_at: remote_detail.created_at,
                                updated_at: remote_detail.updated_at,
                            };
                            return (StatusCode::OK, Json(detail)).into_response();
                        }
                        Err(e) => {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(ErrorResponse {
                                    error: format!(
                                        "failed to fetch session from {}: {}",
                                        remote_instance, e
                                    ),
                                    code: "federation_error".into(),
                                }),
                            )
                                .into_response();
                        }
                    }
                } else {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse {
                            error: format!("unknown federation peer: {}", remote_instance),
                            code: "peer_not_found".into(),
                        }),
                    )
                        .into_response();
                }
            }
        }
    }

    // Local session lookup
    let ns = Namespace::parse(&id);
    match state.store.load(&ns).await {
        Ok(Some(session)) => {
            let detail = SessionDetail {
                namespace: ns.key(),
                messages: session
                    .messages
                    .iter()
                    .filter(|m| {
                        // Skip tool-result messages (user messages that carry
                        // tool output but no human-authored content) and
                        // assistant messages that only contain tool calls with
                        // no visible text.  These are internal plumbing and
                        // showing them causes empty chat bubbles in the UI.
                        if !m.tool_results.is_empty() {
                            return false;
                        }
                        if !m.tool_calls.is_empty() && m.content.is_empty() {
                            return false;
                        }
                        true
                    })
                    .map(|m| MessageInfo {
                        role: format!("{:?}", m.role).to_lowercase(),
                        content: m.content.clone(),
                        timestamp: Some(m.timestamp.to_rfc3339()),
                    })
                    .collect(),
                created_at: session.created_at.to_rfc3339(),
                updated_at: session.updated_at.to_rfc3339(),
            };
            (StatusCode::OK, Json(detail)).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/sessions/:id
// ---------------------------------------------------------------------------

pub async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let ns = Namespace::parse(&id);
    match state.store.delete(&ns).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/settings
// ---------------------------------------------------------------------------

pub async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let auth_source = state.auth_source.read().await.clone();
    let discord_state = state.discord_manager.state().await;

    // Build federation info — always include saved config values for UI form
    let saved_fed_config = config::read_federation_settings(&state.config_path).ok();

    let fed_config_json = if let Some(ref cfg) = saved_fed_config {
        let peers_json: Vec<serde_json::Value> = cfg
            .peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "url": p.url,
                    "has_secret": p.shared_secret.is_some(),
                })
            })
            .collect();

        serde_json::json!({
            "enabled": cfg.enabled,
            "instance_name": cfg.instance_name,
            "shared_secret_set": cfg.shared_secret.is_some(),
            "mdns_enabled": cfg.mdns_enabled,
            "port": cfg.port,
            "exposed_agents": cfg.exposed_agents,
            "peers": peers_json,
        })
    } else {
        serde_json::json!({
            "enabled": false,
            "instance_name": "",
            "shared_secret_set": false,
            "mdns_enabled": true,
            "port": null,
            "exposed_agents": [],
            "peers": [],
        })
    };

    let fed_service = state.federation_manager.service().await;
    let federation = if let Some(ref fed) = fed_service {
        let peers = fed.registry().list_peers().await;
        let remote_agents = fed.registry().remote_agents().await;

        let live_peers_json: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "url": p.url,
                    "health": format!("{:?}", p.health),
                    "agents": p.agents.iter().map(|a| &a.name).collect::<Vec<_>>(),
                    "source": format!("{:?}", p.source),
                })
            })
            .collect();

        let remote_agents_json: Vec<serde_json::Value> = remote_agents
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "personality": a.personality,
                    "model": a.model,
                    "instance": a.instance,
                })
            })
            .collect();

        serde_json::json!({
            "enabled": true,
            "instance_name": fed.instance_name(),
            "mdns_enabled": fed.mdns_enabled(),
            "live_peers": live_peers_json,
            "remote_agents": remote_agents_json,
            "config": fed_config_json,
        })
    } else {
        serde_json::json!({
            "enabled": false,
            "config": fed_config_json,
        })
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "provider": {
                "auth_source": auth_source,
                "configured": state.dynamic_provider.is_configured(),
                "provider_type": state.config_provider_type,
                "model": state.config_model,
                "api_url": state.config_api_url,
            },
            "discord": {
                "connected": discord_state.connected,
                "token_hint": discord_state.token_hint,
                "token_configured": !discord_state.token_hint.is_empty(),
                "filter": discord_state.filter,
                "allowed_users": discord_state.allowed_users,
            },
            "federation": federation,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// PUT /api/settings/provider
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateProviderRequest {
    pub api_key: Option<String>,
    pub provider_type: Option<String>,
    pub model: Option<String>,
    pub api_url: Option<String>,
}

pub async fn update_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateProviderRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let provider_type = request
        .provider_type
        .as_deref()
        .unwrap_or(&state.config_provider_type);

    let model = request.model.as_deref().unwrap_or(&state.config_model);

    let api_url = request
        .api_url
        .as_deref()
        .or(state.config_api_url.as_deref());

    // If a new API key is provided, create and swap the provider
    if let Some(ref api_key) = request.api_key {
        if api_key.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "api_key cannot be empty".into(),
                    code: "bad_request".into(),
                }),
            )
                .into_response();
        }

        let raw_provider: Arc<dyn Provider> = match provider_type {
            "openai" => {
                let mut p = OpenAIProvider::new(api_key, model);
                if let Some(url) = api_url {
                    p = p.with_api_url(url);
                }
                Arc::new(p)
            }
            _ => Arc::new(ClaudeProvider::new(api_key, model)),
        };

        // Wrap in RefreshableProvider for automatic OAuth token refresh
        let refresh = if api_key.starts_with("sk-ant-oat") {
            state.refresh_callback.clone()
        } else {
            None
        };
        let new_provider: Arc<dyn Provider> = Arc::new(
            crate::refreshable_provider::RefreshableProvider::new(raw_provider, refresh),
        );

        state.dynamic_provider.swap(new_provider).await;

        let mut auth = state.auth_source.write().await;
        *auth = if api_key.starts_with("sk-ant-oat") { "cli" } else { "web_ui" }.to_string();

        hlog!(
            "[settings] Provider updated via settings: {} ({})",
            provider_type, model
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "provider_type": provider_type,
            "model": model,
            "auth_source": "web_ui",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// PUT /api/settings/discord
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateDiscordRequest {
    pub token: Option<String>,
    pub filter: Option<String>,
    pub allowed_users: Option<Vec<String>>,
}

pub async fn update_discord(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateDiscordRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // Get current state as defaults
    let current = state.discord_manager.state().await;

    let token = request.token.as_deref().filter(|t| !t.is_empty());
    let filter = request.filter.as_deref().unwrap_or(&current.filter);
    let allowed_users = request
        .allowed_users
        .as_ref()
        .unwrap_or(&current.allowed_users);

    // Validate filter
    match filter {
        "mentions" | "all" => {}
        "dm" => {
            if allowed_users.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "allowed_users must not be empty when filter is \"dm\"".into(),
                        code: "bad_request".into(),
                    }),
                )
                    .into_response();
            }
        }
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "filter must be \"mentions\", \"all\", or \"dm\", got \"{}\"",
                        other
                    ),
                    code: "bad_request".into(),
                }),
            )
                .into_response();
        }
    }

    // Save token to config file if provided
    if let Some(tok) = token {
        if let Err(e) = config::save_discord_token(&state.config_path, tok) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to save config: {}", e),
                    code: "config_write_error".into(),
                }),
            )
                .into_response();
        }
        hlog!("[settings] Discord token saved to config file");
    }

    // Save filter/allowed_users to config file
    if let Err(e) = config::save_discord_settings(&state.config_path, filter, allowed_users) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to save config: {}", e),
                code: "config_write_error".into(),
            }),
        )
            .into_response();
    }

    // Determine the token to use for reconnecting
    // If a new token was provided, use it; otherwise reload from config
    let connect_token = if let Some(tok) = token {
        Some(tok.to_string())
    } else {
        // Try to read the current token from the config file
        config::read_discord_token(&state.config_path)
            .ok()
            .flatten()
    };

    if let Some(tok) = connect_token {
        // Update the discord API config for channel listing
        {
            let mut api = state.discord_api.write().await;
            *api = Some(orra::tools::discord::DiscordConfig::new(&tok));
        }

        // Connect (or reconnect) to Discord
        match state
            .discord_manager
            .connect(
                &tok,
                filter,
                allowed_users.clone(),
                &current.namespace_prefix,
            )
            .await
        {
            Ok(()) => {
                hlog!("[settings] Discord reconnected with new settings");
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "connected": true,
                    })),
                )
                    .into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Settings saved but Discord connection failed: {}", e),
                    code: "discord_connect_error".into(),
                }),
            )
                .into_response(),
        }
    } else {
        // No token available, just save settings
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "connected": false,
            })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// POST /api/settings/discord/disconnect
// ---------------------------------------------------------------------------

pub async fn disconnect_discord(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    state.discord_manager.disconnect().await;
    hlog!("[settings] Discord disconnected via UI");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "connected": false,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/settings/discord/connect
// ---------------------------------------------------------------------------

pub async fn reconnect_discord(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let token = match crate::config::read_discord_token(&state.config_path) {
        Ok(Some(tok)) => tok,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "No Discord token configured. Add a token first.",
                    "code": "no_token",
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to read config: {}", e),
                    "code": "config_read_error",
                })),
            )
                .into_response();
        }
    };

    let current = state.discord_manager.state().await;

    match state
        .discord_manager
        .connect(
            &token,
            &current.filter,
            current.allowed_users.clone(),
            &current.namespace_prefix,
        )
        .await
    {
        Ok(()) => {
            // Update the discord API config for channel listing
            {
                let mut api = state.discord_api.write().await;
                *api = Some(orra::tools::discord::DiscordConfig::new(&token));
            }
            hlog!("[settings] Discord reconnected via UI");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "connected": true,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Discord connection failed: {}", e),
                "code": "discord_connect_error",
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/settings/discord
// ---------------------------------------------------------------------------

pub async fn remove_discord(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // Disconnect and clear all state
    state.discord_manager.clear_state().await;

    // Remove token from config file
    if let Err(e) = crate::config::remove_discord_token(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to update config: {}", e),
                "code": "config_write_error",
            })),
        )
            .into_response();
    }

    // Clear the discord API config
    {
        let mut api = state.discord_api.write().await;
        *api = None;
    }

    hlog!("[settings] Discord bot removed via UI");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "connected": false,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// PUT /api/settings/federation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct FederationPeerUpdate {
    pub name: String,
    pub url: String,
    pub shared_secret: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateFederationRequest {
    pub enabled: bool,
    pub instance_name: Option<String>,
    /// `None` means "don't change the existing secret".
    pub shared_secret: Option<String>,
    pub mdns_enabled: Option<bool>,
    pub port: Option<u16>,
    pub exposed_agents: Option<Vec<String>>,
    pub peers: Option<Vec<FederationPeerUpdate>>,
}

pub async fn update_federation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateFederationRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // Validate instance_name if provided
    if let Some(ref name) = request.instance_name {
        let name = name.trim();
        if name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "instance_name must not be empty".into(),
                    code: "bad_request".into(),
                }),
            )
                .into_response();
        }
    }

    // Validate peer URLs if provided
    if let Some(ref peers) = request.peers {
        for peer in peers {
            if peer.name.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Peer name must not be empty".into(),
                        code: "bad_request".into(),
                    }),
                )
                    .into_response();
            }
            if peer.url.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("URL must not be empty for peer \"{}\"", peer.name),
                        code: "bad_request".into(),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Save federation settings to config file
    let settings = config::FederationSettingsUpdate {
        enabled: request.enabled,
        instance_name: request.instance_name.map(|n| n.trim().to_string()),
        shared_secret: request.shared_secret,
        mdns_enabled: request.mdns_enabled.unwrap_or(true),
        port: request.port,
        exposed_agents: request.exposed_agents.unwrap_or_default(),
    };

    if let Err(e) = config::save_federation_settings(&state.config_path, &settings) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to save federation settings: {}", e),
                code: "config_write_error".into(),
            }),
        )
            .into_response();
    }

    // Save peers if provided
    if let Some(peers) = request.peers {
        let peer_configs: Vec<config::FederationPeerConfig> = peers
            .into_iter()
            .map(|p| config::FederationPeerConfig {
                name: p.name.trim().to_string(),
                url: p.url.trim().to_string(),
                shared_secret: p.shared_secret.filter(|s| !s.is_empty()),
            })
            .collect();

        if let Err(e) = config::save_federation_peers(&state.config_path, &peer_configs) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to save federation peers: {}", e),
                    code: "config_write_error".into(),
                }),
            )
                .into_response();
        }
    }

    hlog!("[settings] Federation settings saved to config file");

    // Hot-reload: apply the new settings at runtime
    if request.enabled {
        // Read back the full saved config
        let fed_config = match config::read_federation_settings(&state.config_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Settings saved but failed to reload config: {}", e),
                        code: "config_read_error".into(),
                    }),
                )
                    .into_response();
            }
        };

        // Build local agent info from current agent profiles
        let profiles = state.agent_profiles.read().await;
        let local_agents: Vec<crate::federation::LocalAgentInfo> = profiles
            .iter()
            .map(|a| crate::federation::LocalAgentInfo {
                name: a.name.clone(),
                personality: a.personality.clone(),
                model: state.config_model.clone(),
            })
            .collect();
        drop(profiles);

        // Restart federation with new config
        if let Err(e) = state
            .federation_manager
            .restart(fed_config, local_agents, state.gateway_port)
            .await
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Settings saved but federation restart failed: {}", e),
                    code: "federation_restart_error".into(),
                }),
            )
                .into_response();
        }

        hlog!("[settings] Federation restarted with new settings");
    } else {
        // Federation disabled — stop it
        state.federation_manager.stop().await;
        hlog!("[settings] Federation stopped");
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "restart_required": false,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/settings/provider/detect
// ---------------------------------------------------------------------------

pub async fn detect_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    // Try environment variable first
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        if !key.is_empty() {
            let raw: Arc<dyn Provider> =
                Arc::new(ClaudeProvider::new(&key, &state.config_model));
            let refresh = if key.starts_with("sk-ant-oat") {
                state.refresh_callback.clone()
            } else {
                None
            };
            let provider: Arc<dyn Provider> = Arc::new(
                crate::refreshable_provider::RefreshableProvider::new(raw, refresh),
            );
            state.dynamic_provider.swap(provider).await;

            let mut auth = state.auth_source.write().await;
            *auth = "env".to_string();

            hlog!("[settings] Provider auto-detected from ANTHROPIC_API_KEY");
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "auth_source": "env",
                })),
            )
                .into_response();
        }
    }

    // Try Claude CLI credentials
    if let Some(key) = config::read_claude_cli_credentials() {
        let raw: Arc<dyn Provider> = Arc::new(ClaudeProvider::new(&key, &state.config_model));
        let provider: Arc<dyn Provider> = Arc::new(
            crate::refreshable_provider::RefreshableProvider::new(
                raw,
                state.refresh_callback.clone(),
            ),
        );
        state.dynamic_provider.swap(provider).await;

        let mut auth = state.auth_source.write().await;
        *auth = "cli".to_string();

        hlog!("[settings] Provider auto-detected from Claude CLI credentials");
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "auth_source": "cli",
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": false,
            "error": "No credentials found. Set ANTHROPIC_API_KEY or install Claude CLI.",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /api/channels
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ChannelInfo {
    pub id: String,
    pub name: String,
    pub channel_type: String,
    pub group: String,
}

pub async fn list_channels(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let mut channels: Vec<ChannelInfo> = Vec::new();

    // Add web sessions
    let prefix = Namespace::new("web");
    if let Ok(namespaces) = state.store.list(Some(&prefix)).await {
        for ns in namespaces {
            if let Ok(Some(session)) = state.store.load(&ns).await {
                let name = session
                    .metadata
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        let key = ns.key();
                        let short = key.strip_prefix("web:").unwrap_or(&key);
                        format!("Session {}", &short[..8.min(short.len())])
                    });
                channels.push(ChannelInfo {
                    id: ns.key(),
                    name,
                    channel_type: "web_session".into(),
                    group: "Web Sessions".into(),
                });
            }
        }
    }

    // Add Discord channels if configured
    let discord_api = state.discord_api.read().await;
    if let Some(ref dc) = *discord_api {
        // Fetch guilds the bot is in
        #[derive(serde::Deserialize)]
        struct PartialGuild {
            id: String,
            name: String,
        }

        #[derive(serde::Deserialize)]
        struct DiscordChannel {
            id: String,
            name: Option<String>,
            #[serde(rename = "type")]
            channel_type: u8,
        }

        if let Ok(resp) = dc
            .request(reqwest::Method::GET, "users/@me/guilds")
            .send()
            .await
        {
            if let Ok(guilds) = resp.json::<Vec<PartialGuild>>().await {
                for guild in guilds {
                    // Fetch channels for each guild
                    if let Ok(resp) = dc
                        .request(
                            reqwest::Method::GET,
                            &format!("guilds/{}/channels", guild.id),
                        )
                        .send()
                        .await
                    {
                        if let Ok(discord_channels) = resp.json::<Vec<DiscordChannel>>().await {
                            for ch in discord_channels {
                                // Only include text-based channels
                                let type_name = match ch.channel_type {
                                    0 => "text",
                                    5 => "announcement",
                                    15 => "forum",
                                    _ => continue,
                                };
                                channels.push(ChannelInfo {
                                    id: ch.id,
                                    name: ch.name.unwrap_or_else(|| "unnamed".into()),
                                    channel_type: type_name.into(),
                                    group: format!("Discord: {}", guild.name),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    (StatusCode::OK, Json(channels)).into_response()
}

// ---------------------------------------------------------------------------
// GET /api/cron
// ---------------------------------------------------------------------------

pub async fn list_cron_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "jobs": [], "enabled": false })),
            )
                .into_response();
        }
    };

    match svc.list_jobs().await {
        Ok(jobs) => (
            StatusCode::OK,
            Json(serde_json::json!({ "jobs": jobs, "enabled": true })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /api/cron
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateCronJobRequest {
    pub name: String,
    pub schedule: serde_json::Value,
    pub payload: serde_json::Value,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub model: Option<String>,
    pub max_turns: Option<usize>,
    pub auto_approve: Option<bool>,
    pub cooldown_secs: Option<u64>,
    pub max_concurrent: Option<u32>,
}

fn default_namespace() -> String {
    "web".into()
}

pub async fn create_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateCronJobRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    // Parse schedule
    let schedule = match parse_schedule_from_json(&request.schedule) {
        Ok(s) => s,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: msg,
                    code: "bad_request".into(),
                }),
            )
                .into_response();
        }
    };

    // Parse payload
    let payload = match parse_payload_from_json(&request.payload) {
        Ok(p) => p,
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: msg,
                    code: "bad_request".into(),
                }),
            )
                .into_response();
        }
    };

    let mut job = CronJob::new(&request.name, schedule, payload, &request.namespace);
    job.model = request.model;
    job.max_turns = request.max_turns;
    job.auto_approve = request.auto_approve;
    job.cooldown_secs = request.cooldown_secs;
    job.max_concurrent = request.max_concurrent;
    match svc.add_job(job).await {
        Ok(job) => (StatusCode::CREATED, Json(serde_json::json!(job))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/cron/:id
// ---------------------------------------------------------------------------

pub async fn get_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    match svc.get_job(&id).await {
        Ok(Some(job)) => (StatusCode::OK, Json(serde_json::json!(job))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Job not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/cron/:id
// ---------------------------------------------------------------------------

pub async fn delete_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    match svc.delete_job(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "deleted": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Job not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /api/cron/:id
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateCronJobRequest {
    pub name: Option<String>,
    pub schedule: Option<serde_json::Value>,
    pub payload: Option<serde_json::Value>,
    pub namespace: Option<String>,
    pub model: Option<String>,
    pub max_turns: Option<usize>,
    pub auto_approve: Option<bool>,
    pub cooldown_secs: Option<u64>,
    pub max_concurrent: Option<u32>,
}

pub async fn update_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateCronJobRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    let mut job = match svc.get_job(&id).await {
        Ok(Some(job)) => job,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("Job not found: {}", id),
                    code: "not_found".into(),
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                    code: "cron_error".into(),
                }),
            )
                .into_response();
        }
    };

    // Update fields if provided
    if let Some(name) = request.name {
        job.name = name;
    }
    if let Some(ns) = request.namespace {
        job.namespace = ns;
    }
    job.model = request.model;
    job.max_turns = request.max_turns;
    job.auto_approve = request.auto_approve;
    job.cooldown_secs = request.cooldown_secs;
    job.max_concurrent = request.max_concurrent;
    if let Some(ref schedule_val) = request.schedule {
        match parse_schedule_from_json(schedule_val) {
            Ok(s) => {
                job.schedule = s;
                // Recompute next_run
                job.next_run = job.compute_next_run(chrono::Utc::now());
            }
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: msg,
                        code: "bad_request".into(),
                    }),
                )
                    .into_response();
            }
        }
    }
    if let Some(ref payload_val) = request.payload {
        match parse_payload_from_json(payload_val) {
            Ok(p) => job.payload = p,
            Err(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: msg,
                        code: "bad_request".into(),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Save via the store (accessed through the service)
    match svc.add_job(job.clone()).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!(job))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /api/cron/:id/pause
// ---------------------------------------------------------------------------

pub async fn pause_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    match svc.pause_job(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "paused": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Job not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /api/cron/:id/resume
// ---------------------------------------------------------------------------

pub async fn resume_cron_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let svc = match &state.cron_service {
        Some(svc) => svc,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Cron service is disabled".into(),
                    code: "cron_disabled".into(),
                }),
            )
                .into_response();
        }
    };

    match svc.resume_job(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "resumed": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Job not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "cron_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /api/sessions/:id/name
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RenameSessionRequest {
    pub name: String,
}

pub async fn rename_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<RenameSessionRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let ns = Namespace::parse(&id);
    match state.store.load(&ns).await {
        Ok(Some(mut session)) => {
            let name = request.name.trim().to_string();
            if name.is_empty() {
                session.metadata.remove("name");
            } else {
                session
                    .metadata
                    .insert("name".into(), serde_json::json!(name));
            }
            match state.store.save(&session).await {
                Ok(()) => (
                    StatusCode::OK,
                    Json(serde_json::json!({ "success": true, "name": name })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: "store_error".into(),
                    }),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /api/sessions/:id/directory
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetDirectoryRequest {
    pub directory: String,
}

pub async fn set_session_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<SetDirectoryRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let ns = Namespace::parse(&id);
    match state.store.load(&ns).await {
        Ok(Some(mut session)) => {
            let dir = request.directory.trim().to_string();
            if dir.is_empty() {
                session.metadata.remove("working_directory");
            } else {
                // Validate that the directory exists
                let path = std::path::Path::new(&dir);
                if !path.is_dir() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("directory does not exist: {}", dir)
                        })),
                    )
                        .into_response();
                }
                session
                    .metadata
                    .insert("working_directory".into(), serde_json::json!(dir));
            }
            match state.store.save(&session).await {
                Ok(()) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "working_directory": dir
                    })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: "store_error".into(),
                    }),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /api/sessions/:id/chaos-mode
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetChaosModeRequest {
    pub enabled: bool,
}

pub async fn set_chaos_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<SetChaosModeRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let ns = Namespace::parse(&id);
    match state.store.load(&ns).await {
        Ok(Some(mut session)) => {
            if request.enabled {
                session
                    .metadata
                    .insert("chaos_mode".into(), serde_json::json!(true));
            } else {
                session.metadata.remove("chaos_mode");
            }
            match state.store.save(&session).await {
                Ok(()) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "chaos_mode": request.enabled
                    })),
                )
                    .into_response(),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                        code: "store_error".into(),
                    }),
                )
                    .into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("session not found: {}", id),
                code: "not_found".into(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
                code: "store_error".into(),
            }),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /api/fs/directories
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListDirectoriesQuery {
    pub path: Option<String>,
}

pub async fn list_directories(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListDirectoriesQuery>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let raw_path = query.path.unwrap_or_default();
    if raw_path.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "directories": Vec::<String>::new() })),
        )
            .into_response();
    }

    // Expand ~ to home directory
    let expanded = if raw_path.starts_with('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
        raw_path.replacen('~', &home, 1)
    } else {
        raw_path.clone()
    };

    let path = std::path::Path::new(&expanded);

    // Determine parent directory and prefix filter
    let (parent, prefix) = if expanded.ends_with('/') {
        // User typed a full directory path — list its children
        (path.to_path_buf(), String::new())
    } else {
        // User is typing a name — filter children of the parent
        let parent = path
            .parent()
            .unwrap_or(std::path::Path::new("/"))
            .to_path_buf();
        let prefix = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        (parent, prefix)
    };

    // Read the parent directory
    let entries = match std::fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(_) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "directories": Vec::<String>::new() })),
            )
                .into_response();
        }
    };

    let show_hidden = prefix.starts_with('.');
    let prefix_lower = prefix.to_lowercase();

    let mut dirs: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }

            let name = entry.file_name().to_string_lossy().to_string();

            // Skip hidden dirs unless the prefix starts with '.'
            if !show_hidden && name.starts_with('.') {
                return None;
            }

            // Filter by prefix
            if !prefix.is_empty() && !name.to_lowercase().starts_with(&prefix_lower) {
                return None;
            }

            Some(entry.path().to_string_lossy().to_string())
        })
        .collect();

    dirs.sort();
    dirs.truncate(20);

    (
        StatusCode::OK,
        Json(serde_json::json!({ "directories": dirs })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Cron JSON parsing helpers
// ---------------------------------------------------------------------------

fn parse_schedule_from_json(v: &serde_json::Value) -> Result<CronScheduleType, String> {
    let stype = v
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing schedule.type")?;
    match stype {
        "at" => {
            let dt_str = v
                .get("datetime")
                .and_then(|v| v.as_str())
                .ok_or("missing schedule.datetime")?;
            let dt: chrono::DateTime<chrono::Utc> = dt_str
                .parse()
                .map_err(|e| format!("invalid datetime: {}", e))?;
            Ok(CronScheduleType::At { datetime: dt })
        }
        "every" => {
            let ms = v
                .get("interval_ms")
                .and_then(|v| v.as_u64())
                .ok_or("missing schedule.interval_ms")?;
            Ok(CronScheduleType::Every { interval_ms: ms })
        }
        "cron" => {
            let expr = v
                .get("expression")
                .and_then(|v| v.as_str())
                .ok_or("missing schedule.expression")?;
            // Validate
            orra::scheduler::CronSchedule::parse(expr)
                .map_err(|e| format!("invalid cron: {}", e))?;
            Ok(CronScheduleType::Cron {
                expression: expr.into(),
            })
        }
        _ => Err(format!("unknown schedule type: {}", stype)),
    }
}

fn parse_payload_from_json(v: &serde_json::Value) -> Result<CronPayload, String> {
    let ptype = v
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing payload.type")?;
    match ptype {
        "agent_turn" => {
            let prompt = v
                .get("prompt")
                .and_then(|v| v.as_str())
                .ok_or("missing payload.prompt")?;
            Ok(CronPayload::AgentTurn {
                prompt: prompt.into(),
            })
        }
        "system_event" => {
            let message = v
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or("missing payload.message")?;
            Ok(CronPayload::SystemEvent {
                message: message.into(),
            })
        }
        _ => Err(format!("unknown payload type: {}", ptype)),
    }
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AgentRequest {
    pub name: String,
    pub personality: Option<String>,
    pub system_prompt: Option<String>,
    pub model: Option<String>,
}

pub async fn list_agents(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let profiles = state.agent_profiles.read().await;
    let default_model = &state.config_model;
    let mut agents: Vec<serde_json::Value> = profiles
        .iter()
        .map(|a| {
            let effective_model = a.model.as_deref().unwrap_or(default_model);
            serde_json::json!({
                "name": a.name,
                "personality": a.personality,
                "system_prompt": a.system_prompt,
                "model": effective_model,
            })
        })
        .collect();

    // Include remote agents from federation
    let fed_svc = state.federation_manager.service().await;
    if let Some(ref fed) = fed_svc {
        let remote = fed.registry().remote_agents().await;
        for ra in remote {
            agents.push(serde_json::json!({
                "name": ra.name,
                "personality": ra.personality,
                "model": ra.model,
                "remote": true,
                "instance": ra.instance,
            }));
        }
    }

    (StatusCode::OK, Json(agents)).into_response()
}

pub async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AgentRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let name = request.name.trim().to_string();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "name is required" })),
        )
            .into_response();
    }

    {
        let profiles = state.agent_profiles.read().await;
        if profiles.iter().any(|a| a.name.eq_ignore_ascii_case(&name)) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": format!("agent '{}' already exists", name) })),
            )
                .into_response();
        }
    }

    let profile = config::AgentProfileConfig {
        name,
        personality: request
            .personality
            .unwrap_or_else(|| "friendly, helpful, and concise".into()),
        system_prompt: request.system_prompt,
        model: request.model,
    };

    {
        let mut profiles = state.agent_profiles.write().await;
        profiles.push(profile);

        // Save to config file
        if let Err(e) = config::save_agents(&state.config_path, &profiles) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

pub async fn update_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(request): Json<AgentRequest>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let new_name = request.name.trim().to_string();
    let is_rename = !new_name.is_empty() && !new_name.eq_ignore_ascii_case(&name);

    // Check for name conflicts when renaming
    if is_rename {
        let profiles = state.agent_profiles.read().await;
        if profiles
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(&new_name))
        {
            return (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "error": format!("agent '{}' already exists", new_name) }),
                ),
            )
                .into_response();
        }
    }

    {
        let mut profiles = state.agent_profiles.write().await;
        let agent = profiles
            .iter_mut()
            .find(|a| a.name.eq_ignore_ascii_case(&name));

        match agent {
            Some(a) => {
                if is_rename {
                    a.name = new_name.clone();
                }
                if let Some(p) = request.personality {
                    a.personality = p;
                }
                a.system_prompt = request.system_prompt;
                a.model = request.model;
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": format!("agent '{}' not found", name) })),
                )
                    .into_response();
            }
        }

        if let Err(e) = config::save_agents(&state.config_path, &profiles) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // If renamed, update the runtime map key and default agent name
    if is_rename {
        let old_key = name.to_lowercase();
        let new_key = new_name.to_lowercase();

        let mut runtimes = state.runtimes.write().await;
        if let Some(rt) = runtimes.remove(&old_key) {
            runtimes.insert(new_key, rt);
        }

        let mut default = state.default_agent.write().await;
        if default.eq_ignore_ascii_case(&name) {
            *default = new_name;
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

pub async fn delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    {
        let mut profiles = state.agent_profiles.write().await;

        if profiles.len() <= 1 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "cannot delete the last agent" })),
            )
                .into_response();
        }

        let before_len = profiles.len();
        profiles.retain(|a| !a.name.eq_ignore_ascii_case(&name));

        if profiles.len() == before_len {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": format!("agent '{}' not found", name) })),
            )
                .into_response();
        }

        if let Err(e) = config::save_agents(&state.config_path, &profiles) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // Remove from runtimes map too
    {
        let mut runtimes = state.runtimes.write().await;
        runtimes.remove(&name.to_lowercase());
    }

    (StatusCode::OK, Json(serde_json::json!({ "success": true }))).into_response()
}

// ---------------------------------------------------------------------------
// GET /api/version
// ---------------------------------------------------------------------------

pub async fn get_version(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let install_type = crate::update::detect_install_type();

    if let Some(info) = state.update_checker.get_cached().await {
        (StatusCode::OK, Json(serde_json::json!(info))).into_response()
    } else {
        // No cached data yet — return current version with null fields
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "current_version": env!("CARGO_PKG_VERSION"),
                "latest_version": null,
                "update_available": false,
                "release_url": null,
                "release_notes": null,
                "published_at": null,
                "assets": [],
                "install_type": install_type.as_str(),
                "can_self_update": install_type.can_self_update(),
            })),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// POST /api/update/check
// ---------------------------------------------------------------------------

pub async fn check_update(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    match state.update_checker.check_now().await {
        Ok(info) => (StatusCode::OK, Json(serde_json::json!(info))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": e,
                "code": "update_check_failed",
            })),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// POST /api/update/install
// ---------------------------------------------------------------------------

pub async fn install_update(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = check_auth(&state, &headers) {
        return e.into_response();
    }

    let info = match state.update_checker.get_cached().await {
        Some(info) if info.update_available => info,
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "restart_required": false,
                    "message": "No update available. Check for updates first.",
                })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "restart_required": false,
                    "message": "No update information cached. Check for updates first.",
                })),
            )
                .into_response();
        }
    };

    match crate::update::download_and_install(&info, &state.data_dir).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!(result))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "restart_required": false,
                "message": e,
            })),
        )
            .into_response(),
    }
}
