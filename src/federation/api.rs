//! Federation HTTP API — Axum handlers for peer-facing endpoints.
//!
//! These endpoints are served on the federation port (separate from the main
//! gateway) and are authenticated via shared secret bearer tokens.
//!
//! | Endpoint                             | Method | Purpose                       |
//! |--------------------------------------|--------|-------------------------------|
//! | `/api/federation/agents`             | GET    | List exposed agents           |
//! | `/api/federation/relay`              | POST   | Relay message to an agent     |
//! | `/api/federation/health`             | GET    | Health check                  |
//! | `/api/federation/sessions`           | GET    | List web sessions             |
//! | `/api/federation/sessions/detail`    | GET    | Get a session's messages      |
//! | `/api/federation/sessions/chat`      | POST   | Chat in a session             |

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use orra::channels::federation::{
    FederatedMessageInfo, FederatedSessionDetail, FederatedSessionInfo, HealthStatus,
    RelayRequest, RelayResponse, SessionChatRequest, SessionChatResponse,
};
use orra::context::CharEstimator;
use orra::message::Message;
use orra::namespace::Namespace;
use orra::runtime::Runtime;
use orra::store::SessionStore;

use super::FederationService;

// ---------------------------------------------------------------------------
// Federation-specific app state
// ---------------------------------------------------------------------------

/// State shared by federation API handlers.
#[derive(Clone)]
pub struct FederationState {
    pub service: Arc<FederationService>,
    /// Named agent runtimes (shared with main app).
    pub runtimes:
        Arc<tokio::sync::RwLock<std::collections::HashMap<String, Arc<Runtime<CharEstimator>>>>>,
    /// Session store (shared with main app), needed to serve session data to peers.
    pub store: Arc<dyn SessionStore>,
}

// ---------------------------------------------------------------------------
// Auth middleware helper
// ---------------------------------------------------------------------------

/// Extract and validate the bearer token from the Authorization header.
fn validate_auth(headers: &HeaderMap, service: &FederationService) -> Result<(), StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !service.validate_secret(token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// GET /api/federation/agents
// ---------------------------------------------------------------------------

/// Returns the list of agents this instance exposes to peers.
pub async fn list_agents(
    State(state): State<FederationState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let agents = state.service.exposed_agents();
    Ok(Json(agents))
}

// ---------------------------------------------------------------------------
// POST /api/federation/relay
// ---------------------------------------------------------------------------

/// Relay a message to a local agent on behalf of a remote peer.
pub async fn relay_message(
    State(state): State<FederationState>,
    headers: HeaderMap,
    Json(request): Json<RelayRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let agent_key = request.agent.to_lowercase();

    // Check if the requested agent is exposed
    let exposed = state.service.exposed_agents();
    if !exposed.iter().any(|a| a.name.to_lowercase() == agent_key) {
        return Err(StatusCode::NOT_FOUND);
    }

    // Find the runtime for this agent
    let runtimes = state.runtimes.read().await;
    let runtime = runtimes
        .get(&agent_key)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    drop(runtimes);

    // Create a federation namespace for session tracking
    let ns = Namespace::parse(&request.namespace);

    // Run the message through the agent's runtime
    let result = runtime
        .run(&ns, Message::user(&request.message))
        .await
        .map_err(|e| {
            eprintln!(
                "[federation] relay to '{}' failed: {e}",
                request.agent
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let response = RelayResponse {
        message: result.final_message.content,
        agent: request.agent,
        instance: state.service.instance_name().to_string(),
    };

    Ok(Json(response))
}

// ---------------------------------------------------------------------------
// GET /api/federation/health
// ---------------------------------------------------------------------------

/// Returns health status of this instance.
pub async fn health(
    State(state): State<FederationState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let agents = state.service.exposed_agents();
    let status = HealthStatus {
        instance: state.service.instance_name().to_string(),
        status: "ok".into(),
        agent_count: agents.len(),
    };

    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// GET /api/federation/sessions
// ---------------------------------------------------------------------------

/// Returns the list of web sessions on this instance.
pub async fn list_sessions(
    State(state): State<FederationState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let prefix = Namespace::new("web");
    let namespaces = state
        .store
        .list(Some(&prefix))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let instance_name = state.service.instance_name().to_string();
    let mut sessions = Vec::new();

    for ns in namespaces {
        if let Ok(Some(session)) = state.store.load(&ns).await {
            let name = session
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            sessions.push(FederatedSessionInfo {
                namespace: ns.key(),
                name,
                message_count: session.message_count(),
                created_at: session.created_at.to_rfc3339(),
                updated_at: session.updated_at.to_rfc3339(),
                instance: instance_name.clone(),
            });
        }
    }

    sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(Json(sessions))
}

// ---------------------------------------------------------------------------
// GET /api/federation/sessions/detail?namespace=...
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SessionDetailQuery {
    pub namespace: String,
}

/// Returns the full detail of a specific session, including messages.
pub async fn get_session_detail(
    State(state): State<FederationState>,
    headers: HeaderMap,
    Query(query): Query<SessionDetailQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let ns = Namespace::parse(&query.namespace);
    match state.store.load(&ns).await {
        Ok(Some(session)) => {
            let detail = FederatedSessionDetail {
                namespace: ns.key(),
                messages: session
                    .messages
                    .iter()
                    .map(|m| FederatedMessageInfo {
                        role: format!("{:?}", m.role).to_lowercase(),
                        content: m.content.clone(),
                    })
                    .collect(),
                created_at: session.created_at.to_rfc3339(),
                updated_at: session.updated_at.to_rfc3339(),
                instance: state.service.instance_name().to_string(),
            };
            Ok(Json(detail).into_response())
        }
        _ => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// POST /api/federation/sessions/chat
// ---------------------------------------------------------------------------

/// Chat within a specific session on behalf of a remote peer.
///
/// This is non-streaming — the full response is returned after the agent
/// finishes processing.
pub async fn session_chat(
    State(state): State<FederationState>,
    headers: HeaderMap,
    Json(request): Json<SessionChatRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    validate_auth(&headers, &state.service)?;

    let ns = Namespace::parse(&request.namespace);

    // Resolve runtime — use specified agent or first available
    let agent_key = request.agent.as_deref().map(|a| a.to_lowercase());
    let runtimes = state.runtimes.read().await;
    let runtime = if let Some(ref key) = agent_key {
        runtimes.get(key).cloned()
    } else {
        runtimes.values().next().cloned()
    }
    .ok_or(StatusCode::NOT_FOUND)?;
    drop(runtimes);

    let result = runtime
        .run(&ns, Message::user(&request.message))
        .await
        .map_err(|e| {
            eprintln!("[federation] session chat failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(SessionChatResponse {
        message: result.final_message.content,
        namespace: request.namespace,
        agent: agent_key,
        instance: state.service.instance_name().to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Create the federation API router.
pub fn federation_router(state: FederationState) -> axum::Router {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/api/federation/agents", get(list_agents))
        .route("/api/federation/relay", post(relay_message))
        .route("/api/federation/health", get(health))
        .route("/api/federation/sessions", get(list_sessions))
        .route("/api/federation/sessions/detail", get(get_session_detail))
        .route("/api/federation/sessions/chat", post(session_chat))
        .with_state(state)
}
