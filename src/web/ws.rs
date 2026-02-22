use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message as WsRawMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use tokio::sync::{mpsc, oneshot};

use orra::agent::detect_agent_mention;
use orra::channels::gateway::{ChatUsage, WsMessage};
use orra::message::Message;
use orra::namespace::Namespace;
use orra::runtime::RuntimeStreamEvent;

use super::handlers::extract_bearer;
use super::AppState;

// ---------------------------------------------------------------------------
// WebSocket upgrade handler
// ---------------------------------------------------------------------------

pub async fn ws_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Check auth before upgrade
    if !state.gateway.authenticate(extract_bearer(&headers)) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "unauthorized",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

// ---------------------------------------------------------------------------
// WebSocket connection handler
//
// The runtime is spawned on a separate tokio task to prevent deadlock:
// the ApprovalHook blocks in `before_tool_call` waiting for user approval,
// but the approval response arrives on the same WebSocket. If we ran the
// runtime inline in the select! loop, we'd be deadlocked.
//
// Architecture:
//   Client <-> WS handler <-> runtime task (spawned)
//                          <-> ApprovalHook (via mpsc/oneshot channels)
// ---------------------------------------------------------------------------

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut session_rx = state.session_events.subscribe();

    // Channel for the spawned runtime task to send results back to this handler
    let (result_tx, mut result_rx) = mpsc::channel::<WsMessage>(64);

    // Pending approval responses: call_id -> oneshot sender
    let mut pending_approvals: HashMap<String, oneshot::Sender<bool>> = HashMap::new();

    loop {
        tokio::select! {
            // Branch 1: Incoming WebSocket messages from the client
            msg = socket.recv() => {
                let msg = match msg {
                    Some(Ok(WsRawMessage::Text(text))) => text,
                    Some(Ok(WsRawMessage::Ping(data))) => {
                        let _ = socket.send(WsRawMessage::Pong(data)).await;
                        continue;
                    }
                    Some(Ok(WsRawMessage::Close(_))) | Some(Err(_)) | None => break,
                    _ => continue,
                };

                // Parse the incoming WsMessage
                let ws_msg: WsMessage = match serde_json::from_str(&msg) {
                    Ok(m) => m,
                    Err(e) => {
                        let err = WsMessage::Error {
                            error: format!("invalid message: {}", e),
                        };
                        let _ = send_ws_msg(&mut socket, &err).await;
                        continue;
                    }
                };

                match ws_msg {
                    WsMessage::Chat { message, namespace, model, agent } => {
                        let ns_key = namespace.unwrap_or_else(|| {
                            format!("web:{}", uuid::Uuid::new_v4())
                        });
                        let ns = Namespace::parse(&ns_key);

                        // If no agent was explicitly selected, check for @mentions
                        let (resolved_agent, cleaned_message) = if agent.is_some() {
                            (agent, message)
                        } else {
                            let agent_names: Vec<String> = state.agent_profiles.read().await
                                .iter()
                                .map(|p| p.name.clone())
                                .collect();
                            let (mentioned, cleaned) = detect_agent_mention(&message, &agent_names);
                            (mentioned.map(|s| s.to_string()), cleaned.trim().to_string())
                        };

                        // Resolve which runtime to use based on the agent name
                        let (runtime, agent_name) = resolve_runtime(&state, resolved_agent.as_deref()).await;

                        // Spawn the runtime on a separate task so approval hooks
                        // don't deadlock the WS handler
                        let result_tx = result_tx.clone();
                        let ns_key_clone = ns_key.clone();
                        let agent_name_clone = agent_name.clone();

                        tokio::spawn(async move {
                            // Try streaming first, fall back to non-streaming
                            match runtime
                                .run_streaming_with_model(&ns, Message::user(&cleaned_message), model.clone())
                                .await
                            {
                                Ok(mut rx) => {
                                    while let Some(event) = rx.recv().await {
                                        let ws_msg = match event {
                                            RuntimeStreamEvent::TextDelta(text) => {
                                                WsMessage::TextDelta { content: text }
                                            }
                                            RuntimeStreamEvent::ToolCallStarted { name, .. } => {
                                                WsMessage::TextDelta {
                                                    content: format!("\n[Using tool: {}]\n", name),
                                                }
                                            }
                                            RuntimeStreamEvent::Done(result) => {
                                                WsMessage::Response {
                                                    message: result.final_message.content.clone(),
                                                    namespace: ns_key_clone.clone(),
                                                    usage: ChatUsage {
                                                        input_tokens: result.total_usage.input_tokens,
                                                        output_tokens: result.total_usage.output_tokens,
                                                        total_tokens: result.total_usage.total_tokens(),
                                                    },
                                                    agent: agent_name_clone.clone(),
                                                }
                                            }
                                            RuntimeStreamEvent::Error(err) => {
                                                WsMessage::Error { error: err }
                                            }
                                            _ => continue,
                                        };
                                        if result_tx.send(ws_msg).await.is_err() {
                                            // WS handler dropped — connection closed
                                            return;
                                        }
                                    }
                                }
                                Err(_) => {
                                    // Streaming not available, fall back to non-streaming
                                    let ws_msg = match runtime.run_with_model(&ns, Message::user(&cleaned_message), model).await {
                                        Ok(result) => {
                                            WsMessage::Response {
                                                message: result.final_message.content.clone(),
                                                namespace: ns_key_clone,
                                                usage: ChatUsage {
                                                    input_tokens: result.total_usage.input_tokens,
                                                    output_tokens: result.total_usage.output_tokens,
                                                    total_tokens: result.total_usage.total_tokens(),
                                                },
                                                agent: agent_name_clone,
                                            }
                                        }
                                        Err(e) => {
                                            WsMessage::Error {
                                                error: e.to_string(),
                                            }
                                        }
                                    };
                                    let _ = result_tx.send(ws_msg).await;
                                }
                            }
                        });
                    }
                    WsMessage::ToolApprovalResponse { call_id, approved } => {
                        // Route the user's approval/denial back to the ApprovalHook
                        if let Some(tx) = pending_approvals.remove(&call_id) {
                            let _ = tx.send(approved);
                        }
                    }
                    WsMessage::Ping => {
                        let _ = send_ws_msg(&mut socket, &WsMessage::Pong).await;
                    }
                    _ => {}
                }
            }

            // Branch 2: Approval requests from the ApprovalHook
            approval = async {
                state.approval_rx.lock().await.recv().await
            } => {
                match approval {
                    Some(req) => {
                        // Store the oneshot sender so we can route the response back
                        pending_approvals.insert(req.call_id.clone(), req.response_tx);

                        // Forward the approval request to the client
                        let ws_msg = WsMessage::ToolApprovalRequest {
                            call_id: req.call_id,
                            tool_name: req.tool_name,
                            arguments: req.arguments,
                        };
                        if send_ws_msg(&mut socket, &ws_msg).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        // Channel closed — shouldn't happen, but handle gracefully
                        continue;
                    }
                }
            }

            // Branch 3: Results from the spawned runtime task
            result = result_rx.recv() => {
                match result {
                    Some(ws_msg) => {
                        if send_ws_msg(&mut socket, &ws_msg).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        // All senders dropped (runtime tasks completed)
                        // This shouldn't break the loop — new Chat messages
                        // will spawn new tasks with fresh senders
                        continue;
                    }
                }
            }

            // Branch 4: Session update notifications (e.g. from cron jobs)
            event = session_rx.recv() => {
                match event {
                    Ok(namespace) => {
                        let notification = serde_json::json!({
                            "type": "session_updated",
                            "namespace": namespace,
                        });
                        let json = serde_json::to_string(&notification).unwrap_or_default();
                        if socket.send(WsRawMessage::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the runtime for a given agent name.
/// Returns the runtime and the agent name (if multi-agent mode is active).
async fn resolve_runtime(
    state: &AppState,
    agent: Option<&str>,
) -> (Arc<orra::runtime::Runtime<orra::context::CharEstimator>>, Option<String>) {
    let runtimes = state.runtimes.read().await;

    if runtimes.is_empty() {
        // Single-agent mode — use the default runtime
        return (state.runtime.clone(), None);
    }

    if let Some(name) = agent {
        let key = name.to_lowercase();
        if let Some(rt) = runtimes.get(&key) {
            return (rt.clone(), Some(name.to_string()));
        }
    }

    // Fall back to default agent
    let default_name = state.default_agent.read().await.clone();
    let key = default_name.to_lowercase();
    if let Some(rt) = runtimes.get(&key) {
        return (rt.clone(), Some(default_name));
    }

    // Last resort: use the base runtime
    (state.runtime.clone(), None)
}

async fn send_ws_msg(
    socket: &mut WebSocket,
    msg: &WsMessage,
) -> Result<(), axum::Error> {
    let json = serde_json::to_string(msg).unwrap_or_default();
    socket
        .send(WsRawMessage::Text(json.into()))
        .await
}
