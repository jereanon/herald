use crate::hlog;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
// Interactive-request guard (RAII counter)
// ---------------------------------------------------------------------------

/// Decrements `interactive_count` when dropped, ensuring the counter stays
/// correct even on early returns or panics inside the spawned runtime task.
struct InteractiveGuard(Arc<AtomicUsize>);

impl Drop for InteractiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

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
        return (axum::http::StatusCode::UNAUTHORIZED, "unauthorized").into_response();
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
    hlog!("[ws] client connected");
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
                    Some(Ok(WsRawMessage::Close(_))) | Some(Err(_)) | None => {
                        hlog!("[ws] client disconnected");
                        break;
                    }
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
                    WsMessage::Chat { message, namespace, model, agent, instance } => {
                        let ns_key = namespace.unwrap_or_else(|| {
                            format!("web:{}", uuid::Uuid::new_v4())
                        });
                        let ns = Namespace::parse(&ns_key);
                        hlog!(
                            "[ws] chat: ns={}, agent={:?}, model={:?}, instance={:?}, msg_len={}",
                            ns_key,
                            agent,
                            model,
                            instance,
                            message.len()
                        );

                        // If `instance` is set and doesn't match local, proxy to the remote peer's session
                        if let Some(ref remote_instance) = instance {
                            let fed_svc = state.federation_manager.service().await;
                            let is_local = fed_svc
                                .as_ref()
                                .map(|f| f.instance_name() == remote_instance.as_str())
                                .unwrap_or(true); // no federation = treat as local

                            if !is_local {
                                if let Some(ref fed) = fed_svc {
                                    let peers = fed.registry().list_peers().await;
                                    if let Some(peer) = peers.iter().find(|p| &p.name == remote_instance) {
                                        let request = orra::channels::federation::SessionChatRequest {
                                            namespace: ns_key.clone(),
                                            message: message.clone(),
                                            agent: agent.clone(),
                                            model: model.clone(),
                                            source_peer: fed.instance_name().to_string(),
                                        };
                                        let peer_url = peer.url.clone();
                                        let peer_secret = peer.shared_secret.clone();
                                        let result_tx = result_tx.clone();
                                        let ns_key_clone = ns_key.clone();

                                        tokio::spawn(async move {
                                            let ws_msg = match crate::federation::client::PeerClient::chat_in_session(
                                                &peer_url,
                                                &peer_secret,
                                                &request,
                                            ).await {
                                                Ok(resp) => WsMessage::Response {
                                                    message: resp.message,
                                                    namespace: ns_key_clone,
                                                    usage: ChatUsage {
                                                        input_tokens: 0,
                                                        output_tokens: 0,
                                                        total_tokens: 0,
                                                    },
                                                    agent: resp.agent.map(|a| format!("{}:{}", resp.instance, a)),
                                                },
                                                Err(e) => WsMessage::Error {
                                                    error: format!("Remote session chat failed: {e}"),
                                                },
                                            };
                                            let _ = result_tx.send(ws_msg).await;
                                        });
                                        continue;
                                    } else {
                                        let err = WsMessage::Error {
                                            error: format!("Unknown federation peer: {}", remote_instance),
                                        };
                                        let _ = send_ws_msg(&mut socket, &err).await;
                                        continue;
                                    }
                                }
                            }
                        }

                        // Check for @peer:agent pattern (federation direct routing)
                        let fed_svc2 = state.federation_manager.service().await;
                        if let Some(ref fed) = fed_svc2 {
                            if let Some(remote_match) = detect_remote_agent_mention(&message, fed).await {
                                let result_tx = result_tx.clone();
                                let ns_key_clone = ns_key.clone();
                                let instance_name = fed.instance_name().to_string();

                                tokio::spawn(async move {
                                    let request = orra::channels::federation::RelayRequest {
                                        agent: remote_match.agent_name.clone(),
                                        message: remote_match.cleaned_message.clone(),
                                        source_peer: instance_name,
                                        source_agent: None,
                                        namespace: format!("federation:web:{}", uuid::Uuid::new_v4()),
                                    };

                                    let ws_msg = match crate::federation::client::PeerClient::relay_message(
                                        &remote_match.peer_url,
                                        &remote_match.peer_secret,
                                        &request,
                                    ).await {
                                        Ok(resp) => WsMessage::Response {
                                            message: resp.message,
                                            namespace: ns_key_clone,
                                            usage: ChatUsage {
                                                input_tokens: 0,
                                                output_tokens: 0,
                                                total_tokens: 0,
                                            },
                                            agent: Some(format!("{}:{}", resp.instance, resp.agent)),
                                        },
                                        Err(e) => WsMessage::Error {
                                            error: format!("Remote relay failed: {e}"),
                                        },
                                    };
                                    let _ = result_tx.send(ws_msg).await;
                                });
                                continue;
                            }
                        }

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
                        hlog!("[ws] dispatching to agent={:?}, ns={}", agent_name, ns_key);

                        // Spawn the runtime on a separate task so approval hooks
                        // don't deadlock the WS handler
                        let result_tx = result_tx.clone();
                        let ns_key_clone = ns_key.clone();
                        let agent_name_clone = agent_name.clone();

                        // Track that an interactive chat is in-flight so cron
                        // jobs can defer and avoid API-key contention.
                        state.interactive_count.fetch_add(1, Ordering::Relaxed);
                        let _guard = InteractiveGuard(state.interactive_count.clone());

                        // Transition thread state → Processing
                        let thread_store = state.store.clone();
                        let thread_ns = ns.clone();
                        {
                            if let Ok(Some(mut session)) = thread_store.load(&thread_ns).await {
                                crate::thread::transition(&mut session, crate::thread::ThreadState::Processing);
                                crate::thread::set_checkpoint(&mut session);
                                let _ = thread_store.save(&session).await;
                            }
                        }

                        let done_store = thread_store.clone();
                        let done_ns = thread_ns.clone();
                        tokio::spawn(async move {
                            // _guard is moved into this task; its Drop decrements the counter.
                            let _guard = _guard;
                            hlog!("[ws] runtime task started: ns={}", ns_key_clone);

                            // Helper: transition thread state after completion
                            let update_thread_state = |store: Arc<dyn orra::store::SessionStore>,
                                                        ns: Namespace,
                                                        state: crate::thread::ThreadState| {
                                async move {
                                    if let Ok(Some(mut session)) = store.load(&ns).await {
                                        crate::thread::transition(&mut session, state);
                                        if state == crate::thread::ThreadState::Completed {
                                            let mut info = crate::thread::thread_info(&session);
                                            info.turn_count = crate::thread::parse_turns(&session).len();
                                            crate::thread::set_thread_info(&mut session, &info);
                                        }
                                        let _ = store.save(&session).await;
                                    }
                                }
                            };

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
                                                hlog!(
                                                    "[ws] stream done: ns={}, turns={}, tokens={}",
                                                    ns_key_clone,
                                                    result.turns.len(),
                                                    result.total_usage.total_tokens()
                                                );
                                                update_thread_state(
                                                    done_store.clone(), done_ns.clone(),
                                                    crate::thread::ThreadState::Completed,
                                                ).await;
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
                                                hlog!("[ws] stream error: ns={}, err={}", ns_key_clone, err);
                                                update_thread_state(
                                                    done_store.clone(), done_ns.clone(),
                                                    crate::thread::ThreadState::Interrupted,
                                                ).await;
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
                                Err(e) => {
                                    // Streaming not available, fall back to non-streaming
                                    hlog!("[ws] streaming unavailable ({}), falling back to non-streaming: ns={}", e, ns_key_clone);
                                    let ws_msg = match runtime.run_with_model(&ns, Message::user(&cleaned_message), model, None).await {
                                        Ok(result) => {
                                            hlog!(
                                                "[ws] non-stream done: ns={}, turns={}, tokens={}",
                                                ns_key_clone,
                                                result.turns.len(),
                                                result.total_usage.total_tokens()
                                            );
                                            update_thread_state(
                                                done_store.clone(), done_ns.clone(),
                                                crate::thread::ThreadState::Completed,
                                            ).await;
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
                                            hlog!("[ws] non-stream error: ns={}, err={}", ns_key_clone, e);
                                            update_thread_state(
                                                done_store.clone(), done_ns.clone(),
                                                crate::thread::ThreadState::Interrupted,
                                            ).await;
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
) -> (
    Arc<orra::runtime::Runtime<orra::context::CharEstimator>>,
    Option<String>,
) {
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

async fn send_ws_msg(socket: &mut WebSocket, msg: &WsMessage) -> Result<(), axum::Error> {
    let json = serde_json::to_string(msg).unwrap_or_default();
    socket.send(WsRawMessage::Text(json.into())).await
}

// ---------------------------------------------------------------------------
// Federation: @peer:agent detection
// ---------------------------------------------------------------------------

struct RemoteAgentMatch {
    agent_name: String,
    peer_url: String,
    peer_secret: String,
    cleaned_message: String,
}

/// Detect `@peer:agent` pattern at the start of a message and look up the
/// remote agent in the federation registry.
async fn detect_remote_agent_mention(
    message: &str,
    federation: &crate::federation::FederationService,
) -> Option<RemoteAgentMatch> {
    let trimmed = message.trim();

    // Match @peer:agent at start of message
    if !trimmed.starts_with('@') {
        return None;
    }

    // Extract the @peer:agent token
    let token_end = trimmed
        .find(|c: char| c.is_whitespace())
        .unwrap_or(trimmed.len());
    let token = &trimmed[1..token_end]; // strip leading @

    // Must contain exactly one ':'
    let (peer_name, agent_name) = token.split_once(':')?;
    if peer_name.is_empty() || agent_name.is_empty() {
        return None;
    }

    // Look up in registry
    let (url, secret, _info) = federation
        .registry()
        .find_agent(Some(peer_name), agent_name)
        .await?;

    let cleaned = trimmed[token_end..].trim().to_string();
    let cleaned = if cleaned.is_empty() {
        // If no message after the mention, use the whole thing
        trimmed.to_string()
    } else {
        cleaned
    };

    Some(RemoteAgentMatch {
        agent_name: agent_name.to_string(),
        peer_url: url,
        peer_secret: secret,
        cleaned_message: cleaned,
    })
}
