//! Remote delegation tool — allows agents to delegate tasks to remote peers.

use std::sync::Arc;

use async_trait::async_trait;
use orra::channels::federation::RelayRequest;
use orra::tool::{Tool, ToolDefinition, ToolError};

use super::client::PeerClient;
use super::manager::FederationManager;

/// Tool that lets an agent delegate a task to a remote agent on a federated peer.
///
/// Follows the same pattern as `DelegateToAgentTool` but routes across instances.
/// Holds a reference to `FederationManager` so it always uses the latest service
/// after a hot-reload.
///
/// When delegating, the tool includes a `tool_callback_url` in the relay request
/// so the remote peer can proxy tool calls back to this instance for local execution.
pub struct DelegateToRemoteAgentTool {
    /// The federation manager to get the current service and registry.
    manager: Arc<FederationManager>,
    /// Name of the agent that owns this tool (for source_agent in relay).
    self_agent: String,
    /// The gateway port, used to compute the federation port for tool callbacks.
    gateway_port: u16,
}

impl DelegateToRemoteAgentTool {
    pub fn new(
        manager: Arc<FederationManager>,
        self_agent: String,
        gateway_port: u16,
    ) -> Self {
        Self {
            manager,
            self_agent,
            gateway_port,
        }
    }
}

#[async_trait]
impl Tool for DelegateToRemoteAgentTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "delegate_to_remote_agent".into(),
            description: "Delegate a task to an agent on a remote federated herald instance. \
                          Use this when a remote agent is better suited for a task. \
                          The target can be specified as just the agent name (searched across \
                          all peers) or as 'peer:agent' for a specific instance."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target agent. Can be 'agent_name' (search all peers) or 'peer:agent_name' (specific peer)"
                    },
                    "task": {
                        "type": "string",
                        "description": "The task or question to delegate to the remote agent"
                    }
                },
                "required": ["target", "task"]
            }),
        }
    }

    async fn execute(&self, input: serde_json::Value) -> Result<String, ToolError> {
        let target = input
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing 'target'".into()))?;

        let task = input
            .get("task")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing 'task'".into()))?;

        // Get the current federation service
        let service = self.manager.service().await.ok_or_else(|| {
            ToolError::ExecutionFailed("Federation is not currently running".into())
        })?;

        let registry = service.registry();
        let instance_name = service.instance_name().to_string();

        // Parse target: "peer:agent" or just "agent"
        let (peer, agent_name) = if let Some((p, a)) = target.split_once(':') {
            (Some(p), a)
        } else {
            (None, target)
        };

        // Look up the remote agent
        let (url, secret, info) =
            registry
                .find_agent(peer, agent_name)
                .await
                .ok_or_else(|| {
                    let available = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(async {
                            let agents = registry.remote_agents().await;
                            agents
                                .iter()
                                .map(|a| format!("{}:{}", a.instance, a.name))
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                    });

                    ToolError::ExecutionFailed(format!(
                        "remote agent '{}' not found. Available remote agents: {}",
                        target,
                        if available.is_empty() {
                            "none".to_string()
                        } else {
                            available
                        }
                    ))
                })?;

        // Build the tool callback URL so the remote peer can proxy tool calls
        // back to us for local execution (with our tools, hooks, and filesystem).
        let fed_port = service.port(self.gateway_port);
        let (tool_callback_url, tool_callback_secret) = {
            // The remote peer needs to reach us via HTTP. We use our machine's
            // hostname + federation port. The remote peer must be able to
            // resolve this hostname (works on LAN with mDNS, or with DNS).
            let host = hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".into());
            let callback_url =
                format!("http://{}:{}/api/federation/tool-exec", host, fed_port);
            let callback_secret = service
                .shared_secret()
                .unwrap_or_default()
                .to_string();
            (Some(callback_url), Some(callback_secret))
        };

        // Create the relay request
        let request = RelayRequest {
            agent: info.name.clone(),
            message: task.to_string(),
            source_peer: instance_name,
            source_agent: Some(self.self_agent.clone()),
            namespace: format!(
                "federation:{}:{}",
                self.self_agent,
                uuid::Uuid::new_v4()
            ),
            tool_callback_url,
            tool_callback_secret,
        };

        // Send the relay request
        let response = PeerClient::relay_message(&url, &secret, &request)
            .await
            .map_err(|e| {
                ToolError::ExecutionFailed(format!(
                    "relay to remote agent '{}' on '{}' failed: {e}",
                    info.name, info.instance
                ))
            })?;

        Ok(format!(
            "[Remote agent '{}' on '{}' responded]\n\n{}",
            response.agent, response.instance, response.message,
        ))
    }
}
