//! Remote tool executor — proxies tool calls back to the originating peer.
//!
//! When a federation relay request includes a `tool_callback_url`, the receiving
//! peer creates a `RemoteToolExecutor` that implements `ToolExecutor`. Instead
//! of running tools locally, it POSTs tool calls back to the originating peer's
//! `/api/federation/tool-exec` endpoint for local execution.

use orra::channels::federation::{ToolCallInfo, ToolExecRequest};
use orra::message::{ToolCall, ToolResult};
use orra::namespace::Namespace;
use orra::runtime::ToolExecutor;

use super::client::PeerClient;

/// Executes tool calls by proxying them back to the originating peer.
///
/// Created when a `RelayRequest` includes `tool_callback_url` / `tool_callback_secret`.
/// The receiving peer's LLM decides which tools to call, but instead of executing
/// them locally, this executor sends them back to the originating peer where the
/// tools, hooks (including approval), and filesystem context are local.
pub struct RemoteToolExecutor {
    callback_url: String,
    callback_secret: String,
    namespace: String,
}

impl RemoteToolExecutor {
    pub fn new(callback_url: String, callback_secret: String, namespace: String) -> Self {
        Self {
            callback_url,
            callback_secret,
            namespace,
        }
    }
}

#[async_trait::async_trait]
impl ToolExecutor for RemoteToolExecutor {
    async fn execute_tool_calls(
        &self,
        _namespace: &Namespace,
        tool_calls: &[ToolCall],
    ) -> Vec<ToolResult> {
        // Convert orra ToolCall types to federation wire types
        let call_infos: Vec<ToolCallInfo> = tool_calls
            .iter()
            .map(|tc| ToolCallInfo {
                id: tc.id.clone(),
                name: tc.name.clone(),
                arguments: tc.arguments.clone(),
            })
            .collect();

        let request = ToolExecRequest {
            namespace: self.namespace.clone(),
            tool_calls: call_infos,
        };

        // POST to the originating peer's tool-exec endpoint
        match PeerClient::execute_tools(&self.callback_url, &self.callback_secret, &request).await {
            Ok(response) => {
                // Convert wire types back to orra ToolResult types
                response
                    .results
                    .into_iter()
                    .map(|r| ToolResult {
                        call_id: r.call_id,
                        content: r.content,
                        is_error: r.is_error,
                    })
                    .collect()
            }
            Err(e) => {
                // If the callback fails, return error results for all tool calls
                eprintln!(
                    "[federation] tool callback to {} failed: {e}",
                    self.callback_url
                );
                tool_calls
                    .iter()
                    .map(|tc| ToolResult {
                        call_id: tc.id.clone(),
                        content: format!("federation tool callback failed: {e}"),
                        is_error: true,
                    })
                    .collect()
            }
        }
    }
}
