//! Federation HTTP client for communicating with peer instances.

use orra::channels::federation::{
    FederatedSessionDetail, FederatedSessionInfo, HealthStatus, RelayRequest, RelayResponse,
    RemoteAgentInfo, SessionChatRequest, SessionChatResponse, ToolExecRequest, ToolExecResponse,
};

/// Client for communicating with a single federation peer.
///
/// All methods are stateless — call them with the peer's URL and shared secret.
pub struct PeerClient;

impl PeerClient {
    /// Discover agents available on a peer.
    pub async fn discover_agents(
        base_url: &str,
        shared_secret: &str,
    ) -> Result<Vec<RemoteAgentInfo>, PeerClientError> {
        let url = format!("{}/api/federation/agents", base_url.trim_end_matches('/'));

        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(shared_secret)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(PeerClientError::Status(resp.status().as_u16()));
        }

        let agents: Vec<RemoteAgentInfo> = resp
            .json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))?;

        Ok(agents)
    }

    /// Relay a message to a remote agent.
    ///
    /// Timeout is 600s because relay now involves multiple round-trips for
    /// tool execution callbacks when `tool_callback_url` is set.
    pub async fn relay_message(
        base_url: &str,
        shared_secret: &str,
        request: &RelayRequest,
    ) -> Result<RelayResponse, PeerClientError> {
        let url = format!("{}/api/federation/relay", base_url.trim_end_matches('/'));

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(shared_secret)
            .json(request)
            .timeout(std::time::Duration::from_secs(600))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(PeerClientError::Relay {
                status,
                message: body,
            });
        }

        let response: RelayResponse = resp
            .json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))?;

        Ok(response)
    }

    /// Check if a peer is healthy.
    pub async fn health_check(
        base_url: &str,
        shared_secret: &str,
    ) -> Result<bool, PeerClientError> {
        let url = format!("{}/api/federation/health", base_url.trim_end_matches('/'));

        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(shared_secret)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(false);
        }

        let status: HealthStatus = resp
            .json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))?;

        Ok(status.status == "ok")
    }

    /// List sessions available on a peer.
    pub async fn list_sessions(
        base_url: &str,
        shared_secret: &str,
    ) -> Result<Vec<FederatedSessionInfo>, PeerClientError> {
        let url = format!(
            "{}/api/federation/sessions",
            base_url.trim_end_matches('/')
        );

        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(shared_secret)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(PeerClientError::Status(resp.status().as_u16()));
        }

        resp.json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))
    }

    /// Get the full detail of a remote session.
    pub async fn get_session(
        base_url: &str,
        shared_secret: &str,
        namespace: &str,
    ) -> Result<FederatedSessionDetail, PeerClientError> {
        let url = format!(
            "{}/api/federation/sessions/detail?namespace={}",
            base_url.trim_end_matches('/'),
            urlencoding::encode(namespace),
        );

        let resp = reqwest::Client::new()
            .get(&url)
            .bearer_auth(shared_secret)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(PeerClientError::Status(resp.status().as_u16()));
        }

        resp.json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))
    }

    /// Execute tool calls on the originating peer via callback.
    ///
    /// Used by `RemoteToolExecutor` to send tool calls back to the peer that
    /// initiated the federation relay request.
    pub async fn execute_tools(
        callback_url: &str,
        callback_secret: &str,
        request: &ToolExecRequest,
    ) -> Result<ToolExecResponse, PeerClientError> {
        let resp = reqwest::Client::new()
            .post(callback_url)
            .bearer_auth(callback_secret)
            .json(request)
            .timeout(std::time::Duration::from_secs(300))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(PeerClientError::Relay {
                status,
                message: body,
            });
        }

        resp.json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))
    }

    /// Send a chat message to a remote session (non-streaming).
    pub async fn chat_in_session(
        base_url: &str,
        shared_secret: &str,
        request: &SessionChatRequest,
    ) -> Result<SessionChatResponse, PeerClientError> {
        let url = format!(
            "{}/api/federation/sessions/chat",
            base_url.trim_end_matches('/')
        );

        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(shared_secret)
            .json(request)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| PeerClientError::Request(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(PeerClientError::Relay {
                status,
                message: body,
            });
        }

        resp.json()
            .await
            .map_err(|e| PeerClientError::Deserialize(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PeerClientError {
    #[error("request failed: {0}")]
    Request(String),

    #[error("peer returned status {0}")]
    Status(u16),

    #[error("relay failed (status {status}): {message}")]
    Relay { status: u16, message: String },

    #[error("failed to deserialize response: {0}")]
    Deserialize(String),
}
