//! Federation module — multi-instance agent discovery and message relay.
//!
//! Enables multiple herald instances to discover each other's agents and
//! route requests to the best-suited instance. The module is composed of:
//!
//! - [`FederationService`] — orchestrator that manages config, registry, and background tasks
//! - [`PeerRegistry`] — thread-safe registry of known peers and their agents
//! - [`client`] — HTTP client for communicating with peers
//! - [`api`] — Axum handlers for incoming peer requests
//! - [`discovery`] — mDNS service registration and browsing
//! - [`tool`] — `DelegateToRemoteAgentTool` for agent-initiated delegation

pub mod api;
pub mod client;
pub mod discovery;
pub mod manager;
pub mod tool;
pub mod tool_executor;

use crate::hlog;
use std::collections::HashMap;
use std::sync::Arc;

use orra::channels::federation::RemoteAgentInfo;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::config::FederationConfig;

// ---------------------------------------------------------------------------
// Peer state
// ---------------------------------------------------------------------------

/// Health status of a known peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerHealth {
    /// Peer is reachable and responding.
    Healthy,
    /// Peer has failed recent health checks.
    Unhealthy,
    /// Peer was recently discovered but not yet checked.
    Unknown,
}

/// State tracked for a single peer instance.
#[derive(Debug, Clone)]
pub struct PeerState {
    /// Display name of the peer (from config or mDNS).
    pub name: String,
    /// Base URL of the peer's federation API.
    pub url: String,
    /// Shared secret used for this peer (global or per-peer override).
    pub shared_secret: String,
    /// Agents available on this peer.
    pub agents: Vec<RemoteAgentInfo>,
    /// Current health status.
    pub health: PeerHealth,
    /// How this peer was discovered.
    pub source: PeerSource,
}

/// How a peer was added to the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSource {
    /// Manually configured in the config file.
    Static,
    /// Discovered via mDNS on the local network.
    Mdns,
}

// ---------------------------------------------------------------------------
// Peer registry
// ---------------------------------------------------------------------------

/// Thread-safe registry of known federation peers and their agents.
///
/// Keyed by peer name. All access goes through `RwLock`.
#[derive(Debug, Clone)]
pub struct PeerRegistry {
    inner: Arc<RwLock<HashMap<String, PeerState>>>,
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Update or insert a peer. Returns `true` if this was a new peer.
    pub async fn update_peer(&self, peer: PeerState) -> bool {
        let mut map = self.inner.write().await;
        let is_new = !map.contains_key(&peer.name);
        map.insert(peer.name.clone(), peer);
        is_new
    }

    /// Mark a peer as unhealthy.
    pub async fn mark_unhealthy(&self, name: &str) {
        let mut map = self.inner.write().await;
        if let Some(peer) = map.get_mut(name) {
            peer.health = PeerHealth::Unhealthy;
        }
    }

    /// Mark a peer as healthy.
    pub async fn mark_healthy(&self, name: &str) {
        let mut map = self.inner.write().await;
        if let Some(peer) = map.get_mut(name) {
            peer.health = PeerHealth::Healthy;
        }
    }

    /// Remove a peer by name. Returns the removed state if it existed.
    pub async fn remove_peer(&self, name: &str) -> Option<PeerState> {
        let mut map = self.inner.write().await;
        map.remove(name)
    }

    /// Get a snapshot of all remote agents across all healthy peers.
    pub async fn remote_agents(&self) -> Vec<RemoteAgentInfo> {
        let map = self.inner.read().await;
        map.values()
            .filter(|p| p.health != PeerHealth::Unhealthy)
            .flat_map(|p| p.agents.iter().cloned())
            .collect()
    }

    /// Find a specific agent. If `peer` is `Some`, search only that peer;
    /// otherwise search all peers. Returns `(peer_url, shared_secret, agent_info)`.
    pub async fn find_agent(
        &self,
        peer: Option<&str>,
        agent_name: &str,
    ) -> Option<(String, String, RemoteAgentInfo)> {
        let map = self.inner.read().await;
        let lower = agent_name.to_lowercase();

        if let Some(peer_name) = peer {
            // Exact peer lookup
            if let Some(state) = map.get(peer_name) {
                if let Some(info) = state
                    .agents
                    .iter()
                    .find(|a| a.name.to_lowercase() == lower)
                {
                    return Some((
                        state.url.clone(),
                        state.shared_secret.clone(),
                        info.clone(),
                    ));
                }
            }
            return None;
        }

        // Search all healthy peers
        for state in map.values() {
            if state.health == PeerHealth::Unhealthy {
                continue;
            }
            if let Some(info) = state
                .agents
                .iter()
                .find(|a| a.name.to_lowercase() == lower)
            {
                return Some((
                    state.url.clone(),
                    state.shared_secret.clone(),
                    info.clone(),
                ));
            }
        }

        None
    }

    /// Get a snapshot of all known peers.
    pub async fn list_peers(&self) -> Vec<PeerState> {
        let map = self.inner.read().await;
        map.values().cloned().collect()
    }

    /// Get the number of known peers.
    #[allow(dead_code)]
    pub async fn peer_count(&self) -> usize {
        let map = self.inner.read().await;
        map.len()
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Federation service
// ---------------------------------------------------------------------------

/// Information about a local agent to expose to peers.
#[derive(Debug, Clone)]
pub struct LocalAgentInfo {
    pub name: String,
    pub personality: String,
    pub model: String,
}

/// Orchestrates federation: owns config, peer registry, and background tasks.
pub struct FederationService {
    config: FederationConfig,
    registry: PeerRegistry,
    local_agents: Vec<LocalAgentInfo>,
}

impl FederationService {
    pub fn new(config: FederationConfig, local_agents: Vec<LocalAgentInfo>) -> Self {
        Self {
            config,
            registry: PeerRegistry::new(),
            local_agents,
        }
    }

    /// Instance name for this herald.
    pub fn instance_name(&self) -> &str {
        &self.config.instance_name
    }

    /// Global shared secret (may be `None` if all peers have per-peer secrets).
    #[allow(dead_code)]
    pub fn shared_secret(&self) -> Option<&str> {
        self.config.shared_secret.as_deref()
    }

    /// Reference to the peer registry.
    pub fn registry(&self) -> &PeerRegistry {
        &self.registry
    }

    /// Whether mDNS is enabled.
    #[allow(dead_code)]
    pub fn mdns_enabled(&self) -> bool {
        self.config.mdns_enabled
    }

    /// The federation port.
    pub fn port(&self, gateway_port: u16) -> u16 {
        self.config.resolve_port(gateway_port)
    }

    /// Agents exposed to peers. Returns the filtered list based on config.
    pub fn exposed_agents(&self) -> Vec<RemoteAgentInfo> {
        let instance = self.config.instance_name.clone();

        self.local_agents
            .iter()
            .filter(|a| {
                self.config.exposed_agents.is_empty()
                    || self.config.exposed_agents.iter().any(|e| {
                        e.eq_ignore_ascii_case(&a.name)
                    })
            })
            .map(|a| RemoteAgentInfo {
                name: a.name.clone(),
                personality: a.personality.clone(),
                model: a.model.clone(),
                instance: instance.clone(),
            })
            .collect()
    }

    /// Validate that a bearer token matches our shared secret.
    pub fn validate_secret(&self, token: &str) -> bool {
        // Check global secret
        if let Some(secret) = &self.config.shared_secret {
            if token == secret {
                return true;
            }
        }

        // Check per-peer secrets (any peer's secret is valid for incoming requests)
        self.config
            .peers
            .iter()
            .any(|p| p.shared_secret.as_deref() == Some(token))
    }

    /// Start background tasks: static peer sync, health checks, mDNS.
    ///
    /// Accepts a `CancellationToken` for cooperative shutdown. When the token
    /// is cancelled, all background loops will exit gracefully.
    ///
    /// Returns join handles for the spawned tasks. Caller should store them
    /// to await or cancel on shutdown.
    pub async fn start(
        &self,
        gateway_port: u16,
        cancel_token: CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        // Seed registry with static peers
        let global_secret = self.config.shared_secret.clone().unwrap_or_default();
        for peer_config in &self.config.peers {
            let secret = peer_config
                .shared_secret
                .clone()
                .unwrap_or_else(|| global_secret.clone());

            self.registry
                .update_peer(PeerState {
                    name: peer_config.name.clone(),
                    url: peer_config.url.clone(),
                    shared_secret: secret,
                    agents: Vec::new(),
                    health: PeerHealth::Unknown,
                    source: PeerSource::Static,
                })
                .await;
        }

        // Background task: discover agents from static peers (every 60s)
        {
            let registry = self.registry.clone();
            let peers: Vec<_> = self.config.peers.clone();
            let global_secret = global_secret.clone();
            let token = cancel_token.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    for peer_config in &peers {
                        let secret = peer_config
                            .shared_secret
                            .clone()
                            .unwrap_or_else(|| global_secret.clone());

                        match client::PeerClient::discover_agents(&peer_config.url, &secret).await {
                            Ok(agents) => {
                                registry
                                    .update_peer(PeerState {
                                        name: peer_config.name.clone(),
                                        url: peer_config.url.clone(),
                                        shared_secret: secret,
                                        agents,
                                        health: PeerHealth::Healthy,
                                        source: PeerSource::Static,
                                    })
                                    .await;
                            }
                            Err(e) => {
                                hlog!(
                                    "[federation] failed to discover agents from '{}': {e}",
                                    peer_config.name
                                );
                                registry.mark_unhealthy(&peer_config.name).await;
                            }
                        }
                    }
                    tokio::select! {
                        _ = token.cancelled() => {
                            hlog!("[federation] peer discovery task shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                    }
                }
            }));
        }

        // Background task: health check all peers (every 30s)
        {
            let registry = self.registry.clone();
            let token = cancel_token.clone();
            handles.push(tokio::spawn(async move {
                // Initial delay to let discovery run first
                tokio::select! {
                    _ = token.cancelled() => {
                        hlog!("[federation] health check task shutting down (during initial delay)");
                        return;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                }
                loop {
                    let peers = registry.list_peers().await;
                    for peer in &peers {
                        match client::PeerClient::health_check(&peer.url, &peer.shared_secret).await
                        {
                            Ok(true) => {
                                registry.mark_healthy(&peer.name).await;
                            }
                            _ => {
                                registry.mark_unhealthy(&peer.name).await;
                            }
                        }
                    }
                    tokio::select! {
                        _ = token.cancelled() => {
                            hlog!("[federation] health check task shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                    }
                }
            }));
        }

        // Background task: mDNS discovery
        if self.config.mdns_enabled {
            let federation_port = self.port(gateway_port);

            // Register our service
            let instance_name = self.config.instance_name.clone();
            let register_token = cancel_token.clone();
            let register_handle = tokio::spawn(async move {
                if let Err(e) =
                    discovery::register_service(&instance_name, federation_port, register_token)
                        .await
                {
                    hlog!("[federation] mDNS registration failed: {e}");
                }
            });
            handles.push(register_handle);

            // Browse for peers
            let registry = self.registry.clone();
            let own_instance = self.config.instance_name.clone();
            let global_secret = global_secret.clone();
            let browse_token = cancel_token.clone();
            let browse_handle = tokio::spawn(async move {
                if let Err(e) = discovery::browse_peers(
                    registry,
                    &own_instance,
                    &global_secret,
                    browse_token,
                )
                .await
                {
                    hlog!("[federation] mDNS browsing failed: {e}");
                }
            });
            handles.push(browse_handle);
        }

        handles
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_registry_crud() {
        let registry = PeerRegistry::new();

        // Insert
        let is_new = registry
            .update_peer(PeerState {
                name: "peer-1".into(),
                url: "http://localhost:9001".into(),
                shared_secret: "secret".into(),
                agents: vec![RemoteAgentInfo {
                    name: "Atlas".into(),
                    personality: "helpful".into(),
                    model: "claude-opus-4-6".into(),
                    instance: "peer-1".into(),
                }],
                health: PeerHealth::Healthy,
                source: PeerSource::Static,
            })
            .await;
        assert!(is_new);
        assert_eq!(registry.peer_count().await, 1);

        // Update existing
        let is_new = registry
            .update_peer(PeerState {
                name: "peer-1".into(),
                url: "http://localhost:9001".into(),
                shared_secret: "secret".into(),
                agents: vec![],
                health: PeerHealth::Healthy,
                source: PeerSource::Static,
            })
            .await;
        assert!(!is_new);
        assert_eq!(registry.peer_count().await, 1);

        // Remove
        let removed = registry.remove_peer("peer-1").await;
        assert!(removed.is_some());
        assert_eq!(registry.peer_count().await, 0);
    }

    #[tokio::test]
    async fn remote_agents_excludes_unhealthy() {
        let registry = PeerRegistry::new();

        registry
            .update_peer(PeerState {
                name: "healthy".into(),
                url: "http://h:9001".into(),
                shared_secret: "s".into(),
                agents: vec![RemoteAgentInfo {
                    name: "Agent1".into(),
                    personality: "".into(),
                    model: "m".into(),
                    instance: "healthy".into(),
                }],
                health: PeerHealth::Healthy,
                source: PeerSource::Static,
            })
            .await;

        registry
            .update_peer(PeerState {
                name: "unhealthy".into(),
                url: "http://u:9001".into(),
                shared_secret: "s".into(),
                agents: vec![RemoteAgentInfo {
                    name: "Agent2".into(),
                    personality: "".into(),
                    model: "m".into(),
                    instance: "unhealthy".into(),
                }],
                health: PeerHealth::Unhealthy,
                source: PeerSource::Static,
            })
            .await;

        let agents = registry.remote_agents().await;
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "Agent1");
    }

    #[tokio::test]
    async fn find_agent_by_name() {
        let registry = PeerRegistry::new();

        registry
            .update_peer(PeerState {
                name: "peer-1".into(),
                url: "http://p1:9001".into(),
                shared_secret: "secret".into(),
                agents: vec![RemoteAgentInfo {
                    name: "CodeBot".into(),
                    personality: "coding".into(),
                    model: "m".into(),
                    instance: "peer-1".into(),
                }],
                health: PeerHealth::Healthy,
                source: PeerSource::Static,
            })
            .await;

        // Case-insensitive search across all peers
        let result = registry.find_agent(None, "codebot").await;
        assert!(result.is_some());
        let (url, secret, info) = result.unwrap();
        assert_eq!(url, "http://p1:9001");
        assert_eq!(secret, "secret");
        assert_eq!(info.name, "CodeBot");

        // Specific peer lookup
        let result = registry.find_agent(Some("peer-1"), "CodeBot").await;
        assert!(result.is_some());

        // Wrong peer
        let result = registry.find_agent(Some("peer-2"), "CodeBot").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mark_health() {
        let registry = PeerRegistry::new();

        registry
            .update_peer(PeerState {
                name: "p".into(),
                url: "http://p:9001".into(),
                shared_secret: "s".into(),
                agents: vec![],
                health: PeerHealth::Healthy,
                source: PeerSource::Static,
            })
            .await;

        registry.mark_unhealthy("p").await;
        let peers = registry.list_peers().await;
        assert_eq!(peers[0].health, PeerHealth::Unhealthy);

        registry.mark_healthy("p").await;
        let peers = registry.list_peers().await;
        assert_eq!(peers[0].health, PeerHealth::Healthy);
    }

    #[test]
    fn exposed_agents_filter() {
        let config = FederationConfig {
            enabled: true,
            instance_name: "test".into(),
            shared_secret: Some("secret".into()),
            port: None,
            mdns_enabled: false,
            exposed_agents: vec!["Atlas".into()],
            peers: vec![],
        };

        let local_agents = vec![
            LocalAgentInfo {
                name: "Atlas".into(),
                personality: "helpful".into(),
                model: "m".into(),
            },
            LocalAgentInfo {
                name: "CodeBot".into(),
                personality: "coding".into(),
                model: "m".into(),
            },
        ];

        let service = FederationService::new(config, local_agents);
        let exposed = service.exposed_agents();
        assert_eq!(exposed.len(), 1);
        assert_eq!(exposed[0].name, "Atlas");
    }

    #[test]
    fn exposed_agents_all_when_empty() {
        let config = FederationConfig {
            enabled: true,
            instance_name: "test".into(),
            shared_secret: Some("secret".into()),
            port: None,
            mdns_enabled: false,
            exposed_agents: vec![],
            peers: vec![],
        };

        let local_agents = vec![
            LocalAgentInfo {
                name: "Atlas".into(),
                personality: "helpful".into(),
                model: "m".into(),
            },
            LocalAgentInfo {
                name: "CodeBot".into(),
                personality: "coding".into(),
                model: "m".into(),
            },
        ];

        let service = FederationService::new(config, local_agents);
        let exposed = service.exposed_agents();
        assert_eq!(exposed.len(), 2);
    }

    #[test]
    fn validate_secret_global() {
        let config = FederationConfig {
            enabled: true,
            instance_name: "test".into(),
            shared_secret: Some("global-secret".into()),
            port: None,
            mdns_enabled: false,
            exposed_agents: vec![],
            peers: vec![],
        };

        let service = FederationService::new(config, vec![]);
        assert!(service.validate_secret("global-secret"));
        assert!(!service.validate_secret("wrong"));
    }

    #[test]
    fn validate_secret_per_peer() {
        let config = FederationConfig {
            enabled: true,
            instance_name: "test".into(),
            shared_secret: None,
            port: None,
            mdns_enabled: false,
            exposed_agents: vec![],
            peers: vec![crate::config::FederationPeerConfig {
                name: "peer".into(),
                url: "http://peer:9001".into(),
                shared_secret: Some("peer-secret".into()),
            }],
        };

        let service = FederationService::new(config, vec![]);
        assert!(service.validate_secret("peer-secret"));
        assert!(!service.validate_secret("wrong"));
    }
}
