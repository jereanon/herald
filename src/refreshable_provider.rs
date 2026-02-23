//! A provider wrapper that automatically refreshes expired OAuth tokens.
//!
//! When the inner provider returns `ProviderError::Auth`, the wrapper calls a
//! user-supplied refresh callback to obtain a fresh provider. If the refresh
//! succeeds the original request is retried exactly once.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use orra::provider::{CompletionRequest, CompletionResponse, Provider, ProviderError};

use crate::hlog;

// ---------------------------------------------------------------------------
// Refresh callback type
// ---------------------------------------------------------------------------

/// A callback that attempts to refresh credentials and return a new provider.
///
/// Returning `Some(provider)` means the refresh succeeded and the new provider
/// should replace the current one.  Returning `None` means the refresh failed
/// and the original error should be propagated.
pub type RefreshFn = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Option<Arc<dyn Provider>>> + Send>> + Send + Sync,
>;

// ---------------------------------------------------------------------------
// RefreshableProvider
// ---------------------------------------------------------------------------

/// Wraps any `Provider` and transparently retries on auth failure after
/// refreshing credentials.
pub struct RefreshableProvider {
    inner: Arc<RwLock<Arc<dyn Provider>>>,
    refresh: Option<RefreshFn>,
}

impl RefreshableProvider {
    /// Create a new refreshable wrapper.
    ///
    /// If `refresh` is `None` the wrapper acts as a transparent passthrough.
    pub fn new(provider: Arc<dyn Provider>, refresh: Option<RefreshFn>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(provider)),
            refresh,
        }
    }

    /// Replace the inner provider (used when the outer `DynamicProvider` swaps).
    pub async fn swap(&self, provider: Arc<dyn Provider>) {
        *self.inner.write().await = provider;
    }
}

#[async_trait]
impl Provider for RefreshableProvider {
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, ProviderError> {
        let provider = self.inner.read().await.clone();
        let result = provider.complete(request.clone()).await;

        match (&result, &self.refresh) {
            (Err(ProviderError::Auth(_)), Some(refresh)) => {
                hlog!("[auth] provider returned auth error, attempting token refresh...");

                match (refresh)().await {
                    Some(new_provider) => {
                        hlog!("[auth] token refreshed, retrying request");
                        *self.inner.write().await = new_provider.clone();
                        new_provider.complete(request).await
                    }
                    None => {
                        hlog!("[auth] token refresh failed");
                        result
                    }
                }
            }
            _ => result,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use orra::message::Message;
    use orra::provider::{CompletionResponse, FinishReason, Usage};

    /// A provider that always succeeds.
    struct OkProvider;

    #[async_trait]
    impl Provider for OkProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<CompletionResponse, ProviderError> {
            Ok(CompletionResponse {
                message: Message::assistant("ok"),
                usage: Usage::default(),
                finish_reason: FinishReason::Stop,
            })
        }
    }

    /// A provider that always returns an auth error.
    struct AuthErrorProvider;

    #[async_trait]
    impl Provider for AuthErrorProvider {
        async fn complete(
            &self,
            _request: CompletionRequest,
        ) -> Result<CompletionResponse, ProviderError> {
            Err(ProviderError::Auth("token expired".into()))
        }
    }

    fn test_request() -> CompletionRequest {
        CompletionRequest {
            messages: vec![Message::user("test")],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            model: None,
        }
    }

    #[tokio::test]
    async fn passthrough_on_success() {
        let provider = RefreshableProvider::new(Arc::new(OkProvider), None);
        let resp = provider.complete(test_request()).await.unwrap();
        assert_eq!(resp.message.content, "ok");
    }

    #[tokio::test]
    async fn no_refresh_without_callback() {
        let provider = RefreshableProvider::new(Arc::new(AuthErrorProvider), None);
        let err = provider.complete(test_request()).await.unwrap_err();
        assert!(matches!(err, ProviderError::Auth(_)));
    }

    #[tokio::test]
    async fn refresh_and_retry_on_auth_error() {
        let refresh: RefreshFn = Arc::new(|| {
            Box::pin(async { Some(Arc::new(OkProvider) as Arc<dyn Provider>) })
        });

        let provider =
            RefreshableProvider::new(Arc::new(AuthErrorProvider), Some(refresh));

        // Should succeed after refreshing
        let resp = provider.complete(test_request()).await.unwrap();
        assert_eq!(resp.message.content, "ok");
    }

    #[tokio::test]
    async fn returns_error_when_refresh_fails() {
        let refresh: RefreshFn = Arc::new(|| Box::pin(async { None }));

        let provider =
            RefreshableProvider::new(Arc::new(AuthErrorProvider), Some(refresh));

        let err = provider.complete(test_request()).await.unwrap_err();
        assert!(matches!(err, ProviderError::Auth(_)));
    }

    #[tokio::test]
    async fn swap_replaces_inner() {
        let provider = RefreshableProvider::new(Arc::new(AuthErrorProvider), None);
        let err = provider.complete(test_request()).await.unwrap_err();
        assert!(matches!(err, ProviderError::Auth(_)));

        // Swap in a working provider
        provider.swap(Arc::new(OkProvider)).await;
        let resp = provider.complete(test_request()).await.unwrap();
        assert_eq!(resp.message.content, "ok");
    }
}
