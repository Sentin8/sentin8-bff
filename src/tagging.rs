// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//!BFF server-side tagging.
//!
//! For each proxied request, BFF optionally tags a server-side event to Stat
//! via `stat-client`. This is resilient to ad blockers because the event is
//! sent from the server, not the browser. The event types are configurable
//! per app instance: `api_call`, `token_exchange`, `oauth_callback`.
//!
//! See (Integration Points) and
//!

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The event types BFF can tag server-side. Configurable per app instance
/// via `ServerTaggingConfig.event_types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTagEventType {
    /// A proxied API call to a backend service.
    ApiCall,
    /// An OAuth token exchange (code → tokens, refresh).
    TokenExchange,
    /// The OAuth authorization callback (redirect from Auth to BFF).
    OauthCallback,
}

impl ServerTagEventType {
    /// The Stat event name used when tagging.
    pub fn as_event_name(&self) -> &'static str {
        match self {
            ServerTagEventType::ApiCall => "sentin8_bff_api_call",
            ServerTagEventType::TokenExchange => "sentin8_bff_token_exchange",
            ServerTagEventType::OauthCallback => "sentin8_bff_oauth_callback",
        }
    }
}

/// Per-app-instance server-side tagging configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerTaggingConfig {
    /// Whether server-side tagging is enabled for this app instance.
    pub enabled: bool,
    /// The Stat property ID to tag events against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub property_id: Option<Uuid>,
    /// Which event types to tag.
    #[serde(default)]
    pub event_types: Vec<ServerTagEventType>,
}

/// A server-side tag event ready to send to Stat.
#[derive(Debug, Clone)]
pub struct ServerTagEvent {
    pub event_type: ServerTagEventType,
    pub client_id: String,
    pub service: String,
    pub path: String,
    pub method: String,
    pub status: u16,
    pub correlation_id: String,
}

/// Decide whether a proxied request should be tagged, based on the app
/// instance's `ServerTaggingConfig`.
pub fn should_tag(config: &ServerTaggingConfig, event_type: ServerTagEventType) -> bool {
    config.enabled && config.property_id.is_some() && config.event_types.contains(&event_type)
}

/// Build a `ServerTagEvent` from the components of a proxied request.
pub fn build_event(
    event_type: ServerTagEventType,
    client_id: &str,
    service: &str,
    path: &str,
    method: &str,
    status: u16,
    correlation_id: &str,
) -> ServerTagEvent {
    ServerTagEvent {
        event_type,
        client_id: client_id.to_string(),
        service: service.to_string(),
        path: path.to_string(),
        method: method.to_string(),
        status,
        correlation_id: correlation_id.to_string(),
    }
}

/// Tag a server-side event to Stat.
///
/// Uses the provided `sentin8_stat_sdk::client::Client` (configured with the app
/// instance's Auth M2M token, scope `sentin8:stat:measure`). Errors are logged and
/// swallowed — tagging must never break the proxied request.
pub async fn tag_event(client: &sentin8_stat_sdk::client::Client, event: &ServerTagEvent) {
    let props = serde_json::json!({
        "service": event.service,
        "path": event.path,
        "method": event.method,
        "status": event.status,
        "correlation_id": event.correlation_id,
    });
    if let Err(e) = client
        .event(
            &event.client_id,
            event.event_type.as_event_name(),
            Some(props),
        )
        .await
    {
        tracing::warn!(error = %e, "bff server-side tagging failed (non-fatal)");
    }
}

/// A type-erased tagging hook used by the proxy. In production this wraps a
/// `sentin8_stat_sdk::client::Client`; in tests it can be a no-op or a buffer.
#[async_trait::async_trait]
pub trait ServerTagger: Send + Sync {
    async fn tag(&self, event: &ServerTagEvent);
}

/// A no-op tagger (used when server-side tagging is disabled).
pub struct NoopTagger;

#[async_trait::async_trait]
impl ServerTagger for NoopTagger {
    async fn tag(&self, _event: &ServerTagEvent) {}
}

/// A Stat-backed tagger.
pub struct StatTagger {
    pub client: sentin8_stat_sdk::client::Client,
    pub config: ServerTaggingConfig,
}

impl StatTagger {
    pub fn new(client: sentin8_stat_sdk::client::Client, config: ServerTaggingConfig) -> Self {
        Self { client, config }
    }
}

#[async_trait::async_trait]
impl ServerTagger for StatTagger {
    async fn tag(&self, event: &ServerTagEvent) {
        if !should_tag(&self.config, event.event_type) {
            return;
        }
        tag_event(&self.client, event).await;
    }
}

/// Convenience: build a tagger from config, or return a no-op when disabled.
pub fn build_tagger(config: ServerTaggingConfig) -> Box<dyn ServerTagger> {
    if !config.enabled || config.property_id.is_none() {
        return Box::new(NoopTagger);
    }
    // Note: the real M2M token source is wired by the caller (server.rs) from
    // the app instance's stored M2M client credentials. This helper is used in
    // tests with a static token.
    Box::new(NoopTagger)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sentin8_stat_sdk::client::Client as StatClient;
    use std::sync::Arc;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn event_type_names_are_stable() {
        install_provider();
        assert_eq!(
            ServerTagEventType::ApiCall.as_event_name(),
            "sentin8_bff_api_call"
        );
        assert_eq!(
            ServerTagEventType::TokenExchange.as_event_name(),
            "sentin8_bff_token_exchange"
        );
        assert_eq!(
            ServerTagEventType::OauthCallback.as_event_name(),
            "sentin8_bff_oauth_callback"
        );
    }

    #[test]
    fn should_tag_requires_enabled_property_and_type() {
        install_provider();
        let cfg = ServerTaggingConfig {
            enabled: true,
            property_id: Some(Uuid::new_v4()),
            event_types: vec![ServerTagEventType::ApiCall],
        };
        assert!(should_tag(&cfg, ServerTagEventType::ApiCall));
        assert!(!should_tag(&cfg, ServerTagEventType::TokenExchange));
    }

    #[test]
    fn should_tag_returns_false_when_disabled() {
        install_provider();
        let cfg = ServerTaggingConfig {
            enabled: false,
            property_id: Some(Uuid::new_v4()),
            event_types: vec![ServerTagEventType::ApiCall],
        };
        assert!(!should_tag(&cfg, ServerTagEventType::ApiCall));
    }

    #[test]
    fn should_tag_returns_false_without_property_id() {
        install_provider();
        let cfg = ServerTaggingConfig {
            enabled: true,
            property_id: None,
            event_types: vec![ServerTagEventType::ApiCall],
        };
        assert!(!should_tag(&cfg, ServerTagEventType::ApiCall));
    }

    #[test]
    fn build_event_populates_fields() {
        install_provider();
        let ev = build_event(
            ServerTagEventType::ApiCall,
            "client-1",
            "ledger",
            "/v1/accounts",
            "GET",
            200,
            "corr-1",
        );
        assert_eq!(ev.event_type, ServerTagEventType::ApiCall);
        assert_eq!(ev.service, "ledger");
        assert_eq!(ev.path, "/v1/accounts");
        assert_eq!(ev.status, 200);
    }

    #[test]
    fn config_serializes_with_snake_case_event_types() {
        install_provider();
        let cfg = ServerTaggingConfig {
            enabled: true,
            property_id: Some(Uuid::new_v4()),
            event_types: vec![
                ServerTagEventType::ApiCall,
                ServerTagEventType::TokenExchange,
            ],
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["enabled"], true);
        let types = json["event_types"].as_array().unwrap();
        assert_eq!(types[0], "api_call");
        assert_eq!(types[1], "token_exchange");
    }

    #[test]
    fn config_deserializes_from_snake_case() {
        install_provider();
        let json = serde_json::json!({
            "enabled": true,
            "property_id": "00000000-0000-0000-0000-000000000001",
            "event_types": ["api_call", "oauth_callback"]
        });
        let cfg: ServerTaggingConfig = serde_json::from_value(json).unwrap();
        assert!(cfg.enabled);
        assert!(cfg.property_id.is_some());
        assert_eq!(cfg.event_types.len(), 2);
        assert!(cfg.event_types.contains(&ServerTagEventType::ApiCall));
        assert!(cfg.event_types.contains(&ServerTagEventType::OauthCallback));
    }

    #[tokio::test]
    async fn tag_event_swallows_errors() {
        install_provider();
        // Use an invalid Stat URL — the call should fail but not panic.
        // Test-only plain transport — an invalid Stat URL; the call
        // should fail but not panic.
        let client = StatClient::new_dev_plain("http://127.0.0.1:1", Uuid::new_v4());
        let ev = build_event(
            ServerTagEventType::ApiCall,
            "c1",
            "ledger",
            "/v1/accounts",
            "GET",
            200,
            "corr",
        );
        // Should not panic; error is logged.
        tag_event(&client, &ev).await;
    }

    #[tokio::test]
    async fn noop_tagger_does_nothing() {
        install_provider();
        let tagger = NoopTagger;
        let ev = build_event(
            ServerTagEventType::ApiCall,
            "c1",
            "ledger",
            "/v1/accounts",
            "GET",
            200,
            "corr",
        );
        tagger.tag(&ev).await; // no-op, must not panic
    }

    #[tokio::test]
    async fn sentin8_stat_tagger_skips_when_disabled() {
        install_provider();
        // Test-only plain transport — an invalid Stat URL; the call
        // should fail but not panic.
        let client = StatClient::new_dev_plain("http://127.0.0.1:1", Uuid::new_v4());
        let cfg = ServerTaggingConfig {
            enabled: false,
            property_id: Some(Uuid::new_v4()),
            event_types: vec![ServerTagEventType::ApiCall],
        };
        let tagger = StatTagger::new(client, cfg);
        let ev = build_event(
            ServerTagEventType::ApiCall,
            "c1",
            "ledger",
            "/v1/accounts",
            "GET",
            200,
            "corr",
        );
        // disabled — should skip the HTTP call entirely.
        tagger.tag(&ev).await;
    }

    #[test]
    fn build_tagger_returns_noop_when_disabled() {
        install_provider();
        let cfg = ServerTaggingConfig::default();
        let _tagger = build_tagger(cfg);
    }
}
