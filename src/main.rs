// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 BFF — Backend for Frontend, server-side OAuth token guardian.
//!
//! Boot runs on the platform `sentin8-shell` crate: registration flag,
//! PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod auth_provision;
#[allow(dead_code)]
mod chat;
#[allow(dead_code)]
mod ciba;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod dcr;
#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod key_rotation;
#[allow(dead_code)]
mod policy;
mod proxy;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod session;
#[allow(dead_code)]
mod sessions;
#[allow(dead_code)]
mod subscribe;
#[allow(dead_code)]
mod tagging;
#[allow(dead_code)]
mod tenant;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Self-registration probe (self-registration ): `--print-registration`
    // prints the BFF's self-description (m2m_grants: bff-delegator) as JSON
    // and exits — `vertical enroll` consumes it to provision
    // `auth.m2m_scope_grants` for the Delegation Gateway identity.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return registration::print(section);
    }

    // Install the Graviola PQ crypto provider before any reqwest HTTPS call.
    let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();

    let _ = dotenvy::dotenv();
    let _ = sentin8::middleware::error_metrics::init_tracing_with_metrics(
        "sentin8:bff",
        std::env::var("RUST_LOG").ok().as_deref().unwrap_or("info"),
    );
    sentin8::middleware::error_metrics::spawn_publisher(
        // VALKEYDERIVE-1: override → else the plane-derived URL.
        std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| sentin8::config::service_valkey_url()),
        "sentin8:bff",
    );

    // Install the default crypto provider for rustls (ring).
    // reqwest is built with `rustls-tls-native-roots` whose `-no-provider`
    // variant does NOT auto-install one, so HTTPS client calls would fail
    // with a TLS handshake error until a provider is installed.

    let config = config::Bff8Config::from_env();
    tracing::info!(
        service = "sentin8:bff",
        version = env!("CARGO_PKG_VERSION"),
        port = config.port,
        "service starting"
    );

    let addr = format!("0.0.0.0:{}", config.port);
    let tls = sentin8::tls::Sentin8Tls::builder()
        .service_identity("sentin8:bff")
        .build()
        .await?;
    server::serve(config, addr, tls).await
}
