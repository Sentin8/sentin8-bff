// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Auth provisioning client (F-A customer auto-add).
//!
//! The BFF auto-adds first-party customer-app users to the app instance's
//! `sentin8:app:{instance_id}` group at OAuth callback - customer apps do
//! not gate on pre-provisioned membership (the F-A strict gate is for
//! staff apps; a customer must never be locked out of the app they just
//! signed up for). The membership is provisioned through **Auth's
//! provisioning API** (`POST /v1/admin/provision/group_member`) with a
//! certificate identity (`sentin8:auth:admin:write` on the `bff-provision`
//! workload) - the BFF never writes auth tables directly (DBX).
//! Copy of sys's/app's `auth_provision.rs` pattern (peers cannot share a
//! crate - dependency direction is one-way).

use std::sync::Arc;

/// Process-global provisioner (`None` when the DCR registration has not
/// completed - the caller logs and fails closed).
static PROVISIONER: tokio::sync::OnceCell<Option<Arc<Provisioner>>> =
    tokio::sync::OnceCell::const_new();

pub struct Provisioner {
    auth_url: String,
    http: reqwest::Client,
}

impl Provisioner {
    /// Build the shared provisioner (auth DESIGN §4.3f):
    /// ensure the `bff-provision` workload CERTIFICATE (load-or-mint from
    /// Acme) and build the cert-presenting transport - Auth's TLS layer
    /// authenticates the handshake; the registry map authorizes
    /// `sentin8:auth:admin:write`.
    pub async fn shared() -> Option<&'static Arc<Provisioner>> {
        PROVISIONER
            .get_or_init(|| async {
                let cfg = sentin8::config::Sentin8Config::from_env();
                let issuer = cfg.sentin8_auth_issuer();
                let ca_cert_path = sentin8::auth::m2m::platform_ca_path();
                let cert = match sentin8::auth::m2m::ensure_workload_certificate(
                    &issuer,
                    "bff-provision",
                    &ca_cert_path,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "bff: provision certificate ensure failed - auto-add disabled");
                        return None;
                    }
                };
                let mtls = sentin8::middleware::mtls::MtlsConfig::new(
                    &cert.ca_cert_path,
                    &cert.cert_path,
                    &cert.key_path,
                );
                let http = match sentin8::middleware::mtls::build_mtls_client(&mtls) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "bff: provision transport build failed - auto-add disabled");
                        return None;
                    }
                };
                Some(Arc::new(Self {
                    auth_url: issuer.trim_end_matches('/').to_string(),
                    http,
                }))
            })
            .await
            .as_ref()
    }

    /// POST to Auth's provisioning API with the target-env header
    /// (auth is env-scoped - the header carries the tenant context).
    async fn post(
        &self,
        path: &str,
        env_id: uuid::Uuid,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let url = format!("{}{}", self.auth_url, path);
        let resp = self
            .http
            .post(&url)
            .header("x-sentin8-target-env-id", env_id.to_string())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("auth provision {path}: {status} {text}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(serde_json::Value::Null))
    }

    /// Add a user to a group (idempotent - returns the post-state count).
    pub async fn group_member(
        &self,
        env_id: uuid::Uuid,
        group_name: &str,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<u64> {
        let v = self
            .post(
                "/v1/admin/provision/group_member",
                env_id,
                serde_json::json!({
                    "env_id": env_id,
                    "group_name": group_name,
                    "user_id": user_id,
                }),
            )
            .await?;
        Ok(v["count"].as_u64().unwrap_or(0))
    }
}
