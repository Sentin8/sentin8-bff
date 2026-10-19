// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! BFF tenant resolution -
//!
//! Resolves the tenant context (env_id, app_id) from:
//! 1. TLS-injected `X-Sentin8-*` headers (primary -).
//! 2. Hostname parsing (legacy fallback for non-TLS local dev).
//!
//! `org_id` is no longer carried in TLS headers - it is resolved from
//! `env_id` via `sentin8_sys_environments` when needed.
//!
//! Also loads the per-app scope whitelist from `sentin8_sys_app_instances`
//! with an in-memory cache.

use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use uuid::Uuid;

/// Tenant context resolved from TLS headers or hostname.
///
/// `org_id` is deliberately absent - it is resolved from `env_id` via
/// `SELECT org_id FROM sys.environments WHERE id = $1` when needed.
#[derive(Debug, Clone, Default)]
pub struct TenantContext {
    pub env_id: Option<Uuid>,
    pub app_id: Option<Uuid>,
    /// True when resolved from TLS headers (not hostname fallback).
    pub from_tls: bool,
    /// True for application BFF (bff.{app_domain}), false for platform BFF.
    pub is_app_bff: bool,
}

impl TenantContext {
    /// Resolve tenant context from request headers.
    ///reads `X-Sentin8-Env-Id`, `X-Sentin8-App-Id`
    /// from the `TLSContext` middleware. Falls back to hostname parsing only
    /// when TLS headers are absent (local dev, not routed through TLS).
    ///
    /// `X-Sentin8-Org-Id` is no longer read - `org_id` is resolved from
    /// `env_id` via `sentin8_sys_environments` when needed.
    pub fn from_headers(headers: &HeaderMap, host: &str) -> Self {
        let env_id = header_uuid(headers, &sentin8::middleware::context::HEADER_ENV_ID);
        let app_id = header_uuid(headers, &sentin8::middleware::context::HEADER_APP_ID);

        if env_id.is_some() || app_id.is_some() {
            // Platform BFF (e.g. bff.dash.{domain}, bff.ops.sys.{domain})
            // is NOT an app BFF - it has full access to all platform
            // services (sys, auth, app).
            // Application BFF (e.g. bff.{app_domain}) is scoped to the
            // app's allowed services only.
            let is_platform_bff = host.starts_with("bff.dash.") || host.starts_with("bff.ops.sys.");
            return TenantContext {
                env_id,
                app_id,
                from_tls: true,
                is_app_bff: !is_platform_bff && (app_id.is_some() || host.starts_with("bff.")),
            };
        }

        // Legacy fallback: hostname parsing (disabled when SENTIN8_BFF_HOSTNAME_FALLBACK=0).
        let allow_fallback = std::env::var("SENTIN8_BFF_HOSTNAME_FALLBACK")
            .unwrap_or_else(|_| "1".to_string())
            != "0";
        if !allow_fallback {
            return TenantContext::default();
        }

        //emit warning when falling back to hostname.
        tracing::warn!(
            "BFF hostname-based tenant resolution fallback is unsafe; \
             set SENTIN8_BFF_HOSTNAME_FALLBACK=0 to disable and route through TLS"
        );

        // Platform BFF: bff.dash.{domain} → no app context.
        // Application BFF: bff.{app_domain} → app context (needs DB lookup, not done here).
        let is_app_bff = host.starts_with("bff.") && !host.starts_with("bff.dash.");
        TenantContext {
            env_id: None,
            app_id: None,
            from_tls: false,
            is_app_bff,
        }
    }
}

/// Per-app scope whitelist.
/// Loaded from `sentin8_sys_app_instances.allowed_scopes` and `allowed_services`.
#[derive(Debug, Clone, Default)]
pub struct AppScopeWhitelist {
    pub allowed_scopes: Vec<String>,
    pub allowed_services: Vec<String>,
}

/// In-memory cache for per-app scope whitelists.
/// Keyed by app_id. Entries expire after the TTL (default 5 min).
pub struct AppScopeCache {
    cache: tokio::sync::RwLock<std::collections::HashMap<Uuid, CacheEntry>>,
    ttl: Duration,
}

struct CacheEntry {
    whitelist: AppScopeWhitelist,
    loaded_at: Instant,
}

impl AppScopeCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Get the whitelist for an app, loading from DB if missing or expired.
    ///loaded lazily on first request for app BFF hostname.
    pub async fn get_or_load(
        &self,
        app_id: Uuid,
        pool: &sqlx::PgPool,
    ) -> Result<AppScopeWhitelist, String> {
        // Check cache.
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&app_id) {
                if entry.loaded_at.elapsed() < self.ttl {
                    return Ok(entry.whitelist.clone());
                }
            }
        }

        // Load from DB.
        let whitelist = load_app_whitelist(pool, app_id).await?;

        // Update cache.
        let mut cache = self.cache.write().await;
        cache.insert(
            app_id,
            CacheEntry {
                whitelist: whitelist.clone(),
                loaded_at: Instant::now(),
            },
        );

        Ok(whitelist)
    }

    /// Invalidate the cache for a specific app (on config change).
    pub async fn invalidate(&self, app_id: Uuid) {
        let mut cache = self.cache.write().await;
        cache.remove(&app_id);
    }
}

/// Load the per-app scope whitelist from `sys.app_instances`.
/// No hardcoded app knowledge in the platform - all scopes come from the DB.
async fn load_app_whitelist(
    pool: &sqlx::PgPool,
    app_id: Uuid,
) -> Result<AppScopeWhitelist, String> {
    // Runtime query (not `sqlx::query!` macro) so the build doesn't require
    // DATABASE_URL at compile time. Schema-qualified: the BFF role's
    // search_path is `bff, public` (DBX ) - unqualified cross-schema
    // names fail at runtime.
    let row: Option<(Vec<String>, Vec<String>)> = sqlx::query_as(
        r#"SELECT
               allowed_scopes,
               allowed_services
           FROM sys.app_instances
           WHERE id = $1 AND status = 'active'"#,
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    match row {
        Some((allowed_scopes, allowed_services)) => Ok(AppScopeWhitelist {
            allowed_scopes,
            allowed_services,
        }),
        None => {
            tracing::warn!(app_id = %app_id, "app instance not found, using empty whitelist");
            Ok(AppScopeWhitelist::default())
        }
    }
}

/// Check if a service is allowed for the app.
pub fn is_service_allowed(whitelist: &AppScopeWhitelist, service: &str) -> bool {
    if whitelist.allowed_services.is_empty() {
        // No whitelist configured → allow all non-platform services.
        return !matches!(service, "auth" | "app" | "sys" | "tls");
    }
    whitelist
        .allowed_services
        .iter()
        .any(|s| s == service || s == "*")
}

/// Resolve `org_id` from `env_id` via `sentin8_sys_environments`.
///
/// Since the `x-sentin8-org-id` header is no longer injected by TLS,
/// callers that need `org_id` must derive it from `env_id` using this
/// helper. Returns `None` if the env does not exist or the query fails.
///
/// The read is context-first :
/// `sys_environments_select` requires `sentin8_context_initialized` and
/// admits the row only when `id = sentin8_current_env_id` (or the org
/// of the current context). The context is transaction-local
/// (`set_config(..., true)`), so the context-set and the SELECT must run
/// in ONE explicit transaction on the SAME connection - on an autocommit
/// connection the context evaporates before the query runs and FORCE RLS
/// hides every row (the "token env not found in environments" class of
/// 403s).
pub async fn resolve_org_id_from_env_id(pool: &sqlx::PgPool, env_id: &str) -> Option<Uuid> {
    let uuid: Uuid = Uuid::parse_str(env_id).ok()?;
    let mut tx = pool.begin().await.ok()?;
    // The env_id comes from a TLS-injected header (trusted upstream) or a
    // verified token claim - it IS the tenant context of this request.
    // is_platform_admin/bypass_rls stay false: the policy's `id =
    // current_env_id` branch alone admits the row.
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(uuid)
        .execute(&mut *tx)
        .await;
    // The context is set for the TARGET env (id = current_env_id branch);
    // the table name is schema-qualified because bff's role search_path is
    // `bff, public` - `environments` exists only in the sys schema.
    let org_id: Option<Uuid> =
        sqlx::query_scalar(r#"SELECT org_id FROM sys.environments WHERE id = $1"#)
            .bind(uuid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
    tx.rollback().await.ok()?;
    org_id
}

// ── Backend service URL resolution ──────────────────────────────────────

/// Resolve the canonical colon service identity for a proxy-path service
/// name.
///
/// The `/proxy/{service}/...` path segment carries the bare name (`auth`,
/// `ledger`) - clients never see the colon identity. This maps the bare
/// name to the registered identity by trying, in order:
/// 1. `sentin8:{service}` - the platform convention (auth → `sentin8:auth`).
/// 2. The runtime registry (`sys.vertical_services`) - exact identity
///
/// match or bare-name suffix match (`bank8:ledger` when `ledger` is asked).
///
/// Falls back to the legacy dash form (`sentin8-{service}`) when the
/// registry is unreachable (dev bootstrapping).
pub async fn resolve_service_identity(pool: &sqlx::PgPool, service: &str) -> String {
    // Already canonical / contains the full form - normalize only.
    if service.contains(':') {
        return sentin8::config::canonical_service_type(service);
    }
    // Platform convention first: bare name = sentin8 service.
    let platform = format!("sentin8:{service}");
    let known: Option<String> = sqlx::query_scalar(
        r#"SELECT service_type FROM sys.vertical_services
           WHERE service_type = $1 OR service_type = $2
           ORDER BY CASE WHEN service_type = $2 THEN 0 ELSE 1 END
           LIMIT 1"#,
    )
    .bind(&platform)
    .bind(service)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    match known {
        Some(identity) => identity,
        None => {
            tracing::debug!(
                service = %service,
                "bff: no registry match for proxy service - assuming platform service"
            );
            platform
        }
    }
}

/// In-memory cache for tenant domain resolution.
/// Keyed by env_id. Avoids a DB round-trip on every proxied request.
static DOMAIN_CACHE: std::sync::LazyLock<
    tokio::sync::RwLock<std::collections::HashMap<Uuid, CachedDomain>>,
> = std::sync::LazyLock::new(|| tokio::sync::RwLock::new(std::collections::HashMap::new()));

struct CachedDomain {
    env_domain: String,
    cached_at: Instant,
}

const DOMAIN_CACHE_TTL: Duration = Duration::from_secs(300);

/// Resolve the backend URL for a service, using tenant domain records.
///
/// Reads `x-sentin8-env-id` from the TLS-injected headers, queries
/// `sentin8_sys_organizations.domain` and `sentin8_sys_environments.slug` to build
/// the env domain, then constructs the service URL as `https://{svc}.{env_domain}`.
/// Results are cached per env_id for 5 minutes.
///
/// `org_id` is no longer read from headers - it is resolved from `env_id`
/// via the `sentin8_sys_environments` join inside `resolve_env_domain_from_db`.
///
/// `service` may be a bare proxy-path name (`auth`, `ledger`) or the full
/// colon identity (`sentin8:auth`, `bank8:ledger`) - both normalize via
/// the runtime registry. The colon identity is the canonical form
/// ; use [`resolve_service_identity`] to
/// obtain it from a bare name.
///
/// For platform BFF (no tenant headers), falls back to the platform domain
/// `{svc}.ops.sys.{sentin8_domain}`.
pub async fn resolve_env_service_url(
    pool: &sqlx::PgPool,
    _config: &crate::config::Bff8Config,
    headers: &HeaderMap,
    service: &str,
) -> Option<String> {
    let env_id = headers
        .get("x-sentin8-env-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());

    // Resolve the subdomain for this service from the runtime registry
    // via the shared `sentin8-config` library - single source of truth.
    // resolve_subdomain normalizes to the canonical colon identity first.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let subdomain = cfg.resolve_subdomain(pool, service).await;

    // Platform services resolve to the platform domain (ops/sys), regardless
    // of the tenant's org/env. Detected via the `vertical` column in the
    // runtime registry - no hardcoded list.
    if cfg.is_platform_service(pool, service).await {
        return Some(format!("https://{}", cfg.platform_domain(&subdomain)));
    }

    match env_id {
        // No tenant headers → platform BFF → use platform domain.
        None => Some(format!("https://{}", cfg.platform_domain(&subdomain))),
        Some(env_id) => {
            // Check cache.
            {
                let cache = DOMAIN_CACHE.read().await;
                if let Some(entry) = cache.get(&env_id) {
                    if entry.cached_at.elapsed() < DOMAIN_CACHE_TTL {
                        return Some(format!("https://{}.{}", subdomain, entry.env_domain));
                    }
                }
            }

            // Query DB for org domain and env slug (org_id resolved via join).
            let env_domain = resolve_env_domain_from_db(pool, env_id).await?;

            // Cache the result.
            {
                let mut cache = DOMAIN_CACHE.write().await;
                cache.insert(
                    env_id,
                    CachedDomain {
                        env_domain: env_domain.clone(),
                        cached_at: Instant::now(),
                    },
                );
            }

            Some(format!("https://{}.{}", subdomain, env_domain))
        }
    }
}

/// Query `sentin8_sys_organizations.domain` and `sentin8_sys_environments.slug` to build
/// the env domain (`{env_slug}.{org_domain}`). Mirrors the pattern used by
/// `app` (handlers.rs:422-426) - reads the authoritative org domain
/// from the DB rather than recomputing from the slug.
///
/// `org_id` is resolved via the JOIN on `e.org_id = o.id` - no separate
/// org_id parameter is needed.
async fn resolve_env_domain_from_db(pool: &sqlx::PgPool, env_id: Uuid) -> Option<String> {
    // Context-first read : set the TARGET
    // env's RLS context inside the same transaction as the query -
    // sys_environments_select admits `id = current_env_id`; sys
    // organizations/environments are also schema-qualified (bff
    // search_path = bff, public).
    let mut tx = pool.begin().await.ok()?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let row: Option<(String, String)> = sqlx::query_as(
        r#"SELECT o.domain, e.slug
             FROM sys.environments e
             JOIN sys.organizations o ON o.id = e.org_id
            WHERE e.id = $1"#,
    )
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()?;
    tx.rollback().await.ok()?;

    let (org_domain, env_slug) = match row {
        Some((d, s)) => (d, s),
        None => {
            tracing::warn!(%env_id, "bff: tenant domain lookup failed (env not found)");
            return None;
        }
    };

    let cfg = sentin8::config::Sentin8Config::from_env();
    Some(cfg.env_domain(&env_slug, &org_domain))
}

/// Extract a UUID from a header value.
fn header_uuid(headers: &HeaderMap, name: &axum::http::HeaderName) -> Option<Uuid> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .and_then(|s| Uuid::parse_str(s).ok())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_context_from_sentin8_tls_headers() {
        let mut headers = HeaderMap::new();
        let env = Uuid::new_v4();
        headers.insert(
            sentin8::middleware::context::HEADER_ENV_ID,
            env.to_string().parse().unwrap(),
        );
        let ctx = TenantContext::from_headers(&headers, "bff.app.ibank.local");
        assert!(ctx.from_tls);
        assert_eq!(ctx.env_id, Some(env));
        assert!(ctx.is_app_bff);
    }

    #[test]
    fn tenant_context_app_id() {
        let mut headers = HeaderMap::new();
        let app = Uuid::new_v4();
        headers.insert(
            sentin8::middleware::context::HEADER_APP_ID,
            app.to_string().parse().unwrap(),
        );
        let ctx = TenantContext::from_headers(&headers, "bff.app.ibank.local");
        assert!(ctx.from_tls);
        assert_eq!(ctx.app_id, Some(app));
        assert!(ctx.is_app_bff);
    }

    #[test]
    fn tenant_context_hostname_fallback() {
        let headers = HeaderMap::new();
        let ctx = TenantContext::from_headers(&headers, "bff.www.ibank.local");
        // No TLS headers → fallback.
        assert!(!ctx.from_tls);
        assert!(ctx.is_app_bff);
    }

    #[test]
    fn tenant_context_platform_bff() {
        let headers = HeaderMap::new();
        let ctx =
            TenantContext::from_headers(&headers, "sentin8-bff.sentin8-dash.ops.sys.sentin8.local");
        assert!(!ctx.from_tls);
        assert!(!ctx.is_app_bff);
    }

    #[test]
    fn is_service_allowed_with_whitelist() {
        let whitelist = AppScopeWhitelist {
            allowed_scopes: vec![],
            allowed_services: vec!["ledger".into(), "payments".into()],
        };
        assert!(is_service_allowed(&whitelist, "ledger"));
        assert!(is_service_allowed(&whitelist, "payments"));
        assert!(!is_service_allowed(&whitelist, "auth"));
        assert!(!is_service_allowed(&whitelist, "fdx"));
    }

    #[test]
    fn is_service_allowed_empty_whitelist() {
        let whitelist = AppScopeWhitelist::default();
        // Empty whitelist → allow all non-platform services.
        assert!(is_service_allowed(&whitelist, "ledger"));
        assert!(is_service_allowed(&whitelist, "fdx"));
        assert!(!is_service_allowed(&whitelist, "auth"));
        assert!(!is_service_allowed(&whitelist, "app"));
        assert!(!is_service_allowed(&whitelist, "sys"));
    }

    #[test]
    fn is_service_allowed_wildcard() {
        let whitelist = AppScopeWhitelist {
            allowed_scopes: vec![],
            allowed_services: vec!["*".into()],
        };
        assert!(is_service_allowed(&whitelist, "ledger"));
        assert!(is_service_allowed(&whitelist, "auth"));
    }

    #[test]
    fn app_scope_cache_new() {
        let cache = AppScopeCache::new(300);
        assert_eq!(cache.ttl, Duration::from_secs(300));
    }

    #[test]
    fn header_uuid_missing() {
        let headers = HeaderMap::new();
        let name = axum::http::HeaderName::from_static("x-missing");
        assert!(header_uuid(&headers, &name).is_none());
    }

    #[test]
    fn header_uuid_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "not-a-uuid".parse().unwrap());
        let name = axum::http::HeaderName::from_static("x-test");
        assert!(header_uuid(&headers, &name).is_none());
    }

    #[test]
    fn header_uuid_valid() {
        let mut headers = HeaderMap::new();
        let id = Uuid::new_v4();
        headers.insert("x-test", id.to_string().parse().unwrap());
        let name = axum::http::HeaderName::from_static("x-test");
        assert_eq!(header_uuid(&headers, &name), Some(id));
    }
}
