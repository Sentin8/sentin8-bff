// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:BFF self-registration (self-registration ).
//!
//! The BFF describes itself to `vertical enroll` via `--print-registration`.
//! Its M2M grants declare the `bff-delegator` workload (the Delegation
//! Gateway identity - auth design ): an Acme-minted client cert with
//! `CN=m2m-bff-delegator`, DCR-registered with `self_signed_tls_client_auth`
//! and the delegate/SCIM/sys scope set. No other workload identities - the
//! BFF's token handling is delegation-only.

use sentin8::registration::{
    AdminScope, CrossSchemaGrant, M2mGrant, PgRole, Registration, SqlMigration,
};

/// Delegator scopes - MUST stay in sync with `proxy.rs::DELEGATOR_SCOPES`
/// (the token request asks for the same set the DCR registers).
const DELEGATOR_SCOPES: &[&str] = &[
    "sentin8:delegate:read",
    "sentin8:scim:read",
    "sentin8:scim:write",
    "sentin8:sys:instances:read",
];

const M2M_GRANTS: &[M2mGrant] = &[
    // The BFF's own Valkey-plane identity (group DESIGN.md §3.1): the
    // session store's cert-CN workload. No scopes - it exists for the
    // enroll-time ACL provisioning (the `~bff:*` key namespace + the
    // typed-command allowlist) and the token-free registry map, the
    // same own-identity row every service declares.
    M2mGrant {
        workload: "sentin8:bff",
        scopes: &[],
    },
    M2mGrant {
        workload: "bff-delegator",
        scopes: DELEGATOR_SCOPES,
    },
    // BFF-5: the push bridge drains BFF's local post_outbox to Post's
    // send API with this M2M client (DBX - no direct post.inbox writes).
    M2mGrant {
        workload: "bff-post",
        scopes: &["sentin8:post:write"],
    },
    // F-A customer auto-add (BFF design - first-party customer-app
    // users are added to the instance's `sentin8:app:{instance_id}` group
    // at callback): the BFF provisions the membership through Auth's
    // provisioning API (no direct auth-table writes - DBX).
    M2mGrant {
        workload: "bff-provision",
        scopes: &["sentin8:auth:admin:write"],
    },
    // The Shield hot-reload consumer (policy design ):
    // `boot_full(pool, issuer, "sentin8:bff", engine)` →
    // `policy_bus_client("sentin8:bff")` registers the `{service}-policy`
    // workload with the consume scope.
    M2mGrant {
        workload: "sentin8:bff-policy",
        scopes: &["sentin8:bus:consume"],
    },
    // The Bus SSE consumer (`server.rs` builds the bus client directly with
    // the short service tag `bff`). The gate's superset check admits any
    // requested subset of a grant row, and both spellings are covered for
    // the other services (auth: `auth`/`sentin8:auth`) - mirror that here.
    M2mGrant {
        workload: "bff",
        scopes: &["sentin8:bus:consume"],
    },
    M2mGrant {
        workload: "bff-policy",
        scopes: &["sentin8:bus:consume"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    M2mGrant {
        workload: "sentin8-bff-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// The OpenAPI spec closure - the BFF carries no utoipa spec (its surface
/// is the per-app `/proxy/*` passthrough, not CLI-derivable commands), so
/// the closure emits `null` (the enroll path skips empty openapi output).
fn openapi_spec() -> serde_json::Value {
    serde_json::Value::Null
}

// Declared cross-schema reads (architecture-principles §6.6a - explicit,
// never blanket): runtime tenant resolution in `tenant.rs` reads the
// platform org/env/instance rows and resolves bare service names against
// the runtime registry. SELECT-only; all writes go through owners' APIs.
const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:delegate:read,sentin8:scim:read,sentin8:scim:write,sentin8:sys:instances:read",
    role: "sentin8_bff_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[
        CrossSchemaGrant {
            schema: "sys",
            table: "environments",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "organizations",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "app_instances",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "sys",
            table: "vertical_services",
            privilege: "SELECT",
        },
        // Delegation Gateway group gate (F-A): the BFF verifies app
        // membership (`sentin8:app:{instance_id}`) by reading auth's
        // groups/group_members under the caller's env context - declared
        // cross-schema reads, never blanket schema grants.
        CrossSchemaGrant {
            schema: "auth",
            table: "groups",
            privilege: "SELECT",
        },
        CrossSchemaGrant {
            schema: "auth",
            table: "group_members",
            privilege: "SELECT",
        },
    ],
}];

pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:bff",
        subdomain: "bff",
        health_path: "/v1/health",
        admin_scopes: &[
            // The BFF's admin surface is proxy configuration read-only
            // (mappings/backends live in Sentin8:Proxy; the BFF exposes none).
            AdminScope::Tuple("sentin8:delegate", "sentin8:delegate:read"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: None,
        sql_migrations: vec![
            // BFF's own schema (dcr_clients + the BFF-5 push sink) rides
            // the tracked migration path - the registration is the ONLY
            // apply surface (no sql_dirs fallback ships).
            SqlMigration {
                version: 1,
                name: "init",
                sql: include_str!("../sql/init.sql"),
            },
            SqlMigration {
                version: 2,
                name: "push_sink",
                sql: include_str!("../sql/v2_push_sink.sql"),
            },
        ],
        pg_roles: PG_ROLES,
        policies: &[],
        relations: &[],
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
