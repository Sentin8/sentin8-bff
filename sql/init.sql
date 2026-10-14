-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:BFF — Backend-for-Frontend DCR client registry.
-- Stores dynamically registered OAuth clients keyed by sentin8_auth_domain.

CREATE SCHEMA IF NOT EXISTS bff;
CREATE TABLE IF NOT EXISTS bff.dcr_clients (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sentin8_auth_domain                TEXT NOT NULL UNIQUE,
    client_id                   TEXT NOT NULL,
    client_name                 TEXT NOT NULL,
    redirect_uris               TEXT[] NOT NULL DEFAULT '{}',
    scopes                      TEXT[] NOT NULL DEFAULT '{}',
    registration_access_token_enc BYTEA NOT NULL DEFAULT '\x',
    env_id              UUID NOT NULL,
    app_slug                    TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_bff_dcr_clients_env ON bff.dcr_clients (env_id);

-- RLS (mandatory on every tenant data table — architecture-principles
-- §4.3d). The SELECT policy additionally admits the
-- platform plane (system env) — same shape as sys_services_select.
ALTER TABLE bff.dcr_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE bff.dcr_clients FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS bff_dcr_clients_select ON bff.dcr_clients;
CREATE POLICY bff_dcr_clients_select ON bff.dcr_clients FOR SELECT
    USING (sentin8_context_initialized()
           AND (env_id = sentin8_current_env_id()
                OR sentin8_current_env_id() = '00000000-0000-0000-0000-000000000002'::uuid));
DROP POLICY IF EXISTS bff_dcr_clients_insert ON bff.dcr_clients;
CREATE POLICY bff_dcr_clients_insert ON bff.dcr_clients FOR INSERT
    WITH CHECK (sentin8_context_initialized());
DROP POLICY IF EXISTS bff_dcr_clients_update ON bff.dcr_clients;
CREATE POLICY bff_dcr_clients_update ON bff.dcr_clients FOR UPDATE
    USING (sentin8_context_initialized());
DROP POLICY IF EXISTS bff_dcr_clients_delete ON bff.dcr_clients;
CREATE POLICY bff_dcr_clients_delete ON bff.dcr_clients FOR DELETE
    USING (sentin8_context_initialized());

-- Note: per-app scope/service whitelist and Sentin8:Stat integration /
-- domain-verification columns live on sentin8_sys_app_instances, which is
-- owned by Sentin8:Sys.

-- ── Grants ─────────────────────────────────────────────────────────

-- sentin8_app_service: DML on bff tables (no dedicated sentin8_bff_service role).
GRANT SELECT, INSERT, UPDATE, DELETE ON bff.dcr_clients TO sentin8_app_service;

-- ── Schema grants (service-owned — the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA bff TO sentin8_bff_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA bff TO sentin8_bff_service;
