-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:BFF
-- SPDX-License-Identifier: Apache-2.0

-- ── BFF-5: push subscription sink (device tokens + local post outbox) ───
-- push_tokens: a session-bound device token registry - one token per
-- session; re-registering replaces it. The push bridge resolves the
-- token per subscription event and forwards delivery to Post.
-- post_outbox: BFF's LOCAL post queue (DBX-POST-3) - the bridge drains
-- it to Post POST /v1/send (M2M bff-post, scope sentin8:post:write).
-- No direct post.inbox writes; no cross-schema INSERT grant.

CREATE TABLE IF NOT EXISTS bff.push_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    session_id    TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    device_token  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_bff_push_tokens_session
    ON bff.push_tokens (session_id);

ALTER TABLE bff.push_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE bff.push_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS bff_push_tokens_dml ON bff.push_tokens;
CREATE POLICY bff_push_tokens_dml ON bff.push_tokens
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- GRANT-2 (D7 outbox pattern): the BFF service role runs these tables'
-- DML through its own DSN (the drain loop SELECTs + UPDATEs pushed;
-- push.rs INSERTs/DELETEs tokens; dcr.rs owns dcr_clients).
CREATE TABLE IF NOT EXISTS bff.post_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    message_type    TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'system',
    priority        TEXT NOT NULL DEFAULT 'normal',
    recipient_user_id UUID,
    recipient_device_token TEXT,
    subject         TEXT NOT NULL,
    body            TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bff_post_outbox_unpushed
    ON bff.post_outbox (created_at) WHERE pushed = false;
ALTER TABLE bff.post_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE bff.post_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS bff_post_outbox_dml ON bff.post_outbox;
CREATE POLICY bff_post_outbox_dml ON bff.post_outbox
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- Owner-side env helper (RLS drain discipline): the push bridger has NO
-- tenant context of its own; this returns only env UUIDs with unpushed
-- rows; the bridger sets per-env context and drains under it.
CREATE OR REPLACE FUNCTION bff.bff_post_outbox_unpushed_envs()
    RETURNS TABLE (env_id UUID)
LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
    RETURN QUERY SELECT DISTINCT o.env_id FROM post_outbox o WHERE o.pushed = false;
END;
$fn$;

-- GRANT-2 (D7 outbox pattern): the BFF service role runs these tables'
-- DML through its own DSN (the drain loop SELECTs + UPDATEs pushed;
-- push.rs INSERTs/DELETEs tokens; dcr.rs owns dcr_clients).
-- AFTER every table exists - GRANT on a not-yet-created table aborts the
-- whole init migration on a fresh bootstrap.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    bff.push_tokens, bff.post_outbox, bff.dcr_clients
    TO sentin8_bff_service;