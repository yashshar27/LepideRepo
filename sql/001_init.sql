BEGIN;

CREATE TABLE IF NOT EXISTS audit_events (
    event_id UUID PRIMARY KEY,
    schema_version TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_instance TEXT NOT NULL,
    source_event_key TEXT NULL,
    event_type TEXT NOT NULL,
    action TEXT NULL,
    occurred_at TIMESTAMPTZ NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id TEXT NULL,
    actor_type TEXT NULL,
    target_path TEXT NULL,
    client_ip INET NULL,
    outcome TEXT NOT NULL DEFAULT 'unknown',
    source_sequence NUMERIC(20,0) NULL,
    source_volume TEXT NULL,
    raw_payload JSONB NOT NULL,
    parser_version TEXT NOT NULL,
    raw_record_sha256 CHAR(64) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_source_key
    ON audit_events (tenant_id, source_id, source_event_key)
    WHERE source_event_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_time
    ON audit_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_source_time
    ON audit_events (tenant_id, source_id, ingested_at DESC);

CREATE INDEX IF NOT EXISTS ix_audit_events_actor
    ON audit_events (tenant_id, actor_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS ingestion_quarantine (
    quarantine_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    input_format TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    error_message TEXT NOT NULL,
    raw_record TEXT NOT NULL,
    raw_record_sha256 CHAR(64) NOT NULL
);

COMMIT;
