CREATE TABLE colortrace.metadata_records (
    namespace TEXT NOT NULL CHECK (
        namespace IN (
            'incident',
            'response-plan',
            'recovery',
            'recovery-task',
            'simulator-action'
        )
    ),
    record_id TEXT NOT NULL CHECK (
        length(record_id) BETWEEN 1 AND 256
        AND record_id = btrim(record_id)
    ),
    record_version BIGINT NOT NULL CHECK (record_version >= 1),
    document BYTEA NOT NULL,
    document_sha256 TEXT NOT NULL CHECK (document_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    chain_sha256 TEXT NOT NULL CHECK (chain_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, record_id),
    CHECK (updated_at >= created_at)
);

-- colortrace-statement
CREATE TABLE colortrace.metadata_record_versions (
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    record_version BIGINT NOT NULL CHECK (record_version >= 1),
    document BYTEA NOT NULL,
    document_sha256 TEXT NOT NULL CHECK (document_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    previous_chain_sha256 TEXT CHECK (
        previous_chain_sha256 IS NULL
        OR previous_chain_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    chain_sha256 TEXT NOT NULL CHECK (chain_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, record_id, record_version),
    FOREIGN KEY (namespace, record_id)
        REFERENCES colortrace.metadata_records (namespace, record_id)
        ON DELETE RESTRICT,
    CHECK (
        (record_version = 1 AND previous_chain_sha256 IS NULL)
        OR (record_version > 1 AND previous_chain_sha256 IS NOT NULL)
    )
);

-- colortrace-statement
CREATE TABLE colortrace.metadata_idempotency (
    namespace TEXT NOT NULL CHECK (
        namespace IN (
            'incident',
            'response-plan',
            'recovery',
            'recovery-task',
            'simulator-action'
        )
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(idempotency_key) BETWEEN 1 AND 256
        AND idempotency_key = btrim(idempotency_key)
    ),
    operation TEXT NOT NULL CHECK (operation IN ('create', 'update', 'complete-claim')),
    request_sha256 TEXT NOT NULL CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    response_document BYTEA NOT NULL,
    response_sha256 TEXT NOT NULL CHECK (response_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (namespace, idempotency_key)
);

-- colortrace-statement
CREATE TABLE colortrace.metadata_claims (
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    owner TEXT NOT NULL CHECK (
        length(owner) BETWEEN 1 AND 256
        AND owner = btrim(owner)
    ),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    record_version BIGINT NOT NULL CHECK (record_version >= 1),
    expires_at TIMESTAMPTZ NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence >= 1),
    event_sha256 TEXT NOT NULL CHECK (event_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (namespace, record_id),
    FOREIGN KEY (namespace, record_id)
        REFERENCES colortrace.metadata_records (namespace, record_id)
        ON DELETE RESTRICT
);

-- colortrace-statement
CREATE INDEX metadata_claims_expiry
    ON colortrace.metadata_claims (expires_at, namespace, record_id);

-- colortrace-statement
CREATE TABLE colortrace.metadata_claim_events (
    namespace TEXT NOT NULL,
    record_id TEXT NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence >= 1),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    event_type TEXT NOT NULL CHECK (
        event_type IN ('acquired', 'reclaimed', 'renewed', 'completed')
    ),
    owner TEXT NOT NULL CHECK (
        length(owner) BETWEEN 1 AND 256
        AND owner = btrim(owner)
    ),
    record_version BIGINT NOT NULL CHECK (record_version >= 1),
    expires_at TIMESTAMPTZ,
    previous_event_sha256 TEXT CHECK (
        previous_event_sha256 IS NULL
        OR previous_event_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    event_sha256 TEXT NOT NULL CHECK (event_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (namespace, record_id, event_sequence),
    FOREIGN KEY (namespace, record_id)
        REFERENCES colortrace.metadata_records (namespace, record_id)
        ON DELETE RESTRICT,
    CHECK (
        (event_sequence = 1 AND previous_event_sha256 IS NULL)
        OR (event_sequence > 1 AND previous_event_sha256 IS NOT NULL)
    ),
    CHECK (
        (event_type = 'completed' AND expires_at IS NULL)
        OR (event_type <> 'completed' AND expires_at IS NOT NULL)
    )
);

-- colortrace-statement
CREATE FUNCTION colortrace.reject_immutable_metadata()
RETURNS trigger
LANGUAGE plpgsql
AS $colortrace$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23000',
        MESSAGE = 'colortrace immutable metadata cannot be changed';
END;
$colortrace$;

-- colortrace-statement
CREATE TRIGGER metadata_record_versions_immutable
BEFORE UPDATE OR DELETE ON colortrace.metadata_record_versions
FOR EACH ROW EXECUTE FUNCTION colortrace.reject_immutable_metadata();

-- colortrace-statement
CREATE TRIGGER metadata_idempotency_immutable
BEFORE UPDATE OR DELETE ON colortrace.metadata_idempotency
FOR EACH ROW EXECUTE FUNCTION colortrace.reject_immutable_metadata();

-- colortrace-statement
CREATE TRIGGER metadata_claim_events_immutable
BEFORE UPDATE OR DELETE ON colortrace.metadata_claim_events
FOR EACH ROW EXECUTE FUNCTION colortrace.reject_immutable_metadata();

-- colortrace-statement
CREATE FUNCTION colortrace.reject_metadata_record_identity_change()
RETURNS trigger
LANGUAGE plpgsql
AS $colortrace$
BEGIN
    IF NEW.namespace <> OLD.namespace
       OR NEW.record_id <> OLD.record_id
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23000',
            MESSAGE = 'colortrace metadata identity cannot be changed';
    END IF;
    RETURN NEW;
END;
$colortrace$;

-- colortrace-statement
CREATE TRIGGER metadata_record_identity_immutable
BEFORE UPDATE ON colortrace.metadata_records
FOR EACH ROW EXECUTE FUNCTION colortrace.reject_metadata_record_identity_change();

-- colortrace-statement
REVOKE ALL ON SCHEMA colortrace FROM PUBLIC;

-- colortrace-statement
REVOKE ALL ON ALL TABLES IN SCHEMA colortrace FROM PUBLIC;

-- colortrace-statement
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA colortrace FROM PUBLIC;
