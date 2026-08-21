DROP TRIGGER IF EXISTS metadata_record_identity_immutable
    ON colortrace.metadata_records;

-- colortrace-statement
DROP FUNCTION IF EXISTS colortrace.reject_metadata_record_identity_change();

-- colortrace-statement
DROP TRIGGER IF EXISTS metadata_claim_events_immutable
    ON colortrace.metadata_claim_events;

-- colortrace-statement
DROP TRIGGER IF EXISTS metadata_idempotency_immutable
    ON colortrace.metadata_idempotency;

-- colortrace-statement
DROP TRIGGER IF EXISTS metadata_record_versions_immutable
    ON colortrace.metadata_record_versions;

-- colortrace-statement
DROP FUNCTION IF EXISTS colortrace.reject_immutable_metadata();

-- colortrace-statement
DROP TABLE IF EXISTS colortrace.metadata_claim_events;

-- colortrace-statement
DROP TABLE IF EXISTS colortrace.metadata_claims;

-- colortrace-statement
DROP TABLE IF EXISTS colortrace.metadata_idempotency;

-- colortrace-statement
DROP TABLE IF EXISTS colortrace.metadata_record_versions;

-- colortrace-statement
DROP TABLE IF EXISTS colortrace.metadata_records;
