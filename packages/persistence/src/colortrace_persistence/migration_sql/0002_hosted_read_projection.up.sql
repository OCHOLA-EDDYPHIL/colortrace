CREATE TABLE colortrace.hosted_read_bindings (
    binding_key TEXT PRIMARY KEY CHECK (binding_key = 'hosted-read-v1'),
    reader_role TEXT NOT NULL CHECK (reader_role ~ '^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$')
);

-- colortrace-statement
CREATE VIEW colortrace.hosted_read_projection_v1
WITH (security_barrier = true)
AS
SELECT
    records.namespace,
    records.record_id,
    records.record_version AS current_version,
    records.document AS current_document,
    records.document_sha256 AS current_document_sha256,
    records.chain_sha256 AS current_chain_sha256,
    versions.record_version AS history_version,
    versions.document AS history_document,
    versions.document_sha256 AS history_document_sha256,
    versions.previous_chain_sha256 AS history_previous_chain_sha256,
    versions.chain_sha256 AS history_chain_sha256
FROM colortrace.metadata_records AS records
JOIN colortrace.metadata_record_versions AS versions
  ON versions.namespace = records.namespace
 AND versions.record_id = records.record_id
JOIN colortrace.hosted_read_bindings AS binding
  ON binding.binding_key = 'hosted-read-v1'
 AND binding.reader_role = SESSION_USER::text
WHERE records.namespace = 'incident'
  AND records.record_id IN (
      'incident-hosted-synthetic-001',
      'hosted-readiness:synthetic-hosted-read-v1'
  );

-- colortrace-statement
REVOKE ALL ON TABLE colortrace.hosted_read_bindings FROM PUBLIC;

-- colortrace-statement
REVOKE ALL ON TABLE colortrace.hosted_read_projection_v1 FROM PUBLIC;
