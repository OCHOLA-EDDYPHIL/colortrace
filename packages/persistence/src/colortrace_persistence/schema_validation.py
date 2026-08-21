from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .ports import DbCursor, PersistenceError

_EXPECTED_COLUMNS = (
    ("metadata_claim_events", 1, "namespace", "text", True, ""),
    ("metadata_claim_events", 2, "record_id", "text", True, ""),
    ("metadata_claim_events", 3, "event_sequence", "bigint", True, ""),
    ("metadata_claim_events", 4, "generation", "bigint", True, ""),
    ("metadata_claim_events", 5, "event_type", "text", True, ""),
    ("metadata_claim_events", 6, "owner", "text", True, ""),
    ("metadata_claim_events", 7, "record_version", "bigint", True, ""),
    ("metadata_claim_events", 8, "expires_at", "timestamp with time zone", False, ""),
    ("metadata_claim_events", 9, "previous_event_sha256", "text", False, ""),
    ("metadata_claim_events", 10, "event_sha256", "text", True, ""),
    ("metadata_claim_events", 11, "occurred_at", "timestamp with time zone", True, ""),
    ("metadata_claims", 1, "namespace", "text", True, ""),
    ("metadata_claims", 2, "record_id", "text", True, ""),
    ("metadata_claims", 3, "owner", "text", True, ""),
    ("metadata_claims", 4, "generation", "bigint", True, ""),
    ("metadata_claims", 5, "record_version", "bigint", True, ""),
    ("metadata_claims", 6, "expires_at", "timestamp with time zone", True, ""),
    ("metadata_claims", 7, "event_sequence", "bigint", True, ""),
    ("metadata_claims", 8, "event_sha256", "text", True, ""),
    ("metadata_idempotency", 1, "namespace", "text", True, ""),
    ("metadata_idempotency", 2, "idempotency_key", "text", True, ""),
    ("metadata_idempotency", 3, "operation", "text", True, ""),
    ("metadata_idempotency", 4, "request_sha256", "text", True, ""),
    ("metadata_idempotency", 5, "response_document", "bytea", True, ""),
    ("metadata_idempotency", 6, "response_sha256", "text", True, ""),
    (
        "metadata_idempotency",
        7,
        "created_at",
        "timestamp with time zone",
        True,
        "clock_timestamp()",
    ),
    ("metadata_record_versions", 1, "namespace", "text", True, ""),
    ("metadata_record_versions", 2, "record_id", "text", True, ""),
    ("metadata_record_versions", 3, "record_version", "bigint", True, ""),
    ("metadata_record_versions", 4, "document", "bytea", True, ""),
    ("metadata_record_versions", 5, "document_sha256", "text", True, ""),
    ("metadata_record_versions", 6, "previous_chain_sha256", "text", False, ""),
    ("metadata_record_versions", 7, "chain_sha256", "text", True, ""),
    (
        "metadata_record_versions",
        8,
        "recorded_at",
        "timestamp with time zone",
        True,
        "clock_timestamp()",
    ),
    ("metadata_records", 1, "namespace", "text", True, ""),
    ("metadata_records", 2, "record_id", "text", True, ""),
    ("metadata_records", 3, "record_version", "bigint", True, ""),
    ("metadata_records", 4, "document", "bytea", True, ""),
    ("metadata_records", 5, "document_sha256", "text", True, ""),
    ("metadata_records", 6, "chain_sha256", "text", True, ""),
    (
        "metadata_records",
        7,
        "created_at",
        "timestamp with time zone",
        True,
        "clock_timestamp()",
    ),
    (
        "metadata_records",
        8,
        "updated_at",
        "timestamp with time zone",
        True,
        "clock_timestamp()",
    ),
    ("schema_migrations", 1, "version", "integer", True, ""),
    ("schema_migrations", 2, "name", "text", True, ""),
    ("schema_migrations", 3, "migration_sha256", "text", True, ""),
    ("schema_migrations", 4, "migration_role", "text", True, ""),
    ("schema_migrations", 5, "runtime_role", "text", True, ""),
    (
        "schema_migrations",
        6,
        "applied_at",
        "timestamp with time zone",
        True,
        "clock_timestamp()",
    ),
)

_EXPECTED_CONSTRAINTS = frozenset(
    {
        ("metadata_claim_events", "c", "CHECK (event_sequence >= 1)"),
        (
            "metadata_claim_events",
            "c",
            "CHECK (event_sequence = 1 AND previous_event_sha256 IS NULL OR "
            "event_sequence > 1 AND previous_event_sha256 IS NOT NULL)",
        ),
        (
            "metadata_claim_events",
            "c",
            "CHECK (event_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_claim_events",
            "c",
            "CHECK (event_type = ANY (ARRAY['acquired'::text, 'reclaimed'::text, "
            "'renewed'::text, 'completed'::text]))",
        ),
        (
            "metadata_claim_events",
            "c",
            "CHECK (event_type = 'completed'::text AND expires_at IS NULL OR "
            "event_type <> 'completed'::text AND expires_at IS NOT NULL)",
        ),
        ("metadata_claim_events", "c", "CHECK (generation >= 1)"),
        (
            "metadata_claim_events",
            "c",
            "CHECK (length(owner) >= 1 AND length(owner) <= 256 AND owner = btrim(owner))",
        ),
        (
            "metadata_claim_events",
            "c",
            "CHECK (previous_event_sha256 IS NULL OR "
            "previous_event_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        ("metadata_claim_events", "c", "CHECK (record_version >= 1)"),
        (
            "metadata_claim_events",
            "f",
            "FOREIGN KEY (namespace, record_id) REFERENCES "
            "colortrace.metadata_records(namespace, record_id) ON DELETE RESTRICT",
        ),
        (
            "metadata_claim_events",
            "p",
            "PRIMARY KEY (namespace, record_id, event_sequence)",
        ),
        ("metadata_claims", "c", "CHECK (event_sequence >= 1)"),
        ("metadata_claims", "c", "CHECK (event_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)"),
        ("metadata_claims", "c", "CHECK (generation >= 1)"),
        (
            "metadata_claims",
            "c",
            "CHECK (length(owner) >= 1 AND length(owner) <= 256 AND owner = btrim(owner))",
        ),
        ("metadata_claims", "c", "CHECK (record_version >= 1)"),
        (
            "metadata_claims",
            "f",
            "FOREIGN KEY (namespace, record_id) REFERENCES "
            "colortrace.metadata_records(namespace, record_id) ON DELETE RESTRICT",
        ),
        ("metadata_claims", "p", "PRIMARY KEY (namespace, record_id)"),
        (
            "metadata_idempotency",
            "c",
            "CHECK (length(idempotency_key) >= 1 AND length(idempotency_key) <= 256 AND "
            "idempotency_key = btrim(idempotency_key))",
        ),
        (
            "metadata_idempotency",
            "c",
            "CHECK (namespace = ANY (ARRAY['incident'::text, 'response-plan'::text, "
            "'recovery'::text, 'recovery-task'::text, 'simulator-action'::text]))",
        ),
        (
            "metadata_idempotency",
            "c",
            "CHECK (operation = ANY (ARRAY['create'::text, 'update'::text, "
            "'complete-claim'::text]))",
        ),
        (
            "metadata_idempotency",
            "c",
            "CHECK (request_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_idempotency",
            "c",
            "CHECK (response_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        ("metadata_idempotency", "p", "PRIMARY KEY (namespace, idempotency_key)"),
        (
            "metadata_record_versions",
            "c",
            "CHECK (chain_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_record_versions",
            "c",
            "CHECK (document_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_record_versions",
            "c",
            "CHECK (previous_chain_sha256 IS NULL OR "
            "previous_chain_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        ("metadata_record_versions", "c", "CHECK (record_version >= 1)"),
        (
            "metadata_record_versions",
            "c",
            "CHECK (record_version = 1 AND previous_chain_sha256 IS NULL OR "
            "record_version > 1 AND previous_chain_sha256 IS NOT NULL)",
        ),
        (
            "metadata_record_versions",
            "f",
            "FOREIGN KEY (namespace, record_id) REFERENCES "
            "colortrace.metadata_records(namespace, record_id) ON DELETE RESTRICT",
        ),
        (
            "metadata_record_versions",
            "p",
            "PRIMARY KEY (namespace, record_id, record_version)",
        ),
        (
            "metadata_records",
            "c",
            "CHECK (chain_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_records",
            "c",
            "CHECK (document_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        (
            "metadata_records",
            "c",
            "CHECK (length(record_id) >= 1 AND length(record_id) <= 256 AND "
            "record_id = btrim(record_id))",
        ),
        (
            "metadata_records",
            "c",
            "CHECK (namespace = ANY (ARRAY['incident'::text, 'response-plan'::text, "
            "'recovery'::text, 'recovery-task'::text, 'simulator-action'::text]))",
        ),
        ("metadata_records", "c", "CHECK (record_version >= 1)"),
        ("metadata_records", "c", "CHECK (updated_at >= created_at)"),
        ("metadata_records", "p", "PRIMARY KEY (namespace, record_id)"),
        (
            "schema_migrations",
            "c",
            "CHECK (migration_sha256 ~ '^sha256:[0-9a-f]{64}$'::text)",
        ),
        ("schema_migrations", "c", "CHECK (version >= 1)"),
        ("schema_migrations", "p", "PRIMARY KEY (version)"),
    }
)

_EXPECTED_INDEXES = frozenset(
    {
        (
            "metadata_claim_events",
            "metadata_claim_events_pkey",
            "CREATE UNIQUE INDEX metadata_claim_events_pkey ON "
            "colortrace.metadata_claim_events USING btree (namespace, record_id, event_sequence)",
        ),
        (
            "metadata_claims",
            "metadata_claims_expiry",
            "CREATE INDEX metadata_claims_expiry ON colortrace.metadata_claims "
            "USING btree (expires_at, namespace, record_id)",
        ),
        (
            "metadata_claims",
            "metadata_claims_pkey",
            "CREATE UNIQUE INDEX metadata_claims_pkey ON colortrace.metadata_claims "
            "USING btree (namespace, record_id)",
        ),
        (
            "metadata_idempotency",
            "metadata_idempotency_pkey",
            "CREATE UNIQUE INDEX metadata_idempotency_pkey ON colortrace.metadata_idempotency "
            "USING btree (namespace, idempotency_key)",
        ),
        (
            "metadata_record_versions",
            "metadata_record_versions_pkey",
            "CREATE UNIQUE INDEX metadata_record_versions_pkey ON "
            "colortrace.metadata_record_versions USING btree "
            "(namespace, record_id, record_version)",
        ),
        (
            "metadata_records",
            "metadata_records_pkey",
            "CREATE UNIQUE INDEX metadata_records_pkey ON colortrace.metadata_records "
            "USING btree (namespace, record_id)",
        ),
        (
            "schema_migrations",
            "schema_migrations_pkey",
            "CREATE UNIQUE INDEX schema_migrations_pkey ON colortrace.schema_migrations "
            "USING btree (version)",
        ),
    }
)

_EXPECTED_TRIGGERS = frozenset(
    {
        (
            "metadata_claim_events",
            "metadata_claim_events_immutable",
            27,
            "O",
            "reject_immutable_metadata",
        ),
        (
            "metadata_idempotency",
            "metadata_idempotency_immutable",
            27,
            "O",
            "reject_immutable_metadata",
        ),
        (
            "metadata_record_versions",
            "metadata_record_versions_immutable",
            27,
            "O",
            "reject_immutable_metadata",
        ),
        (
            "metadata_records",
            "metadata_record_identity_immutable",
            19,
            "O",
            "reject_metadata_record_identity_change",
        ),
    }
)

_IMMUTABLE_FUNCTION_BODY = """
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23000',
        MESSAGE = 'colortrace immutable metadata cannot be changed';
END;
"""

_IDENTITY_FUNCTION_BODY = """
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
"""

_EXPECTED_FUNCTIONS = frozenset(
    {
        (
            "reject_immutable_metadata",
            "",
            "trigger",
            "plpgsql",
            "v",
            False,
            False,
            False,
            " ".join(_IMMUTABLE_FUNCTION_BODY.split()),
        ),
        (
            "reject_metadata_record_identity_change",
            "",
            "trigger",
            "plpgsql",
            "v",
            False,
            False,
            False,
            " ".join(_IDENTITY_FUNCTION_BODY.split()),
        ),
    }
)

_EXPECTED_RELATIONS = frozenset(
    {
        ("metadata_claim_events", "r"),
        ("metadata_claim_events_pkey", "i"),
        ("metadata_claims", "r"),
        ("metadata_claims_expiry", "i"),
        ("metadata_claims_pkey", "i"),
        ("metadata_idempotency", "r"),
        ("metadata_idempotency_pkey", "i"),
        ("metadata_record_versions", "r"),
        ("metadata_record_versions_pkey", "i"),
        ("metadata_records", "r"),
        ("metadata_records_pkey", "i"),
        ("schema_migrations", "r"),
        ("schema_migrations_pkey", "i"),
    }
)

_EXPECTED_TABLE_PRIVILEGES: Mapping[str, frozenset[str]] = {
    "metadata_claim_events": frozenset({"INSERT", "SELECT"}),
    "metadata_claims": frozenset({"DELETE", "INSERT", "SELECT", "UPDATE"}),
    "metadata_idempotency": frozenset({"INSERT", "SELECT"}),
    "metadata_record_versions": frozenset({"INSERT", "SELECT"}),
    "metadata_records": frozenset({"INSERT", "SELECT", "UPDATE"}),
    "schema_migrations": frozenset(),
}
_EXPECTED_READER_TABLE_PRIVILEGES: Mapping[str, frozenset[str]] = {
    "metadata_claim_events": frozenset(),
    "metadata_claims": frozenset(),
    "metadata_idempotency": frozenset(),
    "metadata_record_versions": frozenset({"SELECT"}),
    "metadata_records": frozenset({"SELECT"}),
    "schema_migrations": frozenset(),
}

_TABLE_PRIVILEGES = ("DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE")


def _column_names(cursor: DbCursor) -> tuple[str, ...]:
    description = cursor.description
    if not isinstance(description, (list, tuple)):
        raise PersistenceError("postgres-result-invalid")
    names: list[str] = []
    for value in description:
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
            names.append(value[0])
            continue
        name = getattr(value, "name", None)
        if not isinstance(name, str):
            raise PersistenceError("postgres-result-invalid")
        names.append(name)
    return tuple(names)


def _rows(cursor: DbCursor) -> list[dict[str, Any]]:
    names = _column_names(cursor)
    values = cursor.fetchall()
    rows: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != len(names):
            raise PersistenceError("postgres-result-invalid")
        rows.append(dict(zip(names, value, strict=True)))
    return rows


def _tuples(cursor: DbCursor, names: tuple[str, ...]) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row[name] for name in names) for row in _rows(cursor))


def _validate_relations(cursor: DbCursor, migration_role: str) -> None:
    cursor.execute(
        "SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner) AS owner "
        "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'colortrace' ORDER BY c.relname"
    )
    rows = _rows(cursor)
    relations = frozenset((row["relname"], row["relkind"]) for row in rows)
    if relations != _EXPECTED_RELATIONS or any(row["owner"] != migration_role for row in rows):
        raise PersistenceError("migration-schema-drift")


def _validate_columns(cursor: DbCursor) -> None:
    cursor.execute(
        "SELECT c.relname, a.attnum, a.attname, format_type(a.atttypid, a.atttypmod) "
        "AS data_type, a.attnotnull, COALESCE(pg_get_expr(d.adbin, d.adrelid), '') "
        "AS default_expression FROM pg_class AS c JOIN pg_namespace AS n "
        "ON n.oid = c.relnamespace JOIN pg_attribute AS a ON a.attrelid = c.oid "
        "LEFT JOIN pg_attrdef AS d ON d.adrelid = c.oid AND d.adnum = a.attnum "
        "WHERE n.nspname = 'colortrace' AND c.relkind = 'r' AND a.attnum > 0 "
        "AND NOT a.attisdropped ORDER BY c.relname, a.attnum"
    )
    observed = _tuples(
        cursor,
        ("relname", "attnum", "attname", "data_type", "attnotnull", "default_expression"),
    )
    if observed != _EXPECTED_COLUMNS:
        raise PersistenceError("migration-schema-drift")


def _validate_constraints(cursor: DbCursor) -> None:
    cursor.execute(
        "SELECT r.relname, c.contype, pg_get_constraintdef(c.oid, true) AS definition "
        "FROM pg_constraint AS c JOIN pg_class AS r ON r.oid = c.conrelid "
        "JOIN pg_namespace AS n ON n.oid = r.relnamespace "
        "WHERE n.nspname = 'colortrace'"
    )
    observed = frozenset(_tuples(cursor, ("relname", "contype", "definition")))
    if observed != _EXPECTED_CONSTRAINTS:
        raise PersistenceError("migration-schema-drift")


def _validate_indexes(cursor: DbCursor) -> None:
    cursor.execute(
        "SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'colortrace'"
    )
    observed = frozenset(_tuples(cursor, ("tablename", "indexname", "indexdef")))
    if observed != _EXPECTED_INDEXES:
        raise PersistenceError("migration-schema-drift")


def _validate_functions(cursor: DbCursor, migration_role: str) -> None:
    cursor.execute(
        "SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS arguments, "
        "pg_get_function_result(p.oid) AS result, l.lanname, p.provolatile, p.prosecdef, "
        "p.proleakproof, p.proisstrict, p.prosrc, pg_get_userbyid(p.proowner) AS owner "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "JOIN pg_language AS l ON l.oid = p.prolang WHERE n.nspname = 'colortrace'"
    )
    rows = _rows(cursor)
    observed = frozenset(
        (
            row["proname"],
            row["arguments"],
            row["result"],
            row["lanname"],
            row["provolatile"],
            row["prosecdef"],
            row["proleakproof"],
            row["proisstrict"],
            " ".join(str(row["prosrc"]).split()),
        )
        for row in rows
    )
    if observed != _EXPECTED_FUNCTIONS or any(row["owner"] != migration_role for row in rows):
        raise PersistenceError("migration-schema-drift")


def _validate_triggers(cursor: DbCursor) -> None:
    cursor.execute(
        "SELECT r.relname, t.tgname, t.tgtype, t.tgenabled, p.proname "
        "FROM pg_trigger AS t JOIN pg_class AS r ON r.oid = t.tgrelid "
        "JOIN pg_namespace AS n ON n.oid = r.relnamespace "
        "JOIN pg_proc AS p ON p.oid = t.tgfoid "
        "WHERE n.nspname = 'colortrace' AND NOT t.tgisinternal"
    )
    observed = frozenset(_tuples(cursor, ("relname", "tgname", "tgtype", "tgenabled", "proname")))
    if observed != _EXPECTED_TRIGGERS:
        raise PersistenceError("migration-schema-drift")


def _validate_runtime_privileges(cursor: DbCursor, runtime_role: str) -> None:
    cursor.execute(
        "SELECT has_schema_privilege(%s, n.oid, 'USAGE') AS usage, "
        "has_schema_privilege(%s, n.oid, 'CREATE') AS create_privilege "
        "FROM pg_namespace AS n WHERE n.nspname = 'colortrace'",
        (runtime_role, runtime_role),
    )
    schema_rows = _rows(cursor)
    if len(schema_rows) != 1 or schema_rows[0] != {"usage": True, "create_privilege": False}:
        raise PersistenceError("postgres-runtime-privilege-invalid")

    cursor.execute(
        "SELECT c.relname, "
        "has_table_privilege(%s, c.oid, 'DELETE') AS delete_privilege, "
        "has_table_privilege(%s, c.oid, 'INSERT') AS insert_privilege, "
        "has_table_privilege(%s, c.oid, 'REFERENCES') AS references_privilege, "
        "has_table_privilege(%s, c.oid, 'SELECT') AS select_privilege, "
        "has_table_privilege(%s, c.oid, 'TRIGGER') AS trigger_privilege, "
        "has_table_privilege(%s, c.oid, 'TRUNCATE') AS truncate_privilege, "
        "has_table_privilege(%s, c.oid, 'UPDATE') AS update_privilege "
        "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'colortrace' AND c.relkind = 'r' ORDER BY c.relname",
        (runtime_role,) * len(_TABLE_PRIVILEGES),
    )
    rows = _rows(cursor)
    observed: dict[str, frozenset[str]] = {}
    for row in rows:
        observed[str(row["relname"])] = frozenset(
            privilege
            for privilege in _TABLE_PRIVILEGES
            if row[f"{privilege.lower()}_privilege"] is True
        )
    if observed != _EXPECTED_TABLE_PRIVILEGES:
        raise PersistenceError("postgres-runtime-privilege-invalid")

    cursor.execute(
        "SELECT bool_or(has_function_privilege(%s, p.oid, 'EXECUTE')) AS can_execute "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'colortrace'",
        (runtime_role,),
    )
    function_rows = _rows(cursor)
    if len(function_rows) != 1 or function_rows[0].get("can_execute") is not False:
        raise PersistenceError("postgres-runtime-privilege-invalid")

    cursor.execute(
        "SELECT has_database_privilege(%s, current_database(), 'CONNECT') AS connect, "
        "has_database_privilege(%s, current_database(), 'CREATE') AS create_privilege",
        (runtime_role, runtime_role),
    )
    database_rows = _rows(cursor)
    if len(database_rows) != 1 or database_rows[0] != {
        "connect": True,
        "create_privilege": False,
    }:
        raise PersistenceError("postgres-runtime-privilege-invalid")


def validate_reader_privileges(cursor: DbCursor, reader_role: str) -> None:
    cursor.execute(
        "SELECT has_schema_privilege(%s, n.oid, 'USAGE') AS usage, "
        "has_schema_privilege(%s, n.oid, 'CREATE') AS create_privilege "
        "FROM pg_namespace AS n WHERE n.nspname = 'colortrace'",
        (reader_role, reader_role),
    )
    schema_rows = _rows(cursor)
    if len(schema_rows) != 1 or schema_rows[0] != {"usage": True, "create_privilege": False}:
        raise PersistenceError("postgres-reader-privilege-invalid")

    cursor.execute(
        "SELECT bool_or(has_schema_privilege(%s, n.oid, 'CREATE')) AS can_create "
        "FROM pg_namespace AS n WHERE n.nspname !~ '^pg_' "
        "AND n.nspname <> 'information_schema'",
        (reader_role,),
    )
    create_rows = _rows(cursor)
    if len(create_rows) != 1 or create_rows[0].get("can_create") is not False:
        raise PersistenceError("postgres-reader-privilege-invalid")

    cursor.execute(
        "SELECT n.nspname, c.relname, "
        "has_table_privilege(%s, c.oid, 'DELETE') AS delete_privilege, "
        "has_table_privilege(%s, c.oid, 'INSERT') AS insert_privilege, "
        "has_table_privilege(%s, c.oid, 'REFERENCES') AS references_privilege, "
        "has_table_privilege(%s, c.oid, 'SELECT') AS select_privilege, "
        "has_table_privilege(%s, c.oid, 'TRIGGER') AS trigger_privilege, "
        "has_table_privilege(%s, c.oid, 'TRUNCATE') AS truncate_privilege, "
        "has_table_privilege(%s, c.oid, 'UPDATE') AS update_privilege "
        "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
        "AND c.relkind = 'r' ORDER BY n.nspname, c.relname",
        (reader_role,) * len(_TABLE_PRIVILEGES),
    )
    observed: dict[str, frozenset[str]] = {}
    for row in _rows(cursor):
        schema = str(row["nspname"])
        relation = str(row["relname"])
        privileges = frozenset(
            privilege
            for privilege in _TABLE_PRIVILEGES
            if row[f"{privilege.lower()}_privilege"] is True
        )
        if schema != "colortrace":
            if privileges:
                raise PersistenceError("postgres-reader-privilege-invalid")
            continue
        observed[relation] = privileges
    if observed != _EXPECTED_READER_TABLE_PRIVILEGES:
        raise PersistenceError("postgres-reader-privilege-invalid")

    cursor.execute(
        "SELECT bool_or(has_function_privilege(%s, p.oid, 'EXECUTE')) AS can_execute "
        "FROM pg_proc AS p JOIN pg_namespace AS n ON n.oid = p.pronamespace "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'",
        (reader_role,),
    )
    function_rows = _rows(cursor)
    if len(function_rows) != 1 or function_rows[0].get("can_execute") is not False:
        raise PersistenceError("postgres-reader-privilege-invalid")

    cursor.execute(
        "SELECT has_database_privilege(%s, current_database(), 'CONNECT') AS connect, "
        "has_database_privilege(%s, current_database(), 'CREATE') AS create_privilege, "
        "has_database_privilege(%s, current_database(), 'TEMPORARY') AS temporary",
        (reader_role, reader_role, reader_role),
    )
    database_rows = _rows(cursor)
    if len(database_rows) != 1 or database_rows[0] != {
        "connect": True,
        "create_privilege": False,
        "temporary": False,
    }:
        raise PersistenceError("postgres-reader-privilege-invalid")


def validate_schema(
    cursor: DbCursor,
    *,
    migration_role: str,
    runtime_role: str,
    reader_role: str,
) -> None:
    cursor.execute(
        "SELECT pg_get_userbyid(n.nspowner) AS owner FROM pg_namespace AS n "
        "WHERE n.nspname = 'colortrace'"
    )
    schema_rows = _rows(cursor)
    if len(schema_rows) != 1 or schema_rows[0].get("owner") != migration_role:
        raise PersistenceError("migration-schema-drift")
    _validate_relations(cursor, migration_role)
    _validate_columns(cursor)
    _validate_constraints(cursor)
    _validate_indexes(cursor)
    _validate_functions(cursor, migration_role)
    _validate_triggers(cursor)
    _validate_runtime_privileges(cursor, runtime_role)
    validate_reader_privileges(cursor, reader_role)
