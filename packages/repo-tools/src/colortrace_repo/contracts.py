from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urldefrag, urlparse

from colortrace_repo.common import Finding, load_json, relative_path, sorted_findings

_HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
_SCHEMA_TYPES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})
_SCHEMA_MAP_KEYS = frozenset(
    {
        "$defs",
        "dependentSchemas",
        "patternProperties",
        "properties",
    }
)
_SCHEMA_LIST_KEYS = frozenset(
    {
        "allOf",
        "anyOf",
        "oneOf",
        "prefixItems",
    }
)
_SCHEMA_SINGLE_KEYS = frozenset(
    {
        "additionalProperties",
        "contains",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)


def _pointer_join(pointer: str, value: str | int) -> str:
    escaped = str(value).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{escaped}"


def _location(pointer: str) -> str:
    return f"#{pointer}" if pointer else "#"


@dataclass(frozen=True)
class ResolvedReference:
    document_path: Path
    value: Any
    pointer: str


class ReferenceResolver:
    def __init__(self, contract_root: Path, documents: dict[Path, Any]) -> None:
        self.contract_root = contract_root.resolve()
        self.documents = {path.resolve(): value for path, value in documents.items()}

    def resolve(self, source_path: Path, reference: str) -> ResolvedReference:
        document_part, fragment = urldefrag(reference)
        parsed = urlparse(document_part)
        if parsed.scheme or parsed.netloc:
            raise ValueError("remote references are not permitted")

        if document_part:
            target_path = (source_path.parent / unquote(document_part)).resolve()
        else:
            target_path = source_path.resolve()
        try:
            target_path.relative_to(self.contract_root)
        except ValueError as error:
            raise ValueError("reference escapes the contract tree") from error

        if target_path not in self.documents:
            if target_path.suffix.lower() != ".json" or not target_path.is_file():
                raise ValueError("referenced document does not exist")
            try:
                self.documents[target_path] = load_json(target_path)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(f"referenced document is not valid JSON: {error}") from error

        value = self.documents[target_path]
        pointer = ""
        if fragment:
            decoded_fragment = unquote(fragment)
            if not decoded_fragment.startswith("/"):
                raise ValueError("reference fragment must be a JSON Pointer")
            for raw_part in decoded_fragment[1:].split("/"):
                part = raw_part.replace("~1", "/").replace("~0", "~")
                pointer = _pointer_join(pointer, part)
                if isinstance(value, dict) and part in value:
                    value = value[part]
                elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
                    value = value[int(part)]
                else:
                    raise ValueError(f"JSON Pointer target {_location(pointer)} does not exist")
        return ResolvedReference(target_path, value, pointer)


class SchemaValidator:
    def __init__(self, resolver: ReferenceResolver) -> None:
        self.resolver = resolver

    def validate(
        self,
        instance: Any,
        schema: Any,
        source_path: Path,
        instance_pointer: str = "",
        active_refs: frozenset[tuple[Path, str]] = frozenset(),
    ) -> list[str]:
        if schema is True:
            return []
        if schema is False:
            return [f"{_location(instance_pointer)} is rejected by a false schema"]
        if not isinstance(schema, dict):
            return ["schema is not an object or boolean"]

        messages: list[str] = []
        reference = schema.get("$ref")
        if isinstance(reference, str):
            try:
                resolved = self.resolver.resolve(source_path, reference)
            except ValueError as error:
                return [f"cannot resolve $ref {reference!r}: {error}"]
            identity = (resolved.document_path, resolved.pointer)
            if identity not in active_refs:
                messages.extend(
                    self.validate(
                        instance,
                        resolved.value,
                        resolved.document_path,
                        instance_pointer,
                        active_refs | {identity},
                    )
                )

        if "const" in schema and instance != schema["const"]:
            messages.append(f"{_location(instance_pointer)} does not equal the required constant")
        if isinstance(schema.get("enum"), list) and instance not in schema["enum"]:
            messages.append(f"{_location(instance_pointer)} is not one of the allowed values")

        expected_types = schema.get("type")
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        if isinstance(expected_types, list) and not any(
            self._matches_type(instance, expected) for expected in expected_types
        ):
            messages.append(
                f"{_location(instance_pointer)} does not have type "
                f"{' or '.join(str(value) for value in expected_types)}"
            )
            return messages

        messages.extend(self._validate_composition(instance, schema, source_path, instance_pointer))
        if isinstance(instance, dict):
            messages.extend(self._validate_object(instance, schema, source_path, instance_pointer))
        if isinstance(instance, list):
            messages.extend(self._validate_array(instance, schema, source_path, instance_pointer))
        if isinstance(instance, str):
            messages.extend(self._validate_string(instance, schema, instance_pointer))
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            messages.extend(self._validate_number(instance, schema, instance_pointer))
        return messages

    @staticmethod
    def _matches_type(instance: Any, expected: Any) -> bool:
        return {
            "array": isinstance(instance, list),
            "boolean": isinstance(instance, bool),
            "integer": isinstance(instance, int) and not isinstance(instance, bool),
            "null": instance is None,
            "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
            "object": isinstance(instance, dict),
            "string": isinstance(instance, str),
        }.get(expected, False)

    def _validate_composition(
        self, instance: Any, schema: dict[str, Any], source_path: Path, pointer: str
    ) -> list[str]:
        messages: list[str] = []
        for keyword in ("allOf", "anyOf", "oneOf"):
            branches = schema.get(keyword)
            if not isinstance(branches, list):
                continue
            branch_results = [
                self.validate(instance, branch, source_path, pointer) for branch in branches
            ]
            matches = sum(not result for result in branch_results)
            if keyword == "allOf":
                for result in branch_results:
                    messages.extend(result)
            elif keyword == "anyOf" and matches == 0:
                messages.append(f"{_location(pointer)} does not match any anyOf branch")
            elif keyword == "oneOf" and matches != 1:
                messages.append(
                    f"{_location(pointer)} matches {matches} oneOf branches instead of exactly one"
                )
        if "not" in schema and not self.validate(instance, schema["not"], source_path, pointer):
            messages.append(f"{_location(pointer)} matches a prohibited schema")
        condition = schema.get("if")
        if condition is not None:
            branch = (
                "then" if not self.validate(instance, condition, source_path, pointer) else "else"
            )
            if branch in schema:
                messages.extend(self.validate(instance, schema[branch], source_path, pointer))
        return messages

    def _validate_object(
        self,
        instance: dict[str, Any],
        schema: dict[str, Any],
        source_path: Path,
        pointer: str,
    ) -> list[str]:
        messages: list[str] = []
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if isinstance(key, str) and key not in instance:
                    messages.append(f"{_location(pointer)} is missing required property {key!r}")
        properties = schema.get("properties", {})
        properties = properties if isinstance(properties, dict) else {}
        pattern_properties = schema.get("patternProperties", {})
        pattern_properties = pattern_properties if isinstance(pattern_properties, dict) else {}
        matched: set[str] = set()
        for key, child_schema in properties.items():
            if key in instance:
                matched.add(key)
                messages.extend(
                    self.validate(
                        instance[key], child_schema, source_path, _pointer_join(pointer, key)
                    )
                )
        for expression, child_schema in pattern_properties.items():
            try:
                pattern = re.compile(expression)
            except re.error:
                continue
            for key, value in instance.items():
                if pattern.search(key):
                    matched.add(key)
                    messages.extend(
                        self.validate(value, child_schema, source_path, _pointer_join(pointer, key))
                    )
        additional = schema.get("additionalProperties", True)
        for key in set(instance) - matched:
            if additional is False:
                messages.append(
                    f"{_location(_pointer_join(pointer, key))} is not an allowed property"
                )
            elif isinstance(additional, (dict, bool)):
                messages.extend(
                    self.validate(
                        instance[key], additional, source_path, _pointer_join(pointer, key)
                    )
                )
        minimum = schema.get("minProperties")
        maximum = schema.get("maxProperties")
        if isinstance(minimum, int) and len(instance) < minimum:
            messages.append(f"{_location(pointer)} has fewer than {minimum} properties")
        if isinstance(maximum, int) and len(instance) > maximum:
            messages.append(f"{_location(pointer)} has more than {maximum} properties")
        return messages

    def _validate_array(
        self,
        instance: list[Any],
        schema: dict[str, Any],
        source_path: Path,
        pointer: str,
    ) -> list[str]:
        messages: list[str] = []
        minimum = schema.get("minItems")
        maximum = schema.get("maxItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            messages.append(f"{_location(pointer)} has fewer than {minimum} items")
        if isinstance(maximum, int) and len(instance) > maximum:
            messages.append(f"{_location(pointer)} has more than {maximum} items")
        if schema.get("uniqueItems") is True:
            serialized = [
                json.dumps(value, sort_keys=True, separators=(",", ":")) for value in instance
            ]
            if len(serialized) != len(set(serialized)):
                messages.append(f"{_location(pointer)} contains duplicate items")
        prefix_items = schema.get("prefixItems", [])
        if isinstance(prefix_items, list):
            for index, child_schema in enumerate(prefix_items[: len(instance)]):
                messages.extend(
                    self.validate(
                        instance[index], child_schema, source_path, _pointer_join(pointer, index)
                    )
                )
        items = schema.get("items")
        if isinstance(items, (dict, bool)):
            start = len(prefix_items) if isinstance(prefix_items, list) else 0
            for index in range(start, len(instance)):
                messages.extend(
                    self.validate(
                        instance[index], items, source_path, _pointer_join(pointer, index)
                    )
                )
        return messages

    @staticmethod
    def _validate_string(value: str, schema: dict[str, Any], pointer: str) -> list[str]:
        messages: list[str] = []
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(value) < minimum:
            messages.append(f"{_location(pointer)} is shorter than {minimum} characters")
        if isinstance(maximum, int) and len(value) > maximum:
            messages.append(f"{_location(pointer)} is longer than {maximum} characters")
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            try:
                if re.search(pattern, value) is None:
                    messages.append(f"{_location(pointer)} does not match the required pattern")
            except re.error:
                pass
        value_format = schema.get("format")
        try:
            if value_format == "date":
                date.fromisoformat(value)
            elif value_format == "date-time":
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            elif value_format == "uri" and not urlparse(value).scheme:
                raise ValueError
            elif value_format == "uuid" and not re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
                value,
            ):
                raise ValueError
        except ValueError:
            messages.append(f"{_location(pointer)} is not a valid {value_format}")
        return messages

    @staticmethod
    def _validate_number(value: int | float, schema: dict[str, Any], pointer: str) -> list[str]:
        messages: list[str] = []
        for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            bound = schema.get(keyword)
            if not isinstance(bound, (int, float)):
                continue
            valid = (
                (keyword == "minimum" and value >= bound)
                or (keyword == "maximum" and value <= bound)
                or (keyword == "exclusiveMinimum" and value > bound)
                or (keyword == "exclusiveMaximum" and value < bound)
            )
            if not valid:
                messages.append(f"{_location(pointer)} violates {keyword} {bound}")
        multiple = schema.get("multipleOf")
        if isinstance(multiple, (int, float)) and multiple > 0:
            quotient = value / multiple
            if not math.isclose(quotient, round(quotient), abs_tol=1e-12):
                messages.append(f"{_location(pointer)} is not a multiple of {multiple}")
        return messages


def _schema_findings(
    root: Path,
    path: Path,
    schema: Any,
    pointer: str,
    resolver: ReferenceResolver,
    seen: set[tuple[Path, str]],
) -> list[Finding]:
    identity = (path.resolve(), pointer)
    if identity in seen:
        return []
    seen.add(identity)
    display_path = relative_path(root, path)
    findings: list[Finding] = []
    if isinstance(schema, bool):
        return findings
    if not isinstance(schema, dict):
        return [
            Finding(
                display_path,
                "contract.schema.type",
                "schema must be an object or boolean",
                _location(pointer),
            )
        ]

    schema_type = schema.get("type")
    types: list[object]
    if isinstance(schema_type, str):
        types = [schema_type]
    elif isinstance(schema_type, list) and schema_type:
        types = schema_type
    elif schema_type is None:
        types = []
    else:
        types = [None]
    if any(value not in _SCHEMA_TYPES for value in types):
        findings.append(
            Finding(
                display_path,
                "contract.schema.type",
                "type must contain only JSON Schema primitive type names",
                _location(_pointer_join(pointer, "type")),
            )
        )

    required = schema.get("required")
    if required is not None and (
        not isinstance(required, list)
        or any(not isinstance(value, str) for value in required)
        or len(required) != len(set(required))
    ):
        findings.append(
            Finding(
                display_path,
                "contract.schema.required",
                "required must be an array of unique strings",
                _location(_pointer_join(pointer, "required")),
            )
        )

    enum = schema.get("enum")
    if enum is not None and (not isinstance(enum, list) or not enum):
        findings.append(
            Finding(
                display_path,
                "contract.schema.enum",
                "enum must be a non-empty array",
                _location(_pointer_join(pointer, "enum")),
            )
        )
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        try:
            re.compile(pattern)
        except re.error as error:
            findings.append(
                Finding(
                    display_path,
                    "contract.schema.pattern",
                    f"pattern is not a valid regular expression: {error}",
                    _location(_pointer_join(pointer, "pattern")),
                )
            )

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference:
            findings.append(
                Finding(
                    display_path,
                    "contract.ref.type",
                    "$ref must be a non-empty string",
                    _location(_pointer_join(pointer, "$ref")),
                )
            )
        else:
            try:
                resolved = resolver.resolve(path, reference)
                findings.extend(
                    _schema_findings(
                        root,
                        resolved.document_path,
                        resolved.value,
                        resolved.pointer,
                        resolver,
                        seen,
                    )
                )
            except ValueError as error:
                findings.append(
                    Finding(
                        display_path,
                        "contract.ref.invalid",
                        f"cannot resolve {reference!r}: {error}",
                        _location(_pointer_join(pointer, "$ref")),
                    )
                )

    for key in _SCHEMA_MAP_KEYS:
        value = schema.get(key)
        if value is None:
            continue
        if not isinstance(value, dict):
            findings.append(
                Finding(
                    display_path,
                    "contract.schema.keyword",
                    f"{key} must be an object",
                    _location(_pointer_join(pointer, key)),
                )
            )
            continue
        for child_name, child_schema in value.items():
            findings.extend(
                _schema_findings(
                    root,
                    path,
                    child_schema,
                    _pointer_join(_pointer_join(pointer, key), child_name),
                    resolver,
                    seen,
                )
            )
    for key in _SCHEMA_LIST_KEYS:
        value = schema.get(key)
        if value is None:
            continue
        if not isinstance(value, list) or not value:
            findings.append(
                Finding(
                    display_path,
                    "contract.schema.keyword",
                    f"{key} must be a non-empty array",
                    _location(_pointer_join(pointer, key)),
                )
            )
            continue
        for index, child_schema in enumerate(value):
            findings.extend(
                _schema_findings(
                    root,
                    path,
                    child_schema,
                    _pointer_join(_pointer_join(pointer, key), index),
                    resolver,
                    seen,
                )
            )
    for key in _SCHEMA_SINGLE_KEYS:
        value = schema.get(key)
        if value is not None:
            findings.extend(
                _schema_findings(
                    root,
                    path,
                    value,
                    _pointer_join(pointer, key),
                    resolver,
                    seen,
                )
            )

    validator = SchemaValidator(resolver)
    examples = schema.get("examples")
    if isinstance(examples, list):
        for index, example in enumerate(examples):
            for message in validator.validate(example, schema, path):
                findings.append(
                    Finding(
                        display_path,
                        "contract.example.invalid",
                        message,
                        _location(_pointer_join(_pointer_join(pointer, "examples"), index)),
                    )
                )
    if "example" in schema:
        for message in validator.validate(schema["example"], schema, path):
            findings.append(
                Finding(
                    display_path,
                    "contract.example.invalid",
                    message,
                    _location(_pointer_join(pointer, "example")),
                )
            )
    return findings


def _walk_openapi_nodes(value: Any, pointer: str = "") -> list[tuple[dict[str, Any], str]]:
    nodes: list[tuple[dict[str, Any], str]] = []
    if isinstance(value, dict):
        nodes.append((value, pointer))
        for key, child in value.items():
            nodes.extend(_walk_openapi_nodes(child, _pointer_join(pointer, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            nodes.extend(_walk_openapi_nodes(child, _pointer_join(pointer, index)))
    return nodes


def _openapi_findings(
    root: Path, path: Path, document: dict[str, Any], resolver: ReferenceResolver
) -> list[Finding]:
    display_path = relative_path(root, path)
    findings: list[Finding] = []
    if document.get("openapi") != "3.1.0":
        findings.append(
            Finding(
                display_path,
                "contract.openapi.version",
                "OpenAPI documents must declare openapi 3.1.0",
                "#/openapi",
            )
        )
    info = document.get("info")
    if not isinstance(info, dict) or not all(
        isinstance(info.get(key), str) and info[key].strip() for key in ("title", "version")
    ):
        findings.append(
            Finding(
                display_path,
                "contract.openapi.info",
                "info.title and info.version must be non-empty strings",
                "#/info",
            )
        )
    paths = document.get("paths")
    if not isinstance(paths, dict):
        findings.append(
            Finding(display_path, "contract.openapi.paths", "paths must be an object", "#/paths")
        )
        paths = {}

    operation_ids: dict[str, str] = {}
    for route, path_item in paths.items():
        route_pointer = _pointer_join("/paths", route)
        if not isinstance(route, str) or not route.startswith("/"):
            findings.append(
                Finding(
                    display_path,
                    "contract.openapi.route",
                    "path keys must begin with /",
                    _location(route_pointer),
                )
            )
        if not isinstance(path_item, dict):
            findings.append(
                Finding(
                    display_path,
                    "contract.openapi.path-item",
                    "path item must be an object",
                    _location(route_pointer),
                )
            )
            continue
        for method, operation in path_item.items():
            if method not in _HTTP_METHODS:
                continue
            operation_pointer = _pointer_join(route_pointer, method)
            if not isinstance(operation, dict):
                findings.append(
                    Finding(
                        display_path,
                        "contract.openapi.operation",
                        "operation must be an object",
                        _location(operation_pointer),
                    )
                )
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                findings.append(
                    Finding(
                        display_path,
                        "contract.openapi.operation-id",
                        "operationId must be a non-empty string",
                        _location(_pointer_join(operation_pointer, "operationId")),
                    )
                )
            elif operation_id in operation_ids:
                findings.append(
                    Finding(
                        display_path,
                        "contract.openapi.operation-id",
                        f"operationId duplicates {_location(operation_ids[operation_id])}",
                        _location(_pointer_join(operation_pointer, "operationId")),
                    )
                )
            else:
                operation_ids[operation_id] = operation_pointer
            responses = operation.get("responses")
            if not isinstance(responses, dict) or not responses:
                findings.append(
                    Finding(
                        display_path,
                        "contract.openapi.responses",
                        "operation responses must be a non-empty object",
                        _location(_pointer_join(operation_pointer, "responses")),
                    )
                )

    seen_schemas: set[tuple[Path, str]] = set()
    for node, pointer in _walk_openapi_nodes(document):
        reference = node.get("$ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference:
                findings.append(
                    Finding(
                        display_path,
                        "contract.ref.type",
                        "$ref must be a non-empty string",
                        _location(_pointer_join(pointer, "$ref")),
                    )
                )
            else:
                try:
                    resolver.resolve(path, reference)
                except ValueError as error:
                    findings.append(
                        Finding(
                            display_path,
                            "contract.ref.invalid",
                            f"cannot resolve {reference!r}: {error}",
                            _location(_pointer_join(pointer, "$ref")),
                        )
                    )
        schema = node.get("schema")
        if schema is not None:
            schema_pointer = _pointer_join(pointer, "schema")
            findings.extend(
                _schema_findings(root, path, schema, schema_pointer, resolver, seen_schemas)
            )
            validator = SchemaValidator(resolver)
            examples: list[tuple[str, Any]] = []
            if "example" in node:
                examples.append((_pointer_join(pointer, "example"), node["example"]))
            openapi_examples = node.get("examples")
            if isinstance(openapi_examples, dict):
                for name, candidate in openapi_examples.items():
                    if isinstance(candidate, dict) and "value" in candidate:
                        examples.append(
                            (
                                _pointer_join(
                                    _pointer_join(_pointer_join(pointer, "examples"), name),
                                    "value",
                                ),
                                candidate["value"],
                            )
                        )
            for example_pointer, example in examples:
                for message in validator.validate(example, schema, path):
                    findings.append(
                        Finding(
                            display_path,
                            "contract.example.invalid",
                            message,
                            _location(example_pointer),
                        )
                    )

    components = document.get("components", {})
    if isinstance(components, dict) and isinstance(components.get("schemas"), dict):
        for name, schema in components["schemas"].items():
            findings.extend(
                _schema_findings(
                    root,
                    path,
                    schema,
                    _pointer_join("/components/schemas", name),
                    resolver,
                    seen_schemas,
                )
            )
    return findings


def check_contracts(root: Path, contract_directory: Path | None = None) -> list[Finding]:
    root = root.resolve()
    contract_root = (
        contract_directory.resolve()
        if contract_directory is not None
        else (root / "packages" / "contracts").resolve()
    )
    if not contract_root.is_dir():
        return [
            Finding(
                relative_path(root, contract_root),
                "contract.directory.missing",
                "contract directory does not exist",
            )
        ]

    candidate_files = sorted(
        path
        for path in contract_root.rglob("*")
        if path.is_file()
        and (path.name == "openapi.json" or path.name.endswith((".openapi.json", ".schema.json")))
    )
    if not candidate_files:
        return [
            Finding(
                relative_path(root, contract_root),
                "contract.empty",
                "contract directory contains no JSON documents",
            )
        ]

    findings: list[Finding] = []
    documents: dict[Path, Any] = {}
    for path in candidate_files:
        display_path = relative_path(root, path)
        try:
            documents[path.resolve()] = load_json(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append(
                Finding(display_path, "contract.json.invalid", f"cannot parse JSON: {error}")
            )

    resolver = ReferenceResolver(contract_root, documents)
    for path, document in sorted(documents.items(), key=lambda item: item[0].as_posix()):
        display_path = relative_path(root, path)
        if not isinstance(document, dict):
            findings.append(
                Finding(display_path, "contract.document.type", "contract must be a JSON object")
            )
        elif "openapi" in document:
            findings.extend(_openapi_findings(root, path, document, resolver))
        elif "$schema" in document:
            findings.extend(_schema_findings(root, path, document, "", resolver, set()))
        else:
            findings.append(
                Finding(
                    display_path,
                    "contract.document.kind",
                    "document must declare openapi or $schema",
                )
            )
    return sorted_findings(findings)
