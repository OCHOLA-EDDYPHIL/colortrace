"""Schema-checked binding from fixture receipts to telemetry correlation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from functools import cache, lru_cache
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from colortrace_fixture.fixture import (
    COMPARISON_VERSION as FIXTURE_COMPARISON_VERSION,
)
from colortrace_fixture.fixture import (
    FIXTURE_ID,
    RUNTIME_MANIFEST_VERSION,
    VALIDATOR_RECEIPT_VERSION,
    VALIDATOR_REPORT_VERSION,
)
from colortrace_fixture.fixture import (
    SCHEMA_ROOT as FIXTURE_SCHEMA_ROOT,
)
from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]
from referencing import Registry, Resource

CORRELATION_VERSION = "correlation-contract/v1"
COMPARISON_VERSION = FIXTURE_COMPARISON_VERSION
TELEMETRY_EVENT_VERSION = "telemetry-event/v1"
EMISSION_RECEIPT_VERSION = "telemetry-emission-receipt/v1"
NO_GRAFANA_VERSION = "no-grafana-observation/v1"
OBSERVATION_VERSION = "declared-reference-observation/v1"
SERVICE_NAME = "colortrace-simulator"
SERVICE_VERSION = "simulator-telemetry/v1"
SIGNALS = ("metric", "log", "trace")
SCHEMA_ROOT = Path(__file__).parent / "schemas"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)([.][0-9]+)?$")
_REPORT_KEYS = frozenset(
    {
        "schema",
        "fixture_id",
        "variant_id",
        "ocio_version",
        "comparison_policy",
        "jobs",
        "derivatives",
        "telemetry_events",
        "diff_images",
    }
)
_REPORT_JOB_KEYS = frozenset(
    {
        "job_id",
        "worker_id",
        "output_id",
        "transform_id",
        "nominal_config_sha256",
        "state",
        "comparison",
        "reasons",
        "resource_manifest_sha256",
        "resolved_resource_sha256",
        "evidence",
    }
)
_MEASUREMENT_KEYS = frozenset(
    {
        "maximum_absolute_channel_error",
        "rmse",
        "fraction_pixels_at_or_above_0_02",
        "nearest_rank_p95",
        "pixels",
    }
)


def canonical_json_bytes(value: Any) -> bytes:
    def reject(item: Any) -> None:
        if isinstance(item, float):
            raise TypeError("contract floats must be represented as decimal strings")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("contract keys must be strings")
                reject(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject(child)

    reject(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON token: {token}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


@lru_cache(maxsize=1)
def _schema_registry() -> tuple[Registry[Any], dict[str, dict[str, Any]]]:
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = strict_json(path)
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not isinstance(identifier, str):
            raise ValueError(f"schema lacks $id: {path}")
        schemas[path.name] = schema
        resources.append((identifier, Resource.from_contents(schema)))
        resources.append((path.name, Resource.from_contents(schema)))
    return Registry().with_resources(resources), schemas


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _telemetry_validator(name).validate(dict(value))
    except ValidationError as error:
        raise ValueError(f"{name} validation failed: {error.message}") from error


@cache
def _telemetry_validator(name: str) -> Draft202012Validator:
    registry, schemas = _schema_registry()
    try:
        schema = schemas[name]
    except KeyError as error:
        raise ValueError(f"unknown telemetry schema: {name}") from error
    return Draft202012Validator(schema, registry=registry)


@cache
def _fixture_validator(name: str) -> Draft202012Validator:
    schema = strict_json(FIXTURE_SCHEMA_ROOT / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _validate_fixture_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _fixture_validator(name).validate(dict(value))
    except ValidationError as error:
        raise ValueError(f"{name} schema validation failed: {error.message}") from error


def _load_fixture_pointer(
    root: Path,
    pointer: Mapping[str, Any],
    *,
    label: str,
    schema_name: str | None = None,
) -> tuple[dict[str, Any], str]:
    relative = pointer.get("manifest")
    if not isinstance(relative, str):
        raise ValueError(f"{label} pointer path is invalid")
    path = _checked_file(root, relative)
    digest = _require_digest(f"{label} pointer digest", pointer.get("sha256"))
    if sha256_file(path) != digest:
        raise ValueError(f"{label} pointer digest mismatch")
    document = strict_json(path)
    if schema_name is not None:
        _validate_fixture_schema(schema_name, document)
    return document, digest


def _checked_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "$" in relative:
        raise ValueError("manifest path is unsafe")
    logical = PurePosixPath(relative)
    if logical.is_absolute() or any(part in ("", ".", "..") for part in logical.parts):
        raise ValueError("manifest path is unsafe")
    candidate = root.joinpath(*logical.parts)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"manifest file is absent or a symlink: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"manifest path escapes scenario: {relative}") from error
    if resolved.stat().st_nlink != 1:
        raise ValueError(f"hard-linked manifest input is prohibited: {relative}")
    return resolved


def _require_identifier(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _require_digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _project_fixture_events(
    telemetry: Mapping[str, Any], telemetry_digest: str, job_ids: set[str]
) -> list[dict[str, Any]]:
    if set(telemetry) != {"schema", "events"} or telemetry.get("schema") != "fixture-telemetry/v1":
        raise ValueError("fixture telemetry contract changed")
    source_events = telemetry.get("events")
    if not isinstance(source_events, list) or len(source_events) != 1:
        raise ValueError("fixture telemetry must contain exactly one event")
    expected: list[dict[str, Any]] = []
    event_keys = {
        "event_id",
        "worker_id",
        "start_offset_seconds",
        "duration_seconds",
        "overlapping_job_ids",
        "measurements",
        "resource_edges",
        "lineage_edges",
        "output_mutation",
    }
    for source_event in source_events:
        if not isinstance(source_event, dict) or set(source_event) != event_keys:
            raise ValueError("fixture telemetry event contract changed")
        event_id = _require_identifier("fixture telemetry event_id", source_event["event_id"])
        _require_identifier("fixture telemetry worker_id", source_event["worker_id"])
        start = source_event["start_offset_seconds"]
        duration = source_event["duration_seconds"]
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(duration, int)
            or isinstance(duration, bool)
            or duration < 1
        ):
            raise ValueError("fixture telemetry timing is invalid")
        overlapping = source_event["overlapping_job_ids"]
        if (
            not isinstance(overlapping, list)
            or len(overlapping) != 2
            or any(not isinstance(job_id, str) or job_id not in job_ids for job_id in overlapping)
            or len(set(overlapping)) != 2
        ):
            raise ValueError("fixture telemetry overlap is invalid")
        measurements = source_event["measurements"]
        if (
            not isinstance(measurements, dict)
            or set(measurements) != {"worker.cpu.utilization", "render.queue_wait_ms"}
            or any(
                not isinstance(value, str) or not _DECIMAL.fullmatch(value)
                for value in measurements.values()
            )
        ):
            raise ValueError("fixture telemetry measurements changed")
        if (
            source_event["resource_edges"] != []
            or source_event["lineage_edges"] != []
            or source_event["output_mutation"] is not False
        ):
            raise ValueError("fixture telemetry event carries an operational association")
        expected.append(
            {
                "event_id": event_id,
                "overlapping_job_ids": sorted(overlapping),
                "resource_edges": [],
                "lineage_edges": [],
                "output_mutation": False,
                "evidence": [telemetry_digest],
            }
        )
    return expected


@dataclass(frozen=True, slots=True)
class Correlation:
    fixture_id: str
    run_id: str
    job_id: str
    worker_id: str
    artifact_id: str
    trace_id: str
    config_sha256: str
    resource_sha256: str
    transform_id: str

    def __post_init__(self) -> None:
        validate_schema("correlation-contract-v1.schema.json", self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DeclaredReferenceObservation:
    state: str
    measurements: Mapping[str, str | int] | None

    def __post_init__(self) -> None:
        validate_schema("declared-reference-observation-v1.schema.json", self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": OBSERVATION_VERSION,
            "policy": COMPARISON_VERSION,
            "state": self.state,
            "measurements": dict(self.measurements) if self.measurements is not None else None,
        }


@dataclass(frozen=True, slots=True)
class RuntimeJob:
    source_manifest_sha256: str
    source_run_id: str
    fixture_id: str
    job_id: str
    worker_id: str
    artifact_id: str
    trace_id: str
    config_sha256: str
    resource_sha256: str
    transform_id: str
    observation: DeclaredReferenceObservation

    def correlation(self, run_id: str | None = None) -> Correlation:
        return Correlation(
            fixture_id=self.fixture_id,
            run_id=_require_identifier("run_id", run_id or self.source_run_id),
            job_id=self.job_id,
            worker_id=self.worker_id,
            artifact_id=self.artifact_id,
            trace_id=self.trace_id,
            config_sha256=self.config_sha256,
            resource_sha256=self.resource_sha256,
            transform_id=self.transform_id,
        )


@dataclass(frozen=True, slots=True)
class RuntimeJobs:
    scenario_root: Path
    source_fixture_manifest_sha256: str
    source_validator_report_sha256: str
    source_run_id: str
    jobs: tuple[RuntimeJob, ...]
    job_manifest_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        if len(self.jobs) != 6 or len({job.job_id for job in self.jobs}) != 6:
            raise ValueError("runtime telemetry requires exactly six unique jobs")
        if set(self.job_manifest_sha256) != {job.job_id for job in self.jobs}:
            raise ValueError("job source digests are incomplete")


@dataclass(frozen=True, slots=True)
class CandidateBinding:
    fixture_id: str
    source_run_id: str
    correlation_contract: str
    source_fixture_manifest_sha256: str
    source_validator_report_sha256: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_candidate_binding(scenario_root: Path) -> CandidateBinding:
    runtime = load_runtime_jobs(scenario_root)
    return CandidateBinding(
        fixture_id=runtime.jobs[0].fixture_id,
        source_run_id=runtime.source_run_id,
        correlation_contract=CORRELATION_VERSION,
        source_fixture_manifest_sha256=runtime.source_fixture_manifest_sha256,
        source_validator_report_sha256=runtime.source_validator_report_sha256,
    )


def load_runtime_jobs(scenario_root: Path) -> RuntimeJobs:
    root = scenario_root.resolve(strict=True)
    fixture_path = _checked_file(root, "runtime/manifests/fixture-runtime-manifest.json")
    fixture = strict_json(fixture_path)
    _validate_fixture_schema("fixture-runtime-manifest-v1.schema.json", fixture)
    if fixture.get("schema") != RUNTIME_MANIFEST_VERSION or fixture.get("fixture_id") != FIXTURE_ID:
        raise ValueError("fixture runtime contract identity changed")
    if fixture.get("comparison_policy") != COMPARISON_VERSION:
        raise ValueError("fixture comparison policy changed")
    source_run_id = _require_identifier("source run_id", fixture.get("run_id"))
    receipt_path = _checked_file(root, "reports/validator-receipt.json")
    receipt = strict_json(receipt_path)
    _validate_fixture_schema("validator-receipt-v1.schema.json", receipt)
    if (
        set(receipt)
        != {
            "schema",
            "report",
            "report_sha256",
            "truth_material_inside_runtime_bundle",
        }
        or receipt.get("schema") != VALIDATOR_RECEIPT_VERSION
    ):
        raise ValueError("validator receipt contract changed")
    if receipt.get("truth_material_inside_runtime_bundle") is not False:
        raise ValueError(
            "telemetry input includes material outside the runtime observation boundary"
        )
    report_relative = receipt.get("report")
    if not isinstance(report_relative, str):
        raise ValueError("validator report path is invalid")
    report_path = _checked_file(root, report_relative)
    if report_path.relative_to(root).as_posix() != "reports/validator-report.json":
        raise ValueError("validator receipt points to an unexpected report")
    report_digest = _require_digest("validator report digest", receipt.get("report_sha256"))
    if sha256_file(report_path) != report_digest:
        raise ValueError("validator report digest mismatch")
    report = strict_json(report_path)
    _validate_fixture_schema("fixture-validator-report-v1.schema.json", report)
    if set(report) != _REPORT_KEYS or (
        report.get("schema") != VALIDATOR_REPORT_VERSION
        or report.get("fixture_id") != FIXTURE_ID
        or report.get("variant_id") != fixture.get("variant_id")
        or report.get("comparison_policy") != COMPARISON_VERSION
    ):
        raise ValueError("validator report contract or identity changed")
    report_rows = report.get("jobs")
    if not isinstance(report_rows, list) or len(report_rows) != 6:
        raise ValueError("validator report must contain exactly six jobs")
    report_by_job: dict[str, dict[str, Any]] = {}
    for row in report_rows:
        if not isinstance(row, dict) or set(row) != _REPORT_JOB_KEYS:
            raise ValueError("validator report job contract changed")
        row_job_id = _require_identifier("reported job_id", row.get("job_id"))
        if row_job_id in report_by_job:
            raise ValueError("validator report repeats a job")
        report_by_job[row_job_id] = row
    if list(report_by_job) != sorted(report_by_job):
        raise ValueError("validator report jobs are not in canonical order")
    jobs: list[RuntimeJob] = []
    source_digests: dict[str, str] = {}
    for pointer in fixture["jobs"]:
        expected_digest = _require_digest("job manifest digest", pointer.get("sha256"))
        job_path = _checked_file(root, pointer["manifest"])
        if sha256_file(job_path) != expected_digest:
            raise ValueError("job manifest digest mismatch")
        job = strict_json(job_path)
        _validate_fixture_schema("fixture-job-v1.schema.json", job)
        if (
            job.get("job_id") != pointer.get("job_id")
            or job.get("run_id") != source_run_id
            or job.get("fixture_id") != FIXTURE_ID
        ):
            raise ValueError("job identity differs from fixture runtime manifest")
        resource_path = _checked_file(root, job["resource_manifest"])
        if sha256_file(resource_path) != job["resource_manifest_sha256"]:
            raise ValueError("resolved resource manifest digest mismatch")
        resource = strict_json(resource_path)
        _validate_fixture_schema("resolved-resource-manifest-v1.schema.json", resource)
        if (
            resource.get("job_id") != job["job_id"]
            or resource.get("run_id") != source_run_id
            or resource.get("worker_id") != job["worker_id"]
            or resource.get("nominal_config_sha256") != job["nominal_config_sha256"]
            or resource.get("transform_id") != job["transform_id"]
        ):
            raise ValueError("resolved resource identity differs from job manifest")
        ordered = resource["ordered_resources"]
        resource_sha256 = ordered[0]["sha256"] if ordered else "none"
        output_path = _checked_file(root, job["output_buffer"])
        if sha256_file(output_path) != job["output_buffer_sha256"]:
            raise ValueError("job output digest mismatch")
        trace = job["trace_id"]
        if not isinstance(trace, str) or not _TRACE_ID.fullmatch(trace) or trace == "0" * 32:
            raise ValueError("job trace identity is invalid")
        try:
            report_row = report_by_job[job["job_id"]]
        except KeyError as error:
            raise ValueError("validator report omits a runtime job") from error
        if (
            report_row.get("worker_id") != job["worker_id"]
            or report_row.get("output_id") != job["output_id"]
            or report_row.get("transform_id") != job["transform_id"]
            or report_row.get("nominal_config_sha256") != job["nominal_config_sha256"]
            or report_row.get("resource_manifest_sha256") != job["resource_manifest_sha256"]
            or report_row.get("resolved_resource_sha256")
            != (resource_sha256 if resource_sha256 != "none" else None)
            or report_row.get("evidence") != [expected_digest, job["output_buffer_sha256"]]
            or not isinstance(report_row.get("reasons"), list)
            or any(not isinstance(reason, str) for reason in report_row["reasons"])
        ):
            raise ValueError("validator observation differs from runtime job receipts")
        comparison = report_row.get("comparison")
        state = report_row.get("state")
        reasons = report_row["reasons"]
        if not isinstance(comparison, dict) or comparison.get("state") != state:
            raise ValueError("validator comparison state is inconsistent")
        if state == "unresolved":
            allowed_unresolved = {"state", "reason"} | (
                {"detail"} if "detail" in comparison else set()
            )
            if (
                set(comparison) != allowed_unresolved
                or not isinstance(comparison.get("reason"), str)
                or not reasons
                or comparison["reason"] != reasons[-1]
            ):
                raise ValueError("unresolved comparison contract changed")
            measurements: Mapping[str, str | int] | None = None
        else:
            if (
                state not in {"reference_match", "reference_mismatch"}
                or reasons != []
                or set(comparison) != _MEASUREMENT_KEYS | {"state", "policy"}
                or comparison.get("policy") != COMPARISON_VERSION
            ):
                raise ValueError("validator comparison measurements changed")
            measurements = MappingProxyType(
                {key: comparison[key] for key in sorted(_MEASUREMENT_KEYS)}
            )
        observation = DeclaredReferenceObservation(str(state), measurements)
        runtime_job = RuntimeJob(
            source_manifest_sha256=expected_digest,
            source_run_id=source_run_id,
            fixture_id=FIXTURE_ID,
            job_id=_require_identifier("job_id", job["job_id"]),
            worker_id=_require_identifier("worker_id", job["worker_id"]),
            artifact_id=_require_identifier("artifact_id", job["output_id"]),
            trace_id=trace,
            config_sha256=_require_digest("config_sha256", job["nominal_config_sha256"]),
            resource_sha256=(
                _require_digest("resource_sha256", resource_sha256)
                if resource_sha256 != "none"
                else resource_sha256
            ),
            transform_id=job["transform_id"],
            observation=observation,
        )
        runtime_job.correlation()
        jobs.append(runtime_job)
        source_digests[runtime_job.job_id] = expected_digest
    jobs.sort(key=lambda item: item.job_id)
    job_ids = {job.job_id for job in jobs}
    output_states = {row["output_id"]: row["state"] for row in report_by_job.values()}
    lineage, lineage_digest = _load_fixture_pointer(
        root,
        fixture["lineage"],
        label="artifact lineage",
        schema_name="artifact-lineage-v1.schema.json",
    )
    expected_derivatives = sorted(
        (
            {
                "artifact_id": edge["child_artifact_id"],
                "parent_artifact_id": edge["parent_artifact_id"],
                "state": output_states.get(edge["parent_artifact_id"], "unresolved"),
                "policy": "exact-lineage-propagation/v1",
                "evidence": [lineage_digest],
            }
            for edge in lineage["edges"]
            if edge["edge_type"] == "lossless-derivative/v1"
        ),
        key=lambda item: item["artifact_id"],
    )
    if report["derivatives"] != expected_derivatives:
        raise ValueError("validator derivative projection differs from runtime lineage")

    telemetry, telemetry_digest = _load_fixture_pointer(
        root,
        fixture["telemetry"],
        label="fixture telemetry",
        schema_name="fixture-telemetry-v1.schema.json",
    )
    expected_events = _project_fixture_events(telemetry, telemetry_digest, job_ids)
    if report["telemetry_events"] != expected_events:
        raise ValueError("validator telemetry projection differs from runtime fixture")

    expected_diff_job_ids = sorted(
        row["job_id"]
        for row in report_by_job.values()
        if row["state"] in {"reference_match", "reference_mismatch"}
    )
    diff_images = report["diff_images"]
    if [diff_image["job_id"] for diff_image in diff_images] != expected_diff_job_ids:
        raise ValueError("validator diff image set or order differs from resolved jobs")
    for diff_image in diff_images:
        diff_job_id = diff_image["job_id"]
        expected_relative = f"reports/diffs/{diff_job_id}.png"
        if diff_image["path"] != expected_relative:
            raise ValueError("validator diff image path differs from its job")
        diff_path = _checked_file(root, expected_relative)
        if sha256_file(diff_path) != diff_image["sha256"]:
            raise ValueError("validator diff image digest mismatch")
    return RuntimeJobs(
        scenario_root=root,
        source_fixture_manifest_sha256=sha256_file(fixture_path),
        source_validator_report_sha256=report_digest,
        source_run_id=source_run_id,
        jobs=tuple(jobs),
        job_manifest_sha256=MappingProxyType(dict(sorted(source_digests.items()))),
    )


def event_id(run_id: str, job_id: str, signal: str) -> str:
    if signal not in SIGNALS:
        raise ValueError("unknown telemetry signal")
    payload = canonical_json_bytes(
        {
            "contract": TELEMETRY_EVENT_VERSION,
            "job_id": _require_identifier("job_id", job_id),
            "run_id": _require_identifier("run_id", run_id),
            "signal": signal,
        }
    )
    return "evt-" + sha256_bytes(payload)[:24]


@dataclass(frozen=True, slots=True)
class DeliveryInstruction:
    event_id: str
    job_id: str
    signal: str
    copies: int
    delay_ms: int
    outcome: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DeliveryPlan:
    case_index: int
    run_id: str
    instructions: tuple[DeliveryInstruction, ...]

    @classmethod
    def build(cls, runtime: RuntimeJobs, *, case_index: int, run_id: str) -> DeliveryPlan:
        if not 0 <= case_index < 50:
            raise ValueError("telemetry case index must be in [0, 49]")
        run_id = _require_identifier("run_id", run_id)
        target_job = runtime.jobs[case_index % len(runtime.jobs)].job_id
        target_signal = SIGNALS[(case_index // 5) % len(SIGNALS)]
        mode = case_index % 5
        rows: list[DeliveryInstruction] = []
        for job in runtime.jobs:
            for signal in SIGNALS:
                copies = 1
                delay_ms = 0
                outcome = "on_time"
                if job.job_id == target_job and signal == target_signal:
                    if mode in (1, 4):
                        delay_ms = 61_000 + ((case_index * 7) % 30) * 1_000
                        outcome = "late"
                    elif mode == 2:
                        copies = 2
                        outcome = "duplicate"
                    elif mode == 3:
                        copies = 0
                        outcome = "missing"
                rows.append(
                    DeliveryInstruction(
                        event_id=event_id(run_id, job.job_id, signal),
                        job_id=job.job_id,
                        signal=signal,
                        copies=copies,
                        delay_ms=delay_ms,
                        outcome=outcome,
                    )
                )
        if len(rows) != 18:
            raise AssertionError("six jobs must produce exactly eighteen signal plans")
        return cls(case_index, run_id, tuple(rows))
