"""Pure, deterministic color-state comparison, scope, and claim validation."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import PyOpenColorIO as ocio  # type: ignore[import-untyped]
from colortrace_fixture.fixture import (
    COMPARISON_VERSION,
    OCIO_VERSION,
    SCHEMA_FILES,
    audit_bundle_paths,
    canonical_json_bytes,
    checked_relative_path,
    compare_buffers,
    read_float_buffer,
    read_json,
    sha256_bytes,
    sha256_file,
    stable_processor_identity,
)
from colortrace_fixture.fixture import (
    SCHEMA_ROOT as FIXTURE_SCHEMA_ROOT,
)
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

VALIDATOR_NAME = "colortrace-validator"
VALIDATOR_VERSION = "1.0.0"
REQUEST_VERSION = "color-state-validation-request/v1"
RESULT_VERSION = "color-state-validation-result/v1"
SCOPE_VERSION = "color-state-scope/v1"
SCOPE_POLICY = "single-causal-resource-scope/v1"
LINEAGE_POLICY = "exact-typed-lineage/v1"
CLAIM_POLICY = "deterministic-claim/v1"
MAX_RESULT_BYTES = 262_144
DEFAULT_RUNTIME_MANIFEST = "runtime/manifests/fixture-runtime-manifest.json"
SCHEMA_ROOT = Path(__file__).parent / "schemas"

REASON_CODES = frozenset(
    {
        "candidate-resource-used-by-safe-job",
        "causal-resource-confirmed",
        "causal-resource-matches-approved-declaration",
        "comparison-match-safe",
        "comparison-threshold-indeterminate",
        "contradictory-authoritative-evidence",
        "declared-reference-contract-invalid",
        "declared-reference-digest-mismatch",
        "declared-reference-mismatch",
        "declared-resources-contract-invalid",
        "declared-resources-digest-mismatch",
        "derivative-buffer-digest-mismatch",
        "derivative-inherits-parent-scope",
        "distractor-authoritatively-rejected",
        "exact-lineage-invalid",
        "fixture-contract-invalid",
        "incomplete-decisive-evidence",
        "job-manifest-digest-mismatch",
        "job-manifest-missing",
        "job-runtime-correlation-mismatch",
        "malformed-float-buffer",
        "manifest-json-invalid",
        "missing-approved-resource-control",
        "missing-declared-reference",
        "missing-declared-resources",
        "missing-lineage-manifest",
        "missing-output-buffer",
        "missing-reference-buffer",
        "missing-resolved-resource-manifest",
        "multiple-causal-resource-candidates",
        "no-causal-resource-candidate",
        "no-mismatch-observations",
        "nominal-config-authoritatively-rejected",
        "nominal-config-digest-mismatch",
        "ocio-config-invalid",
        "ocio-processor-identity-mismatch",
        "ocio-resource-resolution-mismatch",
        "ocio-structure-invalid",
        "output-buffer-digest-mismatch",
        "reference-buffer-digest-mismatch",
        "reference-threshold-match",
        "reference-threshold-mismatch",
        "resolved-resource-contract-invalid",
        "resolved-resource-digest-mismatch",
        "resolved-resource-manifest-digest-mismatch",
        "result-size-limit-exceeded",
        "runtime-manifest-digest-mismatch",
        "runtime-manifest-missing",
        "safe-control-missing-on-implicated-worker",
        "telemetry-contract-invalid",
        "telemetry-digest-mismatch",
        "unsafe-path",
        "unsupported-policy",
        "worker-alone-authoritatively-rejected",
    }
)

THRESHOLDS = {
    "match_maximum_absolute_channel_error_lte": "0.000001",
    "match_rmse_lte": "0.0000005",
    "mismatch_maximum_absolute_channel_error_gt": "0.0001",
    "mismatch_fraction_pixels_at_or_above_0_02_gte": "0.10",
    "mismatch_nearest_rank_p95_gte": "0.04",
}


class ValidationFailure(Exception):
    """A bounded fail-closed validation outcome."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in REASON_CODES:
            raise ValueError(reason_code)
        super().__init__(reason_code)
        self.reason_code = reason_code


def _load_schema(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], read_json(path))


REQUEST_SCHEMA = _load_schema(SCHEMA_ROOT / "color-state-validation-request-v1.schema.json")
SCOPE_SCHEMA = _load_schema(SCHEMA_ROOT / "color-state-scope-v1.schema.json")
RESULT_SCHEMA = _load_schema(SCHEMA_ROOT / "color-state-validation-result-v1.schema.json")
REASON_SCHEMA = _load_schema(SCHEMA_ROOT / "validation-reason-code-v1.schema.json")
Draft202012Validator.check_schema(REQUEST_SCHEMA)
Draft202012Validator.check_schema(SCOPE_SCHEMA)
Draft202012Validator.check_schema(RESULT_SCHEMA)
Draft202012Validator.check_schema(REASON_SCHEMA)
REQUEST_VALIDATOR = Draft202012Validator(REQUEST_SCHEMA)
CONTRACT_REGISTRY = Registry().with_resources(
    [
        (cast(str, SCOPE_SCHEMA["$id"]), Resource.from_contents(SCOPE_SCHEMA)),
        (cast(str, REASON_SCHEMA["$id"]), Resource.from_contents(REASON_SCHEMA)),
    ]
)
SCOPE_VALIDATOR = Draft202012Validator(SCOPE_SCHEMA, registry=CONTRACT_REGISTRY)
RESULT_VALIDATOR = Draft202012Validator(RESULT_SCHEMA, registry=CONTRACT_REGISTRY)
FIXTURE_VALIDATORS = {
    schema_name: Draft202012Validator(_load_schema(FIXTURE_SCHEMA_ROOT / filename))
    for schema_name, filename in SCHEMA_FILES.items()
}


def _reason(target: list[str], code: str) -> None:
    if code not in REASON_CODES:
        raise ValueError(code)
    if code not in target:
        target.append(code)


def _unique(items: list[str]) -> list[str]:
    return sorted(set(items))


def _relative(path: Path, root: Path) -> str:
    return path.resolve(strict=True).relative_to(root.resolve(strict=True)).as_posix()


@dataclass
class EvidenceIndex:
    root: Path
    records: dict[str, dict[str, str]] = field(default_factory=dict)

    def add(self, path: Path, kind: str) -> tuple[str, str]:
        digest = sha256_file(path)
        relative = _relative(path, self.root)
        identity = {"kind": kind, "path": relative, "sha256": digest}
        evidence_id = f"evidence:{sha256_bytes(canonical_json_bytes(identity))}"
        self.records[evidence_id] = {"evidence_id": evidence_id, **identity}
        return evidence_id, digest

    def ordered(self) -> list[dict[str, str]]:
        return [self.records[key] for key in sorted(self.records)]


@dataclass
class JobAnalysis:
    job_id: str
    document: dict[str, Any] | None
    comparison: dict[str, Any]
    evidence_ids: list[str]
    resource_digest: str | None
    resource_verified: bool
    output_digest: str | None


def _fixture_contract(document: dict[str, Any], expected_schema: str) -> bool:
    validator = FIXTURE_VALIDATORS.get(expected_schema)
    if validator is None or document.get("schema") != expected_schema:
        return False
    return not list(validator.iter_errors(document))


def _own_contract(document: dict[str, Any], schema: str) -> None:
    if schema == REQUEST_VERSION:
        REQUEST_VALIDATOR.validate(document)
    elif schema == SCOPE_VERSION:
        SCOPE_VALIDATOR.validate(document)
    elif schema == RESULT_VERSION:
        RESULT_VALIDATOR.validate(document)
    else:
        raise ValueError(schema)


def build_request(
    bundle_root: Path,
    *,
    request_id: str,
    incident_id: str,
    runtime_manifest: str = DEFAULT_RUNTIME_MANIFEST,
) -> dict[str, Any]:
    root = bundle_root.resolve(strict=True)
    manifest_path = checked_relative_path(root, runtime_manifest)
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    request = {
        "schema": REQUEST_VERSION,
        "request_id": request_id,
        "incident_id": incident_id,
        "runtime_manifest": {"path": runtime_manifest, "sha256": sha256_file(manifest_path)},
        "policies": {
            "comparison": COMPARISON_VERSION,
            "scope": SCOPE_POLICY,
            "lineage": LINEAGE_POLICY,
            "claim": CLAIM_POLICY,
        },
        "limits": {"max_result_bytes": MAX_RESULT_BYTES},
    }
    _own_contract(request, REQUEST_VERSION)
    return request


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = read_json(path)
    except (OSError, UnicodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _comparison_record(
    *,
    job_id: str,
    job: dict[str, Any] | None,
    state: str,
    metrics: dict[str, Any] | None,
    config_digest: str | None,
    resource_digest: str | None,
    reasons: list[str],
    evidence_ids: list[str],
) -> dict[str, Any]:
    identity = {
        "job_id": job_id,
        "policy": COMPARISON_VERSION,
        "evidence_ids": _unique(evidence_ids),
    }
    return {
        "comparison_id": f"comparison:{sha256_bytes(canonical_json_bytes(identity))}",
        "job_id": job_id,
        "frame_id": job.get("frame_id") if job else None,
        "output_id": job.get("output_id") if job else None,
        "worker_id": job.get("worker_id") if job else None,
        "transform_id": job.get("transform_id") if job else None,
        "state": state,
        "policy": COMPARISON_VERSION,
        "metrics": metrics,
        "nominal_config_sha256": config_digest,
        "resolved_resource_sha256": resource_digest,
        "reason_codes": _unique(reasons),
        "evidence_ids": _unique(evidence_ids),
    }


def classify_reference_metrics(
    *,
    maximum_absolute_channel_error: float,
    rmse: float,
    fraction_pixels_at_or_above_0_02: float,
    nearest_rank_p95: float,
) -> str:
    """Apply only the accepted declared-reference threshold boundaries."""

    if maximum_absolute_channel_error <= 0.000001 and rmse <= 0.0000005:
        return "reference_match"
    if (
        maximum_absolute_channel_error > 0.0001
        and fraction_pixels_at_or_above_0_02 >= 0.10
        and nearest_rank_p95 >= 0.04
    ):
        return "reference_mismatch"
    return "unresolved"


def _pointer_document(
    root: Path,
    pointer: dict[str, Any],
    expected_schema: str,
    evidence: EvidenceIndex,
    kind: str,
    missing_reason: str,
    digest_reason: str,
    contract_reason: str,
) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    try:
        path = checked_relative_path(root, cast(str, pointer["manifest"]))
    except (KeyError, TypeError, ValueError):
        return None, "unsafe-path", []
    if not path.is_file():
        return None, missing_reason, []
    evidence_id, actual_digest = evidence.add(path, kind)
    if actual_digest != pointer.get("sha256"):
        return None, digest_reason, [evidence_id]
    document = _load_json(path)
    if document is None:
        return None, "manifest-json-invalid", [evidence_id]
    if not _fixture_contract(document, expected_schema):
        return None, contract_reason, [evidence_id]
    return document, None, [evidence_id]


def _verify_ocio(
    root: Path,
    runtime: Path,
    fixture: dict[str, Any],
    job: dict[str, Any],
    resource: dict[str, Any],
    evidence: EvidenceIndex,
    reasons: list[str],
    evidence_ids: list[str],
) -> tuple[str | None, bool]:
    worker_id = cast(str, job["worker_id"])
    worker_root = runtime / "workers" / worker_id
    worker_entries = [item for item in fixture["worker_configs"] if item["worker_id"] == worker_id]
    if len(worker_entries) != 1:
        _reason(reasons, "job-runtime-correlation-mismatch")
        return None, False
    worker_entry = worker_entries[0]
    try:
        config_path = checked_relative_path(
            root, cast(str, resource["config_root_relative_path"]), base=runtime
        )
        indexed_config_path = checked_relative_path(root, cast(str, worker_entry["config"]))
    except ValueError:
        _reason(reasons, "unsafe-path")
        return None, False
    if (
        not config_path.is_file()
        or not config_path.is_relative_to(worker_root)
        or config_path.resolve() != indexed_config_path.resolve()
    ):
        _reason(reasons, "ocio-structure-invalid")
        return None, False
    config_evidence, config_digest = evidence.add(config_path, "ocio-config")
    evidence_ids.append(config_evidence)
    if (
        config_digest != resource["nominal_config_sha256"]
        or config_digest != worker_entry["config_sha256"]
    ):
        _reason(reasons, "nominal-config-digest-mismatch")

    ordered = resource["ordered_resources"]
    resource_digest: str | None = None
    resolved_path: Path | None = None
    if job["transform_id"] == "look/main/v1":
        if len(ordered) != 1:
            _reason(reasons, "ocio-structure-invalid")
        else:
            resolved = ordered[0]
            try:
                resolved_path = checked_relative_path(
                    root, cast(str, resolved["resolved_root_relative_path"]), base=runtime
                )
            except ValueError:
                _reason(reasons, "unsafe-path")
            if resolved_path is not None:
                if not resolved_path.is_file() or not resolved_path.is_relative_to(worker_root):
                    _reason(reasons, "ocio-resource-resolution-mismatch")
                else:
                    resource_evidence, resource_digest = evidence.add(
                        resolved_path, "resolved-ocio-resource"
                    )
                    evidence_ids.append(resource_evidence)
                    if (
                        resource_digest != resolved["sha256"]
                        or resolved_path.stat().st_size != resolved["size"]
                    ):
                        _reason(reasons, "resolved-resource-digest-mismatch")
    elif ordered:
        _reason(reasons, "ocio-structure-invalid")

    try:
        ocio.ClearAllCaches()
        config = ocio.Config.CreateFromFile(str(config_path))
        config.validate()
        if ocio.__version__ != OCIO_VERSION or job["ocio_version"] != OCIO_VERSION:
            _reason(reasons, "ocio-config-invalid")
        if job["transform_id"] == "look/main/v1":
            color_space = config.getColorSpace("fixture_output")
            transform = (
                color_space.getTransform(ocio.COLORSPACE_DIR_FROM_REFERENCE)
                if color_space is not None
                else None
            )
            if transform is None or not hasattr(transform, "getSrc"):
                _reason(reasons, "ocio-structure-invalid")
            else:
                source = cast(str, transform.getSrc())
                actual_resolved = Path(
                    config.getCurrentContext().resolveFileLocation(source)
                ).resolve(strict=True)
                if resolved_path is None or actual_resolved != resolved_path.resolve(strict=True):
                    _reason(reasons, "ocio-resource-resolution-mismatch")
            config.getProcessor("fixture_input", "fixture_output")
        else:
            config.getProcessor("fixture_input", "fixture_input")
    except (OSError, RuntimeError, TypeError, ValueError):
        _reason(reasons, "ocio-config-invalid")

    expected_processor = stable_processor_identity(
        config_digest,
        cast(str, job["transform_id"]),
        resource_digest if job["transform_id"] == "look/main/v1" else None,
    )
    if expected_processor != job["processor_identity_sha256"]:
        _reason(reasons, "ocio-processor-identity-mismatch")
    return resource_digest, not reasons


def _analyze_job(
    root: Path,
    fixture: dict[str, Any],
    declared: dict[str, Any],
    pointer: dict[str, Any],
    runtime_evidence_id: str,
    evidence: EvidenceIndex,
) -> JobAnalysis:
    job_id = cast(str, pointer["job_id"])
    reasons: list[str] = []
    evidence_ids = [runtime_evidence_id]
    job, error, job_evidence = _pointer_document(
        root,
        pointer,
        "fixture-job/v1",
        evidence,
        "fixture-job-manifest",
        "job-manifest-missing",
        "job-manifest-digest-mismatch",
        "fixture-contract-invalid",
    )
    evidence_ids.extend(job_evidence)
    if error or job is None:
        _reason(reasons, error or "fixture-contract-invalid")
        comparison = _comparison_record(
            job_id=job_id,
            job=None,
            state="unresolved",
            metrics=None,
            config_digest=None,
            resource_digest=None,
            reasons=reasons,
            evidence_ids=evidence_ids,
        )
        return JobAnalysis(job_id, None, comparison, _unique(evidence_ids), None, False, None)

    runtime = root / "runtime"
    correlation_fields = (
        "fixture_id",
        "fixture_version",
        "variant_id",
        "seed_sha256",
        "run_id",
        "ocio_version",
    )
    if pointer["job_id"] != job["job_id"] or any(
        job[field] != fixture[field] for field in correlation_fields
    ):
        _reason(reasons, "job-runtime-correlation-mismatch")

    resource: dict[str, Any] | None = None
    try:
        resource_path = checked_relative_path(root, cast(str, job["resource_manifest"]))
    except ValueError:
        resource_path = root / ".invalid"
        _reason(reasons, "unsafe-path")
    if not resource_path.is_file():
        _reason(reasons, "missing-resolved-resource-manifest")
    else:
        resource_evidence, resource_manifest_digest = evidence.add(
            resource_path, "resolved-resource-manifest"
        )
        evidence_ids.append(resource_evidence)
        if resource_manifest_digest != job["resource_manifest_sha256"]:
            _reason(reasons, "resolved-resource-manifest-digest-mismatch")
        else:
            resource = _load_json(resource_path)
            if resource is None or not _fixture_contract(resource, "resolved-resource-manifest/v1"):
                resource = None
                _reason(reasons, "resolved-resource-contract-invalid")
    resource_digest: str | None = None
    resource_verified = False
    if resource is not None:
        if (
            any(
                resource[field] != job[field]
                for field in ("job_id", "run_id", "worker_id", "transform_id")
            )
            or resource["nominal_config_sha256"] != job["nominal_config_sha256"]
        ):
            _reason(reasons, "job-runtime-correlation-mismatch")
        resource_digest, resource_verified = _verify_ocio(
            root, runtime, fixture, job, resource, evidence, reasons, evidence_ids
        )

    output_digest: str | None = None
    try:
        output_path = checked_relative_path(root, cast(str, job["output_buffer"]))
    except ValueError:
        output_path = root / ".invalid"
        _reason(reasons, "unsafe-path")
    if not output_path.is_file():
        _reason(reasons, "missing-output-buffer")
    else:
        output_evidence, output_digest = evidence.add(output_path, "authoritative-output-buffer")
        evidence_ids.append(output_evidence)
        if output_digest != job["output_buffer_sha256"]:
            _reason(reasons, "output-buffer-digest-mismatch")

    reference: dict[str, Any] | None = None
    reference_path: Path | None = None
    try:
        reference_manifest_path = checked_relative_path(
            root, cast(str, job["declared_reference_manifest"])
        )
    except ValueError:
        reference_manifest_path = root / ".invalid"
        _reason(reasons, "unsafe-path")
    if not reference_manifest_path.is_file():
        _reason(reasons, "missing-declared-reference")
    else:
        reference_evidence, reference_digest = evidence.add(
            reference_manifest_path, "declared-reference-manifest"
        )
        evidence_ids.append(reference_evidence)
        if reference_digest != job["declared_reference_manifest_sha256"]:
            _reason(reasons, "declared-reference-digest-mismatch")
        else:
            reference = _load_json(reference_manifest_path)
            if reference is None or not _fixture_contract(reference, "declared-reference/v1"):
                reference = None
                _reason(reasons, "declared-reference-contract-invalid")
    if reference is not None:
        if any(
            reference[left] != job[right]
            for left, right in (
                ("reference_id", "declared_reference_id"),
                ("source_id", "source_id"),
                ("transform_id", "transform_id"),
                ("ocio_version", "ocio_version"),
            )
        ):
            _reason(reasons, "declared-reference-mismatch")
        expected_reference_resource = (
            declared["approved_lut_sha256"] if job["transform_id"] == "look/main/v1" else None
        )
        if reference["resolved_resource_sha256"] != expected_reference_resource:
            _reason(reasons, "declared-reference-mismatch")
        expected_reference_processor = stable_processor_identity(
            cast(str, declared["nominal_config_sha256"]),
            cast(str, job["transform_id"]),
            expected_reference_resource,
        )
        if reference["processor_identity_sha256"] != expected_reference_processor:
            _reason(reasons, "declared-reference-mismatch")
        try:
            reference_path = checked_relative_path(root, cast(str, reference["buffer"]))
        except ValueError:
            _reason(reasons, "unsafe-path")
        if reference_path is None or not reference_path.is_file():
            _reason(reasons, "missing-reference-buffer")
        else:
            reference_buffer_evidence, reference_buffer_digest = evidence.add(
                reference_path, "declared-reference-buffer"
            )
            evidence_ids.append(reference_buffer_evidence)
            if reference_buffer_digest != reference["buffer_sha256"]:
                _reason(reasons, "reference-buffer-digest-mismatch")

    metrics: dict[str, Any] | None = None
    state = "unresolved"
    if not reasons and output_path.is_file() and reference_path is not None:
        try:
            raw_comparison = compare_buffers(
                read_float_buffer(output_path), read_float_buffer(reference_path)
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            _reason(reasons, "malformed-float-buffer")
        else:
            state = cast(str, raw_comparison["state"])
            if all(
                key in raw_comparison
                for key in (
                    "maximum_absolute_channel_error",
                    "rmse",
                    "fraction_pixels_at_or_above_0_02",
                    "nearest_rank_p95",
                    "pixels",
                )
            ):
                metrics = {
                    key: raw_comparison[key]
                    for key in (
                        "maximum_absolute_channel_error",
                        "rmse",
                        "fraction_pixels_at_or_above_0_02",
                        "nearest_rank_p95",
                        "pixels",
                    )
                }
                classified_state = classify_reference_metrics(
                    maximum_absolute_channel_error=float(
                        raw_comparison["maximum_absolute_channel_error"]
                    ),
                    rmse=float(raw_comparison["rmse"]),
                    fraction_pixels_at_or_above_0_02=float(
                        raw_comparison["fraction_pixels_at_or_above_0_02"]
                    ),
                    nearest_rank_p95=float(raw_comparison["nearest_rank_p95"]),
                )
                if classified_state != state:
                    state = "unresolved"
                    _reason(reasons, "contradictory-authoritative-evidence")
            if state == "reference_match":
                _reason(reasons, "reference-threshold-match")
            elif state == "reference_mismatch":
                _reason(reasons, "reference-threshold-mismatch")
            else:
                _reason(reasons, "comparison-threshold-indeterminate")
    comparison = _comparison_record(
        job_id=job_id,
        job=job,
        state=state,
        metrics=metrics,
        config_digest=cast(str, job["nominal_config_sha256"]),
        resource_digest=resource_digest,
        reasons=reasons,
        evidence_ids=evidence_ids,
    )
    return JobAnalysis(
        job_id,
        job,
        comparison,
        _unique(evidence_ids),
        resource_digest,
        resource_verified,
        output_digest,
    )


def _claim(
    claim_type: str,
    kind: str,
    value: str | None,
    state: str,
    evidence_ids: list[str],
    reasons: list[str],
) -> dict[str, Any]:
    subject = {"kind": kind, "value": value}
    identity = {"claim_type": claim_type, "subject": subject}
    normalized_inputs_sha256 = sha256_bytes(canonical_json_bytes(subject))
    normalized_evidence = _unique(evidence_ids)
    normalized_reasons = _unique(reasons)
    derivation = sha256_bytes(
        canonical_json_bytes(
            {
                **identity,
                "state": state,
                "policy": CLAIM_POLICY,
                "normalized_inputs_sha256": normalized_inputs_sha256,
                "evidence_ids": normalized_evidence,
                "reason_codes": normalized_reasons,
            }
        )
    )
    return {
        "schema": "claim/v1",
        "claim_id": f"claim:{sha256_bytes(canonical_json_bytes(identity))}",
        "claim_type": claim_type,
        "subject": subject,
        "state": state,
        "policy": CLAIM_POLICY,
        "normalized_inputs_sha256": normalized_inputs_sha256,
        "deterministic_result_evidence_id": f"deterministic-result:{derivation}",
        "derivation_sha256": derivation,
        "contradiction_links": normalized_evidence
        if "contradictory-authoritative-evidence" in normalized_reasons
        else [],
        "evidence_ids": normalized_evidence,
        "reason_codes": normalized_reasons,
    }


def _causal_claim(
    analyses: list[JobAnalysis], declared: dict[str, Any], declared_evidence: list[str]
) -> tuple[dict[str, Any], str | None, list[str]]:
    mismatches = [item for item in analyses if item.comparison["state"] == "reference_mismatch"]
    matches = [item for item in analyses if item.comparison["state"] == "reference_match"]
    unresolved = [item for item in analyses if item.comparison["state"] == "unresolved"]
    evidence_ids = declared_evidence + [eid for item in analyses for eid in item.evidence_ids]
    blockers: list[str] = []
    candidate: str | None = None
    if not mismatches:
        _reason(blockers, "no-mismatch-observations")
    if unresolved:
        _reason(blockers, "incomplete-decisive-evidence")
    candidates = {
        item.resource_digest
        for item in mismatches
        if item.resource_verified and item.resource_digest is not None
    }
    if mismatches and len(candidates) == 0:
        _reason(blockers, "no-causal-resource-candidate")
    elif len(candidates) > 1:
        _reason(blockers, "multiple-causal-resource-candidates")
    elif len(candidates) == 1:
        candidate = next(iter(candidates))
        if any(
            item.resource_digest != candidate or not item.resource_verified for item in mismatches
        ):
            _reason(blockers, "contradictory-authoritative-evidence")
        if candidate == declared["approved_lut_sha256"]:
            _reason(blockers, "causal-resource-matches-approved-declaration")
        if any(item.resource_digest == candidate for item in matches):
            _reason(blockers, "candidate-resource-used-by-safe-job")
        affected_configs = {item.comparison["nominal_config_sha256"] for item in mismatches}
        approved_controls = [
            item
            for item in matches
            if item.resource_digest == declared["approved_lut_sha256"]
            and item.comparison["nominal_config_sha256"] in affected_configs
            and item.comparison["transform_id"] == "look/main/v1"
        ]
        if not approved_controls:
            _reason(blockers, "missing-approved-resource-control")
        implicated_workers = {item.comparison["worker_id"] for item in mismatches}
        for worker_id in implicated_workers:
            if not any(item.comparison["worker_id"] == worker_id for item in matches):
                _reason(blockers, "safe-control-missing-on-implicated-worker")
    state = "confirmed" if candidate is not None and not blockers else "unresolved"
    claim_reasons = list(blockers)
    if state == "confirmed":
        _reason(claim_reasons, "causal-resource-confirmed")
    return (
        _claim(
            "causal-resource",
            "resource-sha256",
            candidate if state == "confirmed" else None,
            state,
            evidence_ids,
            claim_reasons,
        ),
        candidate if state == "confirmed" else None,
        blockers,
    )


def _rejected_claims(
    analyses: list[JobAnalysis],
    telemetry: dict[str, Any] | None,
    telemetry_evidence: list[str],
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    mismatches = [item for item in analyses if item.comparison["state"] == "reference_mismatch"]
    for digest in sorted(
        {
            cast(str, item.comparison["nominal_config_sha256"])
            for item in mismatches
            if item.comparison["nominal_config_sha256"] is not None
        }
    ):
        related = [
            item
            for item in analyses
            if item.comparison["nominal_config_sha256"] == digest
            and item.comparison["state"] != "unresolved"
        ]
        rejected = {item.comparison["state"] for item in related} == {
            "reference_match",
            "reference_mismatch",
        }
        reasons = (
            ["nominal-config-authoritatively-rejected"]
            if rejected
            else ["incomplete-decisive-evidence"]
        )
        claims.append(
            _claim(
                "nominal-config",
                "config-sha256",
                digest,
                "rejected" if rejected else "unresolved",
                [eid for item in related for eid in item.evidence_ids],
                reasons,
            )
        )
    for worker_id in sorted(
        {
            cast(str, item.comparison["worker_id"])
            for item in mismatches
            if item.comparison["worker_id"] is not None
        }
    ):
        related = [item for item in analyses if item.comparison["worker_id"] == worker_id]
        rejected = any(item.comparison["state"] == "reference_match" for item in related)
        reasons = (
            ["worker-alone-authoritatively-rejected"]
            if rejected
            else ["safe-control-missing-on-implicated-worker"]
        )
        claims.append(
            _claim(
                "worker-alone",
                "worker-id",
                worker_id,
                "rejected" if rejected else "unresolved",
                [eid for item in related for eid in item.evidence_ids],
                reasons,
            )
        )
    if telemetry is not None:
        comparison_by_job = {item.job_id: item.comparison["state"] for item in analyses}
        analysis_by_job = {item.job_id: item for item in analyses}
        document_by_job = {
            item.job_id: item.document for item in analyses if item.document is not None
        }
        for event in sorted(telemetry["events"], key=lambda item: item["event_id"]):
            states = {
                comparison_by_job.get(job_id, "unresolved")
                for job_id in event["overlapping_job_ids"]
            }
            related_jobs = [document_by_job.get(job_id) for job_id in event["overlapping_job_ids"]]
            event_start = cast(int, event["start_offset_seconds"])
            event_end = event_start + cast(int, event["duration_seconds"])
            correlations_valid = all(
                job is not None
                and job["worker_id"] == event["worker_id"]
                and max(event_start, cast(int, job["start_offset_seconds"]))
                < min(
                    event_end,
                    cast(int, job["start_offset_seconds"]) + cast(int, job["duration_seconds"]),
                )
                for job in related_jobs
            )
            rejected = (
                correlations_valid
                and not event["resource_edges"]
                and not event["lineage_edges"]
                and event["output_mutation"] is False
                and states == {"reference_match", "reference_mismatch"}
            )
            reasons = (
                ["distractor-authoritatively-rejected"]
                if rejected
                else ["contradictory-authoritative-evidence"]
            )
            claims.append(
                _claim(
                    "distractor",
                    "event-id",
                    cast(str, event["event_id"]),
                    "rejected" if rejected else "unresolved",
                    telemetry_evidence
                    + [
                        evidence_id
                        for job_id in event["overlapping_job_ids"]
                        for evidence_id in (
                            analysis_by_job[job_id].evidence_ids
                            if job_id in analysis_by_job
                            else []
                        )
                    ],
                    reasons,
                )
            )
    return claims


def _load_telemetry(
    root: Path, fixture: dict[str, Any], evidence: EvidenceIndex
) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    reasons: list[str] = []
    pointer = fixture["telemetry"]
    try:
        path = checked_relative_path(root, cast(str, pointer["manifest"]))
    except ValueError:
        return None, ["unsafe-path"], []
    if not path.is_file():
        return None, ["telemetry-contract-invalid"], []
    evidence_id, digest = evidence.add(path, "fixture-telemetry-manifest")
    if digest != pointer["sha256"]:
        return None, ["telemetry-digest-mismatch"], [evidence_id]
    telemetry = _load_json(path)
    if telemetry is None or not _fixture_contract(telemetry, "fixture-telemetry/v1"):
        _reason(reasons, "telemetry-contract-invalid")
        return None, reasons, [evidence_id]
    return telemetry, reasons, [evidence_id]


def _lineage_scope(
    root: Path,
    fixture: dict[str, Any],
    analyses: list[JobAnalysis],
    frame_states: dict[str, str],
    evidence: EvidenceIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    pointer = fixture["lineage"]
    lineage, error, lineage_evidence = _pointer_document(
        root,
        pointer,
        "artifact-lineage/v1",
        evidence,
        "artifact-lineage-manifest",
        "missing-lineage-manifest",
        "exact-lineage-invalid",
        "exact-lineage-invalid",
    )
    if error or lineage is None:
        return [], [error or "exact-lineage-invalid"]
    analysis_by_job = {item.job_id: item for item in analyses}
    output_to_job = {
        cast(str, item.document["output_id"]): item
        for item in analyses
        if item.document is not None
    }
    render_edges = [edge for edge in lineage["edges"] if edge["edge_type"] == "source-to-render/v1"]
    render_artifacts = [
        artifact
        for artifact in lineage["artifacts"]
        if artifact["artifact_type"] == "authoritative-render-output"
    ]
    expected_render_artifacts = {
        (cast(str, item.document["output_id"]), item.job_id)
        for item in analyses
        if item.document is not None
    }
    actual_render_artifacts = {
        (cast(str, artifact["artifact_id"]), cast(str, artifact["job_id"]))
        for artifact in render_artifacts
    }
    expected_render_edges: set[tuple[str, str, str, str]] = set()
    for item in analyses:
        if item.document is not None:
            expected_render_edges.add(
                (
                    f"source-{item.document['source_id']}",
                    cast(str, item.document["output_id"]),
                    item.job_id,
                    cast(str, item.document["correlation_id"]),
                )
            )
    actual_render_edges = {
        (
            cast(str, edge["parent_artifact_id"]),
            cast(str, edge["child_artifact_id"]),
            cast(str, edge["job_id"]),
            cast(str, edge["correlation_id"]),
        )
        for edge in render_edges
    }
    exact_render_edges = (
        len(render_edges) == len(analysis_by_job)
        and len(actual_render_edges) == len(render_edges)
        and actual_render_edges == expected_render_edges
        and actual_render_artifacts == expected_render_artifacts
        and len(actual_render_artifacts) == len(render_artifacts)
    )
    derivatives: list[dict[str, Any]] = []
    lineage_reasons: list[str] = []
    if not exact_render_edges:
        _reason(lineage_reasons, "exact-lineage-invalid")
    derivative_artifacts = [
        artifact
        for artifact in lineage["artifacts"]
        if artifact["artifact_type"] == "lossless-derivative"
    ]
    derivative_edges = [
        edge for edge in lineage["edges"] if edge["edge_type"] == "lossless-derivative/v1"
    ]
    for artifact in sorted(derivative_artifacts, key=lambda item: item["artifact_id"]):
        edges = [
            edge
            for edge in derivative_edges
            if edge["child_artifact_id"] == artifact["artifact_id"]
        ]
        reasons: list[str] = []
        parent_id: str | None = edges[0]["parent_artifact_id"] if len(edges) == 1 else None
        parent = output_to_job.get(parent_id) if parent_id is not None else None
        if len(edges) != 1 or parent is None:
            _reason(reasons, "exact-lineage-invalid")
        try:
            derivative_path = checked_relative_path(root, cast(str, artifact["buffer"]))
        except ValueError:
            derivative_path = root / ".invalid"
            _reason(reasons, "unsafe-path")
        derivative_evidence_ids = list(lineage_evidence)
        if not derivative_path.is_file():
            _reason(reasons, "exact-lineage-invalid")
        else:
            derivative_evidence, derivative_digest = evidence.add(
                derivative_path, "lossless-derivative-buffer"
            )
            derivative_evidence_ids.append(derivative_evidence)
            if (
                derivative_digest != artifact["sha256"]
                or parent is None
                or derivative_digest != parent.output_digest
            ):
                _reason(reasons, "derivative-buffer-digest-mismatch")
        state = "unknown"
        if not reasons and parent_id is not None and parent is not None:
            state = frame_states[parent.job_id]
            derivative_evidence_ids.extend(parent.evidence_ids)
            _reason(reasons, "derivative-inherits-parent-scope")
        else:
            _reason(lineage_reasons, "exact-lineage-invalid")
        derivatives.append(
            {
                "artifact_id": artifact["artifact_id"],
                "parent_artifact_id": parent_id,
                "state": state,
                "lineage_policy": LINEAGE_POLICY,
                "reason_codes": _unique(reasons),
                "evidence_ids": _unique(derivative_evidence_ids),
            }
        )
    if len(derivatives) != len(derivative_edges):
        _reason(lineage_reasons, "exact-lineage-invalid")
    return derivatives, lineage_reasons


def _scope(
    root: Path,
    fixture: dict[str, Any],
    analyses: list[JobAnalysis],
    causal_digest: str | None,
    causal_reasons: list[str],
    evidence: EvidenceIndex,
) -> dict[str, Any]:
    frames: list[dict[str, Any]] = []
    frame_states: dict[str, str] = {}
    for item in analyses:
        comparison = item.comparison
        reasons: list[str] = []
        if comparison["state"] == "reference_match":
            state = "safe"
            _reason(reasons, "comparison-match-safe")
        elif (
            comparison["state"] == "reference_mismatch"
            and causal_digest is not None
            and item.resource_digest == causal_digest
        ):
            state = "affected"
            _reason(reasons, "causal-resource-confirmed")
        else:
            state = "unknown"
            for code in causal_reasons or ["incomplete-decisive-evidence"]:
                _reason(reasons, code)
        frame_states[item.job_id] = state
        frames.append(
            {
                "job_id": item.job_id,
                "frame_id": comparison["frame_id"],
                "output_id": comparison["output_id"],
                "worker_id": comparison["worker_id"],
                "state": state,
                "reason_codes": _unique(reasons),
                "evidence_ids": item.evidence_ids,
            }
        )
    derivatives, lineage_reasons = _lineage_scope(root, fixture, analyses, frame_states, evidence)
    reasons = list(causal_reasons) + lineage_reasons
    if any(item["state"] == "unknown" for item in frames + derivatives):
        _reason(reasons, "incomplete-decisive-evidence")
    scope = {
        "schema": SCOPE_VERSION,
        "state": "unresolved" if reasons else "resolved",
        "policy": SCOPE_POLICY,
        "causal_resource_sha256": causal_digest,
        "frames": sorted(frames, key=lambda item: item["job_id"]),
        "derivatives": sorted(derivatives, key=lambda item: item["artifact_id"]),
        "reason_codes": _unique(reasons),
    }
    _own_contract(scope, SCOPE_VERSION)
    return scope


def _base_result(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": RESULT_VERSION,
        "request_id": request["request_id"],
        "incident_id": request["incident_id"],
        "validator": {
            "name": VALIDATOR_NAME,
            "version": VALIDATOR_VERSION,
            "ocio_version": OCIO_VERSION,
        },
        "policies": {
            "comparison": COMPARISON_VERSION,
            "scope": SCOPE_POLICY,
            "lineage": LINEAGE_POLICY,
            "claim": CLAIM_POLICY,
        },
        "thresholds": THRESHOLDS,
        "request_sha256": sha256_bytes(canonical_json_bytes(request)),
        "runtime_manifest_sha256": request["runtime_manifest"]["sha256"],
    }


def _finalize(result: dict[str, Any]) -> dict[str, Any]:
    derivation = sha256_bytes(canonical_json_bytes(result))
    result["result_id"] = f"validation-result:{derivation}"
    result["derivation_sha256"] = derivation
    ordered = {key: result[key] for key in sorted(result)}
    _own_contract(ordered, RESULT_VERSION)
    encoded = canonical_json_bytes(ordered)
    if len(encoded) > MAX_RESULT_BYTES:
        raise ValidationFailure("result-size-limit-exceeded")
    return ordered


def _unresolved_result(request: dict[str, Any], reason_code: str) -> dict[str, Any]:
    base = _base_result(request)
    causal = _claim(
        "causal-resource",
        "resource-sha256",
        None,
        "unresolved",
        [],
        [reason_code],
    )
    base.update(
        {
            "status": "unresolved",
            "comparisons": [],
            "scope": {
                "schema": SCOPE_VERSION,
                "state": "unresolved",
                "policy": SCOPE_POLICY,
                "causal_resource_sha256": None,
                "frames": [],
                "derivatives": [],
                "reason_codes": [reason_code],
            },
            "claims": [causal],
            "evidence": [],
            "reason_codes": [reason_code],
        }
    )
    return _finalize(base)


def validate_color_state(bundle_root: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Validate one content-addressed fixture request without oracle or network inputs."""

    _own_contract(request, REQUEST_VERSION)
    if request["policies"] != {
        "comparison": COMPARISON_VERSION,
        "scope": SCOPE_POLICY,
        "lineage": LINEAGE_POLICY,
        "claim": CLAIM_POLICY,
    }:
        return _unresolved_result(request, "unsupported-policy")
    try:
        root = bundle_root.resolve(strict=True)
        runtime_path = checked_relative_path(root, request["runtime_manifest"]["path"])
        if not runtime_path.is_file():
            return _unresolved_result(request, "runtime-manifest-missing")
        if sha256_file(runtime_path) != request["runtime_manifest"]["sha256"]:
            return _unresolved_result(request, "runtime-manifest-digest-mismatch")
        audit_bundle_paths(root)
    except (OSError, RuntimeError, ValueError):
        return _unresolved_result(request, "unsafe-path")

    evidence = EvidenceIndex(root)
    runtime_evidence_id, runtime_digest = evidence.add(runtime_path, "fixture-runtime-manifest")
    fixture = _load_json(runtime_path)
    if fixture is None or not _fixture_contract(fixture, "fixture-runtime-manifest/v1"):
        return _unresolved_result(request, "fixture-contract-invalid")

    declared_pointer = fixture["declared_resources"]
    try:
        declared_path = checked_relative_path(root, cast(str, declared_pointer["manifest"]))
    except ValueError:
        return _unresolved_result(request, "unsafe-path")
    if not declared_path.is_file():
        return _unresolved_result(request, "missing-declared-resources")
    declared_evidence_id, declared_digest = evidence.add(
        declared_path, "declared-approved-resources"
    )
    if declared_digest != declared_pointer["sha256"]:
        return _unresolved_result(request, "declared-resources-digest-mismatch")
    declared = _load_json(declared_path)
    if declared is None or not _fixture_contract(declared, "declared-approved-resources/v1"):
        return _unresolved_result(request, "declared-resources-contract-invalid")

    analyses = [
        _analyze_job(
            root,
            fixture,
            declared,
            pointer,
            runtime_evidence_id,
            evidence,
        )
        for pointer in fixture["jobs"]
    ]
    causal_claim, causal_digest, causal_reasons = _causal_claim(
        analyses, declared, [runtime_evidence_id, declared_evidence_id]
    )
    telemetry, telemetry_reasons, telemetry_evidence = _load_telemetry(root, fixture, evidence)
    claims = [causal_claim, *_rejected_claims(analyses, telemetry, telemetry_evidence)]
    scope = _scope(root, fixture, analyses, causal_digest, causal_reasons, evidence)
    global_reasons = list(telemetry_reasons)
    if any(claim["state"] == "unresolved" for claim in claims):
        _reason(global_reasons, "incomplete-decisive-evidence")
    if scope["state"] == "unresolved":
        for code in scope["reason_codes"]:
            _reason(global_reasons, code)
    status = "unresolved" if global_reasons else "resolved"
    result = _base_result(request)
    result.update(
        {
            "status": status,
            "runtime_manifest_sha256": runtime_digest,
            "comparisons": sorted(
                [item.comparison for item in analyses], key=lambda item: item["job_id"]
            ),
            "scope": scope,
            "claims": sorted(claims, key=lambda item: item["claim_id"]),
            "evidence": evidence.ordered(),
            "reason_codes": _unique(global_reasons),
        }
    )
    return _finalize(result)


def validate_result_contract(result: dict[str, Any]) -> None:
    _own_contract(result, RESULT_VERSION)
    derivation_input = {
        key: value for key, value in result.items() if key not in {"result_id", "derivation_sha256"}
    }
    expected = sha256_bytes(canonical_json_bytes(derivation_input))
    if result["derivation_sha256"] != expected or result["result_id"] != (
        f"validation-result:{expected}"
    ):
        raise ValueError("result derivation digest mismatch")
    if len(canonical_json_bytes(result)) > MAX_RESULT_BYTES:
        raise ValueError("result exceeds size limit")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_json_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="colortrace-validator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    request = subparsers.add_parser("request")
    request.add_argument("--bundle", type=Path, required=True)
    request.add_argument("--request-id", required=True)
    request.add_argument("--incident-id", required=True)
    request.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--request", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "request":
            request = build_request(
                args.bundle,
                request_id=args.request_id,
                incident_id=args.incident_id,
            )
            _write_json(args.output, request)
        else:
            request_document = _load_json(args.request)
            if request_document is None:
                return 2
            result = validate_color_state(args.bundle, request_document)
            _write_json(args.output, result)
    except (OSError, RuntimeError, TypeError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
