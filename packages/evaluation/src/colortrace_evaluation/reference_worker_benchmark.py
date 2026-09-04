from __future__ import annotations

import hashlib
import inspect
import json
import os
import platform
import re
import stat
import sys
from argparse import ArgumentParser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol, cast

from colortrace_fixture import (
    ReferenceAssetError,
    ReferenceColorVariant,
    ReferenceFrame,
    ReferenceMediaError,
    ReferenceMediaManifest,
    ReferenceMediaVerification,
    ReferenceScenario,
    ReferenceVariantName,
    load_reference_media_manifest,
    materialize_reference_color_variants,
    reference_render_job,
    reference_scenarios,
    verify_reference_media,
)
from colortrace_simulator.reference_worker import ReferenceWorkerError

from .contracts import (
    ContractError,
    canonical_json_bytes,
    prefixed_sha256,
    sha256_file,
    strict_json_file,
    validate_schema,
)
from .reference_campaign import (
    BenchmarkArtifactObservation,
    BenchmarkEvidenceSource,
    RecordedSelectionReceiptSet,
    ReferenceCampaignError,
    _receipt_equivalent,
    _reference_impact_benchmark_body,
    _validate_receipt,
    build_reference_impact_benchmark,
    run_recorded_reference_campaign,
    run_reference_campaign,
    verify_reference_campaign_report,
)
from .reference_execution import ReferenceWorkerCallable

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXPECTED_SCENARIOS = frozenset(
    {
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    }
)
_EXPECTED_VARIANTS = frozenset({"approved", "shadowed", "stale-rollout"})
_RECEIPT_LIMIT = 65_536
_VERIFIED_EVIDENCE_TOKEN = object()


class ReferenceWorkerBenchmarkError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _freeze_evidence_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_evidence_value(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_evidence_value(child) for child in value)
    return value


class ReferenceSuitePreparer(Protocol):
    def __call__(
        self,
        *,
        source_root: Path,
        config_root: Path,
    ) -> PreparedReferenceBenchmarkSuite: ...


@dataclass(frozen=True, slots=True)
class PreparedReferenceBenchmarkSuite:
    manifest: ReferenceMediaManifest
    media_verification: ReferenceMediaVerification
    scenarios: Mapping[str, ReferenceScenario]
    variants: Mapping[ReferenceVariantName, ReferenceColorVariant]

    def __post_init__(self) -> None:
        scenarios = MappingProxyType(dict(self.scenarios))
        variants = MappingProxyType(dict(self.variants))
        artifact_ids = tuple(
            f"frame:{frame.sequence_id}:{frame.frame:05d}"
            for sequence in self.manifest.sequences
            for frame in sequence.frames
        )
        verification = self.media_verification
        if (
            self.manifest.frame_count != 240
            or len(artifact_ids) != 240
            or len(set(artifact_ids)) != 240
            or set(scenarios) != _EXPECTED_SCENARIOS
            or set(variants) != _EXPECTED_VARIANTS
            or verification.collection_id != self.manifest.collection_id
            or verification.manifest_sha256 != self.manifest.manifest_sha256
            or verification.frame_count != self.manifest.frame_count
            or verification.total_bytes != self.manifest.total_bytes
            or verification.license_spdx != self.manifest.license_spdx
            or verification.source_notice_sha256 != self.manifest.source_notice_sha256
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-suite-invalid")
        expected_artifacts = set(artifact_ids)
        for scenario_id, scenario in scenarios.items():
            if (
                scenario.scenario_id != scenario_id
                or set(scenario.affected_artifact_ids).union(scenario.protected_artifact_ids)
                != expected_artifacts
                or set(scenario.affected_artifact_ids).intersection(scenario.protected_artifact_ids)
            ):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-suite-invalid")
        for name, variant in variants.items():
            if (
                variant.name != name
                or _DIGEST.fullmatch(variant.config_sha256) is None
                or _DIGEST.fullmatch(variant.resource_sha256) is None
                or variant.config_generation < 1
            ):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-suite-invalid")
        object.__setattr__(self, "scenarios", scenarios)
        object.__setattr__(self, "variants", variants)


@dataclass(frozen=True, slots=True, init=False)
class _VerifiedReferenceWorkerEvidence:
    _source: BenchmarkEvidenceSource
    _evidence_set_id: str
    _observations: tuple[BenchmarkArtifactObservation, ...]

    def __init__(self) -> None:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-unverified")

    @classmethod
    def _from_validation(
        cls,
        *,
        source: BenchmarkEvidenceSource,
        evidence_set_id: str,
        observations: tuple[BenchmarkArtifactObservation, ...],
        verification_token: object,
    ) -> _VerifiedReferenceWorkerEvidence:
        if verification_token is not _VERIFIED_EVIDENCE_TOKEN:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-unverified")
        for observation in observations:
            object.__setattr__(
                observation,
                "baseline_receipt",
                _freeze_evidence_value(observation.baseline_receipt),
            )
            object.__setattr__(
                observation,
                "observed_receipt",
                (
                    _freeze_evidence_value(observation.observed_receipt)
                    if observation.observed_receipt is not None
                    else None
                ),
            )
            object.__setattr__(
                observation,
                "selective_receipt",
                (
                    _freeze_evidence_value(observation.selective_receipt)
                    if observation.selective_receipt is not None
                    else None
                ),
            )
        value = object.__new__(cls)
        object.__setattr__(value, "_source", source)
        object.__setattr__(value, "_evidence_set_id", evidence_set_id)
        object.__setattr__(value, "_observations", observations)
        return value

    @property
    def source(self) -> BenchmarkEvidenceSource:
        return self._source

    @property
    def evidence_set_id(self) -> str:
        return self._evidence_set_id

    @property
    def observations(self) -> tuple[BenchmarkArtifactObservation, ...]:
        return self._observations


@dataclass(frozen=True, slots=True)
class _DerivativeCacheProof:
    entry_before: Mapping[str, Any]
    entry_after: Mapping[str, Any]
    observed_receipt: Mapping[str, Any] | None
    invalidation_operation: Mapping[str, Any] | None
    lookup_after_invalidation: str | None


def prepare_sealed_reference_benchmark_suite(
    *,
    source_root: Path,
    config_root: Path,
) -> PreparedReferenceBenchmarkSuite:
    manifest = load_reference_media_manifest()
    verification = verify_reference_media(source_root, manifest)
    variants = materialize_reference_color_variants(config_root)
    return PreparedReferenceBenchmarkSuite(
        manifest=manifest,
        media_verification=verification,
        scenarios=reference_scenarios(manifest),
        variants=variants,
    )


def _safe_root(path: Path, *, create: bool) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    if ".." in absolute.parts or absolute.is_symlink():
        raise ReferenceWorkerBenchmarkError("reference-benchmark-root-unsafe")
    resolved = absolute.resolve(strict=False)
    if (
        resolved != absolute.absolute()
        or resolved == Path(resolved.anchor)
        or len(resolved.parts) < 3
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-root-unsafe")
    try:
        if create:
            resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = resolved.lstat()
    except OSError as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-root-unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-root-unsafe")
    return resolved


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid")
    return path


def _target(root: Path, relative: str) -> Path:
    parts = _relative_path(relative).parts
    target = root.joinpath(*parts)
    resolved_parent = target.parent.resolve(strict=False)
    if resolved_parent != target.parent or not resolved_parent.is_relative_to(root):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid")
    return target


def _present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _safe_existing_file(path: Path, root: Path, *, limit: int | None = None) -> int:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-file-unavailable") from error
    if (
        resolved != path
        or not resolved.is_relative_to(root)
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (limit is not None and not 1 <= metadata.st_size <= limit)
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-file-unsafe")
    return metadata.st_size


def _open_output_parent(root: Path, path: Path) -> int:
    try:
        relative_parent = path.parent.relative_to(root)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except (OSError, ValueError) as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid") from error
    try:
        for part in relative_parent.parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child_fd
    except OSError as error:
        os.close(directory_fd)
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid") from error
    return directory_fd


def _directory_entry_present(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-path-invalid") from error
    return True


def _json_mapping(path: Path, root: Path) -> dict[str, Any]:
    _safe_existing_file(path, root, limit=_RECEIPT_LIMIT)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-json-invalid") from error
    if (
        not isinstance(value, dict)
        or any(not isinstance(key, str) for key in value)
        or raw != canonical_json_bytes(value) + b"\n"
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-json-invalid")
    return cast(dict[str, Any], value)


def _write_exact(path: Path, root: Path, value: Mapping[str, Any]) -> bool:
    data = canonical_json_bytes(value) + b"\n"
    parent_fd = _open_output_parent(root, path)
    try:
        try:
            descriptor = os.open(
                path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError as error:
            if _safe_existing_file(path, root) != len(data) or path.read_bytes() != data:
                raise ReferenceWorkerBenchmarkError(
                    "reference-benchmark-existing-output-conflict"
                ) from error
            return True
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            try:
                os.unlink(path.name, dir_fd=parent_fd)
            except OSError:
                pass
            raise ReferenceWorkerBenchmarkError("reference-benchmark-write-failed") from error
        return False
    finally:
        os.close(parent_fd)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    return value


def _trace_id(manifest_sha256: str, scenario_id: str, phase: str, artifact_id: str) -> str:
    value = f"{manifest_sha256}\0{scenario_id}\0{phase}\0{artifact_id}".encode()
    return hashlib.sha256(value).hexdigest()[:32]


def _receipt_relative_path(job: Mapping[str, Any], phase: str) -> str:
    source = cast(Mapping[str, Any], job["source"])
    source_path = _relative_path(cast(str, source["relative_path"]))
    return (
        f"receipts/{job['scenario_id']}/{phase}/"
        f"{source_path.parent.as_posix()}/{source_path.name}.json"
    )


def _validate_receipt_for_job(
    receipt_value: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    output_root: Path,
) -> dict[str, Any]:
    receipt = _validate_receipt(receipt_value)
    source = cast(Mapping[str, Any], job["source"])
    color = cast(Mapping[str, Any], job["color"])
    runtime = cast(Mapping[str, Any], job["runtime"])
    output = cast(Mapping[str, Any], job["output"])
    expected = {
        "job_id": job["job_id"],
        "scenario_id": job["scenario_id"],
        "incident_class": job["incident_class"],
        "trace_id": job["trace_id"],
        "worker_id": job["worker_id"],
        "artifact_id": job["artifact_id"],
        "source_sha256": source["sha256"],
        "config_sha256": color["config_sha256"],
        "resource_sha256": color["resource_sha256"],
        "effective_generation": runtime["effective_generation"],
        "cache_key": runtime["cache_key"],
        "output_relative_path": output["relative_path"],
        "bytes_read": source["byte_length"],
    }
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-receipt-job-mismatch")
    output_path = _target(output_root, cast(str, output["relative_path"]))
    output_size = _safe_existing_file(output_path, output_root)
    if (
        output_size != receipt["bytes_written"]
        or sha256_file(output_path) != receipt["output_sha256"]
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-output-mismatch")
    return cast(dict[str, Any], _plain(receipt))


@dataclass(slots=True)
class _ReceiptStore:
    output_root: Path
    worker: ReferenceWorkerCallable
    source_root: Path
    config_root: Path
    executed: int = 0
    reused: int = 0

    def require_absent(self, job: Mapping[str, Any], *, phase: str) -> None:
        output = cast(Mapping[str, Any], job["output"])
        output_path = _target(self.output_root, cast(str, output["relative_path"]))
        receipt_path = _target(
            self.output_root,
            _receipt_relative_path(job, phase),
        )
        if _present(output_path) or _present(receipt_path):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-unexpected-selective-output")

    def obtain(self, job: Mapping[str, Any], *, phase: str) -> dict[str, Any]:
        output = cast(Mapping[str, Any], job["output"])
        output_path = _target(self.output_root, cast(str, output["relative_path"]))
        receipt_path = _target(
            self.output_root,
            _receipt_relative_path(job, phase),
        )
        output_present = _present(output_path)
        receipt_present = _present(receipt_path)
        if output_present or receipt_present:
            if not output_present or not receipt_present:
                raise ReferenceWorkerBenchmarkError("reference-benchmark-resume-pair-incomplete")
            receipt = _json_mapping(receipt_path, self.output_root)
            result = _validate_receipt_for_job(receipt, job, output_root=self.output_root)
            self.reused += 1
            return result
        returned = self.worker(
            job,
            source_root=self.source_root,
            config_root=self.config_root,
            output_root=self.output_root,
        )
        if not isinstance(returned, Mapping) or any(not isinstance(key, str) for key in returned):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-worker-receipt-invalid")
        result = _validate_receipt_for_job(returned, job, output_root=self.output_root)
        if _write_exact(receipt_path, self.output_root, result):
            persisted = _json_mapping(receipt_path, self.output_root)
            if persisted != result:
                raise ReferenceWorkerBenchmarkError("reference-benchmark-existing-output-conflict")
        self.executed += 1
        return result


def _operation_path(
    output_root: Path,
    scenario: ReferenceScenario,
    artifact_id: str,
) -> Path:
    relative = f"operations/{scenario.scenario_id}/{artifact_id.replace(':', '-')}.json"
    return _target(output_root, relative)


def _cache_entry_path(
    output_root: Path,
    scenario: ReferenceScenario,
    artifact_id: str,
    state: str,
) -> Path:
    relative = (
        f"derivative-cache/{scenario.scenario_id}/{state}/{artifact_id.replace(':', '-')}.json"
    )
    return _target(output_root, relative)


def _stale_derivative_job(
    *,
    frame: ReferenceFrame,
    stale_parent: ReferenceFrame,
    scenario: ReferenceScenario,
    variants: Mapping[ReferenceVariantName, ReferenceColorVariant],
    trace_id: str,
) -> dict[str, Any]:
    job = reference_render_job(
        frame=frame,
        scenario=scenario,
        variants=variants,
        mode="observed",
        trace_id=trace_id,
    )
    if stale_parent.sequence_id != frame.sequence_id or stale_parent.frame == frame.frame:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-stale-parent-invalid")
    job["job_id"] = f"observed-stale-parent-{frame.sequence_id}-{frame.frame:05d}"
    job["source"] = {
        "relative_path": f"{stale_parent.sequence_id}/{stale_parent.filename}",
        "sha256": stale_parent.sha256,
        "byte_length": stale_parent.byte_length,
    }
    job["output"] = {
        "relative_path": (
            f"{scenario.scenario_id}/observed-stale-parent/{frame.sequence_id}/{frame.filename}"
        )
    }
    return job


def _cache_entry(
    scenario: ReferenceScenario,
    receipt: Mapping[str, Any],
    *,
    state: str,
    derivative_generation: int,
) -> dict[str, Any]:
    cache_key = receipt.get("cache_key")
    if not isinstance(cache_key, str):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-key-missing")
    body = {
        "schema": "reference-derivative-cache-entry/v1",
        "scenario_id": scenario.scenario_id,
        "artifact_id": receipt["artifact_id"],
        "cache_key": cache_key,
        "state": state,
        "derivative_generation": derivative_generation,
        "parent_output_sha256": receipt["output_sha256"],
        "derivative_output_sha256": receipt["output_sha256"],
        "canonical_pixel_sha256": receipt["canonical_pixel_sha256"],
        "byte_length": receipt["bytes_written"],
        "blob_relative_path": receipt["output_relative_path"],
        "source_receipt_sha256": receipt["receipt_sha256"],
    }
    record = {**body, "entry_sha256": prefixed_sha256(body)}
    validate_schema("reference-derivative-cache-entry-v1.schema.json", record)
    return record


def _cache_lookup(
    output_root: Path,
    index_path: Path,
) -> tuple[dict[str, Any] | None, int]:
    if not _present(index_path):
        return None, 0
    entry = _json_mapping(index_path, output_root)
    validate_schema("reference-derivative-cache-entry-v1.schema.json", entry)
    body = {key: value for key, value in entry.items() if key != "entry_sha256"}
    if entry.get("entry_sha256") != prefixed_sha256(body):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-entry-invalid")
    blob = _target(output_root, cast(str, entry["blob_relative_path"]))
    blob_size = _safe_existing_file(blob, output_root)
    if blob_size != entry["byte_length"] or sha256_file(blob) != entry["derivative_output_sha256"]:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-entry-invalid")
    index_bytes = len(canonical_json_bytes(entry)) + 1
    return entry, index_bytes + blob_size


def _install_cache_entry(
    output_root: Path,
    index_path: Path,
    entry: Mapping[str, Any],
) -> tuple[int, int]:
    _write_exact(index_path, output_root, entry)
    persisted, bytes_read = _cache_lookup(output_root, index_path)
    if persisted != entry:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-entry-invalid")
    return len(canonical_json_bytes(entry)) + 1, bytes_read


def _invalidation_record(
    scenario: ReferenceScenario,
    observed_entry: Mapping[str, Any],
    expected_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        observed_entry.get("state") != "stale"
        or observed_entry.get("derivative_generation") != scenario.observed_derivative_generation
        or observed_entry.get("parent_output_sha256") == expected_receipt["output_sha256"]
        or observed_entry.get("derivative_output_sha256") == expected_receipt["output_sha256"]
        or observed_entry.get("canonical_pixel_sha256")
        == expected_receipt["canonical_pixel_sha256"]
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-stale-derivative-not-stale")
    body = {
        "schema": "reference-cache-invalidation-operation/v1",
        "scenario_id": scenario.scenario_id,
        "artifact_id": expected_receipt["artifact_id"],
        "cache_key": observed_entry["cache_key"],
        "invalidated_entry_sha256": observed_entry["entry_sha256"],
        "derivative_generation_before": scenario.observed_derivative_generation,
        "derivative_generation_after": scenario.expected_derivative_generation,
        "stale_parent_output_sha256": observed_entry["parent_output_sha256"],
        "stale_derivative_output_sha256": observed_entry["derivative_output_sha256"],
        "stale_canonical_pixel_sha256": observed_entry["canonical_pixel_sha256"],
        "expected_parent_output_sha256": expected_receipt["output_sha256"],
        "expected_canonical_pixel_sha256": expected_receipt["canonical_pixel_sha256"],
        "lookup_before_invalidation": "stale-hit",
        "lookup_after_invalidation": "miss",
    }
    record = {**body, "operation_sha256": prefixed_sha256(body)}
    validate_schema("reference-cache-invalidation-operation-v1.schema.json", record)
    return record


def _prepare_stale_cache_entry(
    output_root: Path,
    scenario: ReferenceScenario,
    artifact_id: str,
    observed_entry: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    live_path = _cache_entry_path(output_root, scenario, artifact_id, "live")
    invalidated_path = _cache_entry_path(output_root, scenario, artifact_id, "invalidated")
    operation_path = _operation_path(output_root, scenario, artifact_id)
    if _present(operation_path) or _present(invalidated_path):
        if not _present(invalidated_path):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
        persisted, bytes_read = _cache_lookup(output_root, invalidated_path)
    else:
        _written, bytes_read = _install_cache_entry(output_root, live_path, observed_entry)
        persisted = dict(observed_entry)
    if persisted != observed_entry:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-entry-invalid")
    return persisted, bytes_read


def _record_invalidation(
    output_root: Path,
    scenario: ReferenceScenario,
    observed_entry: Mapping[str, Any],
    expected_receipt: Mapping[str, Any],
) -> tuple[dict[str, Any], int, int]:
    artifact_id = cast(str, expected_receipt["artifact_id"])
    live_path = _cache_entry_path(output_root, scenario, artifact_id, "live")
    invalidated_path = _cache_entry_path(output_root, scenario, artifact_id, "invalidated")
    operation_path = _operation_path(output_root, scenario, artifact_id)
    record = _invalidation_record(scenario, observed_entry, expected_receipt)
    record_bytes = len(canonical_json_bytes(record)) + 1
    if _present(operation_path):
        persisted = _json_mapping(operation_path, output_root)
        validate_schema("reference-cache-invalidation-operation-v1.schema.json", persisted)
        if persisted != record:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
        invalidated, bytes_read = _cache_lookup(output_root, invalidated_path)
        if invalidated != observed_entry:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
    else:
        if _present(invalidated_path):
            invalidated, bytes_read = _cache_lookup(output_root, invalidated_path)
            if invalidated != observed_entry or _present(live_path):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
        else:
            live, bytes_read = _cache_lookup(output_root, live_path)
            if live != observed_entry:
                raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
            live_parent_fd = _open_output_parent(output_root, live_path)
            try:
                invalidated_parent_fd = _open_output_parent(output_root, invalidated_path)
                try:
                    if _directory_entry_present(invalidated_parent_fd, invalidated_path.name):
                        raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
                    os.link(
                        live_path.name,
                        invalidated_path.name,
                        src_dir_fd=live_parent_fd,
                        dst_dir_fd=invalidated_parent_fd,
                        follow_symlinks=False,
                    )
                    os.unlink(live_path.name, dir_fd=live_parent_fd)
                finally:
                    os.close(invalidated_parent_fd)
            except ReferenceWorkerBenchmarkError:
                raise
            except OSError as error:
                raise ReferenceWorkerBenchmarkError(
                    "reference-benchmark-operation-invalid"
                ) from error
            finally:
                os.close(live_parent_fd)
        after, _bytes_read = _cache_lookup(output_root, live_path)
        if after is not None:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-invalidation-failed")
        _write_exact(operation_path, output_root, record)
        persisted = _json_mapping(operation_path, output_root)
    body = {key: value for key, value in persisted.items() if key != "operation_sha256"}
    if persisted != record or persisted.get("operation_sha256") != prefixed_sha256(body):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-operation-invalid")
    return record, bytes_read + record_bytes, record_bytes


def _provenance_record(
    suite: PreparedReferenceBenchmarkSuite,
    evidence_source: BenchmarkEvidenceSource,
    *,
    sealed_suite: bool,
    real_worker: bool,
) -> dict[str, Any]:
    if (evidence_source == "recorded-worker-receipts") != (sealed_suite and real_worker):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid")
    implementation_targets: dict[str, Callable[..., Any] | type[Any]] = {
        "reference-assets": materialize_reference_color_variants,
        "reference-campaign": build_reference_impact_benchmark,
        "reference-media": load_reference_media_manifest,
        "reference-scenarios": reference_scenarios,
        "reference-worker-benchmark": run_reference_worker_benchmark,
    }
    if real_worker:
        implementation_targets["reference-worker"] = ReferenceWorkerError
    implementation_files: dict[str, str] = {}
    for name, target in implementation_targets.items():
        source_path = inspect.getsourcefile(target)
        if source_path is None:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid")
        try:
            resolved = Path(source_path).resolve(strict=True)
            metadata = resolved.lstat()
        except OSError as error:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid")
        implementation_files[name] = sha256_file(resolved)

    dependency_lock_sha256: str | None = None
    for parent in Path(__file__).resolve(strict=True).parents:
        candidate = parent / "uv.lock"
        if not candidate.exists():
            continue
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid")
        dependency_lock_sha256 = sha256_file(candidate)
        break

    body = {
        "schema": "reference-worker-benchmark-provenance/v1",
        "evidence_source": evidence_source,
        "reference_manifest_sha256": suite.manifest.manifest_sha256,
        "suite_binding": "sealed-reference-suite" if sealed_suite else "injected-suite",
        "worker_binding": (
            "colortrace-simulator-reference-worker/v1" if real_worker else "injected-worker"
        ),
        "execution_mode": "host-python-module" if real_worker else "injected-worker-callable",
        "container_image_digest": None,
        "source_revision": None,
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "platform_system": platform.system(),
            "platform_machine": platform.machine(),
        },
        "dependency_lock_sha256": dependency_lock_sha256,
        "implementation_files": implementation_files,
        "implementation_sha256": prefixed_sha256(implementation_files),
    }
    return {**body, "provenance_sha256": prefixed_sha256(body)}


def _seal_provenance(
    output_root: Path,
    suite: PreparedReferenceBenchmarkSuite,
    evidence_source: BenchmarkEvidenceSource,
    *,
    sealed_suite: bool,
    real_worker: bool,
) -> Mapping[str, Any]:
    path = _target(output_root, "metadata/reference-worker-benchmark-provenance.json")
    record = _provenance_record(
        suite,
        evidence_source,
        sealed_suite=sealed_suite,
        real_worker=real_worker,
    )
    if not _present(path) and any(output_root.iterdir()):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-missing")
    _write_exact(path, output_root, record)
    persisted = _json_mapping(path, output_root)
    body = {key: value for key, value in persisted.items() if key != "provenance_sha256"}
    if persisted != record or persisted.get("provenance_sha256") != prefixed_sha256(body):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-provenance-invalid")
    return MappingProxyType(persisted)


def _load_real_worker() -> ReferenceWorkerCallable:
    from colortrace_simulator.reference_worker import execute_reference_render_job

    return cast(ReferenceWorkerCallable, execute_reference_render_job)


def _frame_output_after(
    output_root: Path,
    receipt: Mapping[str, Any],
) -> tuple[str, int]:
    path = _target(output_root, cast(str, receipt["output_relative_path"]))
    size = _safe_existing_file(path, output_root)
    digest = sha256_file(path)
    if size != receipt["bytes_written"] or digest != receipt["output_sha256"]:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-preserved-output-mismatch")
    return digest, size


def _benchmark_stale_derivative_cache(
    *,
    output_root: Path,
    store: _ReceiptStore,
    suite: PreparedReferenceBenchmarkSuite,
    scenario: ReferenceScenario,
    frames: tuple[ReferenceFrame, ...],
    baseline_by_artifact: Mapping[str, Mapping[str, Any]],
) -> tuple[
    tuple[BenchmarkArtifactObservation, ...],
    tuple[Mapping[str, Any], ...],
    Mapping[tuple[str, str], _DerivativeCacheProof],
]:
    if scenario.incident_class != "stale-derivative-cache/v1":
        raise ReferenceWorkerBenchmarkError("reference-benchmark-scenario-invalid")

    before_entries: dict[str, dict[str, Any]] = {}
    before_bytes: dict[str, int] = {}
    observed_receipts: dict[str, Mapping[str, Any]] = {}
    stale_parent_by_artifact: dict[str, ReferenceFrame] = {}
    for sequence in suite.manifest.sequences:
        for index, sequence_frame in enumerate(sequence.frames):
            stale_parent_by_artifact[
                f"frame:{sequence_frame.sequence_id}:{sequence_frame.frame:05d}"
            ] = sequence.frames[index - 1]
    for frame in frames:
        artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
        baseline = baseline_by_artifact[artifact_id]
        affected = artifact_id in scenario.affected_artifact_ids
        live_path = _cache_entry_path(output_root, scenario, artifact_id, "live")
        if affected:
            stale_job = _stale_derivative_job(
                frame=frame,
                stale_parent=stale_parent_by_artifact[artifact_id],
                scenario=scenario,
                variants=suite.variants,
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario.scenario_id,
                    "cache-observed",
                    artifact_id,
                ),
            )
            stale_receipt = store.obtain(stale_job, phase="cache-observed-parent-v1")
            observed_receipts[artifact_id] = stale_receipt
            entry = _cache_entry(
                scenario,
                stale_receipt,
                state="stale",
                derivative_generation=scenario.observed_derivative_generation,
            )
            persisted, bytes_read = _prepare_stale_cache_entry(
                output_root,
                scenario,
                artifact_id,
                entry,
            )
        else:
            stale_job = _stale_derivative_job(
                frame=frame,
                stale_parent=stale_parent_by_artifact[artifact_id],
                scenario=scenario,
                variants=suite.variants,
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario.scenario_id,
                    "cache-observed",
                    artifact_id,
                ),
            )
            store.require_absent(stale_job, phase="cache-observed-parent-v1")
            selective_job = reference_render_job(
                frame=frame,
                scenario=scenario,
                variants=suite.variants,
                mode="recovered",
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario.scenario_id,
                    "selective",
                    artifact_id,
                ),
            )
            store.require_absent(selective_job, phase="selective")
            if _present(_operation_path(output_root, scenario, artifact_id)) or _present(
                _cache_entry_path(output_root, scenario, artifact_id, "invalidated")
            ):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-unexpected-operation")
            entry = _cache_entry(
                scenario,
                baseline,
                state="current",
                derivative_generation=scenario.expected_derivative_generation,
            )
            _written, bytes_read = _install_cache_entry(output_root, live_path, entry)
            persisted = dict(entry)
        before_entries[artifact_id] = persisted
        before_bytes[artifact_id] = bytes_read

    observations: list[BenchmarkArtifactObservation] = []
    operation_records: list[Mapping[str, Any]] = []
    cache_proofs: dict[tuple[str, str], _DerivativeCacheProof] = {}
    for frame in frames:
        artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
        if artifact_id not in scenario.affected_artifact_ids:
            continue
        baseline = baseline_by_artifact[artifact_id]
        observed_entry = before_entries[artifact_id]
        operation, operation_bytes_read, operation_bytes_written = _record_invalidation(
            output_root,
            scenario,
            observed_entry,
            baseline,
        )
        operation_records.append(operation)
        selective_job = reference_render_job(
            frame=frame,
            scenario=scenario,
            variants=suite.variants,
            mode="recovered",
            trace_id=_trace_id(
                suite.manifest.manifest_sha256,
                scenario.scenario_id,
                "selective",
                artifact_id,
            ),
        )
        selective = store.obtain(selective_job, phase="selective")
        if not _receipt_equivalent(baseline, selective):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-recovery-mismatch")
        current_entry = _cache_entry(
            scenario,
            selective,
            state="current",
            derivative_generation=scenario.expected_derivative_generation,
        )
        live_path = _cache_entry_path(output_root, scenario, artifact_id, "live")
        entry_bytes_written, recovered_bytes_read = _install_cache_entry(
            output_root,
            live_path,
            current_entry,
        )
        recovered_entry = current_entry
        if (
            recovered_entry != current_entry
            or recovered_entry["derivative_output_sha256"] != baseline["output_sha256"]
            or recovered_entry["canonical_pixel_sha256"] != baseline["canonical_pixel_sha256"]
            or recovered_entry["parent_output_sha256"] != baseline["output_sha256"]
            or recovered_entry["derivative_generation"] != scenario.expected_derivative_generation
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-cache-recovery-mismatch")
        observations.append(
            BenchmarkArtifactObservation(
                scenario_id=scenario.scenario_id,
                artifact_id=artifact_id,
                affected=True,
                baseline_receipt=baseline,
                observed_receipt=observed_receipts[artifact_id],
                selective_receipt=selective,
                operation_compute_units=0,
                operation_bytes_read=operation_bytes_read + recovered_bytes_read,
                operation_bytes_written=operation_bytes_written + entry_bytes_written,
            )
        )
        cache_proofs[(scenario.scenario_id, artifact_id)] = _DerivativeCacheProof(
            entry_before=observed_entry,
            entry_after=current_entry,
            observed_receipt=observed_receipts[artifact_id],
            invalidation_operation=operation,
            lookup_after_invalidation="miss",
        )

    for frame in frames:
        artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
        if artifact_id in scenario.affected_artifact_ids:
            continue
        baseline = baseline_by_artifact[artifact_id]
        before = before_entries[artifact_id]
        live_path = _cache_entry_path(output_root, scenario, artifact_id, "live")
        after, after_bytes_read = _cache_lookup(output_root, live_path)
        if (
            after != before
            or after["derivative_output_sha256"] != baseline["output_sha256"]
            or after["canonical_pixel_sha256"] != baseline["canonical_pixel_sha256"]
            or after["derivative_generation"] != scenario.expected_derivative_generation
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-protected-cache-changed")
        observations.append(
            BenchmarkArtifactObservation(
                scenario_id=scenario.scenario_id,
                artifact_id=artifact_id,
                affected=False,
                baseline_receipt=baseline,
                observed_receipt=None,
                selective_receipt=None,
                preserved_before_output_sha256=cast(str, before["derivative_output_sha256"]),
                preserved_after_output_sha256=cast(str, after["derivative_output_sha256"]),
                preserved_before_canonical_pixel_sha256=cast(str, before["canonical_pixel_sha256"]),
                preserved_after_canonical_pixel_sha256=cast(str, after["canonical_pixel_sha256"]),
                verification_bytes_read=before_bytes[artifact_id] + after_bytes_read,
            )
        )
        cache_proofs[(scenario.scenario_id, artifact_id)] = _DerivativeCacheProof(
            entry_before=before,
            entry_after=cast(Mapping[str, Any], after),
            observed_receipt=None,
            invalidation_operation=None,
            lookup_after_invalidation=None,
        )

    return tuple(observations), tuple(operation_records), MappingProxyType(cache_proofs)


def _evidence_observation(
    item: BenchmarkArtifactObservation,
    proof: _DerivativeCacheProof | None,
) -> dict[str, Any]:
    return {
        "scenario_id": item.scenario_id,
        "artifact_id": item.artifact_id,
        "affected": item.affected,
        "baseline_receipt_sha256": item.baseline_receipt["receipt_sha256"],
        "baseline_receipt": _plain(item.baseline_receipt),
        "observed_receipt_sha256": (
            item.observed_receipt["receipt_sha256"] if item.observed_receipt is not None else None
        ),
        "observed_receipt": (
            _plain(item.observed_receipt) if item.observed_receipt is not None else None
        ),
        "selective_receipt_sha256": (
            item.selective_receipt["receipt_sha256"] if item.selective_receipt is not None else None
        ),
        "selective_receipt": (
            _plain(item.selective_receipt) if item.selective_receipt is not None else None
        ),
        "preserved_before_output_sha256": item.preserved_before_output_sha256,
        "preserved_after_output_sha256": item.preserved_after_output_sha256,
        "preserved_before_canonical_pixel_sha256": (item.preserved_before_canonical_pixel_sha256),
        "preserved_after_canonical_pixel_sha256": (item.preserved_after_canonical_pixel_sha256),
        "verification_bytes_read": item.verification_bytes_read,
        "operation_compute_units": item.operation_compute_units,
        "operation_bytes_read": item.operation_bytes_read,
        "operation_bytes_written": item.operation_bytes_written,
        "operation_cpu_nanoseconds": item.operation_cpu_nanoseconds,
        "operation_wall_nanoseconds": item.operation_wall_nanoseconds,
        "cache_entry_before": _plain(proof.entry_before) if proof is not None else None,
        "cache_entry_after": _plain(proof.entry_after) if proof is not None else None,
        "cache_observed_receipt": (
            _plain(proof.observed_receipt)
            if proof is not None and proof.observed_receipt is not None
            else None
        ),
        "cache_invalidation_operation": (
            _plain(proof.invalidation_operation)
            if proof is not None and proof.invalidation_operation is not None
            else None
        ),
        "cache_lookup_after_invalidation": (
            proof.lookup_after_invalidation if proof is not None else None
        ),
    }


def _evidence_set_record(
    suite: PreparedReferenceBenchmarkSuite,
    observations: tuple[BenchmarkArtifactObservation, ...],
    operation_records: tuple[Mapping[str, Any], ...],
    cache_proofs: Mapping[tuple[str, str], _DerivativeCacheProof],
    evidence_source: BenchmarkEvidenceSource,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": "reference-worker-evidence-set/v1",
        "source": evidence_source,
        "reference_manifest_sha256": suite.manifest.manifest_sha256,
        "media_verification_sha256": prefixed_sha256(suite.media_verification.to_dict()),
        "execution_provenance_sha256": provenance["provenance_sha256"],
        "execution_provenance": _plain(provenance),
        "variant_digests": {
            name: {
                "config_sha256": variant.config_sha256,
                "resource_sha256": variant.resource_sha256,
                "config_generation": variant.config_generation,
            }
            for name, variant in sorted(suite.variants.items())
        },
        "observations": [
            _evidence_observation(
                item,
                cache_proofs.get((item.scenario_id, item.artifact_id)),
            )
            for item in observations
        ],
        "cache_invalidation_operation_sha256": [
            record["operation_sha256"] for record in operation_records
        ],
    }
    record = {**body, "evidence_set_id": prefixed_sha256(body)}
    validate_schema("reference-worker-evidence-set-v1.schema.json", record)
    return record


def _verified_evidence_receipt(
    value: Any,
    claimed_sha256: Any,
    *,
    job: Mapping[str, Any],
    phase: str,
    output_root: Path,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or not isinstance(claimed_sha256, str)
        or value.get("receipt_sha256") != claimed_sha256
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-receipt-invalid")
    receipt = _validate_receipt_for_job(value, job, output_root=output_root)
    receipt_path = _target(output_root, _receipt_relative_path(job, phase))
    if _json_mapping(receipt_path, output_root) != receipt:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-receipt-mismatch")
    return receipt


def _require_evidence_job_absent(
    job: Mapping[str, Any],
    *,
    phase: str,
    output_root: Path,
) -> None:
    output = cast(Mapping[str, Any], job["output"])
    if _present(_target(output_root, cast(str, output["relative_path"]))) or _present(
        _target(output_root, _receipt_relative_path(job, phase))
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-unexpected-output")


def _record_body_matches(value: Mapping[str, Any], digest_field: str) -> bool:
    body = {key: child for key, child in value.items() if key != digest_field}
    return value.get(digest_field) == prefixed_sha256(body)


def _verified_cache_proof(
    raw: Mapping[str, Any],
    *,
    scenario: ReferenceScenario,
    observation: BenchmarkArtifactObservation,
    output_root: Path,
) -> str | None:
    before_value = raw["cache_entry_before"]
    after_value = raw["cache_entry_after"]
    cache_receipt_value = raw["cache_observed_receipt"]
    operation_value = raw["cache_invalidation_operation"]
    lookup_value = raw["cache_lookup_after_invalidation"]
    if scenario.incident_class != "stale-derivative-cache/v1":
        if any(
            value is not None
            for value in (
                before_value,
                after_value,
                cache_receipt_value,
                operation_value,
                lookup_value,
            )
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")
        if any(
            value != 0
            for value in (
                observation.operation_compute_units,
                observation.operation_bytes_read,
                observation.operation_bytes_written,
                observation.operation_cpu_nanoseconds,
                observation.operation_wall_nanoseconds,
            )
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-operation-invalid")
        if (
            not observation.affected
            and observation.verification_bytes_read != observation.baseline_receipt["bytes_written"]
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-operation-invalid")
        return None

    if not isinstance(before_value, Mapping) or not isinstance(after_value, Mapping):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")
    before = cast(dict[str, Any], _plain(before_value))
    after = cast(dict[str, Any], _plain(after_value))
    if not _record_body_matches(before, "entry_sha256") or not _record_body_matches(
        after, "entry_sha256"
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")

    invalidated_path = _cache_entry_path(
        output_root,
        scenario,
        observation.artifact_id,
        "invalidated",
    )
    live_path = _cache_entry_path(output_root, scenario, observation.artifact_id, "live")
    operation_path = _operation_path(output_root, scenario, observation.artifact_id)
    if observation.affected:
        if (
            observation.observed_receipt is None
            or observation.selective_receipt is None
            or not isinstance(cache_receipt_value, Mapping)
            or not isinstance(operation_value, Mapping)
            or lookup_value != "miss"
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")
        cache_receipt = cast(dict[str, Any], _plain(cache_receipt_value))
        operation = cast(dict[str, Any], _plain(operation_value))
        expected_before = _cache_entry(
            scenario,
            observation.observed_receipt,
            state="stale",
            derivative_generation=scenario.observed_derivative_generation,
        )
        expected_after = _cache_entry(
            scenario,
            observation.selective_receipt,
            state="current",
            derivative_generation=scenario.expected_derivative_generation,
        )
        expected_operation = _invalidation_record(
            scenario,
            expected_before,
            observation.baseline_receipt,
        )
        if (
            cache_receipt != observation.observed_receipt
            or before != expected_before
            or after != expected_after
            or operation != expected_operation
            or not _record_body_matches(operation, "operation_sha256")
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")
        persisted_before, before_bytes = _cache_lookup(output_root, invalidated_path)
        persisted_after, after_bytes = _cache_lookup(output_root, live_path)
        if (
            persisted_before != before
            or persisted_after != after
            or _json_mapping(operation_path, output_root) != operation
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-mismatch")
        operation_bytes = len(canonical_json_bytes(operation)) + 1
        after_entry_bytes = len(canonical_json_bytes(after)) + 1
        if (
            observation.verification_bytes_read != 0
            or observation.operation_compute_units != 0
            or observation.operation_bytes_read != before_bytes + operation_bytes + after_bytes
            or observation.operation_bytes_written != operation_bytes + after_entry_bytes
            or observation.operation_cpu_nanoseconds != 0
            or observation.operation_wall_nanoseconds != 0
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-operation-invalid")
        return cast(str, operation["operation_sha256"])

    expected = _cache_entry(
        scenario,
        observation.baseline_receipt,
        state="current",
        derivative_generation=scenario.expected_derivative_generation,
    )
    persisted, cache_bytes = _cache_lookup(output_root, live_path)
    if (
        before != expected
        or after != expected
        or persisted != expected
        or cache_receipt_value is not None
        or operation_value is not None
        or lookup_value is not None
        or _present(invalidated_path)
        or _present(operation_path)
        or observation.verification_bytes_read != cache_bytes * 2
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-cache-invalid")
    return None


def _verify_reference_worker_evidence_set(
    evidence_set: Mapping[str, Any],
    *,
    suite: PreparedReferenceBenchmarkSuite,
    output_root: Path,
) -> _VerifiedReferenceWorkerEvidence:
    output = _safe_root(output_root, create=False)
    document = cast(dict[str, Any], _plain(evidence_set))
    try:
        validate_schema("reference-worker-evidence-set-v1.schema.json", document)
    except ContractError as error:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-invalid") from error
    body = {key: child for key, child in document.items() if key != "evidence_set_id"}
    if document["evidence_set_id"] != prefixed_sha256(body):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-digest-invalid")

    source = cast(BenchmarkEvidenceSource, document["source"])
    provenance = cast(Mapping[str, Any], document["execution_provenance"])
    persisted_provenance = _json_mapping(
        _target(output, "metadata/reference-worker-benchmark-provenance.json"),
        output,
    )
    provenance_body = {
        key: child for key, child in provenance.items() if key != "provenance_sha256"
    }
    sealed_suite = provenance.get("suite_binding") == "sealed-reference-suite"
    real_worker = provenance.get("worker_binding") == "colortrace-simulator-reference-worker/v1"
    if real_worker != (provenance.get("execution_mode") == "host-python-module"):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-provenance-invalid")
    try:
        expected_provenance = _provenance_record(
            suite,
            source,
            sealed_suite=sealed_suite,
            real_worker=real_worker,
        )
    except ReferenceWorkerBenchmarkError as error:
        raise ReferenceWorkerBenchmarkError(
            "reference-benchmark-evidence-provenance-invalid"
        ) from error
    if (
        provenance.get("provenance_sha256") != prefixed_sha256(provenance_body)
        or document["execution_provenance_sha256"] != provenance.get("provenance_sha256")
        or persisted_provenance != provenance
        or dict(provenance) != expected_provenance
        or document["reference_manifest_sha256"] != suite.manifest.manifest_sha256
        or document["media_verification_sha256"]
        != prefixed_sha256(suite.media_verification.to_dict())
        or document["variant_digests"]
        != {
            name: {
                "config_sha256": variant.config_sha256,
                "resource_sha256": variant.resource_sha256,
                "config_generation": variant.config_generation,
            }
            for name, variant in sorted(suite.variants.items())
        }
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-provenance-invalid")

    frames = tuple(frame for sequence in suite.manifest.sequences for frame in sequence.frames)
    frame_by_artifact = {f"frame:{frame.sequence_id}:{frame.frame:05d}": frame for frame in frames}
    stale_parent_by_artifact: dict[str, ReferenceFrame] = {}
    for sequence in suite.manifest.sequences:
        for index, sequence_frame in enumerate(sequence.frames):
            artifact_id = f"frame:{sequence_frame.sequence_id}:{sequence_frame.frame:05d}"
            stale_parent_by_artifact[artifact_id] = sequence.frames[index - 1]

    observations: list[BenchmarkArtifactObservation] = []
    operation_ids: list[str] = []
    raw_observations = cast(list[Mapping[str, Any]], document["observations"])
    expected_pairs = {
        (scenario.scenario_id, artifact_id): artifact_id in scenario.affected_artifact_ids
        for scenario in suite.scenarios.values()
        for artifact_id in (
            *scenario.affected_artifact_ids,
            *scenario.protected_artifact_ids,
        )
    }
    raw_order = [
        (cast(str, item["scenario_id"]), cast(str, item["artifact_id"]))
        for item in raw_observations
    ]
    if raw_order != sorted(expected_pairs):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-scope-invalid")
    for raw in raw_observations:
        scenario_id = cast(str, raw["scenario_id"])
        artifact_id = cast(str, raw["artifact_id"])
        scenario = suite.scenarios.get(scenario_id)
        selected_frame = frame_by_artifact.get(artifact_id)
        if (
            scenario is None
            or selected_frame is None
            or raw["affected"] != (artifact_id in scenario.affected_artifact_ids)
        ):
            raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-scope-invalid")

        baseline_job = reference_render_job(
            frame=selected_frame,
            scenario=scenario,
            variants=suite.variants,
            mode="expected",
            trace_id=_trace_id(
                suite.manifest.manifest_sha256,
                scenario_id,
                "baseline",
                artifact_id,
            ),
        )
        baseline = _verified_evidence_receipt(
            raw["baseline_receipt"],
            raw["baseline_receipt_sha256"],
            job=baseline_job,
            phase="baseline",
            output_root=output,
        )
        selective_job = reference_render_job(
            frame=selected_frame,
            scenario=scenario,
            variants=suite.variants,
            mode="recovered",
            trace_id=_trace_id(
                suite.manifest.manifest_sha256,
                scenario_id,
                "selective",
                artifact_id,
            ),
        )
        if scenario.incident_class == "stale-derivative-cache/v1":
            observed_job = _stale_derivative_job(
                frame=selected_frame,
                stale_parent=stale_parent_by_artifact[artifact_id],
                scenario=scenario,
                variants=suite.variants,
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario_id,
                    "cache-observed",
                    artifact_id,
                ),
            )
            observed_phase = "cache-observed-parent-v1"
        else:
            observed_job = reference_render_job(
                frame=selected_frame,
                scenario=scenario,
                variants=suite.variants,
                mode="observed",
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario_id,
                    "incident-observed",
                    artifact_id,
                ),
            )
            observed_phase = "incident-observed"

        if raw["affected"]:
            observed = _verified_evidence_receipt(
                raw["observed_receipt"],
                raw["observed_receipt_sha256"],
                job=observed_job,
                phase=observed_phase,
                output_root=output,
            )
            selective = _verified_evidence_receipt(
                raw["selective_receipt"],
                raw["selective_receipt_sha256"],
                job=selective_job,
                phase="selective",
                output_root=output,
            )
        else:
            if any(
                raw[name] is not None
                for name in (
                    "observed_receipt_sha256",
                    "observed_receipt",
                    "selective_receipt_sha256",
                    "selective_receipt",
                )
            ):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-receipt-invalid")
            _require_evidence_job_absent(
                observed_job,
                phase=observed_phase,
                output_root=output,
            )
            _require_evidence_job_absent(
                selective_job,
                phase="selective",
                output_root=output,
            )
            observed = None
            selective = None

        observation = BenchmarkArtifactObservation(
            scenario_id=scenario_id,
            artifact_id=artifact_id,
            affected=cast(bool, raw["affected"]),
            baseline_receipt=baseline,
            observed_receipt=observed,
            selective_receipt=selective,
            preserved_before_output_sha256=cast(str | None, raw["preserved_before_output_sha256"]),
            preserved_after_output_sha256=cast(str | None, raw["preserved_after_output_sha256"]),
            preserved_before_canonical_pixel_sha256=cast(
                str | None,
                raw["preserved_before_canonical_pixel_sha256"],
            ),
            preserved_after_canonical_pixel_sha256=cast(
                str | None,
                raw["preserved_after_canonical_pixel_sha256"],
            ),
            verification_bytes_read=cast(int, raw["verification_bytes_read"]),
            operation_compute_units=cast(int, raw["operation_compute_units"]),
            operation_bytes_read=cast(int, raw["operation_bytes_read"]),
            operation_bytes_written=cast(int, raw["operation_bytes_written"]),
            operation_cpu_nanoseconds=cast(int, raw["operation_cpu_nanoseconds"]),
            operation_wall_nanoseconds=cast(int, raw["operation_wall_nanoseconds"]),
        )
        operation_id = _verified_cache_proof(
            raw,
            scenario=scenario,
            observation=observation,
            output_root=output,
        )
        if operation_id is not None:
            operation_ids.append(operation_id)
        observations.append(observation)

    selected = tuple(observations)
    actual_pairs = {(item.scenario_id, item.artifact_id): item for item in selected}
    if (
        len(actual_pairs) != len(selected)
        or set(actual_pairs) != set(expected_pairs)
        or any(item.affected != expected_pairs[key] for key, item in actual_pairs.items())
        or document["cache_invalidation_operation_sha256"] != operation_ids
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-evidence-scope-invalid")
    return _VerifiedReferenceWorkerEvidence._from_validation(
        source=source,
        evidence_set_id=cast(str, document["evidence_set_id"]),
        observations=selected,
        verification_token=_VERIFIED_EVIDENCE_TOKEN,
    )


def _build_verified_recorded_reference_impact_benchmark(
    evidence: _VerifiedReferenceWorkerEvidence,
    campaign_report: Mapping[str, Any],
    *,
    campaign_receipt_set: RecordedSelectionReceiptSet | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        type(evidence) is not _VerifiedReferenceWorkerEvidence
        or evidence.source != "recorded-worker-receipts"
    ):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-recorded-evidence-unverified")
    campaign = verify_reference_campaign_report(
        campaign_report,
        receipt_set=campaign_receipt_set,
    )
    measurements = _reference_impact_benchmark_body(evidence.observations, campaign)
    body = {
        **measurements,
        "evidence": {
            "source": evidence.source,
            "evidence_set_id": evidence.evidence_set_id,
            "recorded_worker_evidence": True,
            "observation_count": len(evidence.observations),
        },
    }
    report = {**body, "report_sha256": prefixed_sha256(body)}
    validate_schema("reference-impact-benchmark-v1.schema.json", report)
    return report


def _verified_campaign_report(
    *,
    campaign_report: Mapping[str, Any] | None,
    campaign_receipt_set: RecordedSelectionReceiptSet | Mapping[str, Any] | None,
) -> dict[str, Any]:
    if campaign_receipt_set is None:
        if campaign_report is not None:
            return verify_reference_campaign_report(campaign_report)
        return run_reference_campaign()

    recomputed = run_recorded_reference_campaign(campaign_receipt_set)
    if campaign_report is not None:
        verify_reference_campaign_report(
            campaign_report,
            receipt_set=campaign_receipt_set,
        )
    return recomputed


def run_reference_worker_benchmark(
    *,
    source_root: Path,
    config_root: Path,
    output_root: Path,
    campaign_report: Mapping[str, Any] | None = None,
    campaign_receipt_set: RecordedSelectionReceiptSet | Mapping[str, Any] | None = None,
    report_relative_path: str | None = None,
    evidence_index_relative_path: str | None = ("reports/reference-worker-evidence-index.json"),
    worker: ReferenceWorkerCallable | None = None,
    suite_preparer: ReferenceSuitePreparer | None = None,
) -> dict[str, Any]:
    source = _safe_root(source_root, create=False)
    config = _safe_root(config_root, create=False)
    output = _safe_root(output_root, create=True)
    if _overlaps(source, config) or _overlaps(source, output) or _overlaps(config, output):
        raise ReferenceWorkerBenchmarkError("reference-benchmark-roots-overlap")
    verified_campaign = _verified_campaign_report(
        campaign_report=campaign_report,
        campaign_receipt_set=campaign_receipt_set,
    )

    recorded = worker is None and suite_preparer is None
    evidence_source: BenchmarkEvidenceSource = (
        "recorded-worker-receipts" if recorded else "controlled-receipt-set"
    )
    prepare = suite_preparer or prepare_sealed_reference_benchmark_suite
    suite = prepare(source_root=source, config_root=config)
    verified_root = Path(suite.media_verification.cache_root).resolve(strict=False)
    if verified_root != source:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-media-root-mismatch")
    provenance = _seal_provenance(
        output,
        suite,
        evidence_source,
        sealed_suite=suite_preparer is None,
        real_worker=worker is None,
    )
    selected_worker = worker or _load_real_worker()
    store = _ReceiptStore(
        output_root=output,
        worker=selected_worker,
        source_root=source,
        config_root=config,
    )

    frames = tuple(frame for sequence in suite.manifest.sequences for frame in sequence.frames)
    observations: list[BenchmarkArtifactObservation] = []
    operation_records: list[Mapping[str, Any]] = []
    cache_proofs: dict[tuple[str, str], _DerivativeCacheProof] = {}
    for scenario_id in sorted(suite.scenarios):
        scenario = suite.scenarios[scenario_id]
        baseline_by_artifact: dict[str, dict[str, Any]] = {}
        for frame in frames:
            artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
            job = reference_render_job(
                frame=frame,
                scenario=scenario,
                variants=suite.variants,
                mode="expected",
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario_id,
                    "baseline",
                    artifact_id,
                ),
            )
            baseline_by_artifact[artifact_id] = store.obtain(job, phase="baseline")

        if scenario.incident_class == "stale-derivative-cache/v1":
            stale_observations, stale_operations, stale_proofs = _benchmark_stale_derivative_cache(
                output_root=output,
                store=store,
                suite=suite,
                scenario=scenario,
                frames=frames,
                baseline_by_artifact=baseline_by_artifact,
            )
            observations.extend(stale_observations)
            operation_records.extend(stale_operations)
            cache_proofs.update(stale_proofs)
            continue

        for frame in frames:
            artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
            affected = artifact_id in scenario.affected_artifact_ids
            baseline = baseline_by_artifact[artifact_id]
            observed: dict[str, Any] | None = None
            selective: dict[str, Any] | None = None
            operation_compute = 0
            operation_bytes_read = 0
            operation_bytes_written = 0
            selective_job = reference_render_job(
                frame=frame,
                scenario=scenario,
                variants=suite.variants,
                mode="recovered",
                trace_id=_trace_id(
                    suite.manifest.manifest_sha256,
                    scenario_id,
                    "selective",
                    artifact_id,
                ),
            )
            if affected:
                observed_job = reference_render_job(
                    frame=frame,
                    scenario=scenario,
                    variants=suite.variants,
                    mode="observed",
                    trace_id=_trace_id(
                        suite.manifest.manifest_sha256,
                        scenario_id,
                        "incident-observed",
                        artifact_id,
                    ),
                )
                observed = store.obtain(observed_job, phase="incident-observed")
                selective = store.obtain(selective_job, phase="selective")
            else:
                observed_job = reference_render_job(
                    frame=frame,
                    scenario=scenario,
                    variants=suite.variants,
                    mode="observed",
                    trace_id=_trace_id(
                        suite.manifest.manifest_sha256,
                        scenario_id,
                        "incident-observed",
                        artifact_id,
                    ),
                )
                store.require_absent(observed_job, phase="incident-observed")
                store.require_absent(selective_job, phase="selective")
            if _present(_operation_path(output, scenario, artifact_id)):
                raise ReferenceWorkerBenchmarkError("reference-benchmark-unexpected-operation")

            preserved_before_output: str | None = None
            preserved_after_output: str | None = None
            preserved_before_pixels: str | None = None
            preserved_after_pixels: str | None = None
            verification_bytes = 0
            if selective is None:
                preserved_before_output = cast(str, baseline["output_sha256"])
                preserved_before_pixels = cast(str, baseline["canonical_pixel_sha256"])
                preserved_after_output, verification_bytes = _frame_output_after(
                    output,
                    baseline,
                )
                preserved_after_pixels = cast(str, baseline["canonical_pixel_sha256"])

            observations.append(
                BenchmarkArtifactObservation(
                    scenario_id=scenario_id,
                    artifact_id=artifact_id,
                    affected=affected,
                    baseline_receipt=baseline,
                    observed_receipt=observed,
                    selective_receipt=selective,
                    preserved_before_output_sha256=preserved_before_output,
                    preserved_after_output_sha256=preserved_after_output,
                    preserved_before_canonical_pixel_sha256=preserved_before_pixels,
                    preserved_after_canonical_pixel_sha256=preserved_after_pixels,
                    verification_bytes_read=verification_bytes,
                    operation_compute_units=operation_compute,
                    operation_bytes_read=operation_bytes_read,
                    operation_bytes_written=operation_bytes_written,
                )
            )

    selected_observations = tuple(
        sorted(observations, key=lambda item: (item.scenario_id, item.artifact_id))
    )
    selected_operation_records = tuple(
        sorted(
            operation_records,
            key=lambda item: (cast(str, item["scenario_id"]), cast(str, item["artifact_id"])),
        )
    )
    if len(selected_observations) != 720:
        raise ReferenceWorkerBenchmarkError("reference-benchmark-observation-count-invalid")
    evidence_record = _evidence_set_record(
        suite,
        selected_observations,
        selected_operation_records,
        cache_proofs,
        evidence_source,
        provenance,
    )
    verified_evidence = _verify_reference_worker_evidence_set(
        evidence_record,
        suite=suite,
        output_root=output,
    )
    if evidence_index_relative_path is not None:
        evidence_path = _target(output, evidence_index_relative_path)
        _write_exact(evidence_path, output, evidence_record)
    if evidence_source == "recorded-worker-receipts":
        report = _build_verified_recorded_reference_impact_benchmark(
            verified_evidence,
            verified_campaign,
            campaign_receipt_set=campaign_receipt_set,
        )
    else:
        report = build_reference_impact_benchmark(
            verified_evidence.observations,
            verified_campaign,
            evidence_source=verified_evidence.source,
            evidence_set_id=verified_evidence.evidence_set_id,
            campaign_receipt_set=campaign_receipt_set,
        )
    if report_relative_path is not None:
        report_path = _target(output, report_relative_path)
        _write_exact(report_path, output, report)
    return report


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-benchmark")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--config-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--campaign-report", type=Path)
    parser.add_argument("--campaign-receipt-set", type=Path)
    parser.add_argument(
        "--report-relative-path",
        default="reports/reference-impact-benchmark.json",
    )
    parser.add_argument(
        "--evidence-index-relative-path",
        default="reports/reference-worker-evidence-index.json",
    )
    arguments = parser.parse_args()
    try:
        campaign_report = (
            strict_json_file(arguments.campaign_report)
            if arguments.campaign_report is not None
            else None
        )
        campaign_receipt_set = (
            strict_json_file(arguments.campaign_receipt_set)
            if arguments.campaign_receipt_set is not None
            else None
        )
        report = run_reference_worker_benchmark(
            source_root=arguments.source_root,
            config_root=arguments.config_root,
            output_root=arguments.output_root,
            campaign_report=campaign_report,
            campaign_receipt_set=campaign_receipt_set,
            report_relative_path=arguments.report_relative_path,
            evidence_index_relative_path=arguments.evidence_index_relative_path,
        )
    except (
        ContractError,
        ReferenceAssetError,
        ReferenceCampaignError,
        ReferenceMediaError,
        ReferenceWorkerBenchmarkError,
        ReferenceWorkerError,
    ) as error:
        code = getattr(error, "code", str(error))
        print(code, file=sys.stderr)
        raise SystemExit(2) from error
    print(canonical_json_bytes(report).decode("utf-8"))
    if not report["passed"]:
        raise SystemExit(1)


__all__ = [
    "PreparedReferenceBenchmarkSuite",
    "ReferenceSuitePreparer",
    "ReferenceWorkerBenchmarkError",
    "main",
    "prepare_sealed_reference_benchmark_suite",
    "run_reference_worker_benchmark",
]


if __name__ == "__main__":
    main()
