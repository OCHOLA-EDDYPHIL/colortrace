from __future__ import annotations

import asyncio
import copy
import hashlib
from array import array
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from colortrace_fixture.fixture import (
    CHANNELS,
    PIXELS,
    canonical_float_bytes,
)
from colortrace_recovery import (
    DeterministicRecoveryVerifier,
    NormalizedActionObservation,
    RecoveryReadService,
    SimulatorActionEvidenceProjection,
    SynchronousRecoveryWorkflowRunner,
    canonical_json_bytes,
    document_sha256,
    project_recovery_verification_snapshot,
    verification_state_sha256,
)
from colortrace_simulator import RecoveryArtifact, RecoverySnapshot
from colortrace_simulator.bundle import RecoverySnapshotError
from colortrace_telemetry.action_emitter import build_action_events
from test_recovery import (
    BASE,
    Clock,
    digest,
    principal,
    seal_outcome,
    setup_services,
    successful_outcome,
)


def _sha(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _document(value: Mapping[str, Any]) -> tuple[bytes, str]:
    raw = canonical_json_bytes(value)
    return raw, _sha(raw)


class OutcomeSource:
    def __init__(self, outcome: dict[str, Any]) -> None:
        self.outcome = outcome

    def outcome_for_incident(
        self,
        incident_id: str,
        *,
        expected_outcome_sha256: str | None = None,
    ) -> dict[str, Any] | None:
        return (
            copy.deepcopy(self.outcome)
            if incident_id == self.outcome["incident_id"]
            and expected_outcome_sha256 == self.outcome["outcome_sha256"]
            else None
        )


class Publication:
    def __init__(
        self,
        snapshot: RecoverySnapshot,
        values: Mapping[RecoveryArtifact, bytes],
    ) -> None:
        self.snapshot = snapshot
        self.values = dict(values)
        self.read_error_role: str | None = None
        self.read_error_classification: str = "failed"
        self.current = True
        self.snapshot_calls = 0
        self.next_observed_at: str | None = None

    def queue_reobservation(self, observed_at: str) -> None:
        self.next_observed_at = observed_at

    def snapshot_for_recovery(self, outcome: Mapping[str, Any]) -> RecoverySnapshot:
        self.snapshot_calls += 1
        assert outcome["outcome_sha256"] == self.snapshot.document["outcome_sha256"]
        if self.next_observed_at is not None:
            document = self.snapshot.to_dict()
            document["observed_at"] = self.next_observed_at
            body = {
                key: child
                for key, child in document.items()
                if key not in {"snapshot_id", "snapshot_sha256"}
            }
            snapshot_sha256 = document_sha256(body)
            self.snapshot = RecoverySnapshot(
                {
                    **body,
                    "snapshot_id": (
                        f"simulator-recovery-snapshot:{snapshot_sha256.removeprefix('sha256:')}"
                    ),
                    "snapshot_sha256": snapshot_sha256,
                },
                self.snapshot.artifacts,
                self.snapshot._publication_id,
                self.snapshot._active_pointer_sha256,
                object(),
            )
            self.next_observed_at = None
        return self.snapshot

    def read_recovery_artifact(
        self,
        snapshot: RecoverySnapshot,
        artifact: RecoveryArtifact,
    ) -> bytes:
        assert snapshot is self.snapshot
        if artifact.role == self.read_error_role:
            raise RecoverySnapshotError(
                "recovery-artifact-unreadable",
                cast(Any, self.read_error_classification),
            )
        return self.values[artifact]

    def assert_recovery_snapshot_current(self, snapshot: RecoverySnapshot) -> None:
        assert snapshot is self.snapshot
        if not self.current:
            raise RecoverySnapshotError("recovery-snapshot-stale", "failed")


class Collector:
    def __init__(self, outcome: Mapping[str, Any], clock: Clock) -> None:
        self.outcome = outcome
        self.clock = clock
        self.calls = 0
        self.mode = "success"
        self.last_batch: Any = None
        self.cancelled = False
        self.catalog_sha256 = digest("c")

    @property
    def simulator_action_catalog_sha256(self) -> str:
        return self.catalog_sha256

    async def collect_simulator_action_projection(
        self,
        batch: Any,
    ) -> SimulatorActionEvidenceProjection:
        self.calls += 1
        self.last_batch = batch
        if self.mode == "timeout":
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True
        if self.mode == "cancel-once":
            self.mode = "success"
            raise asyncio.CancelledError
        if self.mode == "fence":
            self.clock.now = BASE + timedelta(seconds=31)
        elif self.mode == "late":
            self.clock.now = BASE + timedelta(minutes=11)
        else:
            self.clock.now = max(self.clock.now, BASE) + timedelta(seconds=1)
        events = (
            []
            if self.mode == "missing"
            else build_action_events(
                self.outcome,
                emitted_at="2026-08-13T12:00:03.000Z",
            )
        )
        observations: list[NormalizedActionObservation] = []
        for event in events:
            document = event.to_dict()
            observation = cast(Mapping[str, Any], document["observation"])
            if observation["schema"] == "simulator-command-observation/v1":
                result = cast(Mapping[str, Any], observation["result"])
                subject_kind = "command"
                subject_id = cast(str, result["command_id"])
            else:
                subject_kind = "safe"
                subject_id = cast(str, cast(Mapping[str, Any], observation["target"])["id"])
            correlation = cast(Mapping[str, Any], document["correlation"])
            outcome_id = cast(str, self.outcome["outcome_id"])
            if self.mode == "contradiction" and not observations:
                outcome_id = f"simulator-action-outcome:{'f' * 64}"
            observations.append(
                NormalizedActionObservation(
                    event_id=cast(str, document["event_id"]),
                    signal=cast(Any, document["signal"]),
                    subject_kind=cast(Any, subject_kind),
                    subject_id=subject_id,
                    trace_id=cast(str | None, correlation["trace_id"]),
                    outcome_id=outcome_id,
                    outcome_sha256=cast(str, self.outcome["outcome_sha256"]),
                    action_id=cast(str, self.outcome["action_id"]),
                    operation_id=cast(str, self.outcome["operation_id"]),
                    observed_at=cast(str, document["observed_at"]),
                    emitted_at=cast(str, document["emitted_at"]),
                    retrieved_at=self.clock.now.isoformat(timespec="milliseconds").replace(
                        "+00:00",
                        "Z",
                    ),
                    clock_provenance="otel-collector",
                    clock_skew_milliseconds=0,
                    truncated=False,
                    source_label=f"grafana.{document['signal']}",
                    source_envelope=document,
                )
            )
        return SimulatorActionEvidenceProjection(
            request_id=batch.request_id,
            evidence_request_id=(
                f"recovery-evidence-request:{'f' * 64}"
                if self.mode == "authorization-mismatch"
                else batch.evidence_request_id
            ),
            evidence_request_sha256=batch.evidence_request_sha256,
            catalog_sha256=batch.catalog_sha256,
            incident_id=batch.incident_id,
            outcome_id=batch.outcome_id,
            outcome_sha256=batch.outcome_sha256,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            action_id=batch.action_id,
            operation_id=batch.operation_id,
            completed_at=self.clock.now,
            observations=tuple(observations),
        )


def _fixture() -> tuple[dict[str, Any], RecoverySnapshot, dict[RecoveryArtifact, bytes]]:
    outcome = successful_outcome()
    operation_id = cast(str, outcome["operation_id"])
    float_raw = canonical_float_bytes(array("f", [0.25]) * (PIXELS * CHANNELS))
    float_sha = _sha(float_raw)
    resource_raw = b"approved color resource\n"
    resource_sha = _sha(resource_raw)
    safe_raw = b"unchanged safe file\n"
    safe_sha = _sha(safe_raw)
    target_frames = ("frame-affected-a", "frame-affected-b", "frame-affected-c")
    safe_frames = ("frame-safe-a", "frame-safe-b", "frame-safe-c")
    traces = {
        cast(str, cast(Mapping[str, Any], result["target"])["id"]): cast(str, result["trace_id"])
        for result in cast(list[Mapping[str, Any]], outcome["command_outcomes"])
    }
    output_ids = {value: f"output-{value}" for value in (*target_frames, *safe_frames)}
    frames: list[dict[str, Any]] = []
    for frame_id in target_frames:
        frames.append(
            {
                "frame_id": frame_id,
                "output_id": output_ids[frame_id],
                "worker_id": "worker-affected",
                "output_path": f"runtime/frames/{frame_id}/output.rgbf32",
                "output_sha256": float_sha,
                "output_size": len(float_raw),
                "display_path": f"runtime/frames/{frame_id}/display.png",
                "display_sha256": digest("a"),
                "display_size": 10,
                "reference_buffer_path": f"fixture/references/{frame_id}.rgbf32",
                "reference_buffer_sha256": float_sha,
                "trace_id": traces[frame_id],
                "last_operation_id": operation_id,
            }
        )
    for frame_id in safe_frames:
        frames.append(
            {
                "frame_id": frame_id,
                "output_id": output_ids[frame_id],
                "worker_id": "worker-safe",
                "output_path": f"runtime/frames/{frame_id}/output.rgbf32",
                "output_sha256": digest("b"),
                "output_size": 10,
                "display_path": f"runtime/frames/{frame_id}/display.png",
                "display_sha256": digest("c"),
                "display_size": 10,
                "reference_buffer_path": f"fixture/references/{frame_id}.rgbf32",
                "reference_buffer_sha256": digest("d"),
                "trace_id": None,
                "last_operation_id": None,
            }
        )
    derivative_id = "derivative-affected"
    derivative = {
        "artifact_id": derivative_id,
        "parent_artifact_id": output_ids[target_frames[0]],
        "buffer_path": "runtime/derivatives/affected/output.rgbf32",
        "buffer_sha256": float_sha,
        "buffer_size": len(float_raw),
        "display_path": "runtime/derivatives/affected/display.png",
        "display_sha256": digest("e"),
        "display_size": 10,
        "trace_id": traces[derivative_id],
        "last_operation_id": operation_id,
    }
    resources = [
        {
            "worker_id": "worker-affected",
            "resource_path": "runtime/resources/approved.cube",
            "resource_sha256": resource_sha,
            "resource_size": len(resource_raw),
            "trace_id": traces[cast(str, cast(Mapping[str, Any], outcome["targets"][0])["id"])],
            "last_operation_id": operation_id,
        },
        {
            "worker_id": "worker-safe",
            "resource_path": "runtime/resources/safe.cube",
            "resource_sha256": digest("f"),
            "resource_size": 10,
            "trace_id": None,
            "last_operation_id": None,
        },
    ]
    mutable: list[dict[str, Any]] = [
        {
            "kind": "resource",
            "id": cast(Mapping[str, Any], outcome["targets"][0])["id"],
            "path": "runtime/resources/approved.cube",
            "sha256": digest("1"),
            "size": 10,
        }
    ]
    for frame_id in target_frames:
        mutable.extend(
            (
                {
                    "kind": "frame-output",
                    "id": frame_id,
                    "path": f"runtime/frames/{frame_id}/output.rgbf32",
                    "sha256": digest("1"),
                    "size": 10,
                },
                {
                    "kind": "frame-display",
                    "id": frame_id,
                    "path": f"runtime/frames/{frame_id}/display.png",
                    "sha256": digest("2"),
                    "size": 10,
                },
            )
        )
    mutable.extend(
        (
            {
                "kind": "derivative-output",
                "id": derivative_id,
                "path": derivative["buffer_path"],
                "sha256": digest("3"),
                "size": 10,
            },
            {
                "kind": "derivative-display",
                "id": derivative_id,
                "path": derivative["display_path"],
                "sha256": digest("4"),
                "size": 10,
            },
        )
    )
    quarantine_path = f"runtime/quarantine/sha256/{'1' * 64}.cube"
    files = [
        {"path": value["path"], "sha256": digest("1"), "size": 10, "kind": value["kind"]}
        for value in mutable
    ]
    files.extend(
        (
            {
                "path": "manifests/lineage.json",
                "sha256": digest("2"),
                "size": 10,
                "kind": "lineage",
            },
            {"path": quarantine_path, "sha256": digest("1"), "size": 10, "kind": "quarantine"},
            {"path": "runtime/safe.bin", "sha256": safe_sha, "size": len(safe_raw), "kind": "safe"},
        )
    )
    runtime = {
        "schema": "simulator-runtime-manifest/v1",
        "fixture_id": outcome["fixture_id"],
        "generation": outcome["candidate_publication_generation"],
        "source_batch_id": outcome["source_batch_id"],
        "source_batch_sha256": outcome["source_batch_sha256"],
        "resources": resources,
        "frames": frames,
        "derivatives": [derivative],
        "lineage": {"path": "manifests/lineage.json", "sha256": digest("2")},
        "files": files,
    }
    runtime_raw, runtime_sha = _document(runtime)
    lineage = {
        "schema": "artifact-lineage/v1",
        "edges": [
            {
                "edge_type": "lossless-derivative/v1",
                "parent_artifact_id": derivative["parent_artifact_id"],
                "child_artifact_id": derivative_id,
            }
        ],
        "artifacts": [
            {
                "artifact_id": derivative_id,
                "artifact_type": "lossless-derivative",
                "buffer": derivative["buffer_path"],
                "sha256": float_sha.removeprefix("sha256:"),
                "display": derivative["display_path"],
                "display_sha256": digest("e").removeprefix("sha256:"),
                "generator": "lossless-float-copy/v1",
            }
        ],
    }
    lineage_raw, lineage_sha = _document(lineage)
    fixture = {"schema": "simulator-fixture-manifest/v1", "fixture_id": outcome["fixture_id"]}
    fixture_raw, fixture_sha = _document(fixture)
    targets = cast(list[Mapping[str, Any]], outcome["targets"])
    exclusions = cast(list[Mapping[str, Any]], outcome["exclusions"])

    def ordered(values: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        return sorted(
            values,
            key=lambda value: (
                str(value["namespace"]),
                str(value["kind"]),
                str(value["id"]),
            ),
        )

    preservation = {
        "schema": "simulator-preservation-manifest/v1",
        "fixture_id": outcome["fixture_id"],
        "targets_sha256": _sha(canonical_json_bytes(ordered(targets))),
        "exclusions_sha256": _sha(canonical_json_bytes(ordered(exclusions))),
        "mutable_entries": mutable,
        "metadata_reseal_paths": [
            "manifests/fixture.json",
            "manifests/lineage.json",
            "manifests/runtime.json",
        ],
        "allowed_additions": [
            {"kind": "quarantine", "path": quarantine_path, "sha256": digest("1")}
        ],
        "target_invariants": [{"kind": "target", "id": str(index)} for index in range(5)],
        "safe_complement_sha256": "pending",
    }
    target_worker = "worker-affected"
    safe = {
        "schema": "simulator-safe-complement/v1",
        "fixture_id": runtime["fixture_id"],
        "source_batch_id": runtime["source_batch_id"],
        "source_batch_sha256": runtime["source_batch_sha256"],
        "files": [
            {
                "kind": "safe",
                "id": "runtime/safe.bin",
                "path": "runtime/safe.bin",
                "sha256": safe_sha,
                "size": len(safe_raw),
            }
        ],
        "records": sorted(
            [
                {
                    "kind": "resource",
                    "id": value["worker_id"],
                    "record_sha256": _sha(canonical_json_bytes(value)),
                }
                for value in resources
                if value["worker_id"] != target_worker
            ]
            + [
                {
                    "kind": "frame",
                    "id": value["frame_id"],
                    "record_sha256": _sha(canonical_json_bytes(value)),
                }
                for value in frames
                if value["frame_id"] not in target_frames
            ],
            key=lambda value: (str(value["kind"]), str(value["id"])),
        ),
    }
    safe_raw_document, safe_document_sha = _document(safe)
    preservation["safe_complement_sha256"] = safe_document_sha
    preservation_raw, preservation_sha = _document(preservation)
    proof = {
        "schema": "simulator-safe-complement-proof/v1",
        "preservation_manifest_sha256": preservation_sha,
        "before_sha256": safe_document_sha,
        "after_sha256": safe_document_sha,
        "byte_identical": True,
    }
    proof_raw, proof_sha = _document(proof)
    pointer = {
        "schema": "simulator-publication-pointer/v1",
        "publication_id": f"publication:{'a' * 64}",
        "operation_id": operation_id,
        "generation": outcome["candidate_publication_generation"],
        "runtime_manifest_sha256": runtime_sha,
    }
    pointer_sha = _sha(canonical_json_bytes(pointer))
    results = cast(list[dict[str, Any]], outcome["command_outcomes"])
    results[0]["after"]["resource_sha256"] = resource_sha
    results[1]["after"]["derivative_sha256"] = float_sha
    for result in results[2:]:
        result["after"]["output_sha256"] = float_sha
    outcome.update(
        {
            "candidate_publication_pointer_sha256": pointer_sha,
            "active_publication_pointer_sha256": pointer_sha,
            "candidate_fixture_manifest_sha256": fixture_sha,
            "candidate_runtime_manifest_sha256": runtime_sha,
            "active_runtime_manifest_sha256": runtime_sha,
            "candidate_lineage_manifest_sha256": lineage_sha,
            "preservation_manifest_sha256": preservation_sha,
            "safe_complement_before_sha256": safe_document_sha,
            "safe_complement_after_sha256": safe_document_sha,
            "safe_complement_proof_sha256": proof_sha,
        }
    )
    seal_outcome(outcome)
    artifacts = [
        RecoveryArtifact(
            "publication",
            "runtime/resources/approved.cube",
            resource_sha,
            len(resource_raw),
            "resource",
            "active-resource",
            "color-resource",
            cast(str, cast(Mapping[str, Any], outcome["targets"][0])["id"]),
        )
    ]
    values_by_key: dict[tuple[str, str, str], bytes] = {
        ("active-resource", "color-resource", artifacts[0].target_id): resource_raw
    }
    for frame_id in target_frames:
        artifacts.extend(
            (
                RecoveryArtifact(
                    "publication",
                    f"runtime/frames/{frame_id}/output.rgbf32",
                    float_sha,
                    len(float_raw),
                    "frame-output",
                    "affected-output",
                    "frame",
                    frame_id,
                ),
                RecoveryArtifact(
                    "source-batch",
                    f"fixture/references/{frame_id}.rgbf32",
                    float_sha,
                    len(float_raw),
                    "declared-reference",
                    "declared-reference",
                    "frame",
                    frame_id,
                ),
            )
        )
        values_by_key[("affected-output", "frame", frame_id)] = float_raw
        values_by_key[("declared-reference", "frame", frame_id)] = float_raw
    artifacts.extend(
        (
            RecoveryArtifact(
                "publication",
                cast(str, derivative["buffer_path"]),
                float_sha,
                len(float_raw),
                "derivative-output",
                "derivative-output",
                "derivative",
                derivative_id,
            ),
            RecoveryArtifact(
                "publication",
                f"runtime/frames/{target_frames[0]}/output.rgbf32",
                float_sha,
                len(float_raw),
                "frame-output",
                "derivative-parent",
                "frame",
                target_frames[0],
            ),
        )
    )
    values_by_key[("derivative-output", "derivative", derivative_id)] = float_raw
    values_by_key[("derivative-parent", "frame", target_frames[0])] = float_raw
    controls = (
        ("fixture-manifest", "manifests/fixture.json", fixture_raw, fixture_sha),
        ("runtime-manifest", "manifests/runtime.json", runtime_raw, runtime_sha),
        ("lineage-manifest", "manifests/lineage.json", lineage_raw, lineage_sha),
        (
            "preservation-manifest",
            "manifests/preservation.json",
            preservation_raw,
            preservation_sha,
        ),
        ("safe-complement", "manifests/safe-complement.json", safe_raw_document, safe_document_sha),
        ("safe-complement-proof", "manifests/safe-complement-proof.json", proof_raw, proof_sha),
    )
    for role, path, raw, sha in controls:
        artifacts.append(
            RecoveryArtifact(
                "publication",
                path,
                sha,
                len(raw),
                "control",
                role,
                "publication",
                cast(str, pointer["publication_id"]),
            )
        )
        values_by_key[(role, "publication", cast(str, pointer["publication_id"]))] = raw
    artifacts.sort(
        key=lambda value: (
            value.role,
            value.target_kind,
            value.target_id,
            value.root,
            value.logical_path,
        )
    )
    artifact_values = {
        artifact: values_by_key[(artifact.role, artifact.target_kind, artifact.target_id)]
        for artifact in artifacts
    }
    active = {
        "publication_id": pointer["publication_id"],
        "pointer_sha256": pointer_sha,
        "generation": outcome["candidate_publication_generation"],
        "operation_id": operation_id,
        "fixture_manifest_sha256": fixture_sha,
        "runtime_manifest_sha256": runtime_sha,
        "lineage_manifest_sha256": lineage_sha,
        "declared_resource_manifest_sha256": outcome["declared_resource_manifest_sha256"],
        "candidate_seal_sha256": outcome["candidate_seal_sha256"],
        "candidate_tree_sha256": outcome["candidate_tree_sha256"],
        "preservation_manifest_sha256": preservation_sha,
        "safe_complement_before_sha256": safe_document_sha,
        "safe_complement_after_sha256": safe_document_sha,
        "safe_complement_proof_sha256": proof_sha,
    }
    body = {
        "schema": "simulator-recovery-snapshot/v1",
        "outcome_id": outcome["outcome_id"],
        "outcome_sha256": outcome["outcome_sha256"],
        "action_id": outcome["action_id"],
        "incident_id": outcome["incident_id"],
        "incident_version": outcome["incident_version"],
        "operation_id": operation_id,
        "action_started_at": outcome["action_started_at"],
        "action_completed_at": outcome["completed_at"],
        "observed_at": "2026-08-13T12:00:02.500Z",
        "active_publication": active,
        "documents": {
            "publication_pointer": pointer,
            "fixture_manifest": fixture,
            "runtime_manifest": runtime,
            "lineage_manifest": lineage,
            "source_batch_manifest": {"schema": "simulator-source-batch/v1"},
            "preservation_manifest": preservation,
            "safe_complement_manifest": safe,
            "safe_complement_proof": proof,
            "candidate_seal": {"schema": "simulator-candidate-seal/v1"},
        },
        "artifacts": [
            {
                "root": artifact.root,
                "logical_path": artifact.logical_path,
                "sha256": artifact.sha256,
                "size": artifact.size,
                "kind": artifact.kind,
                "role": artifact.role,
                "target_kind": artifact.target_kind,
                "target_id": artifact.target_id,
            }
            for artifact in artifacts
        ],
        "targets": outcome["targets"],
        "exclusions": outcome["exclusions"],
        "command_outcomes": outcome["command_outcomes"],
        "recomputed_safe_complement": safe,
        "recomputed_safe_complement_sha256": safe_document_sha,
    }
    snapshot_sha = document_sha256(body)
    snapshot_document = {
        **body,
        "snapshot_id": f"simulator-recovery-snapshot:{snapshot_sha.removeprefix('sha256:')}",
        "snapshot_sha256": snapshot_sha,
    }
    return (
        outcome,
        RecoverySnapshot(
            snapshot_document,
            tuple(artifacts),
            cast(str, pointer["publication_id"]),
            pointer_sha,
            object(),
        ),
        artifact_values,
    )


OUTCOME_SHA256 = cast(str, _fixture()[0]["outcome_sha256"])


def _workflow(
    tmp_path: Path,
    *,
    collection_timeout_seconds: float = 60.0,
) -> tuple[
    DeterministicRecoveryVerifier,
    Publication,
    Collector,
    Any,
    Any,
    Clock,
]:
    outcome, snapshot, values = _fixture()
    repository, verification, _closure, boundary, clock = setup_services(tmp_path)
    publication = Publication(snapshot, values)
    collector = Collector(outcome, clock)
    workflow = DeterministicRecoveryVerifier(
        outcomes=OutcomeSource(outcome),
        publication=publication,
        collector=collector,
        verification=verification,
        reads=RecoveryReadService(repository),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus-main",
            "loki_datasource_uid": "loki-main",
            "tempo_datasource_uid": "tempo-main",
        },
        evidence_catalog_sha256=digest("c"),
        clock=clock,
        heartbeat_seconds=0.1,
        collection_timeout_seconds=collection_timeout_seconds,
    )
    return workflow, publication, collector, repository, boundary, clock


def test_deterministic_workflow_verifies_and_replays(tmp_path: Path) -> None:
    workflow, _publication, collector, repository, boundary, _clock = _workflow(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-success",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_verified"
    assert [value["check"] for value in packet["check_results"]] == [
        "active-publication",
        "approved-resource-state",
        "declared-reference-recovery",
        "exact-typed-lineage",
        "approved-recovery-scope",
        "safe-complement-preservation",
        "post-action-telemetry-correlation",
    ]
    assert all(value["state"] == "passed" for value in packet["check_results"])
    assert len(repository.durable_aggregate(packet["workflow_id"])["evidence"]) == 21
    assert (
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-success",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
        == packet
    )
    assert (
        SynchronousRecoveryWorkflowRunner(workflow).verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-through-sync-runner",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
        == packet
    )
    assert (
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-success-new-key",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
        == packet
    )
    assert collector.calls == 1


def test_unresolved_same_key_replays_before_fresh_state_equivalent_retry(
    tmp_path: Path,
) -> None:
    workflow, publication, collector, repository, boundary, clock = _workflow(tmp_path)
    collector.mode = "missing"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    first = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-unresolved-replay",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert first["status"] == "recovery_unresolved"
    assert publication.snapshot_calls == 1
    publication.queue_reobservation("2026-08-13T12:00:03.000Z")
    clock.now = BASE + timedelta(seconds=2)
    collector.mode = "success"
    assert (
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-unresolved-replay",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
        == first
    )
    assert publication.snapshot_calls == 1
    assert collector.calls == 1

    second = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-unresolved-new-attempt",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert second["status"] == "recovery_verified"
    assert second["attempt_number"] == 2
    assert second["supersedes_packet_id"] == first["packet_id"]
    assert publication.snapshot_calls == 2
    assert (
        collector.last_batch.snapshot_sha256
        != repository.durable_aggregate(second["workflow_id"])["snapshot"]["snapshot_sha256"]
    )
    aggregate = repository.durable_aggregate(second["workflow_id"])
    assert verification_state_sha256(
        project_recovery_verification_snapshot(collector.outcome, publication.snapshot)
    ) == verification_state_sha256(aggregate["snapshot"])
    assert aggregate["evidence_request"]["state_equivalence_sha256"] == (
        verification_state_sha256(aggregate["snapshot"])
    )


def test_catalog_authority_mismatch_fails_before_repository_mutation(tmp_path: Path) -> None:
    outcome, snapshot, values = _fixture()
    repository, verification, _closure, _boundary, clock = setup_services(tmp_path)
    collector = Collector(outcome, clock)
    collector.catalog_sha256 = digest("f")
    with pytest.raises(Exception, match="evidence-catalog-binding-invalid"):
        DeterministicRecoveryVerifier(
            outcomes=OutcomeSource(outcome),
            publication=Publication(snapshot, values),
            collector=collector,
            verification=verification,
            reads=RecoveryReadService(repository),
            evidence_binding={
                "prometheus_datasource_uid": "prometheus-main",
                "loki_datasource_uid": "loki-main",
                "tempo_datasource_uid": "tempo-main",
            },
            evidence_catalog_sha256=digest("c"),
            clock=clock,
        )
    with repository.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM recovery_workflows").fetchone()[0] == 0


def test_batch_setup_and_late_collection_complete_durable_unresolved(
    tmp_path: Path,
) -> None:
    setup_root = tmp_path / "setup"
    setup_root.mkdir()
    workflow, publication, collector, repository, boundary, clock = _workflow(setup_root)
    publication.queue_reobservation("2026-08-13T12:11:00.000Z")
    clock.now = BASE + timedelta(minutes=11)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-late-batch",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_unresolved"
    assert collector.calls == 0
    assert repository.review(packet["workflow_id"])["status"] == "recovery_unresolved"

    collection_root = tmp_path / "collection"
    collection_root.mkdir()
    workflow, _publication, collector, repository, boundary, _clock = _workflow(collection_root)
    collector.mode = "late"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-late-collection",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_unresolved"
    assert repository.review(packet["workflow_id"])["status"] == "recovery_unresolved"


def test_projection_authorization_mismatch_is_not_accepted(tmp_path: Path) -> None:
    workflow, _publication, collector, repository, boundary, _clock = _workflow(tmp_path)
    collector.mode = "authorization-mismatch"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-authorization-mismatch",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_unresolved"
    assert repository.durable_aggregate(packet["workflow_id"])["evidence"] == []


@pytest.mark.parametrize(
    ("role", "classification", "status"),
    [
        ("affected-output", "failed", "recovery_failed"),
        ("declared-reference", "unresolved", "recovery_unresolved"),
    ],
)
def test_artifact_mutation_classification(
    tmp_path: Path,
    role: str,
    classification: str,
    status: str,
) -> None:
    workflow, publication, _collector, _repository, boundary, _clock = _workflow(tmp_path)
    publication.read_error_role = role
    publication.read_error_classification = classification
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key=f"verify-{role}",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == status


def test_current_incident_version_must_match_before_registration(tmp_path: Path) -> None:
    workflow, _publication, collector, repository, boundary, _clock = _workflow(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    with pytest.raises(Exception, match="recovery-incident-version-conflict"):
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-stale-version",
                expected_incident_version=5,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
    with repository.transaction(write=False) as connection:
        assert connection.execute("SELECT COUNT(*) FROM recovery_workflows").fetchone()[0] == 0
    assert collector.calls == 0


def test_missing_provider_data_is_unresolved_and_correlation_lie_fails(
    tmp_path: Path,
) -> None:
    workflow, _publication, collector, _repository, boundary, _clock = _workflow(tmp_path)
    collector.mode = "missing"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    assert (
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-missing",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
    )["status"] == ("recovery_unresolved")

    second = tmp_path / "second"
    second.mkdir()
    workflow, _publication, collector, _repository, boundary, _clock = _workflow(second)
    collector.mode = "contradiction"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-contradiction",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_failed"


def test_collection_deadline_cancels_and_completes_unresolved(tmp_path: Path) -> None:
    workflow, _publication, collector, _repository, boundary, _clock = _workflow(
        tmp_path,
        collection_timeout_seconds=0.01,
    )
    collector.mode = "timeout"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-timeout",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_unresolved"
    assert collector.cancelled is True


def test_cancelled_run_reclaims_after_lease_and_stale_completion_is_fenced(
    tmp_path: Path,
) -> None:
    workflow, _publication, collector, _repository, boundary, clock = _workflow(tmp_path)
    collector.mode = "cancel-once"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-restart",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
    clock.now = BASE + timedelta(seconds=31)
    packet = asyncio.run(
        workflow.verify(
            verifier,
            "incident-action-01",
            idempotency_key="verify-restart",
            expected_incident_version=4,
            expected_outcome_sha256=OUTCOME_SHA256,
        )
    )
    assert packet["status"] == "recovery_verified"

    second = tmp_path / "fenced"
    second.mkdir()
    workflow, _publication, collector, _repository, boundary, _clock = _workflow(second)
    collector.mode = "fence"
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    with pytest.raises(Exception, match="claim-fenced"):
        asyncio.run(
            workflow.verify(
                verifier,
                "incident-action-01",
                idempotency_key="verify-fenced",
                expected_incident_version=4,
                expected_outcome_sha256=OUTCOME_SHA256,
            )
        )
