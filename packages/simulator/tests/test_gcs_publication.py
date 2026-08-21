from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CANONICAL_SEED,
    build_scenario,
)
from colortrace_simulator.bundle import SimulatorBundleError, canonical_json_bytes
from colortrace_simulator.gcs_publication import (
    GCS_SIMULATOR_REQUIRED_PERMISSIONS,
    GcsPublicationPolicy,
    GcsPublicationPort,
)
from colortrace_simulator.models import BoundSimulatorAction, DispatchIdentity
from colortrace_simulator.renderer import sha256_bytes


class _StatusError(RuntimeError):
    def __init__(self, code: int) -> None:
        self.code = code
        super().__init__(f"status-{code}")


@dataclass(frozen=True)
class _Version:
    value: bytes
    generation: int
    content_type: str
    metadata: dict[str, str]
    cache_control: str | None


class _FakeBlob:
    def __init__(self, bucket: _FakeBucket, name: str) -> None:
        self._bucket = bucket
        self.name = name
        self.generation: int | None = None
        self.metadata: dict[str, str] | None = None
        self.content_type: str | None = None
        self.cache_control: str | None = None

    def reload(self, *, timeout: float | None = None) -> None:
        del timeout
        with self._bucket.lock:
            version = self._bucket.objects.get(self.name)
            if version is None:
                raise _StatusError(404)
            self.generation = version.generation
            self.metadata = dict(version.metadata)
            self.content_type = version.content_type
            self.cache_control = version.cache_control

    def download_as_bytes(
        self,
        *,
        if_generation_match: int | None = None,
        timeout: float | None = None,
    ) -> bytes:
        del timeout
        with self._bucket.lock:
            version = self._bucket.objects.get(self.name)
            if version is None:
                raise _StatusError(404)
            if if_generation_match is not None and version.generation != if_generation_match:
                raise _StatusError(412)
            return version.value

    def upload_from_string(
        self,
        data: bytes,
        *,
        content_type: str,
        if_generation_match: int,
        checksum: str,
        timeout: float | None = None,
    ) -> None:
        del checksum, timeout
        with self._bucket.lock:
            if self._bucket.fail_next_upload:
                self._bucket.fail_next_upload = False
                raise _StatusError(503)
            current = self._bucket.objects.get(self.name)
            actual_generation = 0 if current is None else current.generation
            if if_generation_match != actual_generation:
                raise _StatusError(412)
            self._bucket.next_generation += 1
            version = _Version(
                value=bytes(data),
                generation=self._bucket.next_generation,
                content_type=content_type,
                metadata=dict(self.metadata or {}),
                cache_control=self.cache_control,
            )
            self._bucket.objects[self.name] = version
            self._bucket.uploads.append((self.name, if_generation_match, version.generation))
            self.generation = version.generation
            self.content_type = version.content_type


class _FakeBucket:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.objects: dict[str, _Version] = {}
        self.uploads: list[tuple[str, int, int]] = []
        self.next_generation = 0
        self.fail_next_upload = False

    def blob(self, name: str) -> _FakeBlob:
        return _FakeBlob(self, name)


class _FakeClient:
    def __init__(self) -> None:
        self.bucket_value = _FakeBucket()

    def bucket(self, bucket_name: str) -> _FakeBucket:
        assert bucket_name == "synthetic-publications"
        return self.bucket_value


def _digest(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _clock() -> datetime:
    return datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="session")
def canonical_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("gcs-simulator-fixture")
    fixture = root / "bundle"
    build_scenario(
        fixture,
        oracle_root=root / "oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    return fixture


def _action(plan: dict[str, Any], operation_id: str) -> BoundSimulatorAction:
    commands = tuple(plan["commands"])
    targets = tuple(plan["targets"])
    exclusions = tuple(plan["exclusions"])
    return BoundSimulatorAction(
        action_id=f"action-{operation_id}",
        identity=DispatchIdentity(
            task_key=f"task-{operation_id}",
            operation_id=operation_id,
            payload_sha256="sha256:" + "1" * 64,
        ),
        incident_id="incident-1",
        incident_version=7,
        plan_id="plan-1",
        plan_version=3,
        plan_sha256="sha256:" + "2" * 64,
        approval_id="approval-1",
        approval_sha256="sha256:" + "3" * 64,
        authorization_id="authorization-1",
        authorization_sha256="sha256:" + "4" * 64,
        consumption_id="consumption-1",
        consumption_sha256="sha256:" + "5" * 64,
        action_envelope_sha256=_digest(plan["envelope"]),
        commands_sha256=_digest(list(commands)),
        targets_sha256=_digest(list(targets)),
        exclusions_sha256=_digest(list(exclusions)),
        commands=commands,
        targets=targets,
        exclusions=exclusions,
        dispatch_bundle_sha256="sha256:" + "6" * 64,
    )


def _traces(action: BoundSimulatorAction) -> dict[str, str]:
    return {
        str(command["command_id"]): hashlib.sha256(
            f"trace:{action.identity.operation_id}:{command['command_id']}".encode()
        ).hexdigest()[:32]
        for command in action.commands
    }


def _recovery_outcome(action: BoundSimulatorAction, prepared: Any) -> dict[str, Any]:
    body = {
        "schema": "simulator-action-outcome/v1",
        "action_id": f"simulator-action:{'a' * 64}",
        "task_key": f"dispatch-task:{'b' * 64}",
        "operation_id": action.identity.operation_id,
        "payload_sha256": action.identity.payload_sha256,
        "status": "succeeded",
        "reason_codes": [],
        "incident_id": action.incident_id,
        "incident_version": action.incident_version,
        "plan_id": action.plan_id,
        "plan_version": action.plan_version,
        "plan_sha256": action.plan_sha256,
        "approval_id": action.approval_id,
        "approval_sha256": action.approval_sha256,
        "authorization_id": action.authorization_id,
        "authorization_sha256": action.authorization_sha256,
        "consumption_id": action.consumption_id,
        "consumption_sha256": action.consumption_sha256,
        "admission_id": f"simulator-admission:{'c' * 64}",
        "admission_sha256": f"sha256:{'c' * 64}",
        "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
        "action_envelope_sha256": action.action_envelope_sha256,
        "action_started_at": "2026-08-13T12:00:00.000Z",
        "publication_intent_id": f"simulator-publication-intent:{'d' * 64}",
        "publication_intent_sha256": f"sha256:{'d' * 64}",
        "publication_receipt_id": f"simulator-publication-receipt:{'e' * 64}",
        "publication_receipt_sha256": f"sha256:{'e' * 64}",
        "publication_promoted_at": "2026-08-13T12:00:01.000Z",
        "completed_at": "2026-08-13T12:00:02.000Z",
        "fixture_id": "colortrace-canonical",
        "predecessor_publication_pointer_sha256": prepared.predecessor_pointer_sha256,
        "predecessor_publication_generation": prepared.predecessor_generation,
        "candidate_publication_pointer_sha256": prepared.candidate_pointer_sha256,
        "candidate_publication_generation": prepared.candidate_generation,
        "source_generation": prepared.predecessor_generation,
        "candidate_generation": prepared.candidate_generation,
        "source_batch_id": prepared.source_batch_id,
        "source_batch_sha256": prepared.source_batch_sha256,
        "active_publication_pointer_sha256": prepared.candidate_pointer_sha256,
        "active_runtime_manifest_sha256": prepared.candidate_runtime_manifest_sha256,
        "candidate_fixture_manifest_sha256": prepared.candidate_fixture_manifest_sha256,
        "candidate_runtime_manifest_sha256": prepared.candidate_runtime_manifest_sha256,
        "candidate_lineage_manifest_sha256": prepared.candidate_lineage_manifest_sha256,
        "declared_resource_manifest_sha256": prepared.declared_resource_manifest_sha256,
        "preservation_manifest_sha256": prepared.preservation_manifest_sha256,
        "safe_complement_before_sha256": prepared.safe_complement_before_sha256,
        "safe_complement_after_sha256": prepared.safe_complement_after_sha256,
        "safe_complement_proof_sha256": prepared.safe_complement_proof_sha256,
        "candidate_seal_sha256": prepared.candidate_seal_sha256,
        "candidate_tree_sha256": prepared.candidate_tree_sha256,
        "targets": list(action.targets),
        "exclusions": list(action.exclusions),
        "command_outcomes": list(prepared.command_results),
        "new_trace_ids": sorted(result["trace_id"] for result in prepared.command_results),
    }
    outcome_sha256 = _digest(body)
    return {
        **body,
        "outcome_id": f"simulator-action-outcome:{outcome_sha256.removeprefix('sha256:')}",
        "outcome_sha256": outcome_sha256,
    }


def _port(
    root: Path,
    canonical_bundle: Path,
    client: _FakeClient,
    **kwargs: Any,
) -> GcsPublicationPort:
    kwargs.setdefault("clock", _clock)
    return GcsPublicationPort.bootstrap(
        root=root,
        fixture_bundle=canonical_bundle,
        bucket_name="synthetic-publications",
        client=client,
        **kwargs,
    )


def _prepare(
    port: GcsPublicationPort,
    operation_id: str,
) -> tuple[BoundSimulatorAction, Any]:
    plan = port.canonical_plan_inputs()
    action = _action(plan, operation_id)
    snapshot = port.snapshot_for_action(action)
    return action, port.prepare(snapshot, _traces(action))


def test_gcs_port_has_local_parity_and_digest_addressed_storage(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    client = _FakeClient()
    port = _port(tmp_path / "first", canonical_bundle, client)
    action, prepared = _prepare(port, f"dispatch-operation:{'1' * 64}")

    assert port.inspect_operation(action.identity.operation_id).state == "staged"
    assert prepared.safe_complement_before_sha256 == prepared.safe_complement_after_sha256
    promoted = port.compare_and_swap(prepared)
    assert promoted.state == "promoted"
    assert promoted.pointer_changed is True
    assert port.compare_and_swap(prepared).state == "already-promoted"
    assert port.inspect_operation(action.identity.operation_id).state == "promoted"

    outcome = _recovery_outcome(action, prepared)
    recovery = port.snapshot_for_recovery(outcome)
    port.assert_recovery_snapshot_current(recovery)
    artifact = recovery.artifacts[0]
    value = port.read_recovery_artifact(recovery, artifact)
    assert len(value) == artifact.size
    assert sha256_bytes(value) == artifact.sha256

    entered = False
    with port.guard_recovery_closure(recovery, outcome):
        entered = True
    assert entered is True

    reopened = GcsPublicationPort(
        root=tmp_path / "reopened",
        bucket_name="synthetic-publications",
        client=client,
        clock=_clock,
    )
    assert reopened.inspect_operation(action.identity.operation_id).state == "promoted"
    assert reopened.snapshot_for_recovery(outcome).to_dict() == recovery.to_dict()

    prefix = "colortrace/simulator/v1/objects/sha256/"
    digest_objects = {
        name: version
        for name, version in client.bucket_value.objects.items()
        if name.startswith(prefix)
    }
    assert digest_objects
    for name, version in digest_objects.items():
        assert len(name.removeprefix(prefix)) == 64
        assert version.metadata["colortrace-sha256"] == hashlib.sha256(version.value).hexdigest()
        assert version.metadata["colortrace-content-type"] == version.content_type
        assert version.cache_control == "private, max-age=31536000, immutable"
    assert all(
        expected == 0
        for name, expected, _actual in client.bucket_value.uploads
        if name.startswith(prefix)
    )
    active_uploads = [
        (expected, actual)
        for name, expected, actual in client.bucket_value.uploads
        if name == port._active_key
    ]
    assert active_uploads[0][0] == 0
    assert all(
        current_actual == next_expected
        for (_current_expected, current_actual), (next_expected, _next_actual) in zip(
            active_uploads[:-1],
            active_uploads[1:],
            strict=True,
        )
    )
    assert GCS_SIMULATOR_REQUIRED_PERMISSIONS == (
        "storage.objects.create",
        "storage.objects.delete",
        "storage.objects.get",
    )


def test_generation_cas_allows_one_concurrent_promotion_and_retains_discard_evidence(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    client = _FakeClient()
    first = _port(tmp_path / "first", canonical_bundle, client)
    second = _port(tmp_path / "second", canonical_bundle, client)
    first_action, first_prepared = _prepare(first, "operation-gcs-winner-a")
    second_action, second_prepared = _prepare(second, "operation-gcs-winner-b")
    barrier = threading.Barrier(2)

    for port in (first, second):
        original = port._write_active

        def synchronized_write(
            document: Any,
            *,
            generation: int,
            selected: Any = original,
        ) -> int:
            barrier.wait(timeout=5)
            return selected(document, generation=generation)

        port._write_active = synchronized_write  # type: ignore[method-assign]

    results: dict[str, Any] = {}

    def promote(name: str, port: GcsPublicationPort, prepared: Any) -> None:
        results[name] = port.compare_and_swap(prepared)

    threads = [
        threading.Thread(target=promote, args=("first", first, first_prepared)),
        threading.Thread(target=promote, args=("second", second, second_prepared)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()

    assert sorted(result.state for result in results.values()) == ["conflict", "promoted"]
    loser_port, loser_action, loser_prepared = (
        (second, second_action, second_prepared)
        if results["first"].state == "promoted"
        else (first, first_action, first_prepared)
    )
    loser_port.discard(loser_prepared)
    loser_port.discard(loser_prepared)
    assert loser_port.inspect_operation(loser_action.identity.operation_id).state == "not-found"
    operation_root = loser_port._operation_root(loser_action.identity.operation_id)
    assert f"{operation_root}/prepared.json" in client.bucket_value.objects
    assert f"{operation_root}/discarded.json" in client.bucket_value.objects


def test_remote_pointer_failure_recovers_without_reexecution(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    class _Fault:
        armed = False

        def __call__(self, point: str) -> None:
            if self.armed and point == "gcs-pointer-durable":
                self.armed = False
                raise RuntimeError(point)

    client = _FakeClient()
    fault = _Fault()
    port = _port(tmp_path / "first", canonical_bundle, client, fault_hook=fault)
    action, prepared = _prepare(port, "operation-gcs-recovery")
    fault.armed = True
    with pytest.raises(RuntimeError, match="gcs-pointer-durable"):
        port.compare_and_swap(prepared)

    recovered = GcsPublicationPort(
        root=tmp_path / "recovered",
        bucket_name="synthetic-publications",
        client=client,
        clock=_clock,
    )
    inspected = recovered.inspect_operation(action.identity.operation_id)
    assert inspected.state == "promoted"
    assert inspected.prepared is not None
    assert inspected.prepared.publication_id == prepared.publication_id
    assert inspected.prepared.candidate_seal_sha256 == prepared.candidate_seal_sha256
    assert inspected.prepared.candidate_pointer_sha256 == prepared.candidate_pointer_sha256
    replay = recovered.compare_and_swap(prepared)
    assert replay.state == "already-promoted"
    assert replay.pointer_changed is False


def test_failed_candidate_upload_does_not_change_active_pointer_and_prepare_is_recoverable(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    client = _FakeClient()
    port = _port(tmp_path / "first", canonical_bundle, client)
    plan = port.canonical_plan_inputs()
    action = _action(plan, "operation-gcs-upload-failure")
    snapshot = port.snapshot_for_action(action)
    active_key = port._active_key
    before = client.bucket_value.objects[active_key]
    client.bucket_value.fail_next_upload = True

    with pytest.raises(SimulatorBundleError, match="gcs-object-write-failed"):
        port.prepare(snapshot, _traces(action))
    assert client.bucket_value.objects[active_key] == before

    prepared = port.prepare(snapshot, _traces(action))
    assert port.inspect_operation(action.identity.operation_id).prepared == prepared
    assert port.compare_and_swap(prepared).state == "promoted"


def test_storage_policy_is_explicit_and_rejects_zero_retention() -> None:
    assert GcsPublicationPolicy().document() == {
        "schema": "colortrace-gcs-publication-policy/v1",
        "object_naming": "objects/sha256/{digest}",
        "immutable_object_mutation": "create-only",
        "discard_behavior": "tombstone-and-retain",
        "artifact_retention_days": 7,
        "discarded_candidate_retention_days": 7,
        "noncurrent_pointer_retention_days": 7,
    }
    with pytest.raises(ValueError, match="retention"):
        GcsPublicationPolicy(artifact_retention_days=0)
