from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(child) for child in value]
    return value


@dataclass(frozen=True, slots=True)
class DispatchIdentity:
    """The only untrusted input accepted at the simulator action boundary."""

    task_key: str
    operation_id: str
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class StoredDispatchProof:
    """One transactional view of the authoritative consumed #22 dispatch."""

    plan: Mapping[str, Any]
    approval: Mapping[str, Any]
    authorization: Mapping[str, Any]
    consumption: Mapping[str, Any]
    audit_events: tuple[Mapping[str, Any], ...]
    records: Mapping[str, Mapping[str, Any]]
    trusted_audit_head_sha256: str


class StoredDispatchSource(Protocol):
    def load_current_consumed(self, identity: DispatchIdentity) -> StoredDispatchProof: ...

    def guard_current_consumed(
        self,
        identity: DispatchIdentity,
    ) -> AbstractContextManager[StoredDispatchProof]: ...


@dataclass(frozen=True, slots=True)
class BoundSimulatorAction:
    """A validated, immutable action admitted from a consumed dispatch."""

    action_id: str
    identity: DispatchIdentity
    incident_id: str
    incident_version: int
    plan_id: str
    plan_version: int
    plan_sha256: str
    approval_id: str
    approval_sha256: str
    authorization_id: str
    authorization_sha256: str
    consumption_id: str
    consumption_sha256: str
    action_envelope_sha256: str
    commands_sha256: str
    targets_sha256: str
    exclusions_sha256: str
    commands: tuple[Mapping[str, Any], ...]
    targets: tuple[Mapping[str, Any], ...]
    exclusions: tuple[Mapping[str, Any], ...]
    dispatch_bundle_sha256: str


@dataclass(frozen=True, slots=True)
class ActionClaim:
    action_id: str
    identity: DispatchIdentity
    owner: str
    generation: int
    lease_expires_at: str
    phase: Literal["execute", "reconcile"]
    dispatch_bundle_sha256: str


@dataclass(frozen=True, slots=True)
class ActionSnapshot:
    """The current active publication resolved against one bound action."""

    action: BoundSimulatorAction
    predecessor_pointer: Mapping[str, Any]
    predecessor_pointer_sha256: str
    predecessor_generation: int
    source_batch_id: str
    source_batch_sha256: str
    fixture_manifest_sha256: str
    runtime_manifest_sha256: str
    lineage_manifest_sha256: str
    declared_resource_manifest_sha256: str
    preservation_manifest: Mapping[str, Any]
    preservation_manifest_sha256: str
    safe_complement_manifest: Mapping[str, Any]
    safe_complement_before_sha256: str


@dataclass(frozen=True, slots=True)
class PreparedPublication:
    """A sealed private candidate; references are logical and never absolute paths."""

    operation_id: str
    publication_id: str
    predecessor_pointer: Mapping[str, Any]
    predecessor_pointer_sha256: str
    predecessor_generation: int
    candidate_generation: int
    source_batch_id: str
    source_batch_sha256: str
    candidate_fixture_manifest_sha256: str
    candidate_runtime_manifest_sha256: str
    candidate_lineage_manifest_sha256: str
    declared_resource_manifest_sha256: str
    preservation_manifest_sha256: str
    safe_complement_before_sha256: str
    safe_complement_after_sha256: str
    safe_complement_proof_sha256: str
    candidate_seal_sha256: str
    candidate_tree_sha256: str
    candidate_ref: str
    quarantine: Mapping[str, Any]
    command_results: tuple[Mapping[str, Any], ...]
    candidate_pointer: Mapping[str, Any]
    candidate_pointer_sha256: str
    prepared_at: str


@dataclass(frozen=True, slots=True)
class PromotionResult:
    """CAS evidence; recovered promotion time is the first durable observation time."""

    state: Literal["promoted", "already-promoted", "conflict"]
    before_pointer_sha256: str
    before_generation: int
    after_pointer_sha256: str
    after_generation: int
    pointer_changed: bool
    recovered: bool
    promoted_at: str | None
    observed_at: str


@dataclass(frozen=True, slots=True)
class PublicationOperationState:
    state: Literal[
        "not-found",
        "staged",
        "sealed",
        "promoted",
        "conflict",
    ]
    prepared: PreparedPublication | None
    promotion: PromotionResult | None


@dataclass(frozen=True, slots=True)
class RecoveryArtifact:
    """One allowlisted immutable artifact in a recovery snapshot."""

    root: Literal["publication", "source-batch"]
    logical_path: str
    sha256: str
    size: int
    kind: str
    role: str
    target_kind: str
    target_id: str


@dataclass(frozen=True, slots=True)
class RecoverySnapshot:
    """A data-only view of the exact active publication after one action."""

    document: Mapping[str, Any]
    artifacts: tuple[RecoveryArtifact, ...]
    _publication_id: str
    _active_pointer_sha256: str
    _trust_token: object

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], _plain_json(self.document))


class PublicationPort(Protocol):
    def snapshot_for_action(self, action: BoundSimulatorAction) -> ActionSnapshot: ...

    def prepare(
        self,
        snapshot: ActionSnapshot,
        trace_ids: Mapping[str, str],
        *,
        heartbeat: Callable[[], None] | None = None,
    ) -> PreparedPublication: ...

    def compare_and_swap(self, prepared: PreparedPublication) -> PromotionResult: ...

    def inspect_operation(self, operation_id: str) -> PublicationOperationState: ...

    def discard(self, prepared: PreparedPublication) -> None: ...


class RecoveryPublicationPort(Protocol):
    def snapshot_for_recovery(self, outcome: Mapping[str, Any]) -> RecoverySnapshot: ...

    def read_recovery_artifact(
        self,
        snapshot: RecoverySnapshot,
        artifact: RecoveryArtifact,
    ) -> bytes: ...

    def assert_recovery_snapshot_current(self, snapshot: RecoverySnapshot) -> None: ...

    def guard_recovery_closure(
        self,
        snapshot: RecoverySnapshot,
        outcome: Mapping[str, Any],
    ) -> AbstractContextManager[None]: ...
