from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol


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


@dataclass(frozen=True, slots=True)
class BoundSimulatorAction:
    """A validated, immutable action admitted from a consumed dispatch."""

    action_id: str
    identity: DispatchIdentity
    incident_id: str
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
    fixture_manifest_sha256: str
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


class PublicationPort(Protocol):
    def snapshot_for_action(self, action: BoundSimulatorAction) -> ActionSnapshot: ...

    def prepare(
        self,
        snapshot: ActionSnapshot,
        trace_ids: Mapping[str, str],
    ) -> PreparedPublication: ...

    def compare_and_swap(self, prepared: PreparedPublication) -> PromotionResult: ...

    def inspect_operation(self, operation_id: str) -> PublicationOperationState: ...

    def discard(self, prepared: PreparedPublication) -> None: ...
