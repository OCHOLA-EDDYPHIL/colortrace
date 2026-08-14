from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from colortrace_response_plans import ResponsePlanError

from .authority import (
    ExecutorAuthorization,
    SimulatorAuthorityBoundary,
    SimulatorAuthorityError,
    SimulatorExecutorBoundary,
)
from .bundle import SimulatorBundleError
from .models import DispatchIdentity, PublicationPort, StoredDispatchSource
from .renderer import RendererError
from .repository import SimulatorRepositoryError, SQLiteSimulatorRepository

_REASON_CODE = re.compile(r"[a-z][a-z0-9-]{1,63}")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _trace_id() -> str:
    return secrets.token_hex(16)


TerminalObserver = Callable[[Mapping[str, Any]], object]


class SimulatorActionService:
    """Admit and execute one exact consumed dispatch inside the local publication port."""

    def __init__(
        self,
        *,
        repository: SQLiteSimulatorRepository,
        dispatch_source: StoredDispatchSource,
        authority_boundary: SimulatorAuthorityBoundary,
        executor_boundary: SimulatorExecutorBoundary,
        publication: PublicationPort,
        clock: Callable[[], datetime] = _utc_now,
        trace_id_factory: Callable[[], str] = _trace_id,
        terminal_observer: TerminalObserver | None = None,
    ) -> None:
        self._repository = repository
        self._dispatch_source = dispatch_source
        self._authority_boundary = authority_boundary
        self._executor_boundary = executor_boundary
        self._publication = publication
        self._clock = clock
        self._trace_id_factory = trace_id_factory
        self._terminal_observer = terminal_observer

    @staticmethod
    def _identity_from_outcome(outcome: Mapping[str, Any]) -> DispatchIdentity:
        return DispatchIdentity(
            task_key=str(outcome["task_key"]),
            operation_id=str(outcome["operation_id"]),
            payload_sha256=str(outcome["payload_sha256"]),
        )

    def _observe(self, outcome: Mapping[str, Any]) -> None:
        if self._terminal_observer is None:
            return
        identity = self._identity_from_outcome(outcome)
        try:
            if self._repository.telemetry_delivered(identity):
                return
            receipt = self._terminal_observer(outcome)
            if isinstance(receipt, Mapping):
                self._repository.record_telemetry_receipt(identity, receipt)
        except Exception:
            # The durable outcome remains authoritative. Delivery is at-least-once and
            # must never reopen or rerun simulator execution.
            return

    def _cleanup_conflicted_candidate(
        self,
        identity: DispatchIdentity,
        outcome: Mapping[str, Any],
    ) -> None:
        if outcome.get("reason_codes") != ["publication-pointer-conflict"]:
            return
        try:
            state = self._publication.inspect_operation(identity.operation_id)
            if state.state == "conflict" and state.prepared is not None:
                self._publication.discard(state.prepared)
        except (SimulatorBundleError, RendererError):
            # Cleanup is retryable from the durable terminal outcome and may not
            # rewrite the active publication or the action result.
            return

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]:
        replay = self._repository.replay_admission(identity)
        if replay is not None:
            self._executor_boundary.assert_authorized(
                executor,
                incident_id=str(replay["incident_id"]),
            )
            return replay

        proof = self._dispatch_source.load_current_consumed(identity)
        bundle = self._authority_boundary.bind(identity, proof)
        actor = self._executor_boundary.assert_authorized(
            executor,
            incident_id=bundle.action.incident_id,
        )
        return self._repository.admit(
            bundle,
            executor_actor=actor,
            admitted_at=self._clock(),
        )

    def _terminal_outcome(
        self,
        identity: DispatchIdentity,
        *,
        observe: bool,
    ) -> dict[str, Any] | None:
        outcome = self._repository.outcome(identity)
        if outcome is not None:
            self._cleanup_conflicted_candidate(identity, outcome)
            if observe:
                self._observe(outcome)
        return outcome

    def deliver_pending_telemetry(self, *, limit: int = 100) -> int:
        outcomes = self._repository.pending_telemetry_outcomes(limit=limit)
        for outcome in outcomes:
            identity = self._identity_from_outcome(outcome)
            self._cleanup_conflicted_candidate(identity, outcome)
            self._observe(outcome)
        return sum(
            self._repository.telemetry_delivered(self._identity_from_outcome(outcome))
            for outcome in outcomes
        )

    @staticmethod
    def _failure_reason(error: SimulatorBundleError | RendererError) -> str:
        if _REASON_CODE.fullmatch(error.code) is None:
            return "simulator-precondition-failed"
        return error.code

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> dict[str, Any]:
        existing = self._terminal_outcome(identity, observe=observe_terminal)
        if existing is not None:
            return existing

        action = self._repository.load_action(identity)
        try:
            claim = self._repository.claim_action(action, owner=owner, now=self._clock())
        except SimulatorRepositoryError as error:
            if error.code != "action-complete":
                raise
            completed = self._terminal_outcome(identity, observe=observe_terminal)
            if completed is None:  # pragma: no cover - repository transition is atomic
                raise SimulatorRepositoryError("action-outcome-missing") from error
            return completed

        if claim.phase == "execute":
            try:
                current_proof = self._dispatch_source.load_current_consumed(identity)
                current_bundle = self._authority_boundary.bind(identity, current_proof)
                if current_bundle.action.dispatch_bundle_sha256 != action.dispatch_bundle_sha256:
                    raise SimulatorAuthorityError("dispatch-bundle-stale")
            except (ResponsePlanError, SimulatorAuthorityError):
                failed = self._repository.fail_action(
                    claim,
                    reason_codes=("dispatch-authority-stale",),
                    now=self._clock(),
                )
                if observe_terminal:
                    self._observe(failed)
                return failed

            def heartbeat() -> None:
                nonlocal claim
                claim = self._repository.renew_claim(claim, now=self._clock())

            try:
                snapshot = self._publication.snapshot_for_action(action)
                trace_ids = {
                    str(command["command_id"]): self._trace_id_factory()
                    for command in action.commands
                }
                prepared = self._publication.prepare(
                    snapshot,
                    trace_ids,
                    heartbeat=heartbeat,
                )
            except (SimulatorBundleError, RendererError) as error:
                failed = self._repository.fail_action(
                    claim,
                    reason_codes=(self._failure_reason(error),),
                    now=self._clock(),
                )
                if observe_terminal:
                    self._observe(failed)
                return failed

            claim = self._repository.renew_claim(claim, now=self._clock())
            self._repository.record_publication_intent(
                claim,
                prepared,
                now=self._clock(),
            )

        outcome = self._repository.reconcile_publication(
            claim,
            now=self._clock(),
            promote=self._publication.compare_and_swap,
        )
        self._cleanup_conflicted_candidate(identity, outcome)
        if observe_terminal:
            self._observe(outcome)
        return outcome


__all__ = ["SimulatorActionService", "TerminalObserver"]
