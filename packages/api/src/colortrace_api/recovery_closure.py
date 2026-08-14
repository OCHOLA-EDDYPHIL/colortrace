from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import Any, Protocol, cast

from colortrace_recovery import (
    RecoveryError,
    canonical_json_bytes,
    project_recovery_verification_snapshot,
    validate_verification_snapshot,
    verification_state_sha256,
)
from colortrace_simulator import RecoveryPublicationPort
from colortrace_simulator.bundle import SimulatorBundleError
from colortrace_simulator.repository import SimulatorRepositoryError, SQLiteSimulatorRepository


class RecoveryClosureFence(Protocol):
    def guard(
        self,
        *,
        incident_id: str,
        expected_outcome_sha256: str,
        verified_snapshot: Mapping[str, Any],
    ) -> AbstractContextManager[None]: ...


@contextmanager
def _translate_simulator_guard[T](context: AbstractContextManager[T]) -> Iterator[T]:
    try:
        with context as value:
            yield value
    except (OSError, SimulatorBundleError, SimulatorRepositoryError) as error:
        raise RecoveryError("recovery-closure-currentness-conflict") from error


class LocalRecoveryClosureFence:
    """Hold local simulator authority stable while one verified recovery closes."""

    def __init__(
        self,
        *,
        repository: SQLiteSimulatorRepository,
        publication: RecoveryPublicationPort,
    ) -> None:
        self._repository = repository
        self._publication = publication

    @contextmanager
    def guard(
        self,
        *,
        incident_id: str,
        expected_outcome_sha256: str,
        verified_snapshot: Mapping[str, Any],
    ) -> Iterator[None]:
        stored = validate_verification_snapshot(verified_snapshot)
        stored_outcome = cast(Mapping[str, Any], stored["action_outcome"])
        if (
            stored["incident_id"] != incident_id
            or stored_outcome.get("incident_id") != incident_id
            or stored_outcome.get("outcome_sha256") != expected_outcome_sha256
        ):
            raise RecoveryError("recovery-closure-currentness-conflict")
        stored_state_sha256 = verification_state_sha256(stored)

        repository_guard = self._repository.guard_current_recovery_outcome(
            incident_id,
            expected_outcome_sha256,
        )
        with _translate_simulator_guard(repository_guard) as authoritative_outcome:
            if canonical_json_bytes(authoritative_outcome) != canonical_json_bytes(stored_outcome):
                raise RecoveryError("recovery-closure-currentness-conflict")
            try:
                fresh_simulator_snapshot = self._publication.snapshot_for_recovery(
                    authoritative_outcome
                )
                fresh_core = project_recovery_verification_snapshot(
                    authoritative_outcome,
                    fresh_simulator_snapshot,
                )
            except (OSError, RecoveryError, SimulatorBundleError) as error:
                raise RecoveryError("recovery-closure-currentness-conflict") from error
            if verification_state_sha256(fresh_core) != stored_state_sha256:
                raise RecoveryError("recovery-closure-currentness-conflict")
            publication_guard = self._publication.guard_recovery_closure(
                fresh_simulator_snapshot,
                authoritative_outcome,
            )
            with _translate_simulator_guard(publication_guard):
                yield


__all__ = ["LocalRecoveryClosureFence", "RecoveryClosureFence"]
