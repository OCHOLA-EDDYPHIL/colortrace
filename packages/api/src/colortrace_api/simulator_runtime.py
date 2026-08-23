from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any, Protocol

from colortrace_simulator import DispatchIdentity, RecoveryPublicationPort
from colortrace_simulator.authority import ExecutorAuthorization
from colortrace_simulator.repository import SimulatorRepositoryError
from fastapi import FastAPI


class PendingActionRepository(Protocol):
    def pending_action_identities(self, *, limit: int = 100) -> list[DispatchIdentity]: ...

    def close(self) -> None: ...


class RuntimeSimulatorService(Protocol):
    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]: ...

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> dict[str, Any]: ...

    def deliver_pending_telemetry(self, *, limit: int = 100) -> int: ...


class SimulatorSerialRunner:
    """One local worker for queued execution, fenced recovery, and telemetry drain."""

    def __init__(
        self,
        *,
        repository: PendingActionRepository,
        service: RuntimeSimulatorService,
        owner: str | None = None,
        poll_seconds: float = 1.0,
        action_batch_limit: int = 1,
        telemetry_batch_limit: int = 1,
        join_timeout_seconds: float = 120.0,
    ) -> None:
        if (
            not isinstance(poll_seconds, (int, float))
            or isinstance(poll_seconds, bool)
            or not 0.01 <= poll_seconds <= 30.0
        ):
            raise ValueError("simulator-runner-poll-invalid")
        if (
            not isinstance(action_batch_limit, int)
            or isinstance(action_batch_limit, bool)
            or not 1 <= action_batch_limit <= 100
        ):
            raise ValueError("simulator-runner-action-batch-invalid")
        if (
            not isinstance(telemetry_batch_limit, int)
            or isinstance(telemetry_batch_limit, bool)
            or not 1 <= telemetry_batch_limit <= 10
        ):
            raise ValueError("simulator-runner-telemetry-batch-invalid")
        if (
            not isinstance(join_timeout_seconds, (int, float))
            or isinstance(join_timeout_seconds, bool)
            or not 0.01 <= join_timeout_seconds <= 180.0
        ):
            raise ValueError("simulator-runner-join-timeout-invalid")
        self._repository = repository
        self._service = service
        self._owner = owner or f"local-api-simulator-{os.getpid()}-{secrets.token_hex(8)}"
        self._poll_seconds = float(poll_seconds)
        self._action_batch_limit = action_batch_limit
        self._telemetry_batch_limit = telemetry_batch_limit
        self._join_timeout_seconds = float(join_timeout_seconds)
        self._wake_event = threading.Event()
        self._stop_event = threading.Event()
        self._worker_exited = threading.Event()
        self._execution_lock = threading.RLock()
        self._state_lock = threading.Lock()
        self._state_changed = threading.Condition(self._state_lock)
        self._thread: threading.Thread | None = None
        self._closed = False
        self._stopping = False
        self._accepting = False
        self._admissions_in_flight = 0
        self._last_error: Exception | None = None

    @property
    def last_error(self) -> Exception | None:
        return self._last_error

    @property
    def thread_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        with self._state_lock:
            if self._closed or self._stopping:
                raise RuntimeError("simulator-runner-closed")
            if self._thread is not None:
                return
            thread = threading.Thread(
                target=self._run,
                name="colortrace-local-simulator",
                daemon=True,
            )
            self._thread = thread
            self._worker_exited.clear()
            try:
                thread.start()
            except Exception:
                self._thread = None
                raise
            if not thread.is_alive():
                self._thread = None
                raise RuntimeError("simulator-runner-start-failed")
            self._accepting = True
            self._wake_event.set()

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]:
        with self._state_changed:
            thread = self._thread
            if (
                not self._accepting
                or self._closed
                or self._stopping
                or thread is None
                or not thread.is_alive()
                or self._worker_exited.is_set()
            ):
                self._accepting = False
                raise SimulatorRepositoryError("simulator-runner-unavailable")
            self._admissions_in_flight += 1
        try:
            admission = self._service.admit(identity, executor=executor)
        except BaseException:
            with self._state_changed:
                self._admissions_in_flight -= 1
                self._state_changed.notify_all()
            raise
        with self._state_changed:
            self._admissions_in_flight -= 1
            self._state_changed.notify_all()
            thread = self._thread
            if (
                not self._accepting
                or self._closed
                or self._stopping
                or thread is None
                or not thread.is_alive()
                or self._worker_exited.is_set()
            ):
                self._accepting = False
                raise SimulatorRepositoryError("simulator-runner-unavailable")
            self._wake_event.set()
            return admission

    def close(self) -> None:
        deadline = time.monotonic() + self._join_timeout_seconds
        with self._state_changed:
            if self._closed:
                return
            self._stopping = True
            self._accepting = False
            while self._admissions_in_flight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("simulator-runner-shutdown-timeout")
                self._state_changed.wait(timeout=remaining)
            thread = self._thread
            self._stop_event.set()
            self._wake_event.set()
        if thread is not None:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                raise RuntimeError("simulator-runner-shutdown-timeout")
        self._deliver_telemetry()
        with self._state_lock:
            self._closed = True
            self._stopping = False

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> dict[str, Any]:
        with self._state_lock:
            thread = self._thread
            if (
                not self._accepting
                or self._closed
                or self._stopping
                or thread is None
                or not thread.is_alive()
                or self._worker_exited.is_set()
            ):
                raise SimulatorRepositoryError("simulator-runner-unavailable")
        with self._execution_lock:
            return self._service.execute(
                identity,
                owner=owner,
                observe_terminal=observe_terminal,
            )

    def _record_error(self, error: Exception) -> None:
        self._last_error = error

    def _deliver_telemetry(self) -> None:
        try:
            self._service.deliver_pending_telemetry(limit=self._telemetry_batch_limit)
        except Exception as error:
            self._record_error(error)

    def _drain(self) -> None:
        with self._execution_lock:
            self._drain_locked()

    def _drain_locked(self) -> None:
        try:
            identities = self._repository.pending_action_identities(limit=self._action_batch_limit)
        except Exception as error:
            self._record_error(error)
            identities = []
        for identity in identities:
            if self._stop_event.is_set():
                break
            try:
                self._service.execute(
                    identity,
                    owner=self._owner,
                    observe_terminal=False,
                )
            except Exception as error:
                self._record_error(error)
        self._deliver_telemetry()

    def restore_authored_scenario(
        self,
        reset: Callable[[], Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        deadline = time.monotonic() + self._join_timeout_seconds
        with self._state_changed:
            resume_admission = self._accepting
            self._accepting = False
            while self._admissions_in_flight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("simulator-reset-quiesce-timeout")
                self._state_changed.wait(timeout=remaining)
        try:
            with self._execution_lock:
                reset_owner = (
                    f"simulator-reset-{hashlib.sha256(self._owner.encode()).hexdigest()[:16]}"
                )
                for _attempt in range(1_000):
                    pending = self._repository.pending_action_identities(limit=100)
                    if not pending:
                        break
                    for identity in pending:
                        self._service.execute(
                            identity,
                            owner=reset_owner,
                            observe_terminal=False,
                        )
                else:
                    raise RuntimeError("simulator-reset-drain-limit")
                if self._repository.pending_action_identities(limit=1):
                    raise RuntimeError("simulator-reset-pending-actions")
                result = reset()
                if self._repository.pending_action_identities(limit=1):
                    raise RuntimeError("simulator-reset-race")
                return result
        finally:
            with self._state_changed:
                thread = self._thread
                if (
                    resume_admission
                    and not self._closed
                    and not self._stopping
                    and thread is not None
                    and thread.is_alive()
                    and not self._worker_exited.is_set()
                ):
                    self._accepting = True
                    self._wake_event.set()

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                self._wake_event.wait(self._poll_seconds)
                self._wake_event.clear()
                if self._stop_event.is_set():
                    break
                self._drain()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            self._worker_exited.set()
            with self._state_lock:
                self._accepting = False


class WakingSimulatorAdmission:
    def __init__(
        self,
        *,
        runner: SimulatorSerialRunner,
    ) -> None:
        self._runner = runner

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]:
        return self._runner.admit(identity, executor=executor)


class LocalSimulatorRuntime:
    def __init__(
        self,
        *,
        repository: PendingActionRepository,
        service: RuntimeSimulatorService,
        telemetry_sink: object,
        recovery_publication: RecoveryPublicationPort | None = None,
        poll_seconds: float = 1.0,
        join_timeout_seconds: float = 120.0,
    ) -> None:
        self.repository = repository
        self.service = service
        self.telemetry_sink = telemetry_sink
        self.recovery_publication = recovery_publication
        self.runner = SimulatorSerialRunner(
            repository=repository,
            service=service,
            poll_seconds=poll_seconds,
            join_timeout_seconds=join_timeout_seconds,
        )
        self.admission_service = WakingSimulatorAdmission(
            runner=self.runner,
        )

    def execute(self, identity: DispatchIdentity, *, owner: str) -> dict[str, Any]:
        return self.runner.execute(identity, owner=owner)

    def restore_authored_scenario(self, *, operation_id: str) -> Mapping[str, Any]:
        if not self.runner.thread_alive:
            raise SimulatorRepositoryError("simulator-runner-unavailable")
        resetter = getattr(self.recovery_publication, "restore_authored_scenario", None)
        if not callable(resetter):
            raise RuntimeError("simulator-authored-reset-unavailable")
        result = self.runner.restore_authored_scenario(lambda: resetter(operation_id=operation_id))
        if not isinstance(result, Mapping):
            raise RuntimeError("simulator-authored-reset-invalid")
        return result

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncIterator[None]:
        try:
            self.runner.start()
            yield
        finally:
            self.runner.close()
            shutdown = getattr(self.telemetry_sink, "shutdown", None)
            try:
                if callable(shutdown):
                    shutdown()
            finally:
                self.repository.close()


__all__ = [
    "LocalSimulatorRuntime",
    "PendingActionRepository",
    "RuntimeSimulatorService",
    "SimulatorSerialRunner",
    "WakingSimulatorAdmission",
]
