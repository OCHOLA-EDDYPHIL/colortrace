from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic as system_monotonic
from typing import Any, Protocol, cast
from uuid import uuid4

from colortrace_grafana_mcp import (
    EvidenceBatch,
    ExecutionControls,
    evidence_batch_result_schema,
)
from colortrace_investigation import (
    AlertIntake,
    InvestigationPolicy,
    InvestigationWorkflow,
    ModelCall,
    ModelGateway,
    ModelOutput,
    TrackedSemaphore,
    WorkflowProgress,
)
from colortrace_investigation.contracts import (
    ADAPTIVE_RESPONSE_PACKET_VERSION,
    RESPONSE_PACKET_VERSION,
    canonical_json_bytes,
    finalize_adaptive_response_packet,
    finalize_response_packet,
    sha256,
    timestamp,
)
from colortrace_investigation.workflow import (
    EvidenceCollection,
    EvidenceCollector,
    EvidenceResult,
    ValidatorGateway,
)

from .contracts import (
    CLAIM_HEARTBEAT_SECONDS,
    SliceContractError,
    plain_json,
    require_identifier,
)
from .store import SqliteIncidentStore, WorkItem


class SupportsInventory(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


class SupportsAttempt(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


class QueuedModelGateway:
    def __init__(self, delegate: ModelGateway) -> None:
        self._delegate = delegate
        self._lock = asyncio.Lock()

    async def generate(self, call: ModelCall) -> ModelOutput:
        async with self._lock:
            return await self._delegate.generate(call)


class RecordingEvidenceCollector:
    def __init__(self, delegate: EvidenceCollector) -> None:
        self._delegate = delegate
        self.envelopes: list[Mapping[str, Any]] = []
        self.batches: list[Mapping[str, Any]] = []
        self.tool_calls_used = 0
        self.maximum_calls_in_flight_observed = 0

    def _record(self, result: EvidenceResult) -> None:
        if self.batches:
            raise SliceContractError("evidence-batch-duplicate")
        inventory = cast(SupportsInventory, result.inventory).to_dict()
        attempts = [cast(SupportsAttempt, item).to_dict() for item in result.attempts]
        envelopes = [cast(Mapping[str, Any], plain_json(item)) for item in result.envelopes]
        record = cast(
            Mapping[str, Any],
            plain_json(
                {
                    "schema": evidence_batch_result_schema(envelopes),
                    "inventory": inventory,
                    "tool_calls_used": result.tool_calls_used,
                    "maximum_calls_in_flight_observed": (result.maximum_calls_in_flight_observed),
                    "attempts": attempts,
                    "envelopes": envelopes,
                }
            ),
        )
        self.envelopes.extend(envelopes)
        self.batches.append(record)
        self.tool_calls_used += result.tool_calls_used
        self.maximum_calls_in_flight_observed = max(
            self.maximum_calls_in_flight_observed,
            result.maximum_calls_in_flight_observed,
        )

    @asynccontextmanager
    async def open_collection(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> AsyncIterator[EvidenceCollection]:
        async with self._delegate.open_collection(batch, controls=controls) as collection:
            try:
                yield collection
            finally:
                self._record(collection.result())

    async def collect(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> EvidenceResult:
        result = await self._delegate.collect(batch, controls=controls)
        self._record(result)
        return result


class RecordingValidatorGateway:
    def __init__(self, delegate: ValidatorGateway) -> None:
        self._delegate = delegate
        self.results: list[Mapping[str, Any]] = []

    def validate(self, bundle_root: Path, *, incident_id: str) -> dict[str, Any]:
        result = self._delegate.validate(bundle_root, incident_id=incident_id)
        value = cast(dict[str, Any], plain_json(result))
        self.results.append(value)
        return value


class VerticalSliceApi:
    def __init__(
        self,
        store: SqliteIncidentStore,
        *,
        policy: InvestigationPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(UTC))

    def accept_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        now = timestamp(self._clock().astimezone(UTC))
        if self._policy is None:
            accepted = self._store.accept_alert(alert, now=now)
        else:
            accepted = self._store.accept_alert(
                alert,
                now=now,
                policy_version=self._policy.version,
                policy_sha256=self._policy.digest,
            )
        return accepted.to_dict()

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self._store.incident_view(incident_id)

    def replay(self, incident_id: str) -> dict[str, Any]:
        return self._store.replay(incident_id)

    def reset(self) -> dict[str, int | str]:
        return self._store.reset()


class VerticalSliceWorker:
    def __init__(
        self,
        store: SqliteIncidentStore,
        *,
        policy: InvestigationPolicy,
        model: ModelGateway,
        evidence: EvidenceCollector,
        validator: ValidatorGateway,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        service_timeout_seconds: float = 121.0,
        owner_id: str | None = None,
        heartbeat_sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        if service_timeout_seconds <= 0 or service_timeout_seconds > 121:
            raise SliceContractError("service-timeout-policy")
        self._store = store
        self._policy = policy
        self._model = QueuedModelGateway(model)
        self._evidence = evidence
        self._validator = validator
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or system_monotonic
        self._service_timeout_seconds = service_timeout_seconds
        self._owner_id = require_identifier(
            owner_id or f"worker:{uuid4().hex}", code="claim-owner-invalid"
        )
        self._heartbeat_sleep = heartbeat_sleep or asyncio.sleep
        self._shared = TrackedSemaphore(policy.budgets.maximum_calls_in_flight)

    def _now(self) -> str:
        return timestamp(self._clock().astimezone(UTC))

    async def _maintain_claim(self, work: WorkItem) -> None:
        while True:
            await self._heartbeat_sleep(CLAIM_HEARTBEAT_SECONDS)
            self._store.renew_claim(work, now=self._now())

    @staticmethod
    async def _stop_heartbeat(task: asyncio.Task[None]) -> None:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    def _fallback_packet(
        self,
        work: WorkItem,
        *,
        code: str,
        timed_out: bool,
        evidence: Sequence[Mapping[str, Any]],
        progress: WorkflowProgress,
    ) -> dict[str, Any]:
        intake = progress.intake or AlertIntake.from_mapping(work.alert)
        evidence_ids = [
            cast(str, item["evidence_id"])
            for item in evidence
            if isinstance(item.get("evidence_id"), str)
        ]
        cited = sorted(set(evidence_ids) | progress.evidence_ids)
        deterministic_results = cast(
            list[dict[str, Any]], plain_json(progress.deterministic_results)
        )
        classified_claims = cast(list[dict[str, Any]], plain_json(progress.classified_claims))
        invocations = cast(list[dict[str, Any]], plain_json(progress.invocations))
        scoped_items: dict[tuple[str, str], dict[str, str]] = {}
        if progress.classified_scope is not None:
            for group in ("affected", "safe", "unknown"):
                for raw in cast(
                    Sequence[Mapping[str, str]], progress.classified_scope.get(group, ())
                ):
                    item = {"kind": raw["kind"], "id": raw["id"]}
                    scoped_items[(item["kind"], item["id"])] = item
        state_history = list(progress.state_history)
        if not state_history or state_history[-1] not in {"finalization", "complete"}:
            state_history.append("finalization")
        if state_history[-1] != "complete":
            state_history.append("complete")
        normalized = {
            "incident_id": work.incident_id,
            "reason_codes": [code],
            "evidence_ids": cited,
        }
        normalized_digest = sha256(canonical_json_bytes(normalized))
        claim_body = {
            "schema": "claim/v1",
            "claim_type": "investigation-completeness",
            "subject": {"kind": "incident-id", "value": work.incident_id},
            "state": "unresolved",
            "policy": "investigation-completeness/v1",
            "normalized_inputs_sha256": normalized_digest,
            "deterministic_result_evidence_id": None,
            "source_validator_result_id": None,
            "contradiction_links": [],
            "evidence_ids": cited,
            "reason_codes": [code],
        }
        derivation = sha256(canonical_json_bytes(claim_body))
        claim = {
            **claim_body,
            "claim_id": f"claim:{derivation}",
            "derivation_sha256": derivation,
        }
        packet_body: dict[str, Any] = {
            "schema": (
                ADAPTIVE_RESPONSE_PACKET_VERSION
                if self._policy.adaptive
                else RESPONSE_PACKET_VERSION
            ),
            "incident_id": work.incident_id,
            "version": 2 if self._policy.adaptive else 1,
            "status": "unresolved",
            "fixed_window": intake.window.to_dict(),
            "evidence_ids": cited,
            "deterministic_results": deterministic_results,
            "claims": [*classified_claims, claim],
            "scope": {
                "state": "unresolved",
                "policy": "single-causal-resource-scope/v1",
                "affected": [],
                "safe": [],
                "unknown": [scoped_items[key] for key in sorted(scoped_items)],
                "reason_codes": [code],
            },
            "invocation_records": invocations,
            "budget_use": progress.budget_snapshot(),
            "unresolved_items": [{"code": code, "stage": "worker", "evidence_ids": cited}],
            "candidate_plan": None,
            "no_action_reason": "budget-exhausted" if timed_out else "evidence-unavailable",
            "model_advisory": None,
            "state_history": state_history,
            "finalized_at": timestamp(self._clock().astimezone(UTC)),
        }
        if self._policy.adaptive:
            trace = cast(list[dict[str, Any]], plain_json(progress.adaptive_trace))
            if not trace:
                selection_invocation = next(
                    (
                        item
                        for item in reversed(invocations)
                        if item.get("turn_kind") == "evidence-selection"
                    ),
                    None,
                )
                resolved_result = next(
                    (item for item in deterministic_results if item.get("status") == "resolved"),
                    None,
                )
                trace = []
                for sequence, envelope in enumerate(evidence):
                    observation = envelope.get("observation")
                    query_key = (
                        observation.get("query_key") if isinstance(observation, Mapping) else None
                    )
                    if not isinstance(query_key, str):
                        continue
                    terminal = sequence == len(evidence) - 1
                    sufficient = terminal and resolved_result is not None
                    trace.append(
                        {
                            "sequence": sequence,
                            "selected_by": "policy" if sequence == 0 else "model",
                            "query_key": query_key,
                            "selection_request_sha256": (
                                f"sha256:{sha256(canonical_json_bytes({'query_key': query_key}))}"
                            ),
                            "selection_invocation_id": (
                                None
                                if sequence == 0 or selection_invocation is None
                                else selection_invocation["invocation_id"]
                            ),
                            "selection_output_sha256": (
                                None
                                if sequence == 0 or selection_invocation is None
                                else selection_invocation["output_sha256"]
                            ),
                            "evidence_id": envelope["evidence_id"],
                            "disposition": (
                                "resolved"
                                if sufficient
                                else "unresolved"
                                if terminal
                                else "continue"
                            ),
                            "reason_code": (
                                "sufficient-evidence"
                                if sufficient
                                else code
                                if terminal
                                else "baseline-valid"
                                if sequence == 0
                                else "additional-evidence-required"
                            ),
                            "validator_result_id": (
                                resolved_result["result_id"]
                                if sufficient and resolved_result is not None
                                else None
                            ),
                        }
                    )
                if not trace:
                    trace = [
                        {
                            "sequence": 0,
                            "selected_by": "policy",
                            "query_key": "alert.rule",
                            "selection_request_sha256": (
                                "sha256:"
                                + sha256(canonical_json_bytes({"query_key": "alert.rule"}))
                            ),
                            "selection_invocation_id": None,
                            "selection_output_sha256": None,
                            "evidence_id": None,
                            "disposition": "unresolved",
                            "reason_code": code,
                            "validator_result_id": None,
                        }
                    ]
            packet_body.update(
                {
                    "policy_binding": {
                        "version": self._policy.version,
                        "sha256": self._policy.digest,
                    },
                    "adaptive_trace": trace,
                    "hypotheses": cast(list[dict[str, Any]], plain_json(progress.hypotheses)),
                    "stop_reason": trace[-1]["reason_code"],
                }
            )
            return finalize_adaptive_response_packet(packet_body)
        return finalize_response_packet(packet_body)

    async def execute(self, task_id: str, *, bundle_root: Path) -> dict[str, Any]:
        completed = self._store.completed_packet(task_id)
        if completed is not None:
            return completed
        try:
            work = self._store.claim_task(
                task_id,
                owner=self._owner_id,
                now=self._now(),
                policy_version=self._policy.version,
                policy_sha256=self._policy.digest,
            )
        except SliceContractError as error:
            if error.code != "task-complete":
                raise
            completed = self._store.completed_packet(task_id)
            if completed is None:
                raise SliceContractError("store-integrity") from error
            return completed
        heartbeat = asyncio.create_task(self._maintain_claim(work))
        evidence = RecordingEvidenceCollector(self._evidence)
        validator = RecordingValidatorGateway(self._validator)
        progress = WorkflowProgress()
        workflow = InvestigationWorkflow(
            policy=self._policy,
            model=self._model,
            evidence=evidence,
            validator=validator,
            clock=self._clock,
            monotonic=self._monotonic,
            shared_limiter=self._shared,
            progress=progress,
        )
        try:
            try:
                packet = await asyncio.wait_for(
                    workflow.run(work.alert, bundle_root=bundle_root),
                    timeout=self._service_timeout_seconds,
                )
            except TimeoutError:
                packet = self._fallback_packet(
                    work,
                    code="service-timeout",
                    timed_out=True,
                    evidence=evidence.envelopes,
                    progress=progress,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                packet = self._fallback_packet(
                    work,
                    code="worker-service-failure",
                    timed_out=False,
                    evidence=evidence.envelopes,
                    progress=progress,
                )
            if heartbeat.done():
                heartbeat.result()
            packet_result_ids = {
                cast(str, item["result_id"])
                for item in cast(Sequence[Mapping[str, Any]], packet["deterministic_results"])
            }
            persisted_validator_results = [
                item for item in validator.results if item.get("result_id") in packet_result_ids
            ]
            return self._store.complete_task(
                work,
                packet=packet,
                evidence=evidence.envelopes,
                evidence_batches=evidence.batches,
                validator_results=persisted_validator_results,
                now=self._now(),
            )
        except asyncio.CancelledError:
            with suppress(SliceContractError):
                await self._stop_heartbeat(heartbeat)
            with suppress(SliceContractError):
                self._store.expire_claim(work, now=self._now())
            raise
        finally:
            if not heartbeat.done():
                await self._stop_heartbeat(heartbeat)


async def run_vertical_slice(
    *,
    api: VerticalSliceApi,
    worker: VerticalSliceWorker,
    alert: Mapping[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    accepted = api.accept_alert(alert)
    return await worker.execute(cast(str, accepted["task_id"]), bundle_root=bundle_root)


__all__ = [
    "QueuedModelGateway",
    "RecordingEvidenceCollector",
    "RecordingValidatorGateway",
    "VerticalSliceApi",
    "VerticalSliceWorker",
    "run_vertical_slice",
]
