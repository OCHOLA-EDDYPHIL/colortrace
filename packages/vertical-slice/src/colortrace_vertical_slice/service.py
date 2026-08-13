from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic as system_monotonic
from typing import Any, Protocol, cast

from colortrace_grafana_mcp import EvidenceBatch, ExecutionControls
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
    RESPONSE_PACKET_VERSION,
    canonical_json_bytes,
    finalize_response_packet,
    sha256,
    timestamp,
)
from colortrace_investigation.workflow import EvidenceCollector, EvidenceResult, ValidatorGateway

from .contracts import SliceContractError, plain_json
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

    async def collect(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> EvidenceResult:
        result = await self._delegate.collect(batch, controls=controls)
        if self.batches:
            raise SliceContractError("evidence-batch-duplicate")
        inventory = cast(SupportsInventory, result.inventory).to_dict()
        attempts = [cast(SupportsAttempt, item).to_dict() for item in result.attempts]
        envelopes = [cast(Mapping[str, Any], plain_json(item)) for item in result.envelopes]
        record = cast(
            Mapping[str, Any],
            plain_json(
                {
                    "schema": "grafana-evidence-batch-result/v1",
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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    def accept_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        accepted = self._store.accept_alert(alert, now=timestamp(self._clock().astimezone(UTC)))
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
        self._shared = TrackedSemaphore(policy.budgets.maximum_calls_in_flight)

    def _fallback_packet(
        self,
        work: WorkItem,
        *,
        code: str,
        timed_out: bool,
        evidence_ids: Sequence[str],
        progress: WorkflowProgress,
    ) -> dict[str, Any]:
        intake = progress.intake or AlertIntake.from_mapping(work.alert)
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
        packet_body = {
            "schema": RESPONSE_PACKET_VERSION,
            "incident_id": work.incident_id,
            "version": 1,
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
        return finalize_response_packet(packet_body)

    async def execute(self, task_id: str, *, bundle_root: Path) -> dict[str, Any]:
        completed = self._store.completed_packet(task_id)
        if completed is not None:
            return completed
        now = timestamp(self._clock().astimezone(UTC))
        work = self._store.claim_task(task_id, now=now)
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
            packet = await asyncio.wait_for(
                workflow.run(work.alert, bundle_root=bundle_root),
                timeout=self._service_timeout_seconds,
            )
        except TimeoutError:
            packet = self._fallback_packet(
                work,
                code="service-timeout",
                timed_out=True,
                evidence_ids=[cast(str, item["evidence_id"]) for item in evidence.envelopes],
                progress=progress,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            packet = self._fallback_packet(
                work,
                code="worker-service-failure",
                timed_out=False,
                evidence_ids=[cast(str, item["evidence_id"]) for item in evidence.envelopes],
                progress=progress,
            )
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
            now=timestamp(self._clock().astimezone(UTC)),
        )


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
