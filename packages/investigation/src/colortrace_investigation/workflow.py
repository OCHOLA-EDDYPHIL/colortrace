from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from time import monotonic as system_monotonic
from typing import Any, Literal, Protocol, TypeVar, cast

from colortrace_grafana_mcp import (
    AdapterError,
    AttemptRecord,
    AttemptRequest,
    EvidenceBatch,
    ExecutionControls,
    validate_evidence_envelope,
)
from colortrace_validator import (
    build_request,
    validate_color_state,
    validate_result_contract,
)

from .contracts import (
    ADK_VERSION,
    GENAI_VERSION,
    INVOCATION_VERSION,
    MODEL_ID,
    MODEL_LOCATION,
    POLICY_VERSION,
    QUERY_KEYS,
    RESPONSE_PACKET_VERSION,
    SCHEMA_ROOT,
    TOOL_BY_QUERY,
    AlertIntake,
    ContractError,
    FrozenWindow,
    InvestigationPolicy,
    ModelAdvisory,
    ModelSelection,
    canonical_json_bytes,
    finalize_derived_record,
    finalize_response_packet,
    parse_timestamp,
    prefixed_sha256,
    sha256,
    strict_json_bytes,
    strict_json_file,
    timestamp,
    validate_contract,
)
from .model import AllowedQueryKey, EvidenceTool, ModelCall, ModelFailure, ModelGateway, ModelOutput

_T = TypeVar("_T")
_MODEL_OUTPUT_LIMITS = {"evidence-selection": 512, "response-drafting": 1792}
_MODEL_EVIDENCE_EXCERPT_JSON_BYTES = 1024
_VALIDATOR_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="colortrace-validator")


class WorkflowError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EvidenceResult(Protocol):
    inventory: Any
    envelopes: tuple[Mapping[str, Any], ...]
    tool_calls_used: int
    maximum_calls_in_flight_observed: int
    attempts: tuple[AttemptRecord, ...]


class EvidenceCollector(Protocol):
    def open_collection(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> AbstractAsyncContextManager[EvidenceCollection]: ...

    async def collect(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> EvidenceResult: ...


class EvidenceCollection(Protocol):
    @property
    def query_keys(self) -> tuple[str, ...]: ...

    async def collect(self, query_key: str) -> Mapping[str, Any]: ...

    def result(self) -> EvidenceResult: ...


class ValidatorGateway(Protocol):
    def validate(self, bundle_root: Path, *, incident_id: str) -> dict[str, Any]: ...


class ColorStateValidatorGateway:
    def validate(self, bundle_root: Path, *, incident_id: str) -> dict[str, Any]:
        root = bundle_root.resolve(strict=True)
        if any("oracle" in part.lower() for part in root.parts) or any(
            "oracle" in path.name.lower() for path in root.rglob("*")
        ):
            raise WorkflowError("oracle-boundary")
        request_id = f"validation-{sha256(incident_id.encode('utf-8'))[:24]}"
        request = build_request(root, request_id=request_id, incident_id=incident_id)
        result = validate_color_state(root, request)
        validate_result_contract(result)
        if result.get("incident_id") != incident_id:
            raise WorkflowError("validator-correlation")
        for evidence in cast(Sequence[Mapping[str, Any]], result.get("evidence", ())):
            path = evidence.get("path")
            if not isinstance(path, str) or any(
                "oracle" in part.lower() for part in Path(path).parts
            ):
                raise WorkflowError("oracle-boundary")
        return result


class TrackedSemaphore(asyncio.Semaphore):
    def __init__(self, value: int = 2) -> None:
        super().__init__(value)
        self.capacity = value
        self.in_flight = 0
        self.maximum_observed = 0

    async def acquire(self) -> Literal[True]:
        acquired = await super().acquire()
        self.in_flight += 1
        self.maximum_observed = max(self.maximum_observed, self.in_flight)
        return acquired

    def release(self) -> None:
        if self.in_flight <= 0:
            raise ValueError("tracked semaphore released without acquisition")
        self.in_flight -= 1
        super().release()


@dataclass(frozen=True, slots=True)
class Blocker:
    code: str
    stage: str
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "evidence_ids": sorted(set(self.evidence_ids)),
        }


@dataclass(slots=True)
class BudgetLedger:
    policy: InvestigationPolicy
    monotonic: Callable[[], float]
    started: float = field(init=False)
    model_turns: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    unavailable_input_tokens_reserved: int = 0
    unavailable_output_tokens_reserved: int = 0
    mcp_attempts: int = 0
    validator_calls: int = 0
    trusted_transient_retries: int = 0
    model_visible_bytes: int = 0
    authorized_attempts: list[tuple[str, str, int, bool, str]] = field(default_factory=list)
    _argument_digests: dict[str, str] = field(default_factory=dict)
    _attempt_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self.started = self.monotonic()

    def elapsed_seconds(self) -> float:
        return max(0.0, self.monotonic() - self.started)

    def remaining_seconds(self) -> float:
        return max(0.0, self.policy.budgets.end_to_end_seconds - self.elapsed_seconds())

    def require_time(self) -> None:
        if self.remaining_seconds() <= 0:
            raise WorkflowError("wall-time-exhausted")

    def reserve_model_turns(self, maximum_calls: int) -> None:
        self.require_time()
        if (
            isinstance(maximum_calls, bool)
            or maximum_calls < 1
            or self.model_turns + maximum_calls > self.policy.budgets.maximum_model_turns
        ):
            raise WorkflowError("model-turn-budget")
        self.model_turns += maximum_calls

    def settle_model_turns(self, reserved: int, used: int) -> None:
        if isinstance(used, bool) or used < 1 or used > reserved or reserved > self.model_turns:
            raise WorkflowError("model-turn-budget")
        self.model_turns -= reserved - used

    def record_model_usage(self, input_tokens: int, output_tokens: int) -> bool:
        if (
            isinstance(input_tokens, bool)
            or isinstance(output_tokens, bool)
            or input_tokens < 0
            or output_tokens < 0
        ):
            raise WorkflowError("model-usage-invalid")
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        return (
            self.input_tokens + self.unavailable_input_tokens_reserved
            <= self.policy.budgets.maximum_input_tokens
            and self.output_tokens + self.unavailable_output_tokens_reserved
            <= self.policy.budgets.maximum_output_tokens
        )

    def can_admit_model(self, input_upper_bound: int, output_upper_bound: int) -> bool:
        return (
            input_upper_bound >= 0
            and output_upper_bound >= 0
            and self.input_tokens + self.unavailable_input_tokens_reserved + input_upper_bound
            <= self.policy.budgets.maximum_input_tokens
            and self.output_tokens + self.unavailable_output_tokens_reserved + output_upper_bound
            <= self.policy.budgets.maximum_output_tokens
        )

    def reserve_unavailable_model_usage(
        self, input_upper_bound: int, output_upper_bound: int
    ) -> None:
        if not self.can_admit_model(input_upper_bound, output_upper_bound):
            raise WorkflowError("token-budget")
        self.unavailable_input_tokens_reserved += input_upper_bound
        self.unavailable_output_tokens_reserved += output_upper_bound

    def reserve_model_visible(self, value: bytes) -> None:
        size = len(value)
        if self.model_visible_bytes + size > self.policy.budgets.maximum_model_visible_bytes:
            raise WorkflowError("model-visible-budget")
        self.model_visible_bytes += size

    def reserve_retry(self) -> bool:
        if self.trusted_transient_retries >= self.policy.budgets.maximum_trusted_transient_retries:
            return False
        self.trusted_transient_retries += 1
        return True

    async def authorize_attempt(self, request: AttemptRequest) -> bool:
        async with self._attempt_lock:
            if request.query_key not in QUERY_KEYS or TOOL_BY_QUERY.get(request.query_key) != (
                request.tool
            ):
                return False
            try:
                digest = prefixed_sha256(canonical_json_bytes(request.normalized_arguments))
            except (TypeError, ValueError):
                return False
            if digest != request.arguments_sha256:
                return False
            original = self._argument_digests.get(request.query_key)
            if original is None:
                if request.attempt != 1 or request.retry:
                    return False
                self._argument_digests[request.query_key] = digest
            elif (
                digest != original
                or request.attempt != 2
                or not request.retry
                or not self.reserve_retry()
            ):
                return False
            if self.mcp_attempts >= self.policy.budgets.maximum_mcp_attempts:
                return False
            self.mcp_attempts += 1
            self.authorized_attempts.append(
                (
                    request.query_key,
                    request.tool,
                    request.attempt,
                    request.retry,
                    request.arguments_sha256,
                )
            )
            return True

    def reserve_validator(self) -> None:
        self.require_time()
        if self.validator_calls >= self.policy.budgets.maximum_validator_calls:
            raise WorkflowError("validator-budget")
        self.validator_calls += 1

    def snapshot(self, shared: TrackedSemaphore) -> dict[str, int]:
        return {
            "elapsed_ms": int(self.elapsed_seconds() * 1000),
            "model_turns": self.model_turns,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "unavailable_input_tokens_reserved": self.unavailable_input_tokens_reserved,
            "unavailable_output_tokens_reserved": self.unavailable_output_tokens_reserved,
            "mcp_attempts": self.mcp_attempts,
            "validator_calls": self.validator_calls,
            "trusted_transient_retries": self.trusted_transient_retries,
            "model_visible_bytes": self.model_visible_bytes,
            "maximum_calls_in_flight_observed": shared.maximum_observed,
        }


@dataclass(slots=True)
class WorkflowProgress:
    ledger: BudgetLedger | None = None
    shared_limiter: TrackedSemaphore | None = None
    intake: AlertIntake | None = None
    invocations: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: set[str] = field(default_factory=set)
    deterministic_results: list[dict[str, Any]] = field(default_factory=list)
    classified_claims: list[dict[str, Any]] = field(default_factory=list)
    classified_scope: dict[str, Any] | None = None
    state_history: list[str] = field(default_factory=list)

    def begin(self, ledger: BudgetLedger, shared_limiter: TrackedSemaphore) -> None:
        if self.ledger is not None or self.state_history:
            raise WorkflowError("workflow-progress-reused")
        self.ledger = ledger
        self.shared_limiter = shared_limiter
        self.state_history.append("intake")

    def budget_snapshot(self) -> dict[str, int]:
        if self.ledger is None or self.shared_limiter is None:
            raise WorkflowError("workflow-progress-unavailable")
        return self.ledger.snapshot(self.shared_limiter)


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    evidence_ids: tuple[str, ...]
    model_views: tuple[Mapping[str, Any], ...]
    inventory_version: str
    blockers: tuple[Blocker, ...]


@dataclass(frozen=True, slots=True)
class _EvidenceRecord:
    correlation_sources: tuple[Mapping[str, Any], ...]
    timestamp_values: tuple[Any, ...]


def _normalized_code(value: str) -> str:
    normalized = value.lower().replace("_", "-")
    if not normalized or not normalized[0].isalpha():
        return "internal-failure"
    return "".join(
        character for character in normalized if character.isalnum() or character == "-"
    )[:64]


def _dedupe_blockers(blockers: Sequence[Blocker]) -> list[Blocker]:
    unique = {
        (item.code, item.stage, tuple(sorted(set(item.evidence_ids)))): Blocker(
            item.code, item.stage, tuple(sorted(set(item.evidence_ids)))
        )
        for item in blockers
    }
    return [unique[key] for key in sorted(unique)]


def _bounded_model_excerpt(value: str) -> tuple[str, bool]:
    if len(canonical_json_bytes(value)) <= _MODEL_EVIDENCE_EXCERPT_JSON_BYTES:
        return value, False
    lower = 0
    upper = len(value)
    while lower < upper:
        candidate = (lower + upper + 1) // 2
        if len(canonical_json_bytes(value[:candidate])) <= _MODEL_EVIDENCE_EXCERPT_JSON_BYTES:
            lower = candidate
        else:
            upper = candidate - 1
    return value[:lower], True


def _project_advisory_evidence_views(
    model_views: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for view in model_views:
        excerpt = view.get("display_excerpt")
        if not isinstance(excerpt, str):
            raise WorkflowError("malformed-evidence")
        bounded_excerpt, truncated = _bounded_model_excerpt(excerpt)
        projected.append(
            {
                **view,
                "display_excerpt": bounded_excerpt,
                "display_excerpt_truncated": truncated,
            }
        )
    return projected


def _event_timestamp(value: Any) -> datetime:
    if isinstance(value, bool):
        raise ContractError("invalid-time")
    if isinstance(value, int):
        numeric = Decimal(value)
    elif isinstance(value, str):
        try:
            return parse_timestamp(value)
        except ContractError:
            try:
                numeric = Decimal(value)
            except InvalidOperation as error:
                raise ContractError("invalid-time") from error
    else:
        raise ContractError("invalid-time")
    if not numeric.is_finite() or numeric < 0:
        raise ContractError("invalid-time")
    if numeric >= Decimal("100000000000000"):
        numeric /= Decimal(1_000_000_000)
    elif numeric >= Decimal("100000000000"):
        numeric /= Decimal(1000)
    seconds = int(numeric)
    microseconds = int((numeric - seconds) * Decimal(1_000_000))
    try:
        return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(microseconds=microseconds)
    except (OSError, OverflowError, ValueError) as error:
        raise ContractError("invalid-time") from error


def _mapping_records(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, Mapping) for item in value):
        raise ContractError("malformed-evidence")
    return tuple(cast(Mapping[str, Any], item) for item in value)


def _content_records(query_key: str, content: Mapping[str, Any]) -> tuple[_EvidenceRecord, ...]:
    records: list[_EvidenceRecord] = []
    if query_key == "metric.correlated-observations":
        for row in _mapping_records(content.get("data")):
            metric = row.get("metric")
            sample = row.get("value")
            if (
                not isinstance(metric, Mapping)
                or not isinstance(sample, (list, tuple))
                or len(sample) != 2
            ):
                raise ContractError("malformed-evidence")
            records.append(_EvidenceRecord((metric,), (sample[0],)))
    elif query_key == "log.correlated-events":
        for row in _mapping_records(content.get("data")):
            labels = row.get("labels")
            structured_metadata = row.get("structuredMetadata")
            if (
                not isinstance(labels, Mapping)
                or not isinstance(structured_metadata, Mapping)
                or "timestamp" not in row
            ):
                raise ContractError("malformed-evidence")
            records.append(_EvidenceRecord((labels, structured_metadata), (row["timestamp"],)))
    elif query_key == "trace.by-id":
        trace = content.get("trace")
        if not isinstance(trace, Mapping):
            raise ContractError("malformed-evidence")
        for service in _mapping_records(trace.get("services")):
            resource = service.get("resource")
            if not isinstance(resource, Mapping):
                raise ContractError("malformed-evidence")
            for scope in _mapping_records(service.get("scopes")):
                for span in _mapping_records(scope.get("spans")):
                    attributes = span.get("attributes")
                    if (
                        not isinstance(attributes, Mapping)
                        or "startTimeUnixNano" not in span
                        or "endTimeUnixNano" not in span
                    ):
                        raise ContractError("malformed-evidence")
                    records.append(
                        _EvidenceRecord(
                            (resource, attributes),
                            (span["startTimeUnixNano"], span["endTimeUnixNano"]),
                        )
                    )
    elif query_key == "alert.rule":
        for alert in _mapping_records(content.get("alerts")):
            labels = alert.get("labels")
            if not isinstance(labels, Mapping) or "activeAt" not in alert:
                raise ContractError("malformed-evidence")
            records.append(_EvidenceRecord((labels,), (alert["activeAt"],)))
    else:  # pragma: no cover - query keys are validated before assessment
        raise ContractError("malformed-evidence")
    return tuple(records)


def _record_event_times(query_key: str, record: _EvidenceRecord) -> tuple[datetime, ...]:
    values = record.timestamp_values
    if query_key == "log.correlated-events":
        raw = values[0]
        if isinstance(raw, str) and raw.startswith('"'):
            if len(raw) > 128:
                raise ContractError("invalid-time")
            decoded = strict_json_bytes(raw.encode("utf-8"))
            if not isinstance(decoded, str):
                raise ContractError("invalid-time")
            try:
                numeric = Decimal(decoded)
            except InvalidOperation as error:
                raise ContractError("invalid-time") from error
            if not numeric.is_finite():
                raise ContractError("invalid-time")
            values = (decoded,)
    event_times = tuple(_event_timestamp(value) for value in values)
    if query_key == "trace.by-id" and (len(event_times) != 2 or event_times[0] > event_times[1]):
        raise ContractError("invalid-time")
    return event_times


def _authoritative_correlation_values(
    sources: Sequence[Mapping[str, Any]], keys: frozenset[str]
) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = defaultdict(list)
    for source in sources:
        for key in keys:
            if key in source:
                result[key].append(source[key])
    return result


def _assess_content_records(
    query_key: str,
    content: Mapping[str, Any],
    *,
    expected_correlation: Mapping[str, str],
    window: FrozenWindow,
    evidence_id: str,
) -> list[Blocker]:
    try:
        records = _content_records(query_key, content)
    except (ContractError, KeyError, TypeError, ValueError):
        return [Blocker("malformed-evidence", "assessment", (evidence_id,))]
    if not records:
        return [
            Blocker("incomplete-correlation", "assessment", (evidence_id,)),
            Blocker("incomplete-evidence", "assessment", (evidence_id,)),
        ]

    blockers: list[Blocker] = []
    keys = frozenset(expected_correlation)
    exact_records = 0
    exact_in_window = 0
    sibling_records = 0
    trace_siblings_historical = True
    for record in records:
        observed = _authoritative_correlation_values(record.correlation_sources, keys)
        missing = [key for key in expected_correlation if not observed.get(key)]
        invalid = [
            key
            for key, values in observed.items()
            if any(not isinstance(value, str) or type(value) is not str for value in values)
        ]
        ambiguous = [
            key
            for key, values in observed.items()
            if key not in invalid and len(set(cast(Sequence[str], values))) > 1
        ]
        normalized = {
            key: cast(str, values[0])
            for key, values in observed.items()
            if key not in invalid and key not in ambiguous
        }
        conflicting = any(value != expected_correlation[key] for key, value in normalized.items())
        if missing or invalid:
            blockers.append(Blocker("incomplete-correlation", "assessment", (evidence_id,)))
        if invalid or ambiguous or (missing and conflicting):
            blockers.append(Blocker("contradictory-evidence", "assessment", (evidence_id,)))
        if missing or invalid or ambiguous:
            continue

        exact = all(normalized[key] == expected for key, expected in expected_correlation.items())
        if exact:
            exact_records += 1
        else:
            sibling_records += 1
        try:
            event_times = _record_event_times(query_key, record)
        except (ContractError, TypeError, ValueError):
            if not exact and query_key == "trace.by-id":
                trace_siblings_historical = False
            blockers.extend(
                (
                    Blocker("time-ambiguous", "assessment", (evidence_id,)),
                    Blocker("incomplete-evidence", "assessment", (evidence_id,)),
                )
            )
            continue
        if not event_times:
            if not exact and query_key == "trace.by-id":
                trace_siblings_historical = False
            blockers.append(Blocker("incomplete-evidence", "assessment", (evidence_id,)))
            continue
        inside_window = all(window.start <= event_time <= window.end for event_time in event_times)
        historical = all(event_time < window.start for event_time in event_times)
        if not exact and query_key == "trace.by-id" and not historical:
            trace_siblings_historical = False
        if exact and inside_window:
            exact_in_window += 1
        elif exact:
            blockers.append(Blocker("event-outside-window", "assessment", (evidence_id,)))
        elif not (inside_window or historical):
            blockers.append(Blocker("event-outside-window", "assessment", (evidence_id,)))

    if exact_records == 0:
        blockers.append(Blocker("incomplete-correlation", "assessment", (evidence_id,)))
        if sibling_records:
            blockers.append(Blocker("contradictory-evidence", "assessment", (evidence_id,)))
    elif exact_records > 1:
        blockers.append(Blocker("contradictory-evidence", "assessment", (evidence_id,)))
    elif sibling_records and not (
        exact_in_window == 1
        and (
            query_key == "alert.rule" or (query_key == "trace.by-id" and trace_siblings_historical)
        )
    ):
        blockers.append(Blocker("contradictory-evidence", "assessment", (evidence_id,)))
    return _dedupe_blockers(blockers)


def _model_evidence_view(
    envelope: Mapping[str, Any],
    *,
    intake: AlertIntake,
    now: datetime,
) -> tuple[dict[str, Any] | None, list[Blocker]]:
    evidence_id = envelope.get("evidence_id")
    evidence_ids = (evidence_id,) if isinstance(evidence_id, str) else ()
    try:
        validate_evidence_envelope(envelope)
        observation = envelope["observation"]
        collection = envelope["collection"]
        timing = envelope["timing"]
        source = envelope["source"]
        if not all(
            isinstance(value, Mapping) for value in (observation, collection, timing, source)
        ):
            raise TypeError
        query_key = observation["query_key"]
        expected_batch = intake.evidence_batch(QUERY_KEYS)
        if (
            not isinstance(query_key, str)
            or query_key not in QUERY_KEYS
            or envelope.get("incident_id") != intake.incident_id
            or envelope.get("request_id") != expected_batch.request_id
            or source.get("kind") != "grafana-mcp"
            or source.get("tool") != TOOL_BY_QUERY[query_key]
            or observation.get("model_visible_arguments") != []
            or observation.get("fixed_time_range")
            != {
                "start": timestamp(expected_batch.window_start),
                "end": timestamp(expected_batch.window_end),
            }
            or envelope.get("correlation_keys") != dict(intake.correlation_keys)
        ):
            raise ValueError
    except (AdapterError, KeyError, TypeError, ValueError):
        return None, [Blocker("malformed-evidence", "evidence", evidence_ids)]

    if collection.get("outcome") != "collected" or collection.get("error") is not None:
        error = collection.get("error")
        code = "evidence-unavailable"
        if isinstance(error, Mapping) and isinstance(error.get("code"), str):
            provider_code = _normalized_code(cast(str, error["code"]))
            if "budget" in provider_code:
                code = "budget-exhausted"
            elif provider_code in {"incomplete-result", "malformed-result"}:
                code = "malformed-evidence"
        return None, [Blocker(code, "evidence", evidence_ids)]

    try:
        retrieved_at = parse_timestamp(cast(str, timing["retrieved_at"]))
    except (ContractError, KeyError, TypeError, ValueError):
        return None, [Blocker("time-ambiguous", "assessment", evidence_ids)]
    if (
        retrieved_at > now + timedelta(seconds=5)
        or retrieved_at
        < intake.window.frozen_at - timedelta(seconds=intake.measured_clock_skew_seconds)
        or now - retrieved_at > timedelta(seconds=300)
    ):
        return None, [Blocker("stale-evidence", "assessment", evidence_ids)]

    content = envelope.get("content")
    if not isinstance(content, Mapping):
        return None, [Blocker("malformed-evidence", "assessment", evidence_ids)]
    content_blockers = _assess_content_records(
        cast(str, observation["query_key"]),
        content,
        expected_correlation=intake.correlation_keys,
        window=intake.window,
        evidence_id=cast(str, evidence_id),
    )
    if content_blockers:
        return None, content_blockers
    excerpt = envelope.get("display_excerpt")
    if not isinstance(excerpt, str):
        return None, [Blocker("malformed-evidence", "evidence", evidence_ids)]
    bounded_excerpt, truncated = _bounded_model_excerpt(excerpt)
    return (
        {
            "schema": "grafana-evidence-tool-result/v1",
            "status": "collected",
            "query_key": observation["query_key"],
            "evidence_id": evidence_id,
            "retrieved_at": timing["retrieved_at"],
            "display_excerpt": bounded_excerpt,
            "display_excerpt_truncated": truncated,
            "trust": "untrusted-provider-data",
        },
        [],
    )


class ModelEvidenceLedger:
    _ALLOWED = frozenset(
        {
            "log.correlated-events",
            "metric.correlated-observations",
            "trace.by-id",
        }
    )

    def __init__(
        self,
        *,
        collection: EvidenceCollection,
        budget: BudgetLedger,
        intake: AlertIntake,
        clock: Callable[[], datetime],
    ) -> None:
        self._collection = collection
        self._budget = budget
        self._intake = intake
        self._clock = clock
        self._active = False
        self._seen: set[str] = set()
        self._query_order: list[str] = []
        self._blockers: list[Blocker] = []

    @property
    def blockers(self) -> tuple[Blocker, ...]:
        return tuple(_dedupe_blockers(self._blockers))

    @property
    def query_order(self) -> tuple[str, ...]:
        return tuple(self._query_order)

    def _reject(self, code: str) -> dict[str, Any]:
        self._blockers.append(Blocker(code, "model-tool"))
        return {
            "schema": "grafana-evidence-tool-result/v1",
            "status": "rejected",
            "error_code": code,
        }

    async def get_grafana_evidence(self, query_key: AllowedQueryKey) -> Mapping[str, Any]:
        if self._active:
            return self._reject("parallel-tool-call")
        if type(query_key) is not str or query_key not in self._ALLOWED:
            return self._reject("query-not-allowed")
        if query_key in self._seen:
            return self._reject("duplicate-tool-call")

        self._active = True
        self._seen.add(query_key)
        self._query_order.append(query_key)
        try:
            envelope = await self._collection.collect(query_key)
        except asyncio.CancelledError:
            raise
        except AdapterError as error:
            return self._reject(_normalized_code(error.code))
        except Exception:
            return self._reject("evidence-unavailable")
        finally:
            self._active = False

        view, blockers = _model_evidence_view(
            envelope,
            intake=self._intake,
            now=self._clock().astimezone(UTC),
        )
        if blockers:
            self._blockers.extend(blockers)
            return {
                "schema": "grafana-evidence-tool-result/v1",
                "status": "rejected",
                "error_code": blockers[0].code,
            }
        if view is None:  # pragma: no cover - blockers accompany an absent view
            return self._reject("malformed-evidence")
        try:
            self._budget.reserve_model_visible(canonical_json_bytes(view))
        except WorkflowError as error:
            return self._reject(_normalized_code(error.code))
        return view


def _audit_attempts(result: EvidenceResult, ledger: BudgetLedger) -> list[Blocker]:
    blockers: list[Blocker] = []
    actual: list[tuple[str, str, int, bool, str]] = []
    by_query: dict[str, list[AttemptRecord]] = defaultdict(list)
    for attempt in result.attempts:
        try:
            digest = prefixed_sha256(canonical_json_bytes(attempt.normalized_arguments))
        except (TypeError, ValueError):
            blockers.append(Blocker("argument-drift", "evidence"))
            continue
        if (
            digest != attempt.arguments_sha256
            or TOOL_BY_QUERY.get(attempt.query_key) != attempt.tool
            or attempt.attempt not in {1, 2}
            or attempt.retry != (attempt.attempt == 2)
        ):
            blockers.append(Blocker("argument-drift", "evidence"))
        actual.append(
            (
                attempt.query_key,
                attempt.tool,
                attempt.attempt,
                attempt.retry,
                attempt.arguments_sha256,
            )
        )
        by_query[attempt.query_key].append(attempt)
    if sorted(actual) != sorted(ledger.authorized_attempts):
        blockers.append(Blocker("attempt-ledger-drift", "evidence"))
    for attempts in by_query.values():
        ordered = sorted(attempts, key=lambda item: item.attempt)
        if [item.attempt for item in ordered] not in ([1], [1, 2]):
            blockers.append(Blocker("attempt-sequence-drift", "evidence"))
        if len({item.arguments_sha256 for item in ordered}) != 1:
            blockers.append(Blocker("argument-drift", "evidence"))
        if len(ordered) == 2 and (
            ordered[0].outcome not in {"rate_limit", "service", "timeout", "transport"}
            or ordered[0].query_key == "trace.by-id"
        ):
            blockers.append(Blocker("retry-policy-drift", "evidence"))
    if result.tool_calls_used != len(result.attempts):
        blockers.append(Blocker("attempt-ledger-drift", "evidence"))
    return blockers


def assess_evidence(
    result: EvidenceResult,
    *,
    intake: AlertIntake,
    selected_query_keys: Sequence[str],
    now: datetime,
    ledger: BudgetLedger,
) -> EvidenceAssessment:
    blockers = _audit_attempts(result, ledger)
    expected_request_id = intake.evidence_batch(selected_query_keys).request_id
    authorized_digests: dict[str, set[str]] = defaultdict(set)
    authorized_counts: dict[str, int] = defaultdict(int)
    for (
        authorized_query_key,
        _tool,
        _attempt,
        _retry,
        arguments_sha256,
    ) in ledger.authorized_attempts:
        authorized_digests[authorized_query_key].add(arguments_sha256)
        authorized_counts[authorized_query_key] += 1
    final_outcomes = {
        query_key: max(attempts, key=lambda item: item.attempt).outcome
        for query_key, attempts in (
            (
                query_key,
                [attempt for attempt in result.attempts if attempt.query_key == query_key],
            )
            for query_key in QUERY_KEYS
        )
        if attempts
    }
    if tuple(sorted(selected_query_keys)) != tuple(sorted(QUERY_KEYS)):
        blockers.append(Blocker("incomplete-capability-set", "evidence"))
    if result.maximum_calls_in_flight_observed > 1:
        blockers.append(Blocker("concurrency-budget", "evidence"))
    inventory_version = getattr(result.inventory, "version", None)
    if not isinstance(inventory_version, str) or not inventory_version.startswith("sha256:"):
        blockers.append(Blocker("tool-inventory-drift", "evidence"))
        inventory_version = "sha256:" + "0" * 64

    evidence_ids: list[str] = []
    model_views: list[Mapping[str, Any]] = []
    by_query: dict[str, Mapping[str, Any]] = {}
    expected_predecessor = intake.predecessor_event_sha256
    for envelope in result.envelopes:
        try:
            validate_evidence_envelope(envelope)
        except (AdapterError, TypeError, ValueError):
            blockers.append(Blocker("malformed-evidence", "evidence"))
            continue
        evidence_id = envelope.get("evidence_id")
        observation = envelope.get("observation")
        source = envelope.get("source")
        if (
            not isinstance(evidence_id, str)
            or not isinstance(observation, Mapping)
            or not isinstance(source, Mapping)
        ):
            blockers.append(Blocker("malformed-evidence", "evidence"))
            continue
        query_key = observation.get("query_key")
        if not isinstance(query_key, str) or query_key not in QUERY_KEYS or query_key in by_query:
            blockers.append(Blocker("incomplete-evidence", "evidence", (evidence_id,)))
            continue
        by_query[query_key] = envelope
        if envelope.get("predecessor_event_sha256") != expected_predecessor:
            blockers.append(Blocker("evidence-chain-drift", "evidence", (evidence_id,)))
        expected_predecessor = cast(str, envelope["event_sha256"])
        try:
            arguments_digest = prefixed_sha256(
                canonical_json_bytes(observation["normalized_arguments"])
            )
        except (KeyError, TypeError, ValueError):
            arguments_digest = ""
        collection = cast(Mapping[str, Any], envelope["collection"])
        collection_error = collection.get("error")
        final_outcome = final_outcomes.get(query_key)
        outcome_matches = (
            final_outcome == "collected"
            if collection.get("outcome") == "collected"
            else isinstance(collection_error, Mapping)
            and final_outcome == collection_error.get("code")
        )
        if (
            envelope.get("incident_id") != intake.incident_id
            or envelope.get("request_id") != expected_request_id
            or source.get("kind") != "grafana-mcp"
            or source.get("tool") != TOOL_BY_QUERY[query_key]
            or source.get("inventory_version") != inventory_version
            or arguments_digest not in authorized_digests[query_key]
            or observation.get("model_visible_arguments") != []
            or collection.get("attempts") != authorized_counts[query_key]
            or collection.get("retries") != max(0, authorized_counts[query_key] - 1)
            or not outcome_matches
        ):
            blockers.append(Blocker("evidence-binding-drift", "evidence", (evidence_id,)))
        evidence_ids.append(evidence_id)
        model_views.append(
            {
                "evidence_id": evidence_id,
                "query_key": query_key,
                "retrieved_at": cast(Mapping[str, Any], envelope["timing"])["retrieved_at"],
                "display_excerpt": envelope["display_excerpt"],
                "trust": "untrusted-provider-data",
            }
        )

    if (
        set(by_query) != set(selected_query_keys)
        or set(by_query) != set(QUERY_KEYS)
        or len(evidence_ids) != len(set(evidence_ids))
    ):
        blockers.append(Blocker("incomplete-evidence", "evidence", tuple(evidence_ids)))
    expected_range = {
        "start": timestamp(intake.window.start),
        "end": timestamp(intake.window.end),
    }
    expected_correlation = dict(intake.correlation_keys)
    for query_key, envelope in by_query.items():
        evidence_id = cast(str, envelope["evidence_id"])
        collection = cast(Mapping[str, Any], envelope["collection"])
        observation = cast(Mapping[str, Any], envelope["observation"])
        timing = cast(Mapping[str, Any], envelope["timing"])
        if collection.get("outcome") != "collected" or collection.get("error") is not None:
            blockers.append(Blocker("evidence-unavailable", "evidence", (evidence_id,)))
            continue
        if observation.get("fixed_time_range") != expected_range:
            blockers.append(Blocker("window-drift", "evidence", (evidence_id,)))
        if envelope.get("correlation_keys") != expected_correlation:
            blockers.append(Blocker("correlation-drift", "evidence", (evidence_id,)))
        try:
            retrieved_at = parse_timestamp(cast(str, timing["retrieved_at"]))
        except (ContractError, KeyError, TypeError):
            blockers.append(Blocker("time-ambiguous", "assessment", (evidence_id,)))
            continue
        if retrieved_at > now + timedelta(seconds=5):
            blockers.append(Blocker("time-ambiguous", "assessment", (evidence_id,)))
        elif retrieved_at < intake.window.frozen_at - timedelta(
            seconds=intake.measured_clock_skew_seconds
        ):
            blockers.append(Blocker("stale-evidence", "assessment", (evidence_id,)))
        elif now - retrieved_at > timedelta(seconds=300):
            blockers.append(Blocker("stale-evidence", "assessment", (evidence_id,)))
        content = envelope.get("content")
        if not isinstance(content, Mapping):
            blockers.append(Blocker("incomplete-evidence", "assessment", (evidence_id,)))
            continue
        blockers.extend(
            _assess_content_records(
                query_key,
                content,
                expected_correlation=expected_correlation,
                window=intake.window,
                evidence_id=evidence_id,
            )
        )
    return EvidenceAssessment(
        tuple(sorted(set(evidence_ids))),
        tuple(sorted(model_views, key=lambda item: cast(str, item["query_key"]))),
        inventory_version,
        tuple(_dedupe_blockers(blockers)),
    )


def _deterministic_result(result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "result_id": result["result_id"],
        "validator": result["validator"]["name"],
        "validator_version": result["validator"]["version"],
        "status": result["status"],
        "policy_versions": dict(result["policies"]),
        "derivation_sha256": result["derivation_sha256"],
        "evidence_ids": sorted(
            cast(str, evidence["evidence_id"])
            for evidence in cast(Sequence[Mapping[str, Any]], result["evidence"])
        ),
    }


def _validate_validator_binding(result: Mapping[str, Any], intake: AlertIntake) -> None:
    expected_request_id = f"validation-{sha256(intake.incident_id.encode('utf-8'))[:24]}"
    if (
        result.get("incident_id") != intake.incident_id
        or result.get("request_id") != expected_request_id
    ):
        raise WorkflowError("validator-correlation")
    expected = {
        "job_id": intake.correlation_keys["job_id"],
        "worker_id": intake.correlation_keys["worker_id"],
        "output_id": intake.correlation_keys["artifact_id"],
        "nominal_config_sha256": intake.correlation_keys["config_sha256"],
        "transform_id": intake.correlation_keys["transform_id"],
    }
    matches = [
        comparison
        for comparison in cast(Sequence[Mapping[str, Any]], result.get("comparisons", ()))
        if all(comparison.get(key) == value for key, value in expected.items())
    ]
    if len(matches) != 1:
        raise WorkflowError("validator-correlation")


def classify_claims(
    result: Mapping[str, Any], operational_evidence_ids: Sequence[str]
) -> tuple[list[dict[str, Any]], list[Blocker], set[str]]:
    blockers: list[Blocker] = []
    claims: list[dict[str, Any]] = []
    all_evidence = {
        cast(str, evidence["evidence_id"])
        for evidence in cast(Sequence[Mapping[str, Any]], result["evidence"])
    }
    all_evidence.update(operational_evidence_ids)
    for raw in cast(Sequence[Mapping[str, Any]], result["claims"]):
        state = raw.get("state")
        deterministic_id = cast(str | None, raw.get("deterministic_result_evidence_id"))
        cited = set(cast(Sequence[str], raw.get("evidence_ids", ())))
        identity = {
            "claim_type": raw.get("claim_type"),
            "subject": raw.get("subject"),
        }
        derivation_input = {
            **identity,
            "state": state,
            "policy": raw.get("policy"),
            "normalized_inputs_sha256": raw.get("normalized_inputs_sha256"),
            "evidence_ids": sorted(cited),
            "reason_codes": sorted(cast(Sequence[str], raw.get("reason_codes", ()))),
        }
        expected_derivation = sha256(canonical_json_bytes(derivation_input))
        expected_claim_id = f"claim:{sha256(canonical_json_bytes(identity))}"
        expected_deterministic_id = f"deterministic-result:{expected_derivation}"
        contradictory = "contradictory-authoritative-evidence" in cast(
            Sequence[str], raw.get("reason_codes", ())
        )
        expected_contradictions = sorted(cited) if contradictory else []
        if (
            raw.get("derivation_sha256") != expected_derivation
            or raw.get("claim_id") != expected_claim_id
            or deterministic_id != expected_deterministic_id
            or raw.get("normalized_inputs_sha256")
            != sha256(canonical_json_bytes(raw.get("subject")))
            or raw.get("contradiction_links") != expected_contradictions
        ):
            blockers.append(Blocker("claim-derivation-invalid", "classification", tuple(cited)))
        if deterministic_id is not None:
            all_evidence.add(deterministic_id)
        if state in {"confirmed", "rejected"} and (not cited or deterministic_id is None):
            blockers.append(Blocker("claim-citation-invalid", "classification", tuple(cited)))
        if state in {"inferred", "unresolved"}:
            blockers.append(Blocker("validator-unresolved", "classification", tuple(cited)))
        claim = {
            "schema": "claim/v1",
            "claim_id": raw["claim_id"],
            "claim_type": raw["claim_type"],
            "subject": dict(cast(Mapping[str, Any], raw["subject"])),
            "state": state,
            "policy": raw["policy"],
            "normalized_inputs_sha256": raw["normalized_inputs_sha256"],
            "deterministic_result_evidence_id": deterministic_id,
            "source_validator_result_id": result["result_id"],
            "derivation_sha256": raw["derivation_sha256"],
            "contradiction_links": sorted(cast(Sequence[str], raw.get("contradiction_links", ()))),
            "evidence_ids": sorted(cited),
            "reason_codes": sorted(cast(Sequence[str], raw.get("reason_codes", ()))),
        }
        claims.append(claim)
    if result.get("status") != "resolved":
        blockers.append(Blocker("validator-unresolved", "classification", tuple(all_evidence)))
    return (
        sorted(claims, key=lambda item: cast(str, item["claim_id"])),
        _dedupe_blockers(blockers),
        all_evidence,
    )


def classify_scope(result: Mapping[str, Any]) -> tuple[dict[str, Any], list[Blocker]]:
    raw_scope = cast(Mapping[str, Any], result["scope"])
    affected: list[dict[str, str]] = []
    safe: list[dict[str, str]] = []
    unknown: list[dict[str, str]] = []
    for frame in cast(Sequence[Mapping[str, Any]], raw_scope.get("frames", ())):
        item = {"kind": "frame", "id": cast(str, frame["frame_id"] or frame["job_id"])}
        state = frame.get("state")
        if state == "affected":
            affected.append(item)
        elif state == "safe":
            safe.append(item)
        else:
            unknown.append(item)
    for derivative in cast(Sequence[Mapping[str, Any]], raw_scope.get("derivatives", ())):
        item = {"kind": "derivative", "id": cast(str, derivative["artifact_id"])}
        state = derivative.get("state")
        if state == "affected":
            affected.append(item)
        elif state == "safe":
            safe.append(item)
        else:
            unknown.append(item)
    blockers: list[Blocker] = []
    if raw_scope.get("state") != "resolved" or unknown:
        blockers.append(Blocker("validator-unresolved", "scope"))
    scope = {
        "state": "resolved" if not blockers else "unresolved",
        "policy": "single-causal-resource-scope/v1",
        "affected": sorted(affected, key=lambda item: (item["kind"], item["id"])),
        "safe": sorted(safe, key=lambda item: (item["kind"], item["id"])),
        "unknown": sorted(unknown, key=lambda item: (item["kind"], item["id"])),
        "reason_codes": sorted(cast(Sequence[str], raw_scope.get("reason_codes", ()))),
    }
    return scope, blockers


def _unresolved_claim(
    *, incident_id: str, blockers: Sequence[Blocker], evidence_ids: Sequence[str]
) -> dict[str, Any]:
    reasons = sorted({item.code for item in blockers}) or ["incomplete-evidence"]
    normalized = {
        "incident_id": incident_id,
        "reason_codes": reasons,
        "evidence_ids": sorted(set(evidence_ids)),
    }
    normalized_digest = sha256(canonical_json_bytes(normalized))
    body = {
        "schema": "claim/v1",
        "claim_type": "investigation-completeness",
        "subject": {"kind": "incident-id", "value": incident_id},
        "state": "unresolved",
        "policy": "investigation-completeness/v1",
        "normalized_inputs_sha256": normalized_digest,
        "deterministic_result_evidence_id": None,
        "source_validator_result_id": None,
        "contradiction_links": sorted(
            {
                evidence_id
                for item in blockers
                if item.code == "contradictory-evidence"
                for evidence_id in item.evidence_ids
            }
        ),
        "evidence_ids": sorted(set(evidence_ids)),
        "reason_codes": reasons,
    }
    derivation = sha256(canonical_json_bytes(body))
    return {
        **body,
        "claim_id": f"claim:{derivation}",
        "derivation_sha256": derivation,
    }


def _unknown_scope(scope: Mapping[str, Any] | None, blockers: Sequence[Blocker]) -> dict[str, Any]:
    items: dict[tuple[str, str], dict[str, str]] = {}
    if scope is not None:
        for group in ("affected", "safe", "unknown"):
            for raw in cast(Sequence[Mapping[str, str]], scope.get(group, ())):
                item = {"kind": raw["kind"], "id": raw["id"]}
                items[(item["kind"], item["id"])] = item
    reasons = sorted({item.code for item in blockers}) or ["incomplete-evidence"]
    return {
        "state": "unresolved",
        "policy": "single-causal-resource-scope/v1",
        "affected": [],
        "safe": [],
        "unknown": [items[key] for key in sorted(items)],
        "reason_codes": reasons,
    }


def _candidate_plan(scope: Mapping[str, Any], claims: Sequence[Mapping[str, Any]]) -> Any:
    targets = cast(list[dict[str, str]], scope["affected"])
    decisive = sorted(
        cast(str, claim["claim_id"]) for claim in claims if claim["state"] == "confirmed"
    )
    if not targets or not decisive:
        return None
    body = {
        "schema": "candidate-plan-reference/v1",
        "non_executable": True,
        "targets": targets,
        "claim_ids": decisive,
    }
    digest = sha256(canonical_json_bytes(body))
    return {**body, "plan_id": f"candidate-plan:{digest}"}


def _no_action_reason(blockers: Sequence[Blocker], *, no_targets: bool) -> str | None:
    codes = {item.code for item in blockers}
    if not codes:
        return "no-affected-targets" if no_targets else None
    if any("budget" in code or code == "wall-time-exhausted" for code in codes):
        return "budget-exhausted"
    if "invalid-intake" in codes:
        return "invalid-intake"
    if "policy-drift" in codes:
        return "policy-drift"
    if "contradictory-evidence" in codes:
        return "contradictory-evidence"
    if "stale-evidence" in codes or "time-ambiguous" in codes:
        return "stale-evidence"
    if any(
        code.startswith("model-") or code in {"rate-limit", "service", "timeout", "transport"}
        for code in codes
    ):
        return "model-unavailable"
    if any(code.startswith("validator-") or code == "oracle-boundary" for code in codes):
        return "validator-unresolved"
    if any("unavailable" in code or code in {"authentication", "authorization"} for code in codes):
        return "evidence-unavailable"
    return "incomplete-evidence"


class InvestigationWorkflow:
    def __init__(
        self,
        *,
        policy: InvestigationPolicy,
        model: ModelGateway,
        evidence: EvidenceCollector,
        validator: ValidatorGateway | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        shared_limiter: TrackedSemaphore | None = None,
        progress: WorkflowProgress | None = None,
    ) -> None:
        self._policy = policy
        self._model = model
        self._evidence = evidence
        self._validator = validator or ColorStateValidatorGateway()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or system_monotonic
        self._shared = shared_limiter or TrackedSemaphore(policy.budgets.maximum_calls_in_flight)
        self._progress = progress
        if self._shared.capacity != policy.budgets.maximum_calls_in_flight:
            raise WorkflowError("concurrency-policy")
        self._model_lock = asyncio.Lock()

    async def _validator_call(
        self,
        ledger: BudgetLedger,
        function: Callable[[], _T],
        *,
        final: bool = False,
    ) -> _T:
        ledger.reserve_validator()
        remaining = ledger.remaining_seconds()
        if not final:
            remaining = max(0.0, remaining - 0.25)
        timeout = min(float(self._policy.budgets.evidence_timeout_seconds), remaining)
        if timeout <= 0:
            raise WorkflowError("wall-time-exhausted")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        try:
            await asyncio.wait_for(self._shared.acquire(), timeout=timeout)
        except TimeoutError:
            raise WorkflowError("validator-timeout") from None
        release_deferred = False
        try:
            call_timeout = deadline - loop.time()
            if call_timeout <= 0:
                raise WorkflowError("validator-timeout")
            future = loop.run_in_executor(_VALIDATOR_EXECUTOR, function)

            def release_when_done(_future: asyncio.Future[_T]) -> None:
                self._shared.release()

            try:
                return await asyncio.wait_for(asyncio.shield(future), timeout=call_timeout)
            except TimeoutError:
                release_deferred = True
                future.add_done_callback(release_when_done)
                raise WorkflowError("validator-timeout") from None
            except asyncio.CancelledError:
                release_deferred = True
                future.add_done_callback(release_when_done)
                raise
        finally:
            if not release_deferred:
                self._shared.release()

    def _invocation_record(
        self,
        *,
        intake: AlertIntake,
        turn_kind: str,
        attempt: int,
        input_value: Mapping[str, Any],
        input_evidence_ids: Sequence[str],
        output: ModelOutput | None,
        latency_ms: int,
        result_class: str,
        error_code: str | None,
        inventory_version: str | None,
        failure_usage: tuple[int, int] | None = None,
    ) -> dict[str, Any]:
        output_sha = None if output is None else prefixed_sha256(output.content)
        usage = (output.input_tokens, output.output_tokens) if output is not None else failure_usage
        body = {
            "schema": INVOCATION_VERSION,
            "incident_id": intake.incident_id,
            "turn_kind": turn_kind,
            "attempt": attempt,
            "model": MODEL_ID,
            "location": MODEL_LOCATION,
            "framework": "google-adk",
            "framework_version": ADK_VERSION,
            "client_version": GENAI_VERSION,
            "prompt_version": (
                "evidence-selection/v1"
                if turn_kind == "evidence-selection"
                else "response-drafting/v1"
            ),
            "policy_version": POLICY_VERSION,
            "tool_inventory_version": inventory_version,
            "normalized_input_sha256": prefixed_sha256(canonical_json_bytes(input_value)),
            "input_evidence_ids": sorted(set(input_evidence_ids)),
            "output_sha256": output_sha,
            "latency_ms": max(0, min(latency_ms, 120_000)),
            "usage": {
                "input_tokens": None if usage is None else usage[0],
                "output_tokens": None if usage is None else usage[1],
            },
            "result_class": result_class,
            "error_code": error_code,
            "trace_id": intake.correlation_keys["trace_id"],
        }
        record = finalize_derived_record(
            body, id_field="invocation_id", id_prefix="model-invocation"
        )
        validate_contract("model-tool-invocation-v1.schema.json", record)
        return record

    async def _model_call(
        self,
        *,
        ledger: BudgetLedger,
        intake: AlertIntake,
        turn_kind: str,
        payload: Mapping[str, Any],
        response_schema_name: str,
        input_evidence_ids: Sequence[str],
        inventory_version: str | None,
        evidence_tool: EvidenceTool | None = None,
    ) -> tuple[ModelOutput | None, list[dict[str, Any]], Blocker | None]:
        encoded = canonical_json_bytes(payload)
        try:
            ledger.reserve_model_visible(encoded)
        except WorkflowError as error:
            return (
                None,
                [],
                Blocker(_normalized_code(error.code), "model", tuple(input_evidence_ids)),
            )
        schema = strict_json_file(SCHEMA_ROOT / response_schema_name)
        schema.pop("$schema", None)
        schema.pop("$id", None)
        input_upper_bound = len(encoded) + len(canonical_json_bytes(schema)) + 4096
        records: list[dict[str, Any]] = []
        maximum_model_calls = 4 if evidence_tool is not None else 1
        while True:
            remaining_output = (
                self._policy.budgets.maximum_output_tokens
                - ledger.output_tokens
                - ledger.unavailable_output_tokens_reserved
            )
            maximum_output = min(_MODEL_OUTPUT_LIMITS[turn_kind], remaining_output)
            if maximum_output <= 0 or not ledger.can_admit_model(input_upper_bound, maximum_output):
                return (
                    None,
                    records,
                    Blocker("token-budget", "model", tuple(input_evidence_ids)),
                )
            try:
                ledger.reserve_model_turns(maximum_model_calls)
            except WorkflowError as error:
                return (
                    None,
                    records,
                    Blocker(_normalized_code(error.code), "model", tuple(input_evidence_ids)),
                )
            attempt = len(records) + 1
            started = self._monotonic()
            output: ModelOutput | None = None
            failure: ModelFailure | None = None
            try:
                queue_timeout = max(0.0, ledger.remaining_seconds() - 0.25)
                if queue_timeout <= 0:
                    raise TimeoutError
                await asyncio.wait_for(self._model_lock.acquire(), timeout=queue_timeout)
                try:
                    timeout = min(
                        float(self._policy.budgets.model_timeout_seconds),
                        max(0.0, ledger.remaining_seconds() - 0.25),
                    )
                    if timeout <= 0:
                        raise TimeoutError
                    output = await asyncio.wait_for(
                        self._model.generate(
                            ModelCall(
                                turn_kind,
                                payload,
                                schema,
                                maximum_output,
                                evidence_tool,
                            )
                        ),
                        timeout=timeout,
                    )
                finally:
                    self._model_lock.release()
            except TimeoutError:
                failure = ModelFailure("timeout", transient=True, model_calls=maximum_model_calls)
            except ModelFailure as error:
                failure = error
            except asyncio.CancelledError:
                try:
                    ledger.reserve_unavailable_model_usage(
                        input_upper_bound * maximum_model_calls,
                        maximum_output * maximum_model_calls,
                    )
                except WorkflowError:
                    pass
                records.append(
                    self._invocation_record(
                        intake=intake,
                        turn_kind=turn_kind,
                        attempt=attempt,
                        input_value=payload,
                        input_evidence_ids=input_evidence_ids,
                        output=None,
                        latency_ms=int(max(0.0, self._monotonic() - started) * 1000),
                        result_class="failed",
                        error_code="cancelled",
                        inventory_version=inventory_version,
                    )
                )
                if self._progress is not None:
                    self._progress.invocations.extend(records)
                raise
            except Exception:
                failure = ModelFailure(
                    "model-provider", transient=False, model_calls=maximum_model_calls
                )
            latency_ms = int(max(0.0, self._monotonic() - started) * 1000)
            if failure is not None:
                usage_within_budget = True
                try:
                    ledger.settle_model_turns(maximum_model_calls, failure.model_calls)
                except WorkflowError:
                    usage_within_budget = False
                if failure.input_tokens is not None and failure.output_tokens is not None:
                    usage_within_budget = (
                        ledger.record_model_usage(failure.input_tokens, failure.output_tokens)
                        and usage_within_budget
                    )
                    failure_usage = (failure.input_tokens, failure.output_tokens)
                else:
                    failure_usage = None
                    try:
                        ledger.reserve_unavailable_model_usage(
                            input_upper_bound * failure.model_calls,
                            maximum_output * failure.model_calls,
                        )
                    except WorkflowError:
                        usage_within_budget = False
                record = self._invocation_record(
                    intake=intake,
                    turn_kind=turn_kind,
                    attempt=attempt,
                    input_value=payload,
                    input_evidence_ids=input_evidence_ids,
                    output=None,
                    latency_ms=latency_ms,
                    result_class="failed",
                    error_code=_normalized_code(failure.code).replace("-", "_"),
                    inventory_version=inventory_version,
                    failure_usage=failure_usage,
                )
                records.append(record)
                if not usage_within_budget:
                    return (
                        None,
                        records,
                        Blocker("token-budget", "model", tuple(input_evidence_ids)),
                    )
                if (
                    failure.transient
                    and _normalized_code(failure.code).replace("-", "_")
                    in self._policy.trusted_transient_errors
                    and ledger.reserve_retry()
                ):
                    continue
                return (
                    None,
                    records,
                    Blocker(_normalized_code(failure.code), "model", tuple(input_evidence_ids)),
                )
            if output is None:  # pragma: no cover
                raise WorkflowError("model-incomplete")
            try:
                ledger.settle_model_turns(maximum_model_calls, output.model_calls)
            except WorkflowError:
                turns_within_budget = False
            else:
                turns_within_budget = True
            within_budget = (
                ledger.record_model_usage(output.input_tokens, output.output_tokens)
                and turns_within_budget
            )
            result_class = "accepted" if within_budget else "budget-rejected"
            error_code = (
                None
                if within_budget
                else "model_turn_budget"
                if not turns_within_budget
                else "token_budget"
            )
            records.append(
                self._invocation_record(
                    intake=intake,
                    turn_kind=turn_kind,
                    attempt=attempt,
                    input_value=payload,
                    input_evidence_ids=input_evidence_ids,
                    output=output,
                    latency_ms=latency_ms,
                    result_class=result_class,
                    error_code=error_code,
                    inventory_version=inventory_version,
                )
            )
            if not within_budget:
                code = "model-turn-budget" if not turns_within_budget else "token-budget"
                return None, records, Blocker(code, "model", tuple(input_evidence_ids))
            return output, records, None

    async def run(self, alert: Mapping[str, Any], *, bundle_root: Path) -> dict[str, Any]:
        ledger = BudgetLedger(self._policy, self._monotonic)
        blockers: list[Blocker] = []
        if self._progress is None:
            invocations: list[dict[str, Any]] = []
            evidence_ids: set[str] = set()
            deterministic_results: list[dict[str, Any]] = []
            classified_claims: list[dict[str, Any]] = []
            state_history = ["intake"]
        else:
            self._progress.begin(ledger, self._shared)
            invocations = self._progress.invocations
            evidence_ids = self._progress.evidence_ids
            deterministic_results = self._progress.deterministic_results
            classified_claims = self._progress.classified_claims
            state_history = self._progress.state_history
        classified_scope: dict[str, Any] | None = None
        advisory: ModelAdvisory | None = None
        now = self._clock().astimezone(UTC)
        intake: AlertIntake
        try:
            intake = await self._validator_call(ledger, lambda: AlertIntake.from_mapping(alert))
        except (ContractError, WorkflowError, TypeError, ValueError):
            fallback_id = f"invalid-intake-{sha256(b'invalid-intake')[:16]}"
            intake = AlertIntake(
                fallback_id,
                fallback_id,
                now,
                now,
                0,
                {},
                {"trace_id": "0" * 32},
                None,
                FrozenWindow(now, now, now),
            )
            blockers.append(Blocker("invalid-intake", "intake"))
        if self._progress is not None:
            self._progress.intake = intake

        selection: ModelSelection | None = None
        assessment: EvidenceAssessment | None = None
        result: EvidenceResult | None = None
        if not blockers:
            state_history.append("evidence")
            try:
                batch = intake.evidence_batch(QUERY_KEYS)
                controls = ExecutionControls(
                    shared_limiter=self._shared,
                    attempt_authorizer=ledger.authorize_attempt,
                )
                async with self._evidence.open_collection(batch, controls=controls) as collection:
                    timeout = min(
                        float(self._policy.budgets.evidence_timeout_seconds),
                        max(0.0, ledger.remaining_seconds() - 0.25),
                    )
                    if timeout <= 0:
                        raise WorkflowError("wall-time-exhausted")
                    baseline = await asyncio.wait_for(
                        collection.collect("alert.rule"), timeout=timeout
                    )
                    baseline_view, baseline_blockers = _model_evidence_view(
                        baseline,
                        intake=intake,
                        now=self._clock().astimezone(UTC),
                    )
                    blockers.extend(baseline_blockers)
                    if not blockers and baseline_view is not None:
                        state_history.append("selection")
                        tool_ledger = ModelEvidenceLedger(
                            collection=collection,
                            budget=ledger,
                            intake=intake,
                            clock=self._clock,
                        )
                        selection_payload = {
                            "input_contract": "evidence-selection-input/v1",
                            "policy_version": self._policy.version,
                            "policy_sha256": self._policy.digest,
                            "alert": intake.model_view(),
                            "alert_baseline": baseline_view,
                            "authority": "query-key-selection-only-no-provider-arguments",
                        }
                        inventory_version = getattr(collection.result().inventory, "version", None)
                        output, records, blocker = await self._model_call(
                            ledger=ledger,
                            intake=intake,
                            turn_kind="evidence-selection",
                            payload=selection_payload,
                            response_schema_name="model-selection-v1.schema.json",
                            input_evidence_ids=(cast(str, baseline["evidence_id"]),),
                            inventory_version=(
                                inventory_version if isinstance(inventory_version, str) else None
                            ),
                            evidence_tool=tool_ledger.get_grafana_evidence,
                        )
                        invocations.extend(records)
                        blockers.extend(tool_ledger.blockers)
                        if blocker is not None:
                            blockers.append(blocker)
                        elif output is not None:
                            try:
                                selection = ModelSelection.from_bytes(output.content)
                            except ContractError:
                                blockers.append(Blocker("model-output-invalid", "selection"))
                            else:
                                expected_query_order = (
                                    "alert.rule",
                                    *tool_ledger.query_order,
                                )
                                if (
                                    set(tool_ledger.query_order) != ModelEvidenceLedger._ALLOWED
                                    or selection.query_keys != expected_query_order
                                ):
                                    blockers.append(Blocker("model-tool-sequence", "selection"))
                    result = collection.result()
            except asyncio.CancelledError:
                raise
            except TimeoutError:
                blockers.append(Blocker("evidence-timeout", "evidence"))
            except AdapterError as error:
                blockers.append(Blocker(_normalized_code(error.code), "evidence"))
            except (ContractError, WorkflowError, TypeError, ValueError):
                blockers.append(Blocker("evidence-unavailable", "evidence"))
            except Exception:
                blockers.append(Blocker("evidence-unavailable", "evidence"))

            if result is not None:
                state_history.append("assessment")
                try:
                    assessment = await self._validator_call(
                        ledger,
                        lambda: assess_evidence(
                            result,
                            intake=intake,
                            selected_query_keys=QUERY_KEYS,
                            now=self._clock().astimezone(UTC),
                            ledger=ledger,
                        ),
                    )
                except WorkflowError as error:
                    blockers.append(Blocker(_normalized_code(error.code), "assessment"))
                except Exception:
                    blockers.append(Blocker("malformed-evidence", "assessment"))
                if assessment is not None:
                    evidence_ids.update(assessment.evidence_ids)
                    blockers.extend(assessment.blockers)

        validator_result: dict[str, Any] | None = None
        if not blockers and assessment is not None:
            state_history.append("validation")
            try:
                validator_result = await self._validator_call(
                    ledger,
                    lambda: self._validator.validate(bundle_root, incident_id=intake.incident_id),
                )
                validate_result_contract(validator_result)
                _validate_validator_binding(validator_result, intake)
                deterministic_results.append(_deterministic_result(validator_result))
                evidence_ids.update(deterministic_results[-1]["evidence_ids"])
            except WorkflowError as error:
                blockers.append(Blocker(_normalized_code(error.code), "validation"))
            except Exception:
                blockers.append(Blocker("validator-unresolved", "validation"))

        if not blockers and validator_result is not None:
            try:
                classified_claims, claim_blockers, claim_evidence = await self._validator_call(
                    ledger,
                    lambda: classify_claims(
                        validator_result,
                        () if assessment is None else assessment.evidence_ids,
                    ),
                )
                if self._progress is not None:
                    self._progress.classified_claims = classified_claims
                blockers.extend(claim_blockers)
                evidence_ids.update(claim_evidence)
            except WorkflowError as error:
                blockers.append(Blocker(_normalized_code(error.code), "classification"))
            except Exception:
                blockers.append(Blocker("validator-unresolved", "classification"))

        if not blockers and validator_result is not None:
            try:
                classified_scope, scope_blockers = await self._validator_call(
                    ledger, lambda: classify_scope(validator_result)
                )
                if self._progress is not None:
                    self._progress.classified_scope = classified_scope
                blockers.extend(scope_blockers)
            except WorkflowError as error:
                blockers.append(Blocker(_normalized_code(error.code), "scope"))
            except Exception:
                blockers.append(Blocker("validator-unresolved", "scope"))

        if not blockers and assessment is not None and classified_scope is not None:
            state_history.append("drafting")
            draft_payload = {
                "input_contract": "response-drafting-input/v1",
                "policy_version": self._policy.version,
                "deterministic_facts": {
                    "claims": classified_claims,
                    "scope": classified_scope,
                },
                "quoted_evidence_excerpts": _project_advisory_evidence_views(
                    assessment.model_views
                ),
                "allowed_evidence_ids": sorted(assessment.evidence_ids),
                "authority": "advisory-only",
            }
            output, records, blocker = await self._model_call(
                ledger=ledger,
                intake=intake,
                turn_kind="response-drafting",
                payload=draft_payload,
                response_schema_name="model-advisory-v1.schema.json",
                input_evidence_ids=assessment.evidence_ids,
                inventory_version=assessment.inventory_version,
            )
            invocations.extend(records)
            if blocker is not None:
                blockers.append(blocker)
            elif output is not None:
                try:
                    advisory = ModelAdvisory.from_bytes(
                        output.content, frozenset(assessment.evidence_ids)
                    )
                except ContractError as error:
                    blockers.append(Blocker(_normalized_code(error.code), "drafting"))

        blockers = _dedupe_blockers(blockers)
        state_history.extend(("finalization", "complete"))
        if blockers:
            claims = [
                _unresolved_claim(
                    incident_id=intake.incident_id,
                    blockers=blockers,
                    evidence_ids=sorted(evidence_ids),
                )
            ]
            scope = _unknown_scope(classified_scope, blockers)
            status = "unresolved"
            candidate_plan = None
            model_advisory = None
        else:
            claims = classified_claims
            scope = classified_scope or _unknown_scope(
                None, (Blocker("incomplete-evidence", "scope"),)
            )
            status = "resolved"
            candidate_plan = _candidate_plan(scope, claims)
            model_advisory = None if advisory is None else advisory.to_dict()
        no_action_reason = _no_action_reason(
            blockers,
            no_targets=not cast(Sequence[Any], scope["affected"]),
        )

        def build_packet() -> dict[str, Any]:
            body = {
                "schema": RESPONSE_PACKET_VERSION,
                "incident_id": intake.incident_id,
                "version": 1,
                "status": status,
                "fixed_window": intake.window.to_dict(),
                "evidence_ids": sorted(evidence_ids),
                "deterministic_results": deterministic_results,
                "claims": claims,
                "scope": scope,
                "invocation_records": invocations,
                "budget_use": ledger.snapshot(self._shared),
                "unresolved_items": [item.to_dict() for item in blockers],
                "candidate_plan": candidate_plan,
                "no_action_reason": no_action_reason,
                "model_advisory": model_advisory,
                "state_history": state_history,
                "finalized_at": timestamp(self._clock().astimezone(UTC)),
            }
            return finalize_response_packet(body)

        try:
            return await self._validator_call(ledger, build_packet, final=True)
        except Exception as error:
            raise WorkflowError("packet-finalization") from error
