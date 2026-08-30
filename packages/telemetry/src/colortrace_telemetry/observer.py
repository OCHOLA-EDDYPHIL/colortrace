"""Fail-closed observation and verification against real local backends."""

from __future__ import annotations

import json
import math
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from colortrace_telemetry.contract import (
    NO_GRAFANA_VERSION,
    SIGNALS,
    CandidateBinding,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    strict_json,
    validate_schema,
)

CORRELATION_FIELDS = (
    "fixture_id",
    "run_id",
    "job_id",
    "worker_id",
    "artifact_id",
    "trace_id",
    "config_sha256",
    "resource_sha256",
    "transform_id",
)
_PRIVATE_FIXTURE_MOUNT = "/isolated-fixture-private"
_GRAFANA_READINESS_PATHS = (
    "/api/health",
    "/api/ruler/grafana/api/v1/rules",
)
_GRAFANA_READINESS_TIMEOUT_SECONDS = 60.0
_GRAFANA_READINESS_POLL_SECONDS = 1.0
_GRAFANA_READINESS_REQUEST_TIMEOUT_SECONDS = 5.0
_GRAFANA_READINESS_CONSECUTIVE_MATCHES = 3


@dataclass(frozen=True, slots=True)
class BackendEndpoints:
    otlp: str
    prometheus: str
    loki: str
    tempo: str
    grafana: str

    @classmethod
    def local(cls) -> BackendEndpoints:
        return cls(
            otlp="http://127.0.0.1:14318",
            prometheus="http://127.0.0.1:19090",
            loki="http://127.0.0.1:13100",
            tempo="http://127.0.0.1:13200",
            grafana="http://127.0.0.1:13000",
        )


class BackendUnavailable(RuntimeError):
    pass


def telemetry_isolation_receipt() -> dict[str, Any]:
    private_root = Path(_PRIVATE_FIXTURE_MOUNT)
    private_mount_visible = private_root.exists()
    try:
        (private_root / "neutral-probe").read_bytes()
    except FileNotFoundError:
        probe_outcome = "not-mounted"
    except PermissionError:
        probe_outcome = "read-denied"
    else:
        probe_outcome = "readable"
    try:
        mount_info = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        mount_info = _PRIVATE_FIXTURE_MOUNT
    workspace_root = Path("/workspace")
    material_paths: list[str] = []
    if workspace_root.is_dir():
        for path in sorted(workspace_root.rglob("*")):
            if not path.is_file():
                continue
            if path.name == "fixture-oracle.json" or "offline-oracle" in path.parts:
                material_paths.append(path.relative_to(workspace_root).as_posix())
    argv_reference = any(_PRIVATE_FIXTURE_MOUNT in value for value in sys.argv)
    environment_reference = any(
        _PRIVATE_FIXTURE_MOUNT in key or _PRIVATE_FIXTURE_MOUNT in value
        for key, value in os.environ.items()
    )
    passed = (
        not private_mount_visible
        and probe_outcome == "not-mounted"
        and _PRIVATE_FIXTURE_MOUNT not in mount_info
        and not material_paths
        and not argv_reference
        and not environment_reference
    )
    receipt = {
        "schema": "telemetry-isolation-receipt/v1",
        "private_mount_visible": private_mount_visible,
        "private_probe_read_outcome": probe_outcome,
        "private_mount_in_process_namespace": _PRIVATE_FIXTURE_MOUNT in mount_info,
        "workspace_truth_material_paths": material_paths,
        "argv_contains_private_mount_reference": argv_reference,
        "environment_contains_private_mount_reference": environment_reference,
        "pass": passed,
    }
    validate_schema("telemetry-isolation-receipt-v1.schema.json", receipt)
    return receipt


def _json_get(
    base: str,
    path: str,
    *,
    query: Mapping[str, str | int] | None = None,
    timeout_seconds: float = 5.0,
) -> Any:
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read())
    except (
        OSError,
        TimeoutError,
        urllib.error.HTTPError,
        urllib.error.URLError,
        json.JSONDecodeError,
    ) as error:
        raise BackendUnavailable(f"backend query unavailable: {url}") from error


def _grafana_readiness_probe(
    endpoints: BackendEndpoints,
    *,
    alert_contract: Mapping[str, Any],
    deadline: float,
    monotonic: Callable[[], float],
) -> tuple[bool, int | None, tuple[str, ...]]:
    payloads: list[Any] = []
    for path in _GRAFANA_READINESS_PATHS:
        remaining = deadline - monotonic()
        if remaining <= 0:
            return False, None, ()
        try:
            payloads.append(
                _json_get(
                    endpoints.grafana,
                    path,
                    timeout_seconds=min(_GRAFANA_READINESS_REQUEST_TIMEOUT_SECONDS, remaining),
                )
            )
        except BackendUnavailable:
            return False, None, ()
    target_groups = _target_alert_groups(payloads[-1], str(alert_contract["uid"]))
    observed_intervals = tuple(
        sorted({_safe_readiness_interval(group.get("interval")) for group in target_groups})
    )
    expected_interval = f"{int(alert_contract['scheduler_interval_seconds'])}s"
    return (
        len(target_groups) == 1 and observed_intervals == (expected_interval,),
        len(target_groups),
        observed_intervals,
    )


def _safe_readiness_interval(value: Any) -> str:
    if (
        isinstance(value, str)
        and 2 <= len(value) <= 16
        and value[-1] in {"s", "m", "h"}
        and value[:-1].isdigit()
    ):
        return value
    return "invalid"


def _target_alert_groups(payload: Any, uid: str) -> list[Mapping[str, Any]]:
    target_groups: list[Mapping[str, Any]] = []
    if not isinstance(payload, Mapping):
        return target_groups
    for namespace_groups in payload.values():
        if not isinstance(namespace_groups, list):
            continue
        for group in namespace_groups:
            if not isinstance(group, Mapping):
                continue
            rules = group.get("rules")
            if not isinstance(rules, list):
                continue
            if any(
                isinstance(rule, Mapping)
                and isinstance(rule.get("grafana_alert"), Mapping)
                and rule["grafana_alert"].get("uid") == uid
                for rule in rules
            ):
                target_groups.append(group)
    return target_groups


def _readiness_alert_contract(stack_config_path: Path) -> dict[str, Any]:
    alert_contract_path = stack_config_path.resolve(strict=True).parent / "alert-contract.json"
    alert_contract = strict_json(alert_contract_path.resolve(strict=True))
    validate_schema("grafana-alert-contract-v1.schema.json", alert_contract)
    return alert_contract


def wait_for_grafana_readiness(
    endpoints: BackendEndpoints,
    *,
    stack_config_path: Path = Path("config/telemetry/local-stack.json"),
    timeout_seconds: float = _GRAFANA_READINESS_TIMEOUT_SECONDS,
    poll_seconds: float = _GRAFANA_READINESS_POLL_SECONDS,
    required_consecutive_matches: int = _GRAFANA_READINESS_CONSECUTIVE_MATCHES,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Grafana readiness timeout must be positive and finite")
    if not math.isfinite(poll_seconds) or poll_seconds <= 0:
        raise ValueError("Grafana readiness poll interval must be positive and finite")
    if (
        isinstance(required_consecutive_matches, bool)
        or not isinstance(required_consecutive_matches, int)
        or required_consecutive_matches <= 0
    ):
        raise ValueError("Grafana readiness consecutive matches must be a positive integer")
    alert_contract = _readiness_alert_contract(stack_config_path)
    deadline = monotonic() + timeout_seconds
    target_count: int | None = None
    observed_intervals: tuple[str, ...] = ()
    consecutive_matches = 0
    while monotonic() < deadline:
        ready, observed_count, observed = _grafana_readiness_probe(
            endpoints,
            alert_contract=alert_contract,
            deadline=deadline,
            monotonic=monotonic,
        )
        if observed_count is not None:
            target_count = observed_count
            observed_intervals = observed
        consecutive_matches = consecutive_matches + 1 if ready else 0
        if consecutive_matches >= required_consecutive_matches:
            return
        remaining = deadline - monotonic()
        if remaining > 0:
            sleep(min(poll_seconds, remaining))
    count = "unavailable" if target_count is None else str(target_count)
    intervals = "unavailable" if target_count is None else ",".join(observed_intervals) or "none"
    raise BackendUnavailable(
        "Grafana readiness gate timed out "
        f"(target_rule_count={count}, observed_intervals={intervals})"
    )


def _http_reachable(base: str, path: str) -> bool:
    request = urllib.request.Request(base.rstrip("/") + path, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=0.2) as response:
            return 100 <= int(response.status) < 600
    except urllib.error.HTTPError:
        return True
    except (OSError, TimeoutError, urllib.error.URLError):
        return False


def validated_isolation_receipt(path: Path) -> str:
    receipt = strict_json(path.resolve(strict=True))
    validate_schema("telemetry-isolation-receipt-v1.schema.json", receipt)
    return sha256_file(path)


def observe_without_grafana(
    endpoints: BackendEndpoints,
    candidate: CandidateBinding,
    isolation_receipt_sha256: str,
) -> dict[str, Any]:
    probes = (
        (endpoints.prometheus, "/-/ready"),
        (endpoints.loki, "/ready"),
        (endpoints.tempo, "/ready"),
        (endpoints.grafana, "/api/health"),
    )
    for base, path in probes:
        if _http_reachable(base, path):
            raise ValueError("no-Grafana control unexpectedly reached an observability backend")
    result = {
        "schema": NO_GRAFANA_VERSION,
        "candidate": candidate.to_dict(),
        "isolation_receipt_sha256": isolation_receipt_sha256,
        "outcome": "unavailable",
        "signals": {
            "metric": "unavailable",
            "log": "unavailable",
            "trace": "unavailable",
            "alert": "unavailable",
        },
        "decisive_operational_facts": [],
    }
    validate_schema("no-grafana-observation-v1.schema.json", result)
    return result


def _normalized(attributes: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key).replace(".", "_"): value for key, value in attributes.items()}


def _prometheus_records(endpoints: BackendEndpoints) -> list[dict[str, Any]]:
    payload = _json_get(
        endpoints.prometheus,
        "/api/v1/query",
        query={
            "query": (
                'colortrace_declared_reference_observations_total{fixture_id="ct-shadowed-lut-v1"}'
            )
        },
    )
    results = payload.get("data", {}).get("result", []) if isinstance(payload, dict) else []
    records: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("metric"), dict):
            continue
        value = result.get("value")
        if not isinstance(value, list) or len(value) != 2:
            continue
        copies = int(float(value[1]))
        attributes = _normalized(result["metric"])
        records.extend([attributes] * copies)
    return records


def _loki_records(endpoints: BackendEndpoints) -> list[dict[str, Any]]:
    now_ns = time.time_ns()
    payload = _json_get(
        endpoints.loki,
        "/loki/api/v1/query_range",
        query={
            "query": '{service_name="colortrace-simulator"}',
            "start": now_ns - 15 * 60 * 1_000_000_000,
            "end": now_ns + 1_000_000_000,
            "direction": "forward",
            "limit": 5000,
        },
    )
    results = payload.get("data", {}).get("result", []) if isinstance(payload, dict) else []
    records: list[dict[str, Any]] = []
    for stream in results:
        if not isinstance(stream, dict):
            continue
        labels = stream.get("stream", {})
        if not isinstance(labels, dict):
            labels = {}
        values = stream.get("values", [])
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, list) or len(value) < 2:
                continue
            metadata = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
            records.append(_normalized({**labels, **metadata}))
    return records


def _otel_value(value: Any) -> str | int | bool | None:
    if not isinstance(value, dict):
        return None
    for key in ("stringValue", "intValue", "boolValue", "doubleValue"):
        if key in value:
            raw = value[key]
            if key == "intValue":
                return int(raw)
            return cast(str | int | bool, raw)
    return None


def _otel_attributes(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, list):
        return {}
    result: dict[str, Any] = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("key"), str):
            continue
        value = _otel_value(item.get("value"))
        if value is not None:
            result[item["key"]] = value
    return result


def _trace_records(endpoints: BackendEndpoints, trace_ids: set[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for trace_id in sorted(trace_ids):
        try:
            payload = _json_get(endpoints.tempo, f"/api/traces/{trace_id}")
        except BackendUnavailable:
            continue
        batches = payload.get("batches", []) if isinstance(payload, dict) else []
        if not isinstance(batches, list):
            continue
        for batch in batches:
            if not isinstance(batch, dict):
                continue
            resource = batch.get("resource", {})
            resource_attributes = _otel_attributes(
                resource.get("attributes", {}) if isinstance(resource, dict) else {}
            )
            scopes = batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", []))
            if not isinstance(scopes, list):
                continue
            for scope in scopes:
                if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
                    continue
                for span in scope["spans"]:
                    if not isinstance(span, dict):
                        continue
                    records.append(
                        _normalized(
                            {
                                **resource_attributes,
                                **_otel_attributes(span.get("attributes")),
                            }
                        )
                    )
    return records


def _event_id(attributes: Mapping[str, Any]) -> str | None:
    value = attributes.get("telemetry_event_id")
    return value if isinstance(value, str) else None


def _wait_records(
    fetch: Callable[[], list[dict[str, Any]]],
    expected_deliveries: int,
    *,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    records: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        try:
            records = [record for record in fetch() if _event_id(record) is not None]
        except BackendUnavailable:
            records = []
        if len(records) >= expected_deliveries:
            return records
        time.sleep(1)
    return records


def _instructions(receipt: Mapping[str, Any], signal: str) -> list[dict[str, Any]]:
    return [
        instruction
        for run in receipt["runs"]
        for instruction in run["plans"]
        if instruction["signal"] == signal
    ]


def _event_correlations(receipt: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for run in receipt["runs"]:
        by_job: dict[str, dict[str, Any]] = {}
        for event in run["events"]:
            by_job[event["correlation"]["job_id"]] = event["correlation"]
            result[event["event_id"]] = event["correlation"]
        for instruction in run["plans"]:
            result.setdefault(instruction["event_id"], by_job[instruction["job_id"]])
    return result


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise AssertionError("telemetry event time is absent")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _verify_signal(
    signal: str,
    receipt: Mapping[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    instructions = _instructions(receipt, signal)
    expected = {item["event_id"]: item for item in instructions}
    correlations = _event_correlations(receipt)
    counts = Counter(_event_id(record) for record in records)
    counts.pop(None, None)
    unexpected = set(counts) - set(expected)
    if unexpected:
        raise AssertionError(f"{signal} backend contains unexpected event identities")
    for event_key, instruction in expected.items():
        if counts[event_key] != instruction["copies"]:
            raise AssertionError(
                f"{signal} delivery count differs for {event_key}: "
                f"{counts[event_key]} != {instruction['copies']}"
            )
    by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        identifier = _event_id(record)
        if identifier in expected:
            by_event[cast(str, identifier)].append(record)
    for event_key, event_records in by_event.items():
        instruction = expected[event_key]
        correlation = correlations[event_key]
        for record in event_records:
            for field in CORRELATION_FIELDS:
                if record.get(field) != correlation[field]:
                    raise AssertionError(f"{signal} correlation field {field} differs")
            if record.get("telemetry_contract") != "telemetry-event/v1":
                raise AssertionError(f"{signal} telemetry contract is absent")
            delay = int(record.get("telemetry_delivery_delay_ms", -1))
            if delay != instruction["delay_ms"]:
                raise AssertionError(f"{signal} delivery delay differs")
            scheduled = _parse_time(record.get("telemetry_scheduled_at"))
            emitted = _parse_time(record.get("telemetry_emitted_at"))
            age_ms = int((emitted - scheduled).total_seconds() * 1000)
            if age_ms < delay:
                raise AssertionError(f"{signal} event age was silently filled")
            if instruction["outcome"] == "late" and delay < 11_000:
                raise AssertionError(f"{signal} late event is inside the scheduler interval")
    outcomes = Counter(item["outcome"] for item in instructions)
    jobs = {correlations[item["event_id"]]["job_id"] for item in instructions}
    return {
        "logical_events": len(instructions),
        "deliveries": len(records),
        "jobs": len(jobs),
        "outcomes": {name: outcomes[name] for name in ("on_time", "late", "duplicate", "missing")},
        "correlation_fields": list(CORRELATION_FIELDS),
        "pass": True,
    }


def _metric_series(endpoints: BackendEndpoints) -> int:
    payload = _json_get(
        endpoints.prometheus,
        "/api/v1/series",
        query={"match[]": '{__name__=~"colortrace_.*"}'},
    )
    data = payload.get("data", []) if isinstance(payload, dict) else []
    return len(data) if isinstance(data, list) else 0


def _alert_contract(endpoints: BackendEndpoints, contract: Mapping[str, Any]) -> dict[str, Any]:
    uid = str(contract["uid"])
    rule = _json_get(
        endpoints.grafana,
        f"/api/v1/provisioning/alert-rules/{uid}",
        timeout_seconds=15.0,
    )
    if not isinstance(rule, dict) or rule.get("uid") != uid:
        raise AssertionError("Grafana alert was not provisioned")
    if rule.get("noDataState") != contract["no_data_state"]:
        raise AssertionError("Grafana alert does not expose missing data")
    if rule.get("execErrState") != contract["execution_error_state"]:
        raise AssertionError("Grafana alert does not expose execution errors")
    pending_period_seconds = int(contract["pending_period_seconds"])
    if rule.get("for") != f"{pending_period_seconds}s":
        raise AssertionError("Grafana alert pending period differs from its contract")
    if (
        not isinstance(rule.get("annotations"), dict)
        or rule["annotations"].get("alert_contract") != contract["schema"]
    ):
        raise AssertionError("Grafana alert contract annotation changed")
    data = rule.get("data")
    expression = ""
    if isinstance(data, list):
        for query in data:
            if isinstance(query, dict) and query.get("refId") == "A":
                model = query.get("model", {})
                expression = str(model.get("expr", "")) if isinstance(model, dict) else ""
                if query.get("relativeTimeRange") != {
                    "from": contract["evidence_window_seconds"],
                    "to": 0,
                }:
                    raise AssertionError("Grafana alert evidence window changed")
    selector = contract["selector"]
    if (
        contract["metric"] not in expression
        or f'fixture_id="{selector["fixture_id"]}"' not in expression
        or f'declared_reference_state="{selector["declared_reference_state"]}"' not in expression
        or "[10m]" not in expression
        or any(field in expression for field in contract["excluded_alert_keys"])
    ):
        raise AssertionError("Grafana alert expression violates the symptom contract")
    groups = _json_get(
        endpoints.grafana,
        "/api/ruler/grafana/api/v1/rules",
        timeout_seconds=15.0,
    )
    target_groups = _target_alert_groups(groups, uid)
    scheduler_interval_seconds = int(contract["scheduler_interval_seconds"])
    if len(target_groups) != 1 or target_groups[0].get("interval") != (
        f"{scheduler_interval_seconds}s"
    ):
        observed_intervals = tuple(
            sorted({_safe_readiness_interval(group.get("interval")) for group in target_groups})
        )
        raise AssertionError(
            "Grafana alert scheduler interval differs from its contract "
            f"(target_rule_count={len(target_groups)}, "
            f"observed_intervals={','.join(observed_intervals) or 'none'})"
        )
    return {
        "uid": uid,
        "provisioned": True,
        "scheduler_interval_seconds": scheduler_interval_seconds,
        "pending_period_seconds": pending_period_seconds,
        "evidence_window_seconds": contract["evidence_window_seconds"],
        "execution_error_state": contract["execution_error_state"],
        "no_data_state": contract["no_data_state"],
    }


def _execution_boundary(
    endpoints: BackendEndpoints, stack_config_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved_stack_config = stack_config_path.resolve(strict=True)
    config = strict_json(resolved_stack_config)
    alert_contract_path = resolved_stack_config.parent / "alert-contract.json"
    alert_contract = _readiness_alert_contract(resolved_stack_config)
    image = config.get("image", {})
    components = config.get("components", {})
    contracts = config.get("contracts", {})
    live = config.get("live_target", {})
    if (
        config.get("schema") != "colortrace-local-telemetry-stack/v1"
        or config.get("scope") != "local-50-run-backend-suite-only"
        or not isinstance(contracts, dict)
        or contracts.get("alert") != alert_contract["schema"]
        or not isinstance(image, dict)
        or image.get("name") != "grafana/otel-lgtm"
        or image.get("version") != "0.30.1"
        or image.get("digest")
        != "sha256:bb182ac3174a20923fa58f00d1790fa71eb06cc0150078c0b0e8feb9e6611492"
        or not isinstance(components, dict)
        or components.get("grafana") != "13.1.1"
        or not isinstance(live, dict)
        or live.get("grafana") != "13.2.0"
        or live.get("local_live_parity_claimed") is not False
        or live.get("unsupported_drift_outcome") != "unresolved"
    ):
        raise AssertionError("local/live telemetry stack boundary changed")
    health = _json_get(endpoints.grafana, "/api/health")
    observed = health.get("version") if isinstance(health, dict) else None
    if observed != components["grafana"]:
        raise AssertionError(
            f"local Grafana version drift: {observed!r} != {components['grafana']!r}"
        )
    return (
        {
            "scope": config["scope"],
            "stack_config_sha256": sha256_file(resolved_stack_config),
            "alert_contract_sha256": sha256_file(alert_contract_path),
            "image_digest": image["digest"],
            "expected_grafana_version": components["grafana"],
            "observed_grafana_version": observed,
            "live_parity_claimed": False,
        },
        alert_contract,
    )


def _wait_alert_firing(endpoints: BackendEndpoints, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            payload = _json_get(endpoints.grafana, "/api/prometheus/grafana/api/v1/rules")
        except BackendUnavailable:
            payload = {}
        groups = payload.get("data", {}).get("groups", []) if isinstance(payload, dict) else []
        if isinstance(groups, list):
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("rules"), list):
                    continue
                for rule in group["rules"]:
                    if (
                        not isinstance(rule, dict)
                        or rule.get("name") != "ColorTrace declared-reference visual divergence"
                        or rule.get("state") != "firing"
                        or not isinstance(rule.get("alerts"), list)
                    ):
                        continue
                    for alert in rule["alerts"]:
                        if not isinstance(alert, dict):
                            continue
                        labels = alert.get("labels", {})
                        alert_fields = tuple(
                            field for field in CORRELATION_FIELDS if field != "resource_sha256"
                        )
                        if (
                            isinstance(labels, dict)
                            and labels.get("fixture_id") == "ct-shadowed-lut-v1"
                            and str(labels.get("run_id", "")).startswith("telemetry-run-")
                            and all(labels.get(field) for field in alert_fields)
                            and "resource_sha256" not in labels
                            and alert.get("state") == "Alerting"
                        ):
                            return True
        time.sleep(2)
    return False


def verify_real_backends(
    receipt: Mapping[str, Any],
    endpoints: BackendEndpoints,
    *,
    stack_config_path: Path = Path("config/telemetry/local-stack.json"),
    isolation_receipt_path: Path,
    ingestion_timeout_seconds: float = 30.0,
    alert_timeout_seconds: float = 90.0,
) -> dict[str, Any]:
    if len(receipt.get("runs", [])) != 50:
        raise ValueError("real backend verification requires exactly 50 runs")
    isolation_receipt_sha256 = validated_isolation_receipt(isolation_receipt_path)
    execution_boundary, alert_contract = _execution_boundary(endpoints, stack_config_path)
    expected_deliveries = {
        signal: sum(item["copies"] for item in _instructions(receipt, signal)) for signal in SIGNALS
    }
    trace_ids = {
        event["correlation"]["trace_id"]
        for run in receipt["runs"]
        for event in run["events"]
        if event["signal"] == "trace"
    }
    records = {
        "metric": _wait_records(
            lambda: _prometheus_records(endpoints),
            expected_deliveries["metric"],
            timeout_seconds=ingestion_timeout_seconds,
        ),
        "log": _wait_records(
            lambda: _loki_records(endpoints),
            expected_deliveries["log"],
            timeout_seconds=ingestion_timeout_seconds,
        ),
        "trace": _wait_records(
            lambda: _trace_records(endpoints, trace_ids),
            expected_deliveries["trace"],
            timeout_seconds=ingestion_timeout_seconds,
        ),
    }
    signal_results = {
        signal: _verify_signal(signal, receipt, records[signal]) for signal in SIGNALS
    }
    series = _metric_series(endpoints)
    if not 1 <= series <= 600:
        raise AssertionError(f"ColorTrace metric cardinality {series} exceeds 600")
    alert = _alert_contract(endpoints, alert_contract)
    alert["firing"] = _wait_alert_firing(endpoints, alert_timeout_seconds)
    if not alert["firing"]:
        raise AssertionError("Grafana alert did not enter firing state")
    report = {
        "schema": "backend-correlation-report/v1",
        "receipt_sha256": sha256_bytes(canonical_json_bytes(receipt)),
        "isolation_receipt_sha256": isolation_receipt_sha256,
        "execution_boundary": execution_boundary,
        "run_count": 50,
        "signal_results": signal_results,
        "metric_series": series,
        "metric_series_limit": 600,
        "alert": alert,
        "pass": True,
    }
    validate_schema("backend-correlation-report-v1.schema.json", report)
    return report
