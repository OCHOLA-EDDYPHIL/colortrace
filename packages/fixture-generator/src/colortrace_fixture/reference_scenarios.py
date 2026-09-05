from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, cast

from .reference_media import ReferenceMediaManifest, load_reference_media_manifest

ReferenceIncidentClass = Literal[
    "resource-resolution-drift/v1",
    "configuration-rollout-drift/v1",
    "stale-derivative-cache/v1",
]
RecoveryKind = Literal["reconcile-resource", "pin-rollout", "invalidate-cache"]


@dataclass(frozen=True, slots=True)
class ReferenceScenario:
    scenario_id: str
    incident_class: ReferenceIncidentClass
    title: str
    symptom: str
    recovery_kind: RecoveryKind
    affected_artifact_ids: tuple[str, ...]
    protected_artifact_ids: tuple[str, ...]
    expected_config_generation: int
    observed_config_generation: int
    expected_derivative_generation: int
    observed_derivative_generation: int
    resource_variant: str
    config_variant: str
    frame_pipeline_variant: str
    cache_variant: str

    def __post_init__(self) -> None:
        affected = tuple(self.affected_artifact_ids)
        protected = tuple(self.protected_artifact_ids)
        if (
            not affected
            or not protected
            or set(affected).intersection(protected)
            or affected != tuple(sorted(set(affected)))
            or protected != tuple(sorted(set(protected)))
        ):
            raise ValueError("reference scenario scope is invalid")
        object.__setattr__(self, "affected_artifact_ids", affected)
        object.__setattr__(self, "protected_artifact_ids", protected)

    @property
    def artifact_count(self) -> int:
        return len(self.affected_artifact_ids) + len(self.protected_artifact_ids)

    def to_dict(self) -> dict[str, Any]:
        body = {
            "schema": "reference-scenario/v1",
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class,
            "title": self.title,
            "symptom": self.symptom,
            "recovery_kind": self.recovery_kind,
            "scope": {
                "affected_artifact_ids": list(self.affected_artifact_ids),
                "protected_artifact_ids": list(self.protected_artifact_ids),
            },
            "expected": {
                "config_generation": self.expected_config_generation,
                "derivative_generation": self.expected_derivative_generation,
            },
            "observed": {
                "config_generation": self.observed_config_generation,
                "derivative_generation": self.observed_derivative_generation,
                "resource_variant": self.resource_variant,
                "config_variant": self.config_variant,
                "frame_pipeline_variant": self.frame_pipeline_variant,
                "cache_variant": self.cache_variant,
            },
        }
        body["scenario_sha256"] = _digest(body)
        return body


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value)).hexdigest()}"


def _artifact_ids(manifest: ReferenceMediaManifest) -> tuple[str, ...]:
    return tuple(
        f"frame:{frame.sequence_id}:{frame.frame:05d}"
        for sequence in manifest.sequences
        for frame in sequence.frames
    )


def _scope(
    artifacts: tuple[str, ...],
    scenario_id: str,
    *,
    affected_count: int,
    excluded_from_affected: frozenset[str] = frozenset(),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    ranked = sorted(
        (artifact_id for artifact_id in artifacts if artifact_id not in excluded_from_affected),
        key=lambda artifact_id: hashlib.sha256(f"{scenario_id}\0{artifact_id}".encode()).digest(),
    )
    if len(ranked) < affected_count:
        raise ValueError("reference scenario affected scope is too small")
    affected = tuple(sorted(ranked[:affected_count]))
    protected = tuple(sorted(set(artifacts).difference(affected)))
    return affected, protected


def reference_scenarios(
    manifest: ReferenceMediaManifest | None = None,
) -> Mapping[str, ReferenceScenario]:
    selected = manifest or load_reference_media_manifest()
    artifacts = _artifact_ids(selected)
    if len(artifacts) != 240 or len(set(artifacts)) != len(artifacts):
        raise ValueError("reference media does not match the sealed scenario population")
    sequence_first_artifact_ids = frozenset(
        f"frame:{sequence.frames[0].sequence_id}:{sequence.frames[0].frame:05d}"
        for sequence in selected.sequences
        if sequence.frames
    )

    definitions: tuple[tuple[Any, ...], ...] = (
        (
            "tos-resource-resolution-drift-v1",
            "resource-resolution-drift/v1",
            "A successful render resolved the wrong look resource",
            "Frames completed, but a worker resolved a different LUT than the approved reference.",
            "reconcile-resource",
            7,
            7,
            7,
            7,
            "shadowed",
            "approved",
            "drifted",
            "current",
        ),
        (
            "tos-config-rollout-drift-v1",
            "configuration-rollout-drift/v1",
            "A stale color configuration remained active",
            (
                "Frames completed under an older configuration generation while the LUT "
                "stayed current."
            ),
            "pin-rollout",
            7,
            6,
            7,
            7,
            "approved",
            "stale-rollout",
            "drifted",
            "current",
        ),
        (
            "tos-stale-derivative-cache-v1",
            "stale-derivative-cache/v1",
            "Correct frames served stale review derivatives",
            (
                "The frame pipeline matched the reference, but cached derivatives came from "
                "older parents."
            ),
            "invalidate-cache",
            7,
            7,
            7,
            6,
            "approved",
            "approved",
            "approved",
            "stale",
        ),
    )
    scenarios: dict[str, ReferenceScenario] = {}
    for definition in definitions:
        scenario_id = cast(str, definition[0])
        incident_class = cast(ReferenceIncidentClass, definition[1])
        affected, protected = _scope(
            artifacts,
            scenario_id,
            affected_count=72,
            excluded_from_affected=(
                sequence_first_artifact_ids
                if incident_class == "stale-derivative-cache/v1"
                else frozenset()
            ),
        )
        scenarios[scenario_id] = ReferenceScenario(
            scenario_id=scenario_id,
            incident_class=incident_class,
            title=cast(str, definition[2]),
            symptom=cast(str, definition[3]),
            recovery_kind=cast(RecoveryKind, definition[4]),
            expected_config_generation=cast(int, definition[5]),
            observed_config_generation=cast(int, definition[6]),
            expected_derivative_generation=cast(int, definition[7]),
            observed_derivative_generation=cast(int, definition[8]),
            resource_variant=cast(str, definition[9]),
            config_variant=cast(str, definition[10]),
            frame_pipeline_variant=cast(str, definition[11]),
            cache_variant=cast(str, definition[12]),
            affected_artifact_ids=affected,
            protected_artifact_ids=protected,
        )
    return cast(Mapping[str, ReferenceScenario], MappingProxyType(scenarios))


__all__ = [
    "RecoveryKind",
    "ReferenceIncidentClass",
    "ReferenceScenario",
    "reference_scenarios",
]
