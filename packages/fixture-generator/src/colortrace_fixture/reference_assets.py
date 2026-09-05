from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

import PyOpenColorIO as ocio  # type: ignore[import-untyped]

from .fixture import CONFIG_TEXT, OCIO_VERSION, lut_bytes
from .reference_media import ReferenceFrame
from .reference_scenarios import ReferenceScenario

ReferenceVariantName = Literal["approved", "shadowed", "stale-rollout"]

_STALE_ROLLOUT_CONFIG_TEXT = CONFIG_TEXT.replace(
    "    from_scene_reference: !<FileTransform> "
    "{src: show_look.cube, interpolation: tetrahedral}\n",
    "    from_scene_reference: !<GroupTransform>\n"
    "      children:\n"
    "        - !<FileTransform> {src: show_look.cube, interpolation: tetrahedral}\n"
    "        - !<CDLTransform> {slope: [1.06, 0.93, 0.86], "
    "offset: [0.01, 0.0, 0.015], power: [1.0, 1.0, 1.0], sat: 0.94}\n",
)
if _STALE_ROLLOUT_CONFIG_TEXT == CONFIG_TEXT:
    raise RuntimeError("reference rollout configuration substitution failed")


class ReferenceAssetError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReferenceColorVariant:
    name: ReferenceVariantName
    config_relative_path: str
    config_sha256: str
    resource_relative_path: str
    resource_sha256: str
    config_generation: int
    input_color_space: str = "fixture_input"
    output_color_space: str = "fixture_output"


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _safe_root(root: Path) -> Path:
    absolute = root if root.is_absolute() else Path.cwd() / root
    if ".." in absolute.parts or absolute.is_symlink():
        raise ReferenceAssetError("reference-color-root-unsafe")
    resolved = absolute.resolve(strict=False)
    if (
        resolved != absolute.absolute()
        or resolved == Path(resolved.anchor)
        or len(resolved.parts) < 3
    ):
        raise ReferenceAssetError("reference-color-root-unsafe")
    try:
        resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = resolved.lstat()
    except OSError as error:
        raise ReferenceAssetError("reference-color-root-unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReferenceAssetError("reference-color-root-unsafe")
    resolved.chmod(0o700)
    return resolved


def _write_once(path: Path, root: Path, value: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.resolve(strict=True)
        parent.relative_to(root)
        metadata = path.parent.lstat()
    except (OSError, ValueError) as error:
        raise ReferenceAssetError("reference-color-asset-conflict") from error
    if parent != path.parent.absolute() or stat.S_ISLNK(metadata.st_mode):
        raise ReferenceAssetError("reference-color-asset-conflict")
    path.parent.chmod(0o700)
    if path.exists():
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or path.read_bytes() != value
        ):
            raise ReferenceAssetError("reference-color-asset-conflict")
        return
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise ReferenceAssetError("reference-color-asset-write-failed") from error


def materialize_reference_color_variants(
    root: Path,
) -> Mapping[ReferenceVariantName, ReferenceColorVariant]:
    selected_root = _safe_root(root)
    definitions: tuple[tuple[ReferenceVariantName, int, bytes, bytes], ...] = (
        ("approved", 7, CONFIG_TEXT.encode(), lut_bytes("approved")),
        ("shadowed", 7, CONFIG_TEXT.encode(), lut_bytes("shadowed")),
        ("stale-rollout", 6, _STALE_ROLLOUT_CONFIG_TEXT.encode(), lut_bytes("approved")),
    )
    result: dict[ReferenceVariantName, ReferenceColorVariant] = {}
    for name, generation, config_bytes, resource_bytes in definitions:
        config_relative = Path(name) / "config.ocio"
        resource_relative = Path(name) / "luts" / "show_look.cube"
        config_path = selected_root / config_relative
        resource_path = selected_root / resource_relative
        _write_once(config_path, selected_root, config_bytes)
        _write_once(resource_path, selected_root, resource_bytes)
        try:
            ocio.ClearAllCaches()
            configuration = ocio.Config.CreateFromFile(str(config_path))
            configuration.validate()
            resolved = Path(
                configuration.getCurrentContext().resolveFileLocation("show_look.cube")
            ).resolve(strict=True)
        except Exception as error:
            raise ReferenceAssetError("reference-color-config-invalid") from error
        if ocio.__version__ != OCIO_VERSION or resolved != resource_path.resolve(strict=True):
            raise ReferenceAssetError("reference-color-config-invalid")
        result[name] = ReferenceColorVariant(
            name=name,
            config_relative_path=config_relative.as_posix(),
            config_sha256=_sha256(config_bytes),
            resource_relative_path=resource_relative.as_posix(),
            resource_sha256=_sha256(resource_bytes),
            config_generation=generation,
        )
    return cast(
        Mapping[ReferenceVariantName, ReferenceColorVariant],
        MappingProxyType(result),
    )


def reference_render_job(
    *,
    frame: ReferenceFrame,
    scenario: ReferenceScenario,
    variants: Mapping[ReferenceVariantName, ReferenceColorVariant],
    mode: Literal["expected", "observed", "recovered"],
    trace_id: str,
) -> dict[str, Any]:
    artifact_id = f"frame:{frame.sequence_id}:{frame.frame:05d}"
    affected = artifact_id in scenario.affected_artifact_ids
    variant_name: ReferenceVariantName = "approved"
    if mode == "observed" and affected:
        if scenario.incident_class == "resource-resolution-drift/v1":
            variant_name = "shadowed"
        elif scenario.incident_class == "configuration-rollout-drift/v1":
            variant_name = "stale-rollout"
    variant = variants[variant_name]
    return {
        "schema": "reference-render-job/v1",
        "job_id": f"{mode}-{frame.sequence_id}-{frame.frame:05d}",
        "scenario_id": scenario.scenario_id,
        "incident_class": scenario.incident_class,
        "trace_id": trace_id,
        "worker_id": f"worker-{frame.frame % 8:02d}",
        "artifact_id": artifact_id,
        "source": {
            "relative_path": f"{frame.sequence_id}/{frame.filename}",
            "sha256": frame.sha256,
            "byte_length": frame.byte_length,
        },
        "color": {
            "config_relative_path": variant.config_relative_path,
            "config_sha256": variant.config_sha256,
            "resource_relative_path": variant.resource_relative_path,
            "resource_sha256": variant.resource_sha256,
            "input_color_space": variant.input_color_space,
            "output_color_space": variant.output_color_space,
        },
        "runtime": {
            "effective_generation": variant.config_generation,
            "cache_key": f"cache:{frame.sequence_id}:{frame.frame:05d}:g7",
        },
        "output": {
            "relative_path": (f"{scenario.scenario_id}/{mode}/{frame.sequence_id}/{frame.filename}")
        },
    }


__all__ = [
    "ReferenceAssetError",
    "ReferenceColorVariant",
    "ReferenceVariantName",
    "materialize_reference_color_variants",
    "reference_render_job",
]
