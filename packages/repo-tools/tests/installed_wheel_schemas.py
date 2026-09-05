from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import cast

_PACKAGES = (
    ("colortrace_evaluation.contracts", "SCHEMA_ROOT", "evaluation"),
    ("colortrace_fixture.fixture", "SCHEMA_ROOT", "fixture"),
    ("colortrace_grafana_mcp.adapter", "_SCHEMA_ROOT", "grafana"),
    ("colortrace_investigation.contracts", "SCHEMA_ROOT", "investigation"),
    ("colortrace_simulator.authority", "SCHEMA_ROOT", "simulator"),
    ("colortrace_telemetry.contract", "SCHEMA_ROOT", "telemetry"),
    ("colortrace_vertical_slice.contracts", "SCHEMA_ROOT", "vertical-slice"),
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _load_module(
    module_name: str, schema_root_name: str, installation: Path
) -> tuple[ModuleType, Path, set[str]]:
    module = _installed_module(module_name, installation)
    schema_root = getattr(module, schema_root_name, None)
    _require(isinstance(schema_root, Path), f"{module_name} has no schema root")
    schema_root = cast(Path, schema_root).resolve()
    _require(
        schema_root.is_relative_to(installation) and schema_root.is_dir(),
        f"{module_name} schema root is outside the isolated wheel installation",
    )
    names = {path.name for path in schema_root.glob("*.schema.json") if path.is_file()}
    _require(bool(names), f"{module_name} has no installed schemas")
    return module, schema_root, names


def _installed_module(module_name: str, installation: Path) -> ModuleType:
    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    _require(isinstance(module_file, str), f"{module_name} has no import origin")
    module_path = Path(cast(str, module_file)).resolve()
    _require(
        module_path.is_relative_to(installation),
        f"{module_name} was not imported from the isolated wheel installation",
    )
    return module


def _exercise_loader(kind: str, module: ModuleType, schema_root: Path, names: set[str]) -> None:
    if kind in {"evaluation", "fixture", "simulator"}:
        for name in sorted(names):
            document = json.loads((schema_root / name).read_text(encoding="utf-8"))
            module.Draft202012Validator.check_schema(document)
        return
    if kind == "grafana":
        _, documents = module._schema_registry()
        _require(set(documents) == names, "Grafana MCP loader did not return every schema")
        return
    if kind == "investigation":
        documents = module._schema_documents()
        _require(set(documents) == names, "investigation loader did not return every schema")
        return
    if kind == "telemetry":
        _, documents = module._schema_registry()
        _require(set(documents) == names, "telemetry loader did not return every schema")
        return
    for name in sorted(names):
        module._schema_validator(name)


def _exercise_reference_loaders(installation: Path) -> None:
    fixture = _installed_module("colortrace_fixture.reference_media", installation)
    manifest_path = getattr(fixture, "REFERENCE_MEDIA_MANIFEST", None)
    _require(isinstance(manifest_path, Path), "fixture has no reference manifest path")
    manifest_path = cast(Path, manifest_path)
    _require(
        manifest_path.resolve().is_relative_to(installation)
        and manifest_path.is_file()
        and not manifest_path.is_symlink(),
        "fixture reference manifest is outside the isolated wheel installation",
    )
    load_manifest = getattr(fixture, "load_reference_media_manifest", None)
    _require(callable(load_manifest), "fixture has no reference manifest loader")
    manifest = load_manifest()
    collection_id = getattr(manifest, "collection_id", None)
    manifest_sha256 = getattr(manifest, "manifest_sha256", None)
    _require(
        collection_id == "tears-of-steel-linear-exr-240-v1"
        and getattr(manifest, "frame_count", None) == 240
        and isinstance(manifest_sha256, str),
        "fixture reference manifest loader returned an invalid collection",
    )

    previews = _installed_module("colortrace_api.reference_visuals", installation)
    preview_root = getattr(previews, "REFERENCE_PREVIEW_ROOT", None)
    _require(isinstance(preview_root, Path), "API has no reference preview root")
    preview_root = cast(Path, preview_root)
    _require(
        preview_root.resolve().is_relative_to(installation)
        and preview_root.is_dir()
        and not preview_root.is_symlink(),
        "API reference preview root is outside the isolated wheel installation",
    )
    load_previews = getattr(previews, "load_reference_preview_catalog", None)
    _require(callable(load_previews), "API has no reference preview loader")
    catalog = load_previews(expected_reference_manifest_sha256=manifest_sha256)
    scenarios = getattr(catalog, "scenarios", None)
    _require(
        isinstance(scenarios, Mapping)
        and len(scenarios) == 3
        and all(
            isinstance(visuals, Mapping) and len(visuals) == 4 for visuals in scenarios.values()
        ),
        "API reference preview loader returned an invalid catalog",
    )

    results = _installed_module("colortrace_api.reference_results", installation)
    result_path = getattr(results, "REFERENCE_RESULT_PATH", None)
    _require(isinstance(result_path, Path), "API has no reference result path")
    result_path = cast(Path, result_path)
    _require(
        result_path.resolve().is_relative_to(installation),
        "API reference result path is outside the isolated wheel installation",
    )
    load_result = getattr(results, "load_reference_impact_result", None)
    _require(callable(load_result), "API has no reference result loader")
    if result_path.exists() or result_path.is_symlink():
        _require(
            result_path.is_file() and not result_path.is_symlink(),
            "API reference result is not a regular installed file",
        )
        result = load_result(
            expected_collection_id=collection_id,
            expected_manifest_sha256=manifest_sha256,
        )
        _require(
            isinstance(result, dict) and result.get("passed") is True,
            "API reference result loader returned an invalid result",
        )
        return

    error_type = getattr(results, "ReferenceResultError", None)
    _require(
        isinstance(error_type, type) and issubclass(error_type, RuntimeError),
        "API has no reference result error type",
    )
    try:
        load_result(
            expected_collection_id=collection_id,
            expected_manifest_sha256=manifest_sha256,
        )
    except RuntimeError as error:
        _require(
            isinstance(error, error_type)
            and getattr(error, "code", None) == "reference-result-unavailable",
            "absent API reference result did not fail as unavailable",
        )
    else:
        raise RuntimeError("absent API reference result unexpectedly loaded")


def main() -> None:
    _require(len(sys.argv) == 2, "usage: installed_wheel_schemas.py INSTALLATION")
    installation = Path(sys.argv[1]).resolve()
    _require(installation.is_dir(), "wheel installation must be a directory")
    for module_name, schema_root_name, kind in _PACKAGES:
        module, schema_root, names = _load_module(module_name, schema_root_name, installation)
        _exercise_loader(kind, module, schema_root, names)
    _exercise_reference_loaders(installation)


if __name__ == "__main__":
    main()
