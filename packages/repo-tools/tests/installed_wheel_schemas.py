from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

_PACKAGES = (
    ("colortrace_evaluation.contracts", "SCHEMA_ROOT", "evaluation"),
    ("colortrace_grafana_mcp.adapter", "_SCHEMA_ROOT", "grafana"),
    ("colortrace_investigation.contracts", "SCHEMA_ROOT", "investigation"),
    ("colortrace_vertical_slice.contracts", "SCHEMA_ROOT", "vertical-slice"),
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _load_module(
    module_name: str, schema_root_name: str, installation: Path
) -> tuple[ModuleType, Path, set[str]]:
    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    _require(isinstance(module_file, str), f"{module_name} has no import origin")
    module_path = Path(cast(str, module_file)).resolve()
    _require(
        module_path.is_relative_to(installation),
        f"{module_name} was not imported from the isolated wheel installation",
    )
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


def _exercise_loader(kind: str, module: ModuleType, schema_root: Path, names: set[str]) -> None:
    if kind == "evaluation":
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
    for name in sorted(names):
        module._schema_validator(name)


def main() -> None:
    _require(len(sys.argv) == 2, "usage: installed_wheel_schemas.py INSTALLATION")
    installation = Path(sys.argv[1]).resolve()
    _require(installation.is_dir(), "wheel installation must be a directory")
    for module_name, schema_root_name, kind in _PACKAGES:
        module, schema_root, names = _load_module(module_name, schema_root_name, installation)
        _exercise_loader(kind, module, schema_root, names)


if __name__ == "__main__":
    main()
