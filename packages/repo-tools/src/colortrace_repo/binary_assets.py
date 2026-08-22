from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from colortrace_repo.common import (
    IGNORED_DIRECTORIES,
    REDISTRIBUTION_REVIEW_STATES,
    Finding,
    contained_path,
    contained_repository_path,
    is_canonical_spdx,
    lexical_relative_path,
    load_json,
    sorted_findings,
    walk_files,
)

_ASSET_KEYS = {
    "capture_output",
    "capture_profile",
    "license",
    "path",
    "provenance",
    "redistribution_review",
    "sha256",
    "viewport",
}
_PROFILE_KEYS = {
    "candidate",
    "environment",
    "inputs",
    "invocations",
    "reproduction_receipt_sha256",
    "reproducibility",
}
_INVOCATION_KEYS = {
    "capture_outputs",
    "command",
    "environment_variables",
    "expected_result",
    "id",
}
_CAPTURE_OUTPUT_KEYS = {"capture_output", "path"}
_RESULT_KEYS = {"allowed_failures", "exit_code", "failed", "passed", "skipped", "status"}
_INPUT_ROLES = {"config", "fixture", "font", "font-declaration", "lockfile", "package", "test"}
_REQUIRED_INPUT_ROLES = {"config", "fixture", "font-declaration", "lockfile", "package", "test"}


def _candidate_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
        )
    except OSError:
        return walk_files(root)
    if result.returncode != 0:
        return walk_files(root)
    paths = []
    for raw in result.stdout.split(b"\0"):
        try:
            path = root / raw.decode()
        except UnicodeDecodeError:
            continue
        if raw and (path.is_file() or path.is_symlink()):
            paths.append(path)
    return sorted(paths)


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
        return b"\0" in sample or not _is_utf8(sample)
    except OSError:
        return False


def _is_utf8(value: bytes) -> bool:
    try:
        value.decode()
        return True
    except UnicodeDecodeError:
        return False


def _exact(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= set("0123456789abcdef")


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _capture_output(value: object) -> bool:
    return value == "path" or (
        isinstance(value, str)
        and value.startswith("attachment:")
        and len(value) > 11
        and not set(value) & {"\n", "\r"}
    )


def _container_path(value: object) -> bool:
    if not isinstance(value, str) or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (
        path.is_absolute() and path.as_posix() == value and value != "/" and ".." not in path.parts
    )


def _environment_variable(value: object) -> bool:
    if not isinstance(value, str):
        return False
    key, separator, setting = value.partition("=")
    return (
        bool(separator and setting)
        and bool(key)
        and key[:1] in "_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        and set(key) <= set("_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        and not set(setting) & {"\n", "\r"}
    )


def _pinned_image(value: object) -> bool:
    if not isinstance(value, str) or value.count("@sha256:") != 1:
        return False
    name, _, digest = value.partition("@sha256:")
    return (
        bool(name)
        and name == name.strip()
        and "@" not in name
        and not any(character.isspace() for character in name)
        and _sha256(digest)
    )


def _expected_result(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _RESULT_KEYS:
        return False
    allowed = value["allowed_failures"]
    counts = [value[key] for key in ("exit_code", "failed", "passed", "skipped")]
    valid = (
        isinstance(allowed, list)
        and all(_nonempty(item) for item in allowed)
        and len(allowed) == len(set(allowed))
        and all(
            isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in counts
        )
        and sum(counts[1:]) > 0
    )
    if not valid:
        return False
    return (value["status"] == "pass" and counts[0] == counts[1] == 0 and not allowed) or (
        value["status"] == "expected-post-write-assertion-failure"
        and counts[0] > 0
        and counts[1] == len(allowed) > 0
    )


def _png_dimensions(path: Path) -> tuple[int, int] | None:
    try:
        header = path.read_bytes()[:24]
    except OSError:
        return None
    if len(header) != 24 or header[:8] != b"\x89PNG\r\n\x1a\n" or header[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", header[16:24])


def _capture_input(root: Path, value: object) -> bool:
    if not isinstance(value, dict) or value.get("role") not in _INPUT_ROLES:
        return False
    if value["role"] == "font":
        return (
            set(value) == {"family", "path", "postscript_name", "role", "sha256"}
            and all(_nonempty(value[key]) for key in ("family", "postscript_name"))
            and _container_path(value["path"])
            and _sha256(value["sha256"])
        )
    return (
        set(value) == {"path", "role", "sha256"}
        and contained_path(root, value["path"]) is not None
        and _sha256(value["sha256"])
    )


def _capture_environment(value: object, inputs: dict[str, dict[str, Any]]) -> bool:
    if not isinstance(value, dict) or set(value) != {"browser", "fonts", "render_environment"}:
        return False
    browser, fonts, render = (value[key] for key in ("browser", "fonts", "render_environment"))
    browser_keys = {"automation", "binary", "engine", "revision", "sha256", "status", "version"}
    if not _exact(browser, browser_keys) or not _exact(browser["automation"], {"name", "version"}):
        return False
    browser_valid = (
        browser["status"] == "exact"
        and all(_nonempty(browser[key]) for key in ("engine", "revision", "version"))
        and all(_nonempty(browser["automation"][key]) for key in ("name", "version"))
        and _container_path(browser["binary"])
        and _sha256(browser["sha256"])
    )
    if not _exact(fonts, {"selected_inputs", "selection_method", "status"}):
        return False
    selected = fonts["selected_inputs"]
    fonts_valid = (
        fonts["status"] == "exact"
        and _nonempty(fonts["selection_method"])
        and isinstance(selected, list)
        and bool(selected)
        and all(isinstance(item, str) for item in selected)
        and len(selected) == len(set(selected))
        and all(item in inputs and inputs[item]["role"] == "font" for item in selected)
    )
    text_keys = {
        "architecture",
        "browser_locale",
        "color_profile",
        "color_scheme",
        "graphics",
        "operating_system",
        "process_locale",
        "timezone",
    }
    render_keys = text_keys | {
        "device_scale_factor",
        "external_calls",
        "headless",
        "image",
        "network",
        "retries",
        "status",
        "workers",
    }
    render_valid = (
        _exact(render, render_keys)
        and render["status"] == "exact"
        and all(_nonempty(render[key]) for key in text_keys)
        and _pinned_image(render["image"])
        and render["headless"] is True
        and render["network"] == "none"
        and render["external_calls"] == render["retries"] == 0
        and all(not isinstance(render[key], bool) for key in ("external_calls", "retries"))
        and isinstance(render["device_scale_factor"], (int, float))
        and not isinstance(render["device_scale_factor"], bool)
        and render["device_scale_factor"] > 0
        and isinstance(render["workers"], int)
        and not isinstance(render["workers"], bool)
        and render["workers"] > 0
    )
    return browser_valid and fonts_valid and render_valid


def _git_bytes(root: Path, specification: str) -> bytes | None:
    operation = "rev-parse" if specification.endswith("^{tree}") else "show"
    try:
        result = subprocess.run(
            ["git", "-C", str(root), operation, specification], capture_output=True, check=False
        )
    except OSError:
        return None
    return result.stdout if result.returncode == 0 else None


def _capture_invocations(root: Path, value: object) -> bool:
    if not isinstance(value, list) or not value:
        return False
    ids: set[str] = set()
    outputs_seen: dict[str, str] = {}
    for invocation in value:
        if not _exact(invocation, _INVOCATION_KEYS) or not _nonempty(invocation["id"]):
            return False
        variables, outputs = invocation["environment_variables"], invocation["capture_outputs"]
        valid = (
            invocation["id"] not in ids
            and _nonempty(invocation["command"])
            and not set(invocation["command"]) & {"\0", "\r", "\n"}
            and isinstance(variables, list)
            and bool(variables)
            and all(_environment_variable(item) for item in variables)
            and len(variables) == len(set(variables))
            and len({item.partition("=")[0] for item in variables}) == len(variables)
            and isinstance(outputs, list)
            and bool(outputs)
            and all(
                _exact(item, _CAPTURE_OUTPUT_KEYS)
                and contained_path(root, item["path"]) is not None
                and _capture_output(item["capture_output"])
                for item in outputs
            )
            and len({(item["path"], item["capture_output"]) for item in outputs}) == len(outputs)
            and _expected_result(invocation["expected_result"])
        )
        if not valid:
            return False
        ids.add(invocation["id"])
        for output in outputs:
            previous = outputs_seen.setdefault(output["path"], output["capture_output"])
            if previous != output["capture_output"]:
                return False
    return True


def _capture_registries(
    root: Path, document: dict[str, object]
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[tuple[str, str]],
]:
    inputs: dict[str, dict[str, Any]] = {}
    environments: dict[str, dict[str, Any]] = {}
    profiles: dict[str, dict[str, Any]] = {}
    errors: list[tuple[str, str]] = []
    raw_inputs = document["capture_inputs"]
    if isinstance(raw_inputs, dict) and raw_inputs:
        for input_id, item in raw_inputs.items():
            if _nonempty(input_id) and _capture_input(root, item):
                inputs[input_id] = item
            else:
                errors.append(("binary.capture.input", f"#/capture_inputs/{input_id}"))
    else:
        errors.append(("binary.capture.inputs", "#/capture_inputs"))

    raw_environments = document["capture_environments"]
    if isinstance(raw_environments, dict) and raw_environments:
        for environment_id, environment in raw_environments.items():
            if _nonempty(environment_id) and _capture_environment(environment, inputs):
                environments[environment_id] = environment
            else:
                errors.append(
                    ("binary.capture.environment", f"#/capture_environments/{environment_id}")
                )
    else:
        errors.append(("binary.capture.environments", "#/capture_environments"))

    raw_profiles = document["capture_profiles"]
    if not isinstance(raw_profiles, dict) or not raw_profiles:
        return (
            inputs,
            environments,
            profiles,
            errors + [("binary.capture.profiles", "#/capture_profiles")],
        )
    for profile_id, profile in raw_profiles.items():
        location = f"#/capture_profiles/{profile_id}"
        if not _nonempty(profile_id) or not _exact(profile, _PROFILE_KEYS):
            errors.append(("binary.capture.profile", location))
            continue
        profiles[profile_id] = profile
        candidate, input_ids = profile["candidate"], profile["inputs"]
        candidate_valid = (
            _exact(candidate, {"commit", "tree"})
            and _hex(candidate["commit"], 40)
            and _hex(candidate["tree"], 40)
        )
        inputs_valid = (
            isinstance(input_ids, list)
            and bool(input_ids)
            and all(isinstance(item, str) for item in input_ids)
            and len(input_ids) == len(set(input_ids))
            and all(item in inputs for item in input_ids)
        )
        if not candidate_valid:
            errors.append(("binary.capture.candidate", location))
        if not inputs_valid or (
            inputs_valid
            and not _REQUIRED_INPUT_ROLES <= {inputs[item]["role"] for item in input_ids}
        ):
            errors.append(("binary.capture.inputs", location))
        environment_id = profile["environment"]
        if not isinstance(environment_id, str) or environment_id not in environments:
            errors.append(("binary.capture.environment.reference", location))
        if (
            not _capture_invocations(root, profile["invocations"])
            or not _sha256(profile["reproduction_receipt_sha256"])
            or profile["reproducibility"] != "pixel-reproducible"
        ):
            errors.append(("binary.capture.reproducibility", location))
        if candidate_valid and inputs_valid:
            tree = _git_bytes(root, f"{candidate['commit']}^{{tree}}")
            if tree is None or tree.decode(errors="replace").strip() != candidate["tree"]:
                errors.append(("binary.capture.candidate", location))
            for input_id in input_ids:
                item = inputs[input_id]
                if item["role"] != "font":
                    content = _git_bytes(root, f"{candidate['commit']}:{item['path']}")
                    if content is None or hashlib.sha256(content).hexdigest() != item["sha256"]:
                        errors.append(
                            ("binary.capture.input.mismatch", f"#/capture_inputs/{input_id}")
                        )
    return inputs, environments, profiles, errors


def _viewport(value: object) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    parts = value.split("x")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    width, height = (int(part) for part in parts)
    return (width, height) if width > 0 and height > 0 else None


def _bad(display: str, code: str, location: str = "") -> Finding:
    return Finding(display, code, "binary asset provenance policy is invalid", location)


def check_binary_assets(root: Path, policy_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    requested_path = policy_path or root / "policy/binary-assets.json"
    display = lexical_relative_path(root, requested_path)
    policy_path = contained_repository_path(root, requested_path)
    if policy_path is None:
        return [
            Finding(
                display,
                "binary.policy.path",
                "policy path must be a lexical, non-symlink path within the repository",
            )
        ]
    try:
        document = load_json(policy_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display, "binary.policy.invalid", f"cannot load policy: {error}")]
    if (
        not _exact(
            document,
            {
                "schema_version",
                "assets",
                "capture_environments",
                "capture_inputs",
                "capture_profiles",
            },
        )
        or document.get("schema_version") != 3
        or not isinstance(document["assets"], list)
    ):
        return [_bad(display, "binary.policy.invalid")]

    findings: list[Finding] = []
    capture_inputs, environments, profiles, capture_errors = _capture_registries(root, document)
    for code, location in capture_errors:
        findings.append(_bad(display, code, location))

    registry: dict[str, dict[str, object]] = {}
    referenced_profiles: set[str] = set()
    for index, asset in enumerate(document["assets"]):
        location = f"#/assets/{index}"
        if not _exact(asset, _ASSET_KEYS):
            findings.append(_bad(display, "binary.policy.entry", location))
            continue
        path = contained_path(root, asset["path"])
        if path is None:
            findings.append(_bad(display, "binary.policy.path", location))
            continue
        name = asset["path"]
        if name in registry:
            findings.append(_bad(display, "binary.policy.duplicate", location))
        registry[name] = asset
        if not is_canonical_spdx(asset["license"]):
            findings.append(_bad(display, "binary.license.invalid", location))
        review = asset["redistribution_review"]
        if not isinstance(review, str) or review not in REDISTRIBUTION_REVIEW_STATES:
            findings.append(_bad(display, "binary.redistribution.invalid", location))
        if not isinstance(asset["provenance"], str) or not asset["provenance"]:
            findings.append(_bad(display, "binary.provenance.invalid", location))
        if not _sha256(asset["sha256"]):
            findings.append(_bad(display, "binary.digest.invalid", location))
        profile_id = asset["capture_profile"]
        if not isinstance(profile_id, str) or profile_id not in profiles:
            findings.append(_bad(display, "binary.capture.reference", location))
        else:
            referenced_profiles.add(profile_id)
        output = asset["capture_output"]
        if not _capture_output(output):
            findings.append(_bad(display, "binary.capture.output", location))
        if _png_dimensions(path) != _viewport(asset["viewport"]):
            findings.append(_bad(display, "binary.capture.viewport", location))

    for profile_id, profile in profiles.items():
        registered_outputs = {
            name: asset.get("capture_output")
            for name, asset in registry.items()
            if asset.get("capture_profile") == profile_id
        }
        invocations = profile.get("invocations")
        valid_invocations = invocations if isinstance(invocations, list) else []
        declared_outputs = {
            output["path"]: output["capture_output"]
            for invocation in valid_invocations
            if isinstance(invocation, dict) and isinstance(invocation.get("capture_outputs"), list)
            for output in invocation["capture_outputs"]
            if isinstance(output, dict)
            and isinstance(output.get("path"), str)
            and isinstance(output.get("capture_output"), str)
        }
        if declared_outputs != registered_outputs:
            findings.append(
                _bad(display, "binary.capture.outputs", f"#/capture_profiles/{profile_id}")
            )

    for profile_id in set(profiles) - referenced_profiles:
        findings.append(_bad(display, "binary.capture.unused", f"#/capture_profiles/{profile_id}"))
    referenced_environments = {
        profile["environment"]
        for profile in profiles.values()
        if isinstance(profile.get("environment"), str)
    }
    for environment_id in set(environments) - referenced_environments:
        findings.append(
            _bad(
                display,
                "binary.capture.environment.unused",
                f"#/capture_environments/{environment_id}",
            )
        )
    referenced_inputs = {
        input_id
        for profile in profiles.values()
        if isinstance(profile.get("inputs"), list)
        for input_id in profile["inputs"]
        if isinstance(input_id, str)
    }
    referenced_inputs.update(
        input_id
        for environment in environments.values()
        if isinstance(environment.get("fonts"), dict)
        and isinstance(environment["fonts"].get("selected_inputs"), list)
        for input_id in environment["fonts"]["selected_inputs"]
        if isinstance(input_id, str)
    )
    for input_id in set(capture_inputs) - referenced_inputs:
        findings.append(
            _bad(display, "binary.capture.input.unused", f"#/capture_inputs/{input_id}")
        )

    binary_paths: set[str] = set()
    for path in _candidate_files(root):
        name = path.relative_to(root).as_posix()
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            findings.append(_bad(name, "binary.asset.symlink"))
            continue
        if not _is_binary(path):
            continue
        binary_paths.add(name)
        asset = registry.get(name)
        if asset is None:
            findings.append(_bad(name, "binary.asset.unregistered"))
            continue
        if _sha256(asset["sha256"]):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != asset["sha256"]:
                findings.append(_bad(name, "binary.digest.mismatch"))

    for name in set(registry) - binary_paths:
        code = "binary.asset.missing" if not (root / name).is_file() else "binary.asset.not-binary"
        findings.append(_bad(name, code))
    return sorted_findings(findings)
