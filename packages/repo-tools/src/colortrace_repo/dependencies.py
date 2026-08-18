from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from colortrace_repo.common import Finding, load_json, relative_path, sorted_findings, walk_files

_MANIFEST_NAMES = frozenset({"package.json", "pyproject.toml"})
_PYTHON_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?(.*)$")
_INTEGRITY = re.compile(r"^(sha256|sha384|sha512)[:-][A-Za-z0-9+/=_-]+$")
_SPDX_TOKEN = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9.+-]+)")


def _normalize_python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _normalize_registry(value: str) -> str:
    return value.rstrip("/")


@dataclass(frozen=True, order=True)
class LockedPackage:
    ecosystem: str
    name: str
    version: str
    source: str
    integrities: tuple[str, ...]
    artifact_urls: tuple[str, ...] = ()

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass(frozen=True)
class InventoryRecord:
    ecosystem: str
    name: str
    version: str
    source: str
    license_expression: str

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


def resolved_locked_packages(root: Path) -> tuple[list[LockedPackage], list[Finding]]:
    """Return every third-party package resolved by the repository lockfiles.

    Missing lockfiles are left to the dependency policy check. This helper lets
    narrower policies inspect whichever ecosystems are present in a fixture.
    """

    root = root.resolve()
    python_first_party, node_first_party, findings = _project_names(root)
    packages: list[LockedPackage] = []
    uv_path = root / "uv.lock"
    if uv_path.is_file():
        python_packages, _names, lock_findings = _uv_packages(
            root,
            uv_path,
            python_first_party,
        )
        packages.extend(python_packages)
        findings.extend(lock_findings)
    pnpm_path = root / "pnpm-lock.yaml"
    if pnpm_path.is_file():
        node_packages, _names, lock_findings = _pnpm_packages(
            root,
            pnpm_path,
            node_first_party,
            "https://registry.npmjs.org",
        )
        packages.extend(node_packages)
        findings.extend(lock_findings)
    return sorted(set(packages)), sorted_findings(findings)


def _parse_requirement(requirement: str) -> tuple[str | None, str]:
    base = requirement.split(";", 1)[0].strip()
    match = _PYTHON_REQUIREMENT.fullmatch(base)
    if not match:
        return None, base
    return _normalize_python_name(match.group(1)), match.group(2).strip()


def _project_names(root: Path) -> tuple[set[str], set[str], list[Finding]]:
    python_names: set[str] = set()
    node_names: set[str] = set()
    findings: list[Finding] = []
    for path in walk_files(root, _MANIFEST_NAMES):
        display_path = relative_path(root, path)
        try:
            if path.name == "pyproject.toml":
                with path.open("rb") as handle:
                    document = tomllib.load(handle)
                project = document.get("project", {})
                if isinstance(project, dict) and isinstance(project.get("name"), str):
                    python_names.add(_normalize_python_name(project["name"]))
            else:
                document = load_json(path)
                if isinstance(document, dict) and isinstance(document.get("name"), str):
                    node_names.add(document["name"].lower())
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
        ) as error:
            findings.append(
                Finding(
                    display_path,
                    "dependency.manifest.invalid",
                    f"cannot parse dependency manifest: {error}",
                )
            )
    return python_names, node_names, findings


def _uv_packages(
    root: Path,
    lock_path: Path,
    first_party: set[str],
) -> tuple[list[LockedPackage], set[str], list[Finding]]:
    display_path = relative_path(root, lock_path)
    try:
        with lock_path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        return (
            [],
            set(),
            [
                Finding(
                    display_path, "dependency.lock.invalid", f"cannot parse uv lockfile: {error}"
                )
            ],
        )
    raw_packages = document.get("package")
    if not isinstance(raw_packages, list):
        return (
            [],
            set(),
            [
                Finding(
                    display_path,
                    "dependency.lock.invalid",
                    "uv lockfile must contain a package array",
                )
            ],
        )

    packages: list[LockedPackage] = []
    locked_names: set[str] = set()
    findings: list[Finding] = []
    for index, raw_package in enumerate(raw_packages):
        pointer = f"#/package/{index}"
        if not isinstance(raw_package, dict):
            findings.append(
                Finding(
                    display_path, "dependency.lock.package", "package must be an object", pointer
                )
            )
            continue
        name_value = raw_package.get("name")
        version = raw_package.get("version")
        source = raw_package.get("source")
        if (
            not isinstance(name_value, str)
            or not isinstance(version, str)
            or not isinstance(source, dict)
        ):
            findings.append(
                Finding(
                    display_path,
                    "dependency.lock.package",
                    "package requires string name/version and an object source",
                    pointer,
                )
            )
            continue
        name = _normalize_python_name(name_value)
        locked_names.add(name)
        registry = source.get("registry")
        if not isinstance(registry, str):
            if name not in first_party:
                findings.append(
                    Finding(
                        display_path,
                        "dependency.source.non-registry",
                        f"third-party package {name!r} is not locked from a registry",
                        f"{pointer}/source",
                    )
                )
            continue

        artifact_records: list[dict[str, Any]] = []
        sdist = raw_package.get("sdist")
        if isinstance(sdist, dict):
            artifact_records.append(sdist)
        wheels = raw_package.get("wheels")
        if isinstance(wheels, list):
            artifact_records.extend(value for value in wheels if isinstance(value, dict))
        integrities: list[str] = []
        urls: list[str] = []
        for artifact in artifact_records:
            hash_value = artifact.get("hash")
            url_value = artifact.get("url")
            if isinstance(hash_value, str):
                integrities.append(hash_value)
            if isinstance(url_value, str):
                urls.append(url_value)
        if not integrities:
            findings.append(
                Finding(
                    display_path,
                    "dependency.integrity.missing",
                    f"registry package {name!r} has no locked artifact hash",
                    pointer,
                )
            )
        packages.append(
            LockedPackage(
                "pypi",
                name,
                version,
                _normalize_registry(registry),
                tuple(sorted(set(integrities))),
                tuple(sorted(set(urls))),
            )
        )
    return packages, locked_names, findings


def _unquote_yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, str) else value
        except json.JSONDecodeError:
            return value
    return value


def _inline_yaml_value(mapping: str, key: str) -> str | None:
    match = re.search(rf"(?:^|,\s*){re.escape(key)}:\s*([^,}}]+)", mapping)
    return _unquote_yaml_scalar(match.group(1)) if match else None


def _pnpm_identity(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/")
    if "@" not in key:
        return None
    name, version = key.rsplit("@", 1)
    version = version.split("(", 1)[0]
    if not name or not version:
        return None
    return name.lower(), version


def _pnpm_packages(
    root: Path,
    lock_path: Path,
    first_party: set[str],
    default_registry: str,
) -> tuple[list[LockedPackage], set[str], list[Finding]]:
    display_path = relative_path(root, lock_path)
    try:
        lines = lock_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        return (
            [],
            set(),
            [
                Finding(
                    display_path, "dependency.lock.invalid", f"cannot read pnpm lockfile: {error}"
                )
            ],
        )

    lock_version: str | None = None
    package_section = False
    current_key: str | None = None
    current_integrity: str | None = None
    current_tarball: str | None = None
    raw_packages: list[tuple[str, str | None, str | None, int]] = []

    def finish() -> None:
        nonlocal current_key, current_integrity, current_tarball
        if current_key is not None:
            raw_packages.append(
                (current_key, current_integrity, current_tarball, len(raw_packages))
            )
        current_key = None
        current_integrity = None
        current_tarball = None

    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            if stripped.startswith("lockfileVersion:"):
                lock_version = _unquote_yaml_scalar(stripped.split(":", 1)[1])
            if package_section:
                finish()
            package_section = stripped == "packages:"
            continue
        if not package_section:
            continue
        if indent == 2 and stripped.endswith(":"):
            finish()
            current_key = _unquote_yaml_scalar(stripped[:-1])
            continue
        if current_key is None or indent < 4:
            continue
        if stripped.startswith("resolution:"):
            inline = stripped.split(":", 1)[1].strip()
            if inline.startswith("{") and inline.endswith("}"):
                current_integrity = _inline_yaml_value(inline[1:-1], "integrity")
                current_tarball = _inline_yaml_value(inline[1:-1], "tarball")
        elif stripped.startswith("integrity:"):
            current_integrity = _unquote_yaml_scalar(stripped.split(":", 1)[1])
        elif stripped.startswith("tarball:"):
            current_tarball = _unquote_yaml_scalar(stripped.split(":", 1)[1])
    if package_section:
        finish()

    findings: list[Finding] = []
    if lock_version is None:
        findings.append(
            Finding(
                display_path,
                "dependency.lock.invalid",
                "pnpm lockfile is missing lockfileVersion",
            )
        )
    if not raw_packages:
        findings.append(
            Finding(
                display_path,
                "dependency.lock.invalid",
                "pnpm lockfile contains no package records",
            )
        )

    packages: list[LockedPackage] = []
    locked_names: set[str] = set()
    for key, integrity, tarball, index in raw_packages:
        identity = _pnpm_identity(key)
        pointer = f"#/packages/{index}"
        if identity is None:
            findings.append(
                Finding(
                    display_path,
                    "dependency.lock.package",
                    f"cannot determine package name and version from {key!r}",
                    pointer,
                )
            )
            continue
        name, version = identity
        locked_names.add(name)
        if version.startswith(("file:", "git", "http:", "https:", "link:", "workspace:")):
            if name not in first_party:
                findings.append(
                    Finding(
                        display_path,
                        "dependency.source.non-registry",
                        f"third-party package {name!r} is not locked from a registry",
                        pointer,
                    )
                )
            continue
        source = default_registry
        artifact_urls: tuple[str, ...] = ()
        if tarball:
            parsed = urlparse(tarball)
            if not parsed.scheme or not parsed.netloc:
                findings.append(
                    Finding(
                        display_path,
                        "dependency.source.non-registry",
                        f"package {name!r} has a non-registry tarball reference",
                        pointer,
                    )
                )
            source = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else tarball
            artifact_urls = (tarball,)
        integrities = (integrity,) if integrity else ()
        if not integrities:
            findings.append(
                Finding(
                    display_path,
                    "dependency.integrity.missing",
                    f"registry package {name!r} has no locked integrity",
                    pointer,
                )
            )
        packages.append(
            LockedPackage(
                "npm", name, version, _normalize_registry(source), integrities, artifact_urls
            )
        )
    return packages, locked_names, findings


def _runtime_python_dependencies(
    root: Path, locked_names: set[str], first_party: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for path in walk_files(root, frozenset({"pyproject.toml"})):
        display_path = relative_path(root, path)
        try:
            with path.open("rb") as handle:
                document = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            continue
        project = document.get("project", {})
        if not isinstance(project, dict):
            continue
        requirements: list[tuple[str, str]] = []
        base = project.get("dependencies", [])
        if isinstance(base, list):
            requirements.extend(
                (value, f"#/project/dependencies/{index}")
                for index, value in enumerate(base)
                if isinstance(value, str)
            )
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group, values in optional.items():
                if isinstance(values, list):
                    requirements.extend(
                        (value, f"#/project/optional-dependencies/{group}/{index}")
                        for index, value in enumerate(values)
                        if isinstance(value, str)
                    )
        runtime_names: set[str] = set()
        for requirement, pointer in requirements:
            name, suffix = _parse_requirement(requirement)
            if name is None:
                findings.append(
                    Finding(
                        display_path,
                        "dependency.requirement.invalid",
                        f"cannot parse runtime requirement {requirement!r}",
                        pointer,
                    )
                )
                continue
            runtime_names.add(name)
            if suffix.startswith("@"):
                findings.append(
                    Finding(
                        display_path,
                        "dependency.source.non-registry",
                        f"runtime dependency {name!r} uses a direct reference",
                        pointer,
                    )
                )
            if name not in first_party and name not in locked_names:
                findings.append(
                    Finding(
                        display_path,
                        "dependency.lock.missing",
                        f"runtime dependency {name!r} is absent from uv.lock",
                        pointer,
                    )
                )

        tool = document.get("tool", {})
        uv = tool.get("uv", {}) if isinstance(tool, dict) else {}
        sources = uv.get("sources", {}) if isinstance(uv, dict) else {}
        if isinstance(sources, dict):
            for raw_name, source in sources.items():
                name = _normalize_python_name(raw_name)
                if name not in runtime_names or not isinstance(source, dict):
                    continue
                if source.get("workspace") is True and name in first_party:
                    continue
                if any(key in source for key in ("git", "path", "url")):
                    findings.append(
                        Finding(
                            display_path,
                            "dependency.source.non-registry",
                            f"runtime dependency {name!r} uses a non-registry uv source",
                            f"#/tool/uv/sources/{raw_name}",
                        )
                    )
    return findings


def _runtime_node_dependencies(
    root: Path, locked_names: set[str], first_party: set[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for path in walk_files(root, frozenset({"package.json"})):
        display_path = relative_path(root, path)
        try:
            document = load_json(path)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        for section_name in ("dependencies", "optionalDependencies"):
            section = document.get(section_name, {})
            if not isinstance(section, dict):
                continue
            for raw_name, specifier in section.items():
                pointer = f"#/{section_name}/{raw_name}"
                if not isinstance(raw_name, str) or not isinstance(specifier, str):
                    findings.append(
                        Finding(
                            display_path,
                            "dependency.requirement.invalid",
                            "runtime dependency names and specifiers must be strings",
                            pointer,
                        )
                    )
                    continue
                name = raw_name.lower()
                if specifier.startswith("workspace:"):
                    if name not in first_party:
                        findings.append(
                            Finding(
                                display_path,
                                "dependency.source.non-registry",
                                f"external runtime dependency {name!r} uses workspace provenance",
                                pointer,
                            )
                        )
                    continue
                if specifier.startswith(
                    ("file:", "git", "github:", "http:", "https:", "link:", "npm:", "../", "./")
                ):
                    findings.append(
                        Finding(
                            display_path,
                            "dependency.source.non-registry",
                            f"runtime dependency {name!r} uses non-registry "
                            f"specifier {specifier!r}",
                            pointer,
                        )
                    )
                if name not in first_party and name not in locked_names:
                    findings.append(
                        Finding(
                            display_path,
                            "dependency.lock.missing",
                            f"runtime dependency {name!r} is absent from pnpm-lock.yaml",
                            pointer,
                        )
                    )
    return findings


class _SpdxParser:
    def __init__(
        self, expression: str, allowed_ids: set[str], allowed_exceptions: set[str]
    ) -> None:
        self.expression = expression
        self.allowed_ids = allowed_ids
        self.allowed_exceptions = allowed_exceptions
        self.tokens = self._tokens(expression)
        self.index = 0

    @staticmethod
    def _tokens(expression: str) -> list[str]:
        tokens: list[str] = []
        position = 0
        while position < len(expression):
            match = _SPDX_TOKEN.match(expression, position)
            if not match:
                raise ValueError(f"invalid token at character {position + 1}")
            tokens.append(match.group(1))
            position = match.end()
        return tokens

    def parse(self) -> None:
        if not self.tokens:
            raise ValueError("license expression is empty")
        self._or_expression()
        if self.index != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.index]!r}")

    def _or_expression(self) -> None:
        self._and_expression()
        while self._peek() == "OR":
            self.index += 1
            self._and_expression()

    def _and_expression(self) -> None:
        self._factor()
        while self._peek() == "AND":
            self.index += 1
            self._factor()

    def _factor(self) -> None:
        token = self._peek()
        if token == "(":
            self.index += 1
            self._or_expression()
            if self._peek() != ")":
                raise ValueError("missing closing parenthesis")
            self.index += 1
            return
        if token is None or token in {"AND", "OR", "WITH", ")"}:
            raise ValueError("expected a license identifier")
        self.index += 1
        if token not in self.allowed_ids:
            raise ValueError(f"license identifier {token!r} is not allowed")
        if self._peek() == "WITH":
            self.index += 1
            exception = self._peek()
            if exception is None or exception not in self.allowed_exceptions:
                raise ValueError(f"license exception {exception!r} is not allowed")
            self.index += 1

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None


def _inventory_records(
    root: Path, inventory_path: Path
) -> tuple[dict[tuple[str, str, str], InventoryRecord], list[Finding]]:
    display_path = relative_path(root, inventory_path)
    try:
        document = load_json(inventory_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return {}, [
            Finding(display_path, "dependency.inventory.invalid", f"cannot load inventory: {error}")
        ]
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return {}, [
            Finding(
                display_path,
                "dependency.inventory.invalid",
                "inventory must be a schema_version 1 object",
            )
        ]
    raw_records = document.get("packages")
    if not isinstance(raw_records, list):
        return {}, [
            Finding(
                display_path,
                "dependency.inventory.invalid",
                "inventory packages must be an array",
            )
        ]
    records: dict[tuple[str, str, str], InventoryRecord] = {}
    findings: list[Finding] = []
    for index, raw in enumerate(raw_records):
        pointer = f"#/packages/{index}"
        if not isinstance(raw, dict) or any(
            not isinstance(raw.get(key), str)
            for key in ("ecosystem", "name", "version", "source", "license")
        ):
            findings.append(
                Finding(
                    display_path,
                    "dependency.inventory.record",
                    "record requires string ecosystem, name, version, source, and license",
                    pointer,
                )
            )
            continue
        ecosystem = raw["ecosystem"]
        name = _normalize_python_name(raw["name"]) if ecosystem == "pypi" else raw["name"].lower()
        record = InventoryRecord(
            ecosystem,
            name,
            raw["version"],
            _normalize_registry(raw["source"]),
            raw["license"],
        )
        if record.identity in records:
            findings.append(
                Finding(
                    display_path,
                    "dependency.inventory.duplicate",
                    f"duplicate inventory record for {'/'.join(record.identity)}",
                    pointer,
                )
            )
        records[record.identity] = record
    return records, findings


def _validate_locked_packages(
    root: Path,
    locked_packages: list[LockedPackage],
    inventory: dict[tuple[str, str, str], InventoryRecord],
    policy: dict[str, Any],
    inventory_path: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    display_inventory = relative_path(root, inventory_path)
    registry_policy = policy.get("registries", {})
    artifact_host_policy = policy.get("artifact_hosts", {})
    allowed_ids = {str(value) for value in policy.get("allowed_license_ids", [])}
    allowed_exceptions = {str(value) for value in policy.get("allowed_license_exceptions", [])}
    actual_identities: set[tuple[str, str, str]] = set()
    for package in locked_packages:
        actual_identities.add(package.identity)
        allowed_registries = (
            {
                _normalize_registry(str(value))
                for value in registry_policy.get(package.ecosystem, [])
            }
            if isinstance(registry_policy, dict)
            else set()
        )
        if package.source not in allowed_registries:
            findings.append(
                Finding(
                    display_inventory,
                    "dependency.source.disallowed",
                    f"{'/'.join(package.identity)} uses unapproved registry {package.source!r}",
                )
            )
        for integrity in package.integrities:
            if _INTEGRITY.fullmatch(integrity) is None:
                findings.append(
                    Finding(
                        display_inventory,
                        "dependency.integrity.invalid",
                        f"{'/'.join(package.identity)} has invalid integrity {integrity!r}",
                    )
                )
        allowed_hosts = (
            {str(value).lower() for value in artifact_host_policy.get(package.ecosystem, [])}
            if isinstance(artifact_host_policy, dict)
            else set()
        )
        for url in package.artifact_urls:
            parsed = urlparse(url)
            if parsed.scheme != "https" or (parsed.hostname or "").lower() not in allowed_hosts:
                findings.append(
                    Finding(
                        display_inventory,
                        "dependency.artifact.disallowed",
                        f"{'/'.join(package.identity)} has unapproved artifact URL host",
                    )
                )

        record = inventory.get(package.identity)
        if record is None:
            findings.append(
                Finding(
                    display_inventory,
                    "dependency.license.unknown",
                    f"{'/'.join(package.identity)} has no exact-version license inventory record",
                )
            )
            continue
        if record.source != package.source:
            findings.append(
                Finding(
                    display_inventory,
                    "dependency.inventory.source",
                    f"{'/'.join(package.identity)} inventory source does not match its lockfile",
                )
            )
        try:
            _SpdxParser(record.license_expression, allowed_ids, allowed_exceptions).parse()
        except ValueError as error:
            findings.append(
                Finding(
                    display_inventory,
                    "dependency.license.disallowed",
                    f"{'/'.join(package.identity)} license is not allowed: {error}",
                )
            )

    for identity in set(inventory) - actual_identities:
        findings.append(
            Finding(
                display_inventory,
                "dependency.inventory.stale",
                f"{'/'.join(identity)} is not present in a required lockfile",
            )
        )
    return findings


def _npmrc_findings(root: Path, allowed_registries: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob(".npmrc")):
        if any(part in {".git", "node_modules"} for part in path.parts):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            findings.append(
                Finding(relative_path(root, path), "dependency.npmrc.invalid", str(error))
            )
            continue
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
                continue
            key, value = (part.strip() for part in stripped.split("=", 1))
            if key == "registry" or key.endswith(":registry"):
                if _normalize_registry(value) not in allowed_registries:
                    findings.append(
                        Finding(
                            relative_path(root, path),
                            "dependency.source.disallowed",
                            f"npm registry {value!r} is not approved",
                            f":{line_number}",
                        )
                    )
    return findings


def check_dependencies(
    root: Path,
    policy_path: Path | None = None,
    inventory_path: Path | None = None,
) -> list[Finding]:
    root = root.resolve()
    policy_path = (
        policy_path.resolve() if policy_path else (root / "policy" / "dependency-policy.json")
    )
    inventory_path = (
        inventory_path.resolve()
        if inventory_path
        else (root / "policy" / "dependency-inventory.json")
    )
    display_policy = relative_path(root, policy_path)
    try:
        policy = load_json(policy_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [
            Finding(display_policy, "dependency.policy.invalid", f"cannot load policy: {error}")
        ]
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        return [
            Finding(
                display_policy,
                "dependency.policy.invalid",
                "dependency policy must be a schema_version 1 object",
            )
        ]

    required = policy.get("required_lockfiles")
    if not isinstance(required, dict) or any(
        ecosystem not in required or not isinstance(required[ecosystem], str)
        for ecosystem in ("npm", "pypi")
    ):
        return [
            Finding(
                display_policy,
                "dependency.policy.invalid",
                "required_lockfiles must define npm and pypi paths",
            )
        ]

    python_first_party, node_first_party, findings = _project_names(root)
    locked_packages: list[LockedPackage] = []
    locked_python_names: set[str] = set()
    locked_node_names: set[str] = set()

    uv_path = root / required["pypi"]
    if not uv_path.is_file():
        findings.append(
            Finding(
                relative_path(root, uv_path),
                "dependency.lock.missing",
                "required uv lockfile does not exist",
            )
        )
    else:
        packages, locked_python_names, lock_findings = _uv_packages(
            root, uv_path, python_first_party
        )
        locked_packages.extend(packages)
        findings.extend(lock_findings)

    registries = policy.get("registries", {})
    npm_registries = registries.get("npm", []) if isinstance(registries, dict) else []
    default_npm_registry = (
        _normalize_registry(str(npm_registries[0]))
        if isinstance(npm_registries, list) and npm_registries
        else ""
    )
    pnpm_path = root / required["npm"]
    if not pnpm_path.is_file():
        findings.append(
            Finding(
                relative_path(root, pnpm_path),
                "dependency.lock.missing",
                "required pnpm lockfile does not exist",
            )
        )
    else:
        packages, locked_node_names, lock_findings = _pnpm_packages(
            root, pnpm_path, node_first_party, default_npm_registry
        )
        locked_packages.extend(packages)
        findings.extend(lock_findings)

    findings.extend(_runtime_python_dependencies(root, locked_python_names, python_first_party))
    findings.extend(_runtime_node_dependencies(root, locked_node_names, node_first_party))

    inventory, inventory_findings = _inventory_records(root, inventory_path)
    findings.extend(inventory_findings)
    findings.extend(
        _validate_locked_packages(root, locked_packages, inventory, policy, inventory_path)
    )
    findings.extend(
        _npmrc_findings(root, {_normalize_registry(str(value)) for value in npm_registries})
    )
    return sorted_findings(findings)
