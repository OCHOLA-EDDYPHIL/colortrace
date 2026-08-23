"""Remove narrowly identified build-time entropy from the runtime virtualenv."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

EXPECTED_UV_CACHE_SOURCES = {
    "colortrace_api-0.1.0.dist-info/uv_cache.json": "file:///source/packages/api",
    "colortrace_fixture-0.1.0.dist-info/uv_cache.json": (
        "file:///source/packages/fixture-generator"
    ),
    "colortrace_grafana_mcp-1.0.0.dist-info/uv_cache.json": ("file:///source/packages/grafana-mcp"),
    "colortrace_investigation-1.0.0.dist-info/uv_cache.json": (
        "file:///source/packages/investigation"
    ),
    "colortrace_persistence-0.1.0.dist-info/uv_cache.json": ("file:///source/packages/persistence"),
    "colortrace_recovery-0.1.0.dist-info/uv_cache.json": ("file:///source/packages/recovery"),
    "colortrace_response_plans-1.0.0.dist-info/uv_cache.json": (
        "file:///source/packages/response-plans"
    ),
    "colortrace_simulator-0.1.0.dist-info/uv_cache.json": ("file:///source/packages/simulator"),
    "colortrace_telemetry-0.1.0.dist-info/uv_cache.json": ("file:///source/packages/telemetry"),
    "colortrace_validator-1.0.0.dist-info/uv_cache.json": ("file:///source/packages/validators"),
    "colortrace_vertical_slice-1.0.0.dist-info/uv_cache.json": (
        "file:///source/packages/vertical-slice"
    ),
}

_OCIO_DIST_INFO = "opencolorio-2.5.2.dist-info"
_OCIO_BINARIES = (
    "PyOpenColorIO/bin/ocioconvert",
    "PyOpenColorIO/bin/ociolutimage",
)
_OCIO_BUILD_ROOT = re.compile(
    rb"/root/\.cache/uv/sdists-v9/pypi/opencolorio/2\.5\.2/([A-Za-z0-9_-]{16})(?=/)"
)
_OCIO_BUILD_ROOT_PREFIX = b"/root/.cache/uv/sdists-v9/pypi/opencolorio/2.5.2/"
_NORMALIZED_BUILD_TOKEN = b"0" * 16
_GNU_BUILD_ID_SECTION = b".note.gnu.build-id"
_DEFAULT_OBJCOPY = Path("/usr/bin/objcopy")
_SHA256_RECORD = re.compile(r"sha256=([A-Za-z0-9_-]{43})")

Objcopy = Callable[[Path], None]


class ReproducibleVenvError(ValueError):
    """A fail-closed virtualenv normalization error."""


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    normalized_ocio_binaries: int
    removed_bytecode_directories: int
    removed_bytecode_files: int
    removed_uv_cache_files: int
    rewritten_records: int


@dataclass(slots=True)
class _Record:
    path: Path
    rows: list[list[str]]


def _fail(code: str) -> NoReturn:
    raise ReproducibleVenvError(code)


def _unique_json(value: bytes, code: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                _fail(code)
            result[key] = item
        return result

    try:
        return json.loads(value.decode("utf-8"), object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(code)


def _regular_file(path: Path, root: Path, code: str) -> os.stat_result:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        _fail(code)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not resolved.is_relative_to(root)
    ):
        _fail(code)
    return metadata


def _site_packages(venv: Path) -> tuple[Path, Path]:
    try:
        metadata = venv.lstat()
        root = venv.resolve(strict=True)
    except OSError:
        _fail("venv.invalid")
    if not stat.S_ISDIR(metadata.st_mode):
        _fail("venv.invalid")
    candidates = [
        path
        for path in sorted((root / "lib").glob("python*/site-packages"))
        if path.is_dir() and not path.is_symlink()
    ]
    if len(candidates) != 1:
        _fail("venv.site-packages.invalid")
    site_packages = candidates[0].resolve(strict=True)
    if not site_packages.is_relative_to(root):
        _fail("venv.site-packages.invalid")
    return root, site_packages


def _record_target(value: str, site_packages: Path, venv: Path) -> Path:
    if not value or "\\" in value or "\x00" in value:
        _fail("record.path.invalid")
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value:
        _fail("record.path.invalid")
    target = site_packages.joinpath(*relative.parts).resolve(strict=False)
    if not target.is_relative_to(venv):
        _fail("record.path.escape")
    return target


def _record_digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()


def _read_records(site_packages: Path, venv: Path) -> list[_Record]:
    dist_infos = sorted(site_packages.glob("*.dist-info"))
    if not dist_infos:
        _fail("record.missing")
    paths: list[Path] = []
    for dist_info in dist_infos:
        try:
            metadata = dist_info.lstat()
            resolved = dist_info.resolve(strict=True)
        except OSError:
            _fail("record.distribution.invalid")
        if not stat.S_ISDIR(metadata.st_mode) or not resolved.is_relative_to(venv):
            _fail("record.distribution.invalid")
        record = dist_info / "RECORD"
        _regular_file(record, venv, "record.missing")
        paths.append(record)
    documents: list[_Record] = []
    digest_cache: dict[Path, tuple[str, int]] = {}
    for path in paths:
        _regular_file(path, venv, "record.invalid")
        try:
            text = path.read_text(encoding="utf-8")
            rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except (OSError, UnicodeDecodeError, csv.Error):
            _fail("record.invalid")
        if not rows:
            _fail("record.invalid")
        own_name = path.relative_to(site_packages).as_posix()
        seen: set[str] = set()
        saw_self = False
        for row in rows:
            if len(row) != 3 or row[0] in seen:
                _fail("record.invalid")
            seen.add(row[0])
            target = _record_target(row[0], site_packages, venv)
            if row[0] == own_name:
                if row[1:] != ["", ""]:
                    _fail("record.self.invalid")
                saw_self = True
                continue
            if not row[1] or not row[2] or _SHA256_RECORD.fullmatch(row[1]) is None:
                _fail("record.hash.invalid")
            metadata = _regular_file(target, venv, "record.target.invalid")
            if not row[2].isdigit() or row[2] != str(metadata.st_size):
                _fail("record.size.invalid")
            cached = digest_cache.get(target)
            if cached is None:
                try:
                    content = target.read_bytes()
                except OSError:
                    _fail("record.target.invalid")
                cached = (_record_digest(content), len(content))
                digest_cache[target] = cached
            if row[1] != f"sha256={cached[0]}" or int(row[2]) != cached[1]:
                _fail("record.hash.mismatch")
        if not saw_self:
            _fail("record.self.missing")
        documents.append(_Record(path=path, rows=rows))
    return documents


def _record_owners(
    records: Sequence[_Record], site_packages: Path, venv: Path
) -> dict[Path, list[tuple[_Record, int]]]:
    owners: dict[Path, list[tuple[_Record, int]]] = {}
    for document in records:
        for index, row in enumerate(document.rows):
            target = _record_target(row[0], site_packages, venv)
            owners.setdefault(target, []).append((document, index))
    return owners


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            path = current_path / name
            try:
                metadata = path.lstat()
            except OSError:
                _fail("venv.walk.invalid")
            if stat.S_ISLNK(metadata.st_mode):
                directories.remove(name)
            elif not stat.S_ISDIR(metadata.st_mode):
                _fail("venv.walk.invalid")
        files.extend(current_path / name for name in names)
    return sorted(files)


def _validate_uv_caches(
    site_packages: Path,
    venv: Path,
    owners: dict[Path, list[tuple[_Record, int]]],
) -> list[Path]:
    caches: dict[str, Path] = {}
    for path in _walk_files(venv):
        if path.name != "uv_cache.json":
            continue
        if not path.is_relative_to(site_packages):
            _fail("uv-cache.inventory")
        caches[path.relative_to(site_packages).as_posix()] = path
    if set(caches) != set(EXPECTED_UV_CACHE_SOURCES):
        _fail("uv-cache.inventory")
    for relative, expected_source in EXPECTED_UV_CACHE_SOURCES.items():
        path = caches[relative]
        _regular_file(path, venv, "uv-cache.invalid")
        try:
            content = path.read_bytes()
        except OSError:
            _fail("uv-cache.invalid")
        value = _unique_json(content, "uv-cache.invalid")
        if (
            not isinstance(value, dict)
            or list(value) != ["timestamp", "commit", "tags", "env", "directories"]
            or value.get("commit") is not None
            or value.get("tags") is not None
            or value.get("env") != {}
        ):
            _fail("uv-cache.invalid")
        timestamp = value.get("timestamp")
        directories = value.get("directories")
        if (
            not isinstance(timestamp, dict)
            or list(timestamp) != ["secs_since_epoch", "nanos_since_epoch"]
            or not isinstance(timestamp.get("secs_since_epoch"), int)
            or isinstance(timestamp.get("secs_since_epoch"), bool)
            or timestamp["secs_since_epoch"] < 0
            or not isinstance(timestamp.get("nanos_since_epoch"), int)
            or isinstance(timestamp.get("nanos_since_epoch"), bool)
            or not 0 <= timestamp["nanos_since_epoch"] < 1_000_000_000
            or not isinstance(directories, dict)
            or list(directories) != ["src"]
            or not isinstance(directories.get("src"), int)
            or isinstance(directories.get("src"), bool)
            or directories["src"] < 0
            or json.dumps(value, separators=(",", ":")).encode() != content
        ):
            _fail("uv-cache.invalid")
        dist_info = path.parent
        direct_url = dist_info / "direct_url.json"
        _regular_file(direct_url, venv, "uv-cache.source.invalid")
        try:
            direct_value = _unique_json(direct_url.read_bytes(), "uv-cache.source.invalid")
        except OSError:
            _fail("uv-cache.source.invalid")
        if direct_value != {
            "url": expected_source,
            "dir_info": {"editable": False},
        }:
            _fail("uv-cache.source.invalid")
        direct_url_entries = owners.get(direct_url.resolve(strict=True), [])
        if (
            len(direct_url_entries) != 1
            or direct_url_entries[0][0].path.parent != dist_info
            or direct_url_entries[0][0].rows[direct_url_entries[0][1]][0]
            != f"{dist_info.name}/direct_url.json"
        ):
            _fail("uv-cache.source.record.invalid")
        record_name = f"{dist_info.name}/uv_cache.json"
        entries = owners.get(path.resolve(strict=True), [])
        if len(entries) != 1 or entries[0][0].path.parent != dist_info:
            _fail("uv-cache.record.invalid")
        if entries[0][0].rows[entries[0][1]][0] != record_name:
            _fail("uv-cache.record.invalid")
    return [caches[name] for name in sorted(caches)]


def _collect_bytecode(site_packages: Path, venv: Path) -> tuple[list[Path], list[Path]]:
    cache_directories: list[Path] = []
    bytecode: list[Path] = []
    outside_cache: list[Path] = []
    for current, directories, names in os.walk(site_packages, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            path = current_path / name
            try:
                metadata = path.lstat()
            except OSError:
                _fail("bytecode.invalid")
            if name == "__pycache__":
                if not stat.S_ISDIR(metadata.st_mode) or not path.resolve(
                    strict=True
                ).is_relative_to(venv):
                    _fail("bytecode.invalid")
                cache_directories.append(path)
                directories.remove(name)
                for member in path.iterdir():
                    if (
                        member.is_symlink()
                        or not member.is_file()
                        or member.suffix
                        not in {
                            ".pyc",
                            ".pyo",
                        }
                    ):
                        _fail("bytecode.invalid")
                    _regular_file(member, venv, "bytecode.invalid")
                    bytecode.append(member)
            elif stat.S_ISLNK(metadata.st_mode):
                directories.remove(name)
            elif not stat.S_ISDIR(metadata.st_mode):
                _fail("bytecode.invalid")
        for name in names:
            if Path(name).suffix in {".pyc", ".pyo"}:
                outside_cache.append(current_path / name)
    if outside_cache:
        _fail("bytecode.location.invalid")
    return sorted(bytecode), sorted(
        cache_directories, key=lambda path: len(path.parts), reverse=True
    )


def _build_root_matches(site_packages: Path, venv: Path) -> dict[Path, set[bytes]]:
    matches: dict[Path, set[bytes]] = {}
    for path in _walk_files(site_packages):
        try:
            metadata = path.lstat()
        except OSError:
            _fail("ocio.build-root.invalid")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        _regular_file(path, venv, "ocio.build-root.invalid")
        try:
            content = path.read_bytes()
        except OSError:
            _fail("ocio.build-root.invalid")
        found = list(_OCIO_BUILD_ROOT.finditer(content))
        if content.count(_OCIO_BUILD_ROOT_PREFIX) != len(found):
            _fail("ocio.build-root.invalid")
        tokens = {match.group(1) for match in found}
        if tokens:
            matches[path.resolve(strict=True)] = tokens
    return matches


def _default_objcopy(path: Path) -> None:
    _default_objcopy_at(path, _DEFAULT_OBJCOPY)


def _default_objcopy_at(path: Path, executable: Path) -> None:
    if not executable.is_absolute():
        _fail("ocio.objcopy.invalid")
    try:
        resolved = executable.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        _fail("ocio.objcopy.invalid")
    if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_IXUSR:
        _fail("ocio.objcopy.invalid")
    try:
        completed = subprocess.run(
            [str(resolved), "--remove-section=.note.gnu.build-id", str(path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        _fail("ocio.objcopy.failed")
    if completed.returncode != 0:
        _fail("ocio.objcopy.failed")


def _elf_sections(content: bytes, code: str) -> list[tuple[bytes, int]]:
    if len(content) < 16 or content[:4] != b"\x7fELF" or content[6] != 1:
        _fail(code)
    elf_class = content[4]
    byte_order = content[5]
    if byte_order == 1:
        prefix = "<"
    elif byte_order == 2:
        prefix = ">"
    else:
        _fail(code)
    if elf_class == 1:
        header_format = f"{prefix}HHIIIIIHHHHHH"
        section_format = f"{prefix}IIIIIIIIII"
        header_size = 52
        section_size = 40
    elif elf_class == 2:
        header_format = f"{prefix}HHIQQQIHHHHHH"
        section_format = f"{prefix}IIQQQQIIQQ"
        header_size = 64
        section_size = 64
    else:
        _fail(code)
    try:
        header = struct.unpack_from(header_format, content, 16)
    except struct.error:
        _fail(code)
    section_offset = int(header[5])
    declared_header_size = int(header[7])
    declared_section_size = int(header[10])
    section_count = int(header[11])
    string_table_index = int(header[12])
    if (
        int(header[2]) != 1
        or declared_header_size != header_size
        or declared_section_size != section_size
        or section_offset < header_size
        or section_offset + section_size > len(content)
    ):
        _fail(code)

    def section(index: int) -> tuple[int, ...]:
        offset = section_offset + index * section_size
        if index < 0 or offset + section_size > len(content):
            _fail(code)
        try:
            return tuple(
                int(value) for value in struct.unpack_from(section_format, content, offset)
            )
        except struct.error:
            _fail(code)

    section_zero = section(0)
    if section_count == 0:
        section_count = section_zero[5]
    if string_table_index == 0xFFFF:
        string_table_index = section_zero[6]
    maximum_sections = (len(content) - section_offset) // section_size
    if (
        section_count < 1
        or section_count > maximum_sections
        or string_table_index < 1
        or string_table_index >= section_count
    ):
        _fail(code)
    string_table = section(string_table_index)
    if string_table[1] != 3:
        _fail(code)
    names_offset = string_table[4]
    names_size = string_table[5]
    if names_size < 1 or names_offset + names_size > len(content):
        _fail(code)
    names = content[names_offset : names_offset + names_size]
    if names[0] != 0:
        _fail(code)
    result: list[tuple[bytes, int]] = []
    for index in range(section_count):
        current = section(index)
        name_offset = current[0]
        if name_offset >= len(names):
            _fail(code)
        name_end = names.find(b"\0", name_offset)
        if name_end < 0:
            _fail(code)
        result.append((names[name_offset:name_end], current[1]))
    return result


def _normalize_binary(path: Path, venv: Path, objcopy: Objcopy | None, objcopy_path: Path) -> None:
    metadata = _regular_file(path, venv, "ocio.binary.invalid")
    try:
        content = path.read_bytes()
    except OSError:
        _fail("ocio.binary.invalid")
    if not content.startswith(b"\x7fELF"):
        _fail("ocio.binary.invalid")
    build_id_sections = [
        section_type
        for name, section_type in _elf_sections(content, "ocio.binary.invalid")
        if name == _GNU_BUILD_ID_SECTION
    ]
    if build_id_sections != [7]:
        _fail("ocio.build-id.invalid")
    tokens = {match.group(1) for match in _OCIO_BUILD_ROOT.finditer(content)}
    if len(tokens) != 1 or _NORMALIZED_BUILD_TOKEN in tokens:
        _fail("ocio.build-root.invalid")
    normalized, replacements = _OCIO_BUILD_ROOT.subn(
        lambda match: match.group(0)[: -len(match.group(1))] + _NORMALIZED_BUILD_TOKEN,
        content,
    )
    if replacements < 1 or len(normalized) != len(content):
        _fail("ocio.build-root.invalid")
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.colortrace-", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        temporary = Path(temporary_name)
        try:
            if objcopy is None:
                _default_objcopy_at(temporary, objcopy_path)
            else:
                objcopy(temporary)
        except ReproducibleVenvError:
            raise
        except (OSError, subprocess.SubprocessError):
            _fail("ocio.objcopy.failed")
        _regular_file(temporary, venv, "ocio.objcopy.failed")
        result = temporary.read_bytes()
        result_tokens = {match.group(1) for match in _OCIO_BUILD_ROOT.finditer(result)}
        if (
            not result.startswith(b"\x7fELF")
            or result_tokens != {_NORMALIZED_BUILD_TOKEN}
            or any(
                name == _GNU_BUILD_ID_SECTION
                for name, _ in _elf_sections(result, "ocio.objcopy.failed")
            )
        ):
            _fail("ocio.objcopy.failed")
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        os.replace(temporary, path)
        temporary_name = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def _validate_ocio(
    site_packages: Path,
    venv: Path,
    owners: dict[Path, list[tuple[_Record, int]]],
) -> list[Path]:
    dist_info = site_packages / _OCIO_DIST_INFO
    metadata_path = dist_info / "METADATA"
    _regular_file(metadata_path, venv, "ocio.metadata.invalid")
    try:
        metadata_text = metadata_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        _fail("ocio.metadata.invalid")
    if (
        "\nName: opencolorio\n" not in f"\n{metadata_text}"
        or "\nVersion: 2.5.2\n" not in f"\n{metadata_text}"
    ):
        _fail("ocio.metadata.invalid")
    targets = [site_packages / name for name in _OCIO_BINARIES]
    for path in targets:
        _regular_file(path, venv, "ocio.binary.invalid")
    resolved_targets = {path.resolve(strict=True) for path in targets}
    matches = _build_root_matches(venv, venv)
    if set(matches) != resolved_targets:
        _fail("ocio.build-root.inventory")
    token_sets = [matches[path.resolve(strict=True)] for path in targets]
    if any(len(tokens) != 1 for tokens in token_sets) or token_sets[0] != token_sets[1]:
        _fail("ocio.build-root.invalid")
    for path, relative in zip(targets, _OCIO_BINARIES, strict=True):
        file_metadata = _regular_file(path, venv, "ocio.binary.invalid")
        if not file_metadata.st_mode & stat.S_IXUSR:
            _fail("ocio.binary.invalid")
        entries = owners.get(path.resolve(strict=True), [])
        if len(entries) != 1 or entries[0][0].path.parent != dist_info:
            _fail("ocio.record.invalid")
        if entries[0][0].rows[entries[0][1]][0] != relative:
            _fail("ocio.record.invalid")
    return targets


def _record_bytes(rows: Sequence[Sequence[str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _atomic_write(path: Path, content: bytes) -> None:
    metadata = path.stat()
    descriptor = -1
    temporary_name = ""
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.colortrace-", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = ""
    except OSError:
        _fail("record.write.failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def normalize_venv(
    venv: Path,
    *,
    objcopy: Objcopy | None = None,
    objcopy_path: Path = _DEFAULT_OBJCOPY,
) -> NormalizationResult:
    """Normalize the exact runtime venv or fail before accepting its contents."""

    root, site_packages = _site_packages(venv)
    records = _read_records(site_packages, root)
    owners = _record_owners(records, site_packages, root)
    caches = _validate_uv_caches(site_packages, root, owners)
    bytecode, cache_directories = _collect_bytecode(root, root)
    binaries = _validate_ocio(site_packages, root, owners)

    for path in binaries:
        _normalize_binary(path, root, objcopy, objcopy_path)

    removed = {path.resolve(strict=True) for path in [*caches, *bytecode]}
    normalized = {path.resolve(strict=True) for path in binaries}
    changed_records: list[_Record] = []
    for document in records:
        changed = False
        next_rows: list[list[str]] = []
        for row in document.rows:
            target = _record_target(row[0], site_packages, root)
            if target in removed:
                changed = True
                continue
            if target in normalized:
                content = target.read_bytes()
                next_rows.append([row[0], f"sha256={_record_digest(content)}", str(len(content))])
                changed = True
            else:
                next_rows.append(row)
        if changed:
            document.rows = next_rows
            changed_records.append(document)

    for path in caches:
        try:
            path.unlink()
        except OSError:
            _fail("uv-cache.remove.failed")
    for path in bytecode:
        try:
            path.unlink()
        except OSError:
            _fail("bytecode.remove.failed")
    for path in cache_directories:
        try:
            path.rmdir()
        except OSError:
            _fail("bytecode.remove.failed")
    for document in changed_records:
        _atomic_write(document.path, _record_bytes(document.rows))

    _read_records(site_packages, root)
    if any(path.name == "uv_cache.json" for path in _walk_files(root)):
        _fail("uv-cache.postcondition")
    remaining_bytecode, remaining_directories = _collect_bytecode(root, root)
    if remaining_bytecode or remaining_directories:
        _fail("bytecode.postcondition")
    remaining_roots = _build_root_matches(root, root)
    if set(remaining_roots) != normalized or any(
        tokens != {_NORMALIZED_BUILD_TOKEN} for tokens in remaining_roots.values()
    ):
        _fail("ocio.build-root.postcondition")

    return NormalizationResult(
        normalized_ocio_binaries=len(binaries),
        removed_bytecode_directories=len(cache_directories),
        removed_bytecode_files=len(bytecode),
        removed_uv_cache_files=len(caches),
        rewritten_records=len(changed_records),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--venv", required=True, type=Path)
    parser.add_argument("--objcopy", default=_DEFAULT_OBJCOPY, type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(arguments)
    try:
        result = normalize_venv(args.venv, objcopy_path=args.objcopy)
    except ReproducibleVenvError as error:
        print(f"reproducible venv normalization failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
