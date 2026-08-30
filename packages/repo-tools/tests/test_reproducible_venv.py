from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import struct
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from colortrace_repo.reproducible_venv import (
    EXPECTED_UV_CACHE_SOURCES,
    ReproducibleVenvError,
    normalize_venv,
)

_FIRST_BUILD_TOKEN = "A" * 16
_SECOND_BUILD_TOKEN = ("B" * 7) + "-" + ("B" * 6) + "_B"


def _record_hash(content: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
    return f"sha256={value.decode()}"


def _write(path: Path, content: bytes | str, *, executable: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    if executable:
        path.chmod(0o755)
    return path


def _record_bytes(rows: list[list[str]]) -> bytes:
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    return output.getvalue().encode()


def _write_record(site_packages: Path, dist_info_name: str, files: list[Path]) -> Path:
    record = site_packages / dist_info_name / "RECORD"
    rows: list[list[str]] = []
    for path in sorted(files):
        content = path.read_bytes()
        rows.append(
            [
                path.relative_to(site_packages).as_posix(),
                _record_hash(content),
                str(len(content)),
            ]
        )
    rows.append([record.relative_to(site_packages).as_posix(), "", ""])
    return _write(record, _record_bytes(rows))


def _replace_record_row(site_packages: Path, target: Path) -> None:
    record = target.parent / "RECORD"
    rows = list(csv.reader(io.StringIO(record.read_text(), newline="")))
    relative = target.relative_to(site_packages).as_posix()
    content = target.read_bytes()
    for row in rows:
        if row[0] == relative:
            row[1:] = [_record_hash(content), str(len(content))]
            break
    record.write_bytes(_record_bytes(rows))


def _fixture(root: Path, *, token: str, timestamp: int) -> tuple[Path, Path]:
    venv = root / "venv"
    site_packages = venv / "lib" / "python3.12" / "site-packages"
    site_packages.mkdir(parents=True)
    (venv / "lib64").symlink_to("lib", target_is_directory=True)
    for relative, source in EXPECTED_UV_CACHE_SOURCES.items():
        cache = site_packages / relative
        dist_info = cache.parent
        direct_url = _write(
            dist_info / "direct_url.json",
            json.dumps(
                {"url": source, "dir_info": {"editable": False}},
                separators=(",", ":"),
            ),
        )
        metadata = _write(
            dist_info / "METADATA",
            f"Metadata-Version: 2.4\nName: {dist_info.name}\nVersion: 1\n",
        )
        _write(
            cache,
            json.dumps(
                {
                    "timestamp": {
                        "secs_since_epoch": timestamp,
                        "nanos_since_epoch": 123456789,
                    },
                    "commit": None,
                    "tags": None,
                    "env": {},
                    "directories": {"src": timestamp + 1},
                },
                separators=(",", ":"),
            ),
        )
        _write_record(site_packages, dist_info.name, [cache, direct_url, metadata])

    ocio_dist_info = site_packages / "opencolorio-2.5.2.dist-info"
    ocio_metadata = _write(
        ocio_dist_info / "METADATA",
        "Metadata-Version: 2.4\nName: opencolorio\nVersion: 2.5.2\n",
    )
    build_root = (
        b"/root/.cache/uv/sdists-v9/pypi/opencolorio/2.5.2/" + token.encode() + b"/src/file.cpp"
    )
    binaries = [
        _write(
            site_packages / "PyOpenColorIO" / "bin" / name,
            _test_elf(build_root),
            executable=True,
        )
        for name in ("ocioconvert", "ociolutimage")
    ]
    wrapper = _write(venv / "bin" / "ocioconvert", "#!/bin/sh\nexit 0\n", executable=True)
    ocio_record = _write_record(site_packages, ocio_dist_info.name, [ocio_metadata, *binaries])
    rows = list(csv.reader(io.StringIO(ocio_record.read_text(), newline=""), strict=True))
    wrapper_content = wrapper.read_bytes()
    rows.insert(
        -1,
        [
            "../../../bin/ocioconvert",
            _record_hash(wrapper_content),
            str(len(wrapper_content)),
        ],
    )
    ocio_record.write_bytes(_record_bytes(rows))
    _write(
        site_packages / "example" / "__pycache__" / "module.cpython-312.pyc",
        b"bytecode-" + str(timestamp).encode(),
    )
    return venv, site_packages


def _fake_objcopy(path: Path) -> None:
    content = bytearray(path.read_bytes())
    if b"BUILDID" not in content:
        raise OSError("missing build id")
    build_id_offset = content.index(b"BUILDID")
    content[build_id_offset : build_id_offset + len(b"BUILDID")] = bytes(len(b"BUILDID"))
    section_offset = struct.unpack_from("<Q", content, 40)[0]
    content[section_offset + 128 : section_offset + 192] = bytes(64)
    path.write_bytes(content)


def _test_elf(build_root: bytes) -> bytes:
    section_names = b"\0.shstrtab\0.note.gnu.build-id\0"
    body = b"\0" + build_root + b"\0BUILDID\0"
    names_offset = 64 + len(body)
    padding = bytes((-names_offset - len(section_names)) % 8)
    section_offset = names_offset + len(section_names) + len(padding)
    identity = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = identity + struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        62,
        1,
        0,
        0,
        section_offset,
        0,
        64,
        0,
        0,
        64,
        3,
        1,
    )
    null_section = bytes(64)
    names_section = struct.pack(
        "<IIQQQQIIQQ",
        1,
        3,
        0,
        0,
        names_offset,
        len(section_names),
        0,
        0,
        1,
        0,
    )
    build_id_section = struct.pack(
        "<IIQQQQIIQQ",
        section_names.index(b".note.gnu.build-id"),
        7,
        0,
        0,
        body.index(b"BUILDID") + 64,
        len(b"BUILDID"),
        0,
        0,
        4,
        0,
    )
    return header + body + section_names + padding + null_section + names_section + build_id_section


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class ReproducibleVenvTest(unittest.TestCase):
    def test_normalizes_two_different_builds_to_identical_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first, first_site = _fixture(
                root / "first", token=_FIRST_BUILD_TOKEN, timestamp=1_787_401_465
            )
            second, second_site = _fixture(
                root / "second", token=_SECOND_BUILD_TOKEN, timestamp=1_787_403_684
            )

            first_result = normalize_venv(first, objcopy=_fake_objcopy)
            second_result = normalize_venv(second, objcopy=_fake_objcopy)

            self.assertEqual(first_result.normalized_ocio_binaries, 2)
            self.assertEqual(first_result.removed_bytecode_files, 1)
            self.assertEqual(first_result.removed_bytecode_directories, 1)
            self.assertEqual(first_result.removed_uv_cache_files, 10)
            self.assertEqual(first_result.rewritten_records, 11)
            self.assertEqual(first_result, second_result)
            self.assertEqual(_files(first_site), _files(second_site))
            self.assertFalse(list(first_site.rglob("*.pyc")))
            self.assertFalse(list(first_site.rglob("uv_cache.json")))
            self.assertEqual((first / "bin" / "ocioconvert").read_text(), "#!/bin/sh\nexit 0\n")
            for name in ("ocioconvert", "ociolutimage"):
                content = (first_site / "PyOpenColorIO" / "bin" / name).read_bytes()
                self.assertIn(b"/0000000000000000/src/file.cpp", content)
                self.assertNotIn(b"BUILDID", content)

    def test_rejects_uv_cache_inventory_and_record_drift(self) -> None:
        mutations: dict[str, Callable[[Path], object]] = {
            "missing": lambda site: next(site.rglob("uv_cache.json")).unlink(),
            "unexpected": lambda site: _write(
                site / "unexpected-1.0.dist-info" / "uv_cache.json", "{}"
            ),
            "hash": lambda site: next(site.rglob("uv_cache.json")).write_text("{}"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
                mutate(site)
                with self.assertRaises(ReproducibleVenvError):
                    normalize_venv(venv, objcopy=_fake_objcopy)

    def test_rejects_malformed_cache_after_record_is_rebound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            cache = next(site.rglob("uv_cache.json"))
            cache.write_text('{"timestamp":{}}', encoding="utf-8")
            _replace_record_row(site, cache)
            with self.assertRaisesRegex(ReproducibleVenvError, "uv-cache.invalid"):
                normalize_venv(venv, objcopy=_fake_objcopy)

    def test_rejects_missing_record_and_unowned_direct_url(self) -> None:
        mutations: dict[str, Callable[[Path], object]] = {
            "missing-record": lambda site: next(
                site.glob("colortrace_*.dist-info/RECORD")
            ).unlink(),
            "unowned-direct-url": self._remove_direct_url_record_row,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
                mutate(site)
                with self.assertRaises(ReproducibleVenvError):
                    normalize_venv(venv, objcopy=_fake_objcopy)

    @staticmethod
    def _remove_direct_url_record_row(site: Path) -> None:
        direct_url = next(site.rglob("direct_url.json"))
        record = direct_url.parent / "RECORD"
        relative = direct_url.relative_to(site).as_posix()
        rows = list(csv.reader(io.StringIO(record.read_text(), newline=""), strict=True))
        record.write_bytes(_record_bytes([row for row in rows if row[0] != relative]))

    def test_rejects_record_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            record = next(site.glob("colortrace_*.dist-info/RECORD"))
            rows = list(csv.reader(io.StringIO(record.read_text(), newline="")))
            rows.insert(0, ["../../../../escape", "sha256=" + "a" * 43, "1"])
            record.write_bytes(_record_bytes(rows))
            with self.assertRaisesRegex(ReproducibleVenvError, "record.path.escape"):
                normalize_venv(venv, objcopy=_fake_objcopy)

    def test_rejects_bytecode_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            bytecode = next(site.rglob("*.pyc"))
            bytecode.unlink()
            bytecode.symlink_to(site / "PyOpenColorIO" / "bin" / "ocioconvert")
            with self.assertRaisesRegex(ReproducibleVenvError, "bytecode.invalid"):
                normalize_venv(venv, objcopy=_fake_objcopy)

    def test_rejects_an_unexpected_random_build_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            _write(
                site / "unexpected.bin",
                b"/root/.cache/uv/sdists-v9/pypi/opencolorio/2.5.2/2LerKmJAMyOOrLi8/src",
            )
            with self.assertRaisesRegex(ReproducibleVenvError, "ocio.build-root.inventory"):
                normalize_venv(venv, objcopy=_fake_objcopy)

    def test_rejects_objcopy_failure_without_replacing_the_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            target = site / "PyOpenColorIO" / "bin" / "ocioconvert"
            original = target.read_bytes()

            def fail_objcopy(path: Path) -> None:
                raise OSError("fixture failure")

            with self.assertRaisesRegex(ReproducibleVenvError, "ocio.objcopy.failed"):
                normalize_venv(venv, objcopy=fail_objcopy)
            self.assertEqual(target.read_bytes(), original)

    def test_rejects_noop_objcopy_without_replacing_the_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            target = site / "PyOpenColorIO" / "bin" / "ocioconvert"
            original = target.read_bytes()

            with self.assertRaisesRegex(ReproducibleVenvError, "ocio.objcopy.failed"):
                normalize_venv(venv, objcopy=lambda path: None)
            self.assertEqual(target.read_bytes(), original)

    def test_removes_recorded_bytecode_and_its_record_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, site = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            bytecode = next(site.rglob("*.pyc"))
            record = next(site.glob("colortrace_*.dist-info/RECORD"))
            rows = list(csv.reader(io.StringIO(record.read_text(), newline=""), strict=True))
            content = bytecode.read_bytes()
            relative = bytecode.relative_to(site).as_posix()
            rows.insert(-1, [relative, _record_hash(content), str(len(content))])
            record.write_bytes(_record_bytes(rows))

            normalize_venv(venv, objcopy=_fake_objcopy)

            self.assertFalse(bytecode.exists())
            normalized_rows = list(
                csv.reader(io.StringIO(record.read_text(), newline=""), strict=True)
            )
            self.assertNotIn(relative, {row[0] for row in normalized_rows})

    def test_removes_bytecode_outside_site_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            venv, _ = _fixture(root, token=_FIRST_BUILD_TOKEN, timestamp=1)
            bytecode = _write(
                venv / "bin" / "__pycache__" / "helper.cpython-312.pyc",
                b"bytecode",
            )

            normalize_venv(venv, objcopy=_fake_objcopy)

            self.assertFalse(bytecode.exists())


if __name__ == "__main__":
    unittest.main()
