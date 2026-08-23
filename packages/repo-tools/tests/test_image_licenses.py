from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from colortrace_repo.distribution import _PYTHON_PROJECTS
from colortrace_repo.image_licenses import (
    FIRST_PARTY_PYTHON_DISTRIBUTIONS,
    BundleError,
    build_runtime_bundle,
    build_web_bundle,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
COMMIT = "1" * 40
TREE = "2" * 40


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _uvarint(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _common_inputs(root: Path) -> dict[str, Any]:
    return {
        "source_commit": COMMIT,
        "source_tree": TREE,
        "base_image": "example@sha256:" + "3" * 64,
        "root_license": _write(root / "LICENSE", "project license\n"),
        "apk_database": _write(
            root / "installed",
            "P:base\nV:1-r0\nA:x86_64\nL:gpl-2.0-only\n"
            "U:https://example.invalid/base\no:base\nc:" + "4" * 40 + "\n\n"
            "P:.runtime-deps\nV:1\nA:noarch\nL:\nU:\n\n",
        ),
        "os_release": _write(
            root / "os-release",
            'NAME="Alpine Linux"\nVERSION_ID=3.24.1\nHOME_URL="https://alpinelinux.org/"\n',
        ),
    }


def _python_inputs(root: Path) -> dict[str, Path]:
    site_packages = root / "site-packages"
    _write(
        site_packages / "licensed-1.0.dist-info" / "METADATA",
        "Metadata-Version: 2.4\nName: licensed\nVersion: 1.0\n"
        "License-Expression: MIT\nLicense-File: LICENSE\n"
        "Project-URL: Source, https://example.invalid/licensed\n\n",
    )
    _write(site_packages / "licensed-1.0.dist-info" / "licenses" / "LICENSE", "MIT\n")
    _write(
        site_packages / "unresolved-2.0.dist-info" / "METADATA",
        "Metadata-Version: 2.4\nName: unresolved\nVersion: 2.0\n\n",
    )
    global_site_packages = root / "global-site-packages"
    pip_metadata = (
        "Metadata-Version: 2.4\nName: pip\nVersion: 25.0.1\nLicense: MIT\n"
        "License-File: LICENSE.txt\nLicense-File: AUTHORS.txt\n\n"
    )
    pip_dist_info = global_site_packages / "pip-25.0.1.dist-info"
    _write(pip_dist_info / "METADATA", pip_metadata)
    _write(pip_dist_info / "LICENSE.txt", "MIT\n")
    _write(pip_dist_info / "AUTHORS.txt", "Pip authors\n")
    ensurepip_wheel = root / "ensurepip" / "pip-25.0.1-py3-none-any.whl"
    ensurepip_wheel.parent.mkdir(parents=True)
    with zipfile.ZipFile(ensurepip_wheel, "w") as archive:
        archive.writestr("pip-25.0.1.dist-info/METADATA", pip_metadata)
        archive.writestr("pip-25.0.1.dist-info/LICENSE.txt", "MIT\n")
        archive.writestr("pip-25.0.1.dist-info/AUTHORS.txt", "Pip authors\n")
    return {
        "python_site_packages": site_packages,
        "global_python_site_packages": global_site_packages,
        "ensurepip_wheel": ensurepip_wheel,
        "python_license": _write(root / "python-license", "Python license\n"),
        "uv_lock": _write(root / "uv.lock", "version = 1\n"),
    }


def _web_inputs(root: Path) -> dict[str, Path]:
    first_party = root / "first-party"
    for directory, name in (
        ("api-client", "@colortrace/api-client"),
        ("web", "@colortrace/web"),
        ("workspace-model", "@colortrace/workspace-model"),
    ):
        _write(
            first_party / directory / "package.json",
            json.dumps({"name": name, "version": "0.0.0", "license": "Apache-2.0"}),
        )
    third_party = root / "third-party"
    versions = {"react": "19.2.8", "react-dom": "19.2.8", "scheduler": "0.27.0"}
    for name, version in versions.items():
        _write(
            third_party / name / "package.json",
            json.dumps(
                {
                    "name": name,
                    "version": version,
                    "license": "MIT",
                    "repository": {"url": "https://example.invalid/react.git"},
                }
            ),
        )
        _write(third_party / name / "LICENSE", "MIT\n")
    return {
        "node_license": _write(root / "node-license", "Node notices\n"),
        "node_version": _write(root / "node-version", "v24.19.0\n"),
        "pnpm_lock": _write(root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        "first_party_web_manifests": first_party,
        "web_packages": third_party,
    }


def _bundle_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class ImageLicenseBundleTest(unittest.TestCase):
    def test_python_first_party_inventory_matches_installable_repository_projects(self) -> None:
        expected = {name for name, _ in _PYTHON_PROJECTS.values() if name != "colortrace-workspace"}
        self.assertEqual(FIRST_PARTY_PYTHON_DISTRIBUTIONS, expected)

    def test_runtime_bundle_is_deterministic_and_preserves_unresolved_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            first_output = root / "first"
            second_output = root / "second"
            for output in (first_output, second_output):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **python_inputs,
                        output=output,
                        profile="hosted-readonly",
                        mcp_binary=None,
                    )
                )

            self.assertEqual(_bundle_files(first_output), _bundle_files(second_output))
            manifest = json.loads((first_output / "manifest.json").read_text())
            components = {(item["kind"], item["name"]): item for item in manifest["components"]}
            self.assertEqual(
                components[("apk", "base")]["owner_legal_status"],
                "pending",
            )
            self.assertEqual(
                components[("apk", ".runtime-deps")]["license_evidence_status"],
                "unresolved",
            )
            self.assertEqual(
                components[("apk", ".runtime-deps")]["owner_legal_status"],
                "pending",
            )
            self.assertEqual(
                components[("apk", ".runtime-deps")]["license_source"]["path"],
                "sources/alpine/installed",
            )
            self.assertEqual(
                components[("python-distribution", "licensed")]["license_evidence_status"],
                "delivered-text",
            )
            self.assertEqual(
                components[("python-distribution", "unresolved")]["license_evidence_status"],
                "unresolved",
            )
            self.assertEqual(
                components[("python-distribution", "unresolved")]["owner_legal_status"],
                "pending",
            )
            self.assertEqual(
                components[("python-distribution", "pip")]["provenance"],
                {"kind": "base-image", "reference": common["base_image"]},
            )
            self.assertEqual(components[("embedded-python-wheel", "pip")]["version"], "25.0.1")
            installed_metadata = components[("python-distribution", "licensed")]["license_sources"][
                0
            ]
            embedded_metadata = components[("embedded-python-wheel", "pip")]["license_sources"][0]
            with zipfile.ZipFile(python_inputs["ensurepip_wheel"]) as archive:
                embedded_metadata_bytes = archive.read("pip-25.0.1.dist-info/METADATA")
            for source, original in (
                (
                    installed_metadata,
                    python_inputs["python_site_packages"] / "licensed-1.0.dist-info" / "METADATA",
                ),
                (embedded_metadata, embedded_metadata_bytes),
            ):
                self.assertTrue(source["path"].endswith("/metadata.txt"))
                self.assertNotIn(".dist-info", source["path"])
                self.assertEqual(
                    hashlib.sha256((first_output / source["path"]).read_bytes()).hexdigest(),
                    source["sha256"],
                )
                if isinstance(original, Path):
                    self.assertEqual(
                        (first_output / source["path"]).read_bytes(), original.read_bytes()
                    )
                else:
                    self.assertEqual((first_output / source["path"]).read_bytes(), original)
            checksum_lines = (first_output / "SHA256SUMS").read_text().splitlines()
            checksum_paths = [line.split("  ", 1)[1] for line in checksum_lines]
            self.assertEqual(checksum_paths, sorted(checksum_paths))
            for line in checksum_lines:
                expected, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((first_output / relative).read_bytes()).hexdigest(), expected
                )

    def test_runtime_bundle_uses_exact_first_party_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            site_packages = python_inputs["python_site_packages"]
            _write(
                site_packages / "colortrace_api-1.0.dist-info" / "METADATA",
                "Metadata-Version: 2.4\nName: colortrace-api\nVersion: 1.0\n\n",
            )
            _write(
                site_packages / "colortrace_impostor-1.0.dist-info" / "METADATA",
                "Metadata-Version: 2.4\nName: colortrace-impostor\nVersion: 1.0\n\n",
            )
            output = root / "bundle"
            build_runtime_bundle(
                SimpleNamespace(
                    **common,
                    **python_inputs,
                    output=output,
                    profile="hosted-readonly",
                    mcp_binary=None,
                )
            )

            components = json.loads((output / "manifest.json").read_text())["components"]
            distributions = {
                item["name"]: item for item in components if item["kind"] == "python-distribution"
            }
            root_license_path = "sources/first-party/LICENSE"
            self.assertIn(
                root_license_path,
                {source["path"] for source in distributions["colortrace-api"]["license_sources"]},
            )
            self.assertNotIn(
                root_license_path,
                {
                    source["path"]
                    for source in distributions["colortrace-impostor"]["license_sources"]
                },
            )
            self.assertEqual(
                distributions["colortrace-impostor"]["license_evidence_status"], "unresolved"
            )

    def test_runtime_bundle_rejects_missing_declared_license_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            _write(
                python_inputs["python_site_packages"] / "licensed-1.0.dist-info" / "METADATA",
                "Metadata-Version: 2.4\nName: licensed\nVersion: 1.0\n"
                "License-Expression: MIT\nLicense-File: MISSING\n\n",
            )
            with self.assertRaisesRegex(BundleError, "declared Python License-File is missing"):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **python_inputs,
                        output=root / "bundle",
                        profile="hosted-readonly",
                        mcp_binary=None,
                    )
                )

    def test_runtime_bundle_rejects_symlinked_distribution_metadata_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            outside = root / "outside" / "escaped-1.0.dist-info"
            _write(
                outside / "METADATA",
                "Metadata-Version: 2.4\nName: escaped\nVersion: 1.0\n\n",
            )
            (python_inputs["python_site_packages"] / "escaped-1.0.dist-info").symlink_to(
                outside, target_is_directory=True
            )
            with self.assertRaisesRegex(BundleError, "symlink path component"):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **python_inputs,
                        output=root / "bundle",
                        profile="hosted-readonly",
                        mcp_binary=None,
                    )
                )

    def test_bundle_rejects_mutable_base_image_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            common["base_image"] = "python:latest"
            with self.assertRaisesRegex(BundleError, "base image must be an immutable"):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **_python_inputs(root),
                        output=root / "bundle",
                        profile="hosted-readonly",
                        mcp_binary=None,
                    )
                )

    def test_bundle_profiles_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            with self.assertRaisesRegex(BundleError, "private-full requires"):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **python_inputs,
                        output=root / "private",
                        profile="private-full",
                        mcp_binary=None,
                    )
                )
            with self.assertRaisesRegex(BundleError, "hosted-readonly forbids"):
                build_runtime_bundle(
                    SimpleNamespace(
                        **common,
                        **python_inputs,
                        output=root / "hosted",
                        profile="hosted-readonly",
                        mcp_binary=root / "unexpected-mcp",
                    )
                )
            with self.assertRaisesRegex(BundleError, "unsupported web profile"):
                build_web_bundle(
                    SimpleNamespace(
                        **common,
                        **_web_inputs(root),
                        output=root / "web",
                        profile="private-full",
                    )
                )

    def test_runtime_bundle_extracts_exact_mcp_go_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            python_inputs = _python_inputs(root)
            module_text = (
                "path\tgithub.com/grafana/mcp-grafana/cmd/mcp-grafana\n"
                "mod\tgithub.com/grafana/mcp-grafana\tv1.1.0\th1:exactsource=\n"
                "dep\texample.invalid/module\tv1.2.3\th1:exact=\n"
                "build\tvcs.revision=" + "5" * 40 + "\n"
            ).encode()
            framed = (
                b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6" + module_text + bytes(16)
            )
            version = b"go1.26.6"
            binary = _write(
                root / "mcp-grafana",
                b"binary-prefix"
                + b"\xff Go buildinf:"
                + bytes((8, 2))
                + bytes(16)
                + _uvarint(len(version))
                + version
                + _uvarint(len(framed))
                + framed,
            )
            lock = {
                "schema": "mcp-grafana-runtime-lock/v2",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "release_version": "1.1.0",
                "source_commit": "5" * 40,
                "source_module": "github.com/grafana/mcp-grafana",
                "source_module_sum": "h1:exactsource=",
                "source_module_version": "v1.1.0",
                "source_repository": "https://github.com/grafana/mcp-grafana",
                "source_tree": "6" * 40,
                "toolchain_version": "go1.26.6",
            }
            lock_path = _write(root / "mcp-lock.json", json.dumps(lock))
            output = root / "bundle"
            build_runtime_bundle(
                SimpleNamespace(
                    **common,
                    **python_inputs,
                    output=output,
                    profile="private-full",
                    mcp_binary=binary,
                    mcp_lock=lock_path,
                    mcp_license=_write(root / "mcp-license", "Apache\n"),
                    go_license=_write(root / "go-license", "Go license\n"),
                )
            )

            components = json.loads((output / "manifest.json").read_text())["components"]
            go_module = next(item for item in components if item["kind"] == "go-module")
            self.assertEqual(go_module["name"], "example.invalid/module")
            self.assertEqual(go_module["source_checksum"], "h1:exact=")
            self.assertEqual(go_module["license_evidence_status"], "unresolved")
            main_module = next(
                item
                for item in components
                if item["kind"] == "go-module" and item["name"] == "github.com/grafana/mcp-grafana"
            )
            self.assertEqual(main_module["version"], "v1.1.0")
            self.assertEqual(main_module["source_checksum"], "h1:exactsource=")
            self.assertEqual(main_module["source_tree"], "6" * 40)
            self.assertEqual(main_module["license_evidence_status"], "delivered-text")

    def test_web_bundle_covers_exact_first_and_third_party_runtime_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            common = _common_inputs(root)
            web_inputs = _web_inputs(root)
            versions = {"react": "19.2.8", "react-dom": "19.2.8", "scheduler": "0.27.0"}
            output = root / "bundle"
            build_web_bundle(
                SimpleNamespace(
                    **common,
                    **web_inputs,
                    output=output,
                    profile="public-readonly",
                )
            )

            components = json.loads((output / "manifest.json").read_text())["components"]
            names = {item["name"] for item in components}
            self.assertTrue(set(versions) <= names)
            self.assertTrue(
                {"@colortrace/api-client", "@colortrace/web", "@colortrace/workspace-model"}
                <= names
            )
            components_by_name = {item["name"]: item for item in components}
            package_inputs = {
                "@colortrace/api-client": web_inputs["first_party_web_manifests"]
                / "api-client"
                / "package.json",
                "@colortrace/web": web_inputs["first_party_web_manifests"] / "web" / "package.json",
                "@colortrace/workspace-model": web_inputs["first_party_web_manifests"]
                / "workspace-model"
                / "package.json",
                **{name: web_inputs["web_packages"] / name / "package.json" for name in versions},
            }
            for name, original in package_inputs.items():
                component = components_by_name[name]
                package_source = component["package_source"]
                self.assertIn("sources/web/package-metadata/", package_source["path"])
                self.assertTrue(package_source["path"].endswith(".metadata.txt"))
                self.assertNotIn("/package.json", package_source["path"])
                copied = (output / package_source["path"]).read_bytes()
                self.assertEqual(copied, original.read_bytes())
                self.assertEqual(hashlib.sha256(copied).hexdigest(), package_source["sha256"])
                self.assertEqual(
                    component["kind"],
                    "bundled-first-party-javascript"
                    if name.startswith("@colortrace/")
                    else "bundled-javascript",
                )
            checksum_paths = [
                line.split("  ", 1)[1] for line in (output / "SHA256SUMS").read_text().splitlines()
            ]
            self.assertEqual(checksum_paths, sorted(checksum_paths))

    def test_web_bundle_rejects_symlinked_metadata_parents(self) -> None:
        for input_name, child in (
            ("first_party_web_manifests", "api-client"),
            ("web_packages", "react"),
        ):
            with self.subTest(input_name=input_name):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    common = _common_inputs(root)
                    web_inputs = _web_inputs(root)
                    package_directory = web_inputs[input_name] / child
                    outside = root / "outside" / input_name / child
                    outside.parent.mkdir(parents=True)
                    package_directory.rename(outside)
                    package_directory.symlink_to(outside, target_is_directory=True)
                    with self.assertRaisesRegex(BundleError, "symlink path component"):
                        build_web_bundle(
                            SimpleNamespace(
                                **common,
                                **web_inputs,
                                output=root / "bundle",
                                profile="public-readonly",
                            )
                        )

    def test_final_web_image_uses_cleaned_rootfs_without_inherited_yarn(self) -> None:
        dockerfile = (REPOSITORY_ROOT / "Dockerfile.web").read_text(encoding="utf-8")
        self.assertIn("/opt/yarn-v1.22.22", dockerfile)
        self.assertIn("/usr/local/bin/docker-entrypoint.sh", dockerfile)
        final_stage = dockerfile.split("\nFROM scratch\n", maxsplit=1)
        self.assertEqual(len(final_stage), 2)
        self.assertIn("COPY --from=runtime-rootfs / /", final_stage[1])
        self.assertNotIn("YARN", final_stage[1].upper())
        self.assertIn(
            "colortrace-image-license-bundle/v1",
            (
                REPOSITORY_ROOT / "packages/repo-tools/src/colortrace_repo/image_licenses.py"
            ).read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
