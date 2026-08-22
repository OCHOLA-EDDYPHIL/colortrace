from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from colortrace_repo.final_image_evidence import (
    EvidenceError,
    ImageEvidenceInput,
    _archive_binding,
    _bundle_bom_ref,
    _reconcile,
    _verify_bundle,
    build_final_image_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE = "a" * 40
TREE = "b" * 40
SCANNER = "scanner@sha256:" + "c" * 64


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def _gzip(value: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(value)
    return output.getvalue()


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _write_archive(
    root: Path,
    name: str,
    profile: str,
    *,
    yarn_path: bool = False,
    yarn_config: bool = False,
    corrupt_blob: bool = False,
    missing_layer: bool = False,
    nested_index: bool = False,
    malformed_layer: bool = False,
) -> tuple[Path, str]:
    layer_name = "usr/local/lib/node_modules/yarn/bin/yarn.js" if yarn_path else "app/colortrace"
    plain_layer = _tar_bytes({layer_name: b"fixture\n"})
    layer = b"not-a-tar" if malformed_layer else _gzip(plain_layer)
    layer_digest = _digest(layer)
    config = _json_bytes(
        {
            "architecture": "amd64",
            "config": {
                "Env": ["YARN_VERSION=1.22.22"] if yarn_config else [],
                "Labels": {
                    "org.colortrace.runtime-profile": profile,
                    "org.colortrace.source-tree": TREE,
                    "org.opencontainers.image.revision": CANDIDATE,
                },
                "User": "65532:65532",
            },
            "history": [],
            "os": "linux",
            "rootfs": {"diff_ids": [_digest(plain_layer)], "type": "layers"},
        }
    )
    config_digest = _digest(config)
    manifest = _json_bytes(
        {
            "config": {
                "digest": config_digest,
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": layer_digest,
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": len(layer),
                }
            ],
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2,
        }
    )
    manifest_digest = _digest(manifest)
    reference = f"fixture-{name}:{CANDIDATE}"

    def blob(digest: str) -> str:
        return f"blobs/sha256/{digest.removeprefix('sha256:')}"

    image_descriptor = {
        "digest": manifest_digest,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "size": len(manifest),
    }
    blobs = {
        blob(config_digest): config + (b"corrupt" if corrupt_blob else b""),
        blob(layer_digest): layer,
        blob(manifest_digest): manifest,
    }
    top_descriptor = image_descriptor
    if nested_index:
        attestation_config = _json_bytes({"architecture": "unknown", "os": "unknown"})
        attestation_layer = b"fixture attestation"
        attestation_manifest = _json_bytes(
            {
                "config": {
                    "digest": _digest(attestation_config),
                    "mediaType": "application/vnd.oci.empty.v1+json",
                    "size": len(attestation_config),
                },
                "layers": [
                    {
                        "digest": _digest(attestation_layer),
                        "mediaType": "application/vnd.in-toto+json",
                        "size": len(attestation_layer),
                    }
                ],
                "schemaVersion": 2,
            }
        )
        nested = _json_bytes(
            {
                "manifests": [
                    image_descriptor,
                    {
                        "digest": _digest(attestation_manifest),
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "size": len(attestation_manifest),
                    },
                ],
                "schemaVersion": 2,
            }
        )
        top_descriptor = {
            "digest": _digest(nested),
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "size": len(nested),
        }
        blobs.update(
            {
                blob(_digest(attestation_config)): attestation_config,
                blob(_digest(attestation_layer)): attestation_layer,
                blob(_digest(attestation_manifest)): attestation_manifest,
                blob(_digest(nested)): nested,
            }
        )
    files = {
        "index.json": _json_bytes({"manifests": [top_descriptor], "schemaVersion": 2}),
        "manifest.json": _json_bytes(
            [
                {
                    "Config": blob(config_digest),
                    "Layers": [blob(layer_digest)],
                    "RepoTags": [reference],
                }
            ]
        ),
        "oci-layout": _json_bytes({"imageLayoutVersion": "1.0.0"}),
        **blobs,
    }
    if missing_layer:
        files.pop(blob(layer_digest))
    path = root / f"{name}.tar"
    path.write_bytes(_tar_bytes(files))
    return path, reference


def _component(
    kind: str,
    name: str,
    version: str,
    *,
    license_expression: str | None = None,
    unresolved: bool = False,
    source: dict[str, str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "kind": kind,
        "license_evidence_status": "unresolved" if unresolved else "delivered-text",
        "license_expression": license_expression,
        "name": name,
        "owner_legal_status": "pending" if unresolved else None,
        "source_url": f"https://example.invalid/{name}",
        "version": version,
    }
    if not unresolved:
        result["license_sources"] = [source]
    return result


def _bundle_components(
    profile: str, source: dict[str, str], extra_source: dict[str, str]
) -> list[dict[str, Any]]:
    components = [
        _component("application", "ColorTrace", CANDIDATE, source=source),
        _component(
            "operating-system-aggregate",
            "Alpine Linux",
            "3.20.3",
            unresolved=True,
        ),
        {
            **_component("apk", "busybox", "1.36.1-r29", license_expression="MIT", source=source),
            "license_evidence_status": "declared-in-installed-database",
            "license_source": source,
            "license_sources": [],
        },
    ]
    if profile in {"private-full", "hosted-readonly"}:
        components.extend(
            [
                _component("language-runtime", "Python", "3.12.7", source=source),
                _component(
                    "apk",
                    ".python-rundeps",
                    "20240801.120000",
                    unresolved=True,
                ),
                {
                    **_component("embedded-python-wheel", "pip", "24.2", source=source),
                    "license_sources": [source, extra_source],
                },
                {
                    **_component(
                        "python-distribution",
                        "Demo_Package",
                        "1.0",
                        license_expression="MIT",
                        source=source,
                    ),
                    "license_evidence_status": "declared-in-metadata",
                },
            ]
        )
    if profile == "private-full":
        components.extend(
            [
                _component(
                    "application",
                    "mcp-grafana",
                    "0.7.0",
                    license_expression="Apache-2.0",
                    source=source,
                ),
                _component("language-runtime", "Go standard library", "1.24.0", source=source),
                _component(
                    "go-module",
                    "github.com/grafana/mcp-grafana",
                    "v1.1.0",
                    license_expression="Apache-2.0",
                    source=source,
                ),
                _component(
                    "go-module",
                    "example.com/module",
                    "v1.0.0",
                    unresolved=True,
                ),
            ]
        )
    if profile == "public-readonly":
        components.append(_component("language-runtime", "Node.js", "22.12.0", source=source))
        for name in (
            "@colortrace/api-client",
            "@colortrace/web",
            "@colortrace/workspace-model",
        ):
            components.append(
                _component("bundled-first-party-javascript", name, "0.0.0", source=source)
            )
        for name, version in (
            ("react", "18.3.1"),
            ("react-dom", "18.3.1"),
            ("scheduler", "0.23.2"),
        ):
            components.append(
                _component(
                    "bundled-javascript",
                    name,
                    version,
                    license_expression="MIT",
                    source=source,
                )
            )
    return sorted(components, key=lambda value: (value["kind"], value["name"]))


def _refresh_bundle_checksums(root: Path) -> None:
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_bundle(
    root: Path,
    name: str,
    profile: str,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[Path, dict[str, Any]]:
    bundle = root / name / "bundle"
    (bundle / "sources").mkdir(parents=True)
    source_path = bundle / "sources" / "LICENSE"
    source_path.write_text("fixture license\n", encoding="utf-8")
    source = {
        "path": "sources/LICENSE",
        "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
    }
    extra_path = bundle / "sources" / "NOTICE"
    extra_path.write_text("fixture notice\n", encoding="utf-8")
    extra_source = {
        "path": "sources/NOTICE",
        "sha256": hashlib.sha256(extra_path.read_bytes()).hexdigest(),
    }
    manifest = {
        "base_image": "base@sha256:" + "d" * 64,
        "compatibility_decision": "owner-legal-pending",
        "components": _bundle_components(profile, source, extra_source),
        "profile": profile,
        "schema": "colortrace-image-license-bundle/v1",
        "source_commit": CANDIDATE,
        "source_tree": TREE,
    }
    if mutate is not None:
        mutate(manifest)
    (bundle / "manifest.json").write_bytes(_json_bytes(manifest))
    _refresh_bundle_checksums(bundle)
    return bundle, manifest


def _scanner_component(
    name: str,
    version: str,
    package_type: str,
    *,
    license_expression: str | None = None,
    component_type: str = "library",
    detected_type: str | None = None,
) -> dict[str, Any]:
    properties = [{"name": "aquasecurity:trivy:PkgType", "value": package_type}]
    if detected_type is not None:
        properties.append({"name": "aquasecurity:trivy:Type", "value": detected_type})
    result: dict[str, Any] = {
        "bom-ref": f"pkg:{package_type}/{name}@{version}",
        "name": name,
        "properties": properties,
        "type": component_type,
        "version": version,
    }
    if license_expression is not None:
        result["licenses"] = [{"license": {"id": license_expression}}]
    return result


def _raw_sbom(profile: str) -> dict[str, Any]:
    components = [
        _scanner_component(
            "alpine",
            "3.20.3",
            "alpine",
            component_type="operating-system",
            detected_type="alpine",
        ),
        _scanner_component("busybox", "1.36.1-r29", "alpine", license_expression="MIT"),
    ]
    if profile in {"private-full", "hosted-readonly"}:
        components.extend(
            [
                _scanner_component(".python-rundeps", "20240801.120000", "alpine"),
                _scanner_component("demo-package", "1.0", "python-pkg", license_expression="MIT"),
            ]
        )
    if profile == "private-full":
        components.extend(
            [
                _scanner_component(
                    "/usr/local/bin/mcp-grafana",
                    "",
                    "gobinary",
                    license_expression="Apache-2.0",
                    component_type="application",
                    detected_type="gobinary",
                ),
                _scanner_component(
                    "github.com/grafana/mcp-grafana",
                    "v1.1.0",
                    "gobinary",
                    license_expression="Apache-2.0",
                ),
                _scanner_component("stdlib", "v1.24.0", "gobinary"),
                _scanner_component("example.com/module", "v1.0.0", "gobinary"),
            ]
        )
    references = [value["bom-ref"] for value in components]
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": [{"dependsOn": list(reversed(references)), "ref": "root"}],
        "metadata": {"timestamp": "2026-08-22T00:00:00Z"},
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "specVersion": "1.6",
        "version": 1,
    }


class FinalImageEvidenceTest(unittest.TestCase):
    def test_builds_deterministic_bound_evidence_without_changing_raw_output(self) -> None:
        profiles = {
            "runtime": "private-full",
            "hosted-runtime": "hosted-readonly",
            "web": "public-readonly",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "evidence"
            inputs: list[ImageEvidenceInput] = []
            raw_hashes: dict[str, str] = {}
            for name, profile in profiles.items():
                archive, reference = _write_archive(root, name, profile)
                bundle, _ = _write_bundle(output / "images", name, profile)
                raw = output / "images" / name / "raw-sbom.cdx.json"
                raw.write_bytes(_json_bytes(_raw_sbom(profile)))
                raw_hashes[name] = _digest(raw.read_bytes())
                inputs.append(ImageEvidenceInput(name, archive, bundle, raw, reference))

            self.assertEqual(
                build_final_image_evidence(
                    REPOSITORY_ROOT,
                    output,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    scanner_image=SCANNER,
                    images=tuple(reversed(inputs)),
                ),
                [],
            )

            summary = json.loads((output / "images" / "summary.json").read_text())
            self.assertEqual(summary["status"], "pass")
            for name in profiles:
                image_output = output / "images" / name
                binding = json.loads((image_output / "image-binding.json").read_text())
                coverage = json.loads((image_output / "coverage.json").read_text())
                self.assertEqual(binding["status"], "pass")
                self.assertEqual(binding["candidate"], {"commit": CANDIDATE, "tree": TREE})
                self.assertEqual(binding["reports"]["raw_sbom_sha256"], raw_hashes[name])
                self.assertEqual(
                    _digest((image_output / "raw-sbom.cdx.json").read_bytes()), raw_hashes[name]
                )
                self.assertEqual(coverage["status"], "pass")
                self.assertEqual(coverage["candidate"], {"commit": CANDIDATE, "tree": TREE})
                self.assertEqual(coverage["scanner_image"], SCANNER)
                self.assertEqual(
                    coverage["image"]["platform_manifest_digest"],
                    binding["image"]["platform_manifest_digest"],
                )
                self.assertTrue(coverage["source_inputs"])
            self.assertEqual(
                json.loads((output / "images" / "web" / "coverage.json").read_text())["counts"][
                    "bundle_only"
                ],
                8,
            )
            web_enriched = json.loads(
                (output / "images" / "web" / "enriched-sbom.cdx.json").read_text()
            )
            colortrace = next(
                value for value in web_enriched["components"] if value["name"] == "ColorTrace"
            )
            property_names = {value["name"] for value in colortrace["properties"]}
            self.assertIn("colortrace:bundle-manifest-sha256", property_names)
            self.assertIn("colortrace:notice:sources/LICENSE:sha256", property_names)

    def test_reconciliation_is_order_independent_and_fails_closed_on_mutations(self) -> None:
        profile = "hosted-readonly"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            bundle_path, bundle = _write_bundle(root, "hosted", profile)
            _, bundle_record, bundle_findings = _verify_bundle(
                bundle_path,
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
                profile=profile,
            )
            self.assertEqual(bundle_findings, [])
            raw = _raw_sbom(profile)
            enriched, coverage, findings = _reconcile(raw, bundle, bundle_record, profile)
            self.assertEqual(findings, [])
            self.assertEqual(coverage["status"], "pass")

            reordered = copy.deepcopy(raw)
            reordered["components"].reverse()
            reordered["dependencies"][0]["dependsOn"].reverse()
            other_enriched, other_coverage, other_findings = _reconcile(
                reordered, bundle, bundle_record, profile
            )
            self.assertEqual(other_findings, [])
            self.assertEqual(other_enriched, enriched)
            self.assertEqual(other_coverage, coverage)

            missing = copy.deepcopy(raw)
            missing["components"].pop()
            _, _, findings = _reconcile(missing, bundle, bundle_record, profile)
            self.assertIn("image.coverage.missing", {value.code for value in findings})

            duplicate = copy.deepcopy(raw)
            duplicate["components"].append(copy.deepcopy(duplicate["components"][1]))
            duplicate["components"][-1]["bom-ref"] = "duplicate"
            _, _, findings = _reconcile(duplicate, bundle, bundle_record, profile)
            self.assertIn("image.coverage.duplicate", {value.code for value in findings})

            duplicate_only = copy.deepcopy(bundle)
            first_party = next(
                value for value in duplicate_only["components"] if value["name"] == "ColorTrace"
            )
            repeated = copy.deepcopy(first_party)
            repeated["version"] = "different-version"
            duplicate_only["components"].append(repeated)
            _, _, findings = _reconcile(raw, duplicate_only, bundle_record, profile)
            self.assertIn("image.coverage.duplicate", {value.code for value in findings})

            colliding_ref = copy.deepcopy(raw)
            colliding_ref["components"][0]["bom-ref"] = _bundle_bom_ref(first_party)
            _, _, findings = _reconcile(colliding_ref, bundle, bundle_record, profile)
            self.assertIn("image.coverage.duplicate", {value.code for value in findings})

            version = copy.deepcopy(raw)
            version["components"][-1]["version"] = "2.0"
            _, _, findings = _reconcile(version, bundle, bundle_record, profile)
            self.assertIn("image.coverage.version", {value.code for value in findings})

            conflict_bundle = copy.deepcopy(bundle)
            next(
                value for value in conflict_bundle["components"] if value["name"] == "Demo_Package"
            )["license_expression"] = "MIT OR Apache-2.0"
            conflict = copy.deepcopy(raw)
            conflict["components"][-1]["licenses"] = [{"expression": "MIT AND Apache-2.0"}]
            conflict_enriched, conflict_coverage, findings = _reconcile(
                conflict, conflict_bundle, bundle_record, profile
            )
            self.assertIn("image.coverage.conflict", {value.code for value in findings})
            self.assertEqual(conflict_coverage["conflicts"][0]["status"], "unexplained")
            scanner_component = next(
                value
                for value in conflict_enriched["components"]
                if value["name"] == "demo-package"
            )
            self.assertEqual(scanner_component["licenses"], [{"expression": "MIT AND Apache-2.0"}])

            unknown = copy.deepcopy(raw)
            unknown["components"][-1]["properties"][0]["value"] = "ruby-pkg"
            with self.assertRaisesRegex(EvidenceError, "unknown scanner class") as raised:
                _reconcile(unknown, bundle, bundle_record, profile)
            self.assertEqual(raised.exception.code, "image.coverage.unknown-class")

    def test_bundle_verifier_rejects_stale_duplicate_and_checksum_mutations(self) -> None:
        profile = "hosted-readonly"
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stale, _ = _write_bundle(
                root,
                "stale",
                profile,
                lambda value: value.update(source_commit="e" * 40),
            )
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(stale, candidate_sha=CANDIDATE, candidate_tree=TREE, profile=profile)
            self.assertEqual(raised.exception.code, "image.bundle.stale")

            def duplicate_component(value: dict[str, Any]) -> None:
                value["components"].append(copy.deepcopy(value["components"][0]))

            duplicate, _ = _write_bundle(root, "duplicate", profile, duplicate_component)
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(
                    duplicate, candidate_sha=CANDIDATE, candidate_tree=TREE, profile=profile
                )
            self.assertEqual(raised.exception.code, "image.bundle.duplicate")

            checksum, _ = _write_bundle(root, "checksum", profile)
            (checksum / "sources" / "LICENSE").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(
                    checksum, candidate_sha=CANDIDATE, candidate_tree=TREE, profile=profile
                )
            self.assertEqual(raised.exception.code, "image.bundle.checksum")

            def metadata_is_not_a_license(value: dict[str, Any]) -> None:
                component = next(
                    item for item in value["components"] if item["kind"] == "embedded-python-wheel"
                )
                component["license_sources"] = component["license_sources"][:1]

            metadata_only, _ = _write_bundle(
                root, "metadata-only", profile, metadata_is_not_a_license
            )
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(
                    metadata_only,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    profile=profile,
                )
            self.assertEqual(raised.exception.code, "image.bundle.invalid")

            def missing_apk_license_source(value: dict[str, Any]) -> None:
                component = next(item for item in value["components"] if item["name"] == "busybox")
                component.pop("license_source")

            apk_without_source, _ = _write_bundle(
                root, "apk-without-source", profile, missing_apk_license_source
            )
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(
                    apk_without_source,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    profile=profile,
                )
            self.assertEqual(raised.exception.code, "image.bundle.invalid")

            def missing_metadata_source(value: dict[str, Any]) -> None:
                component = next(
                    item for item in value["components"] if item["name"] == "Demo_Package"
                )
                component["license_sources"] = []

            metadata_without_source, _ = _write_bundle(
                root, "metadata-without-source", profile, missing_metadata_source
            )
            with self.assertRaises(EvidenceError) as raised:
                _verify_bundle(
                    metadata_without_source,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    profile=profile,
                )
            self.assertEqual(raised.exception.code, "image.bundle.invalid")

            def missing_gpl_review(value: dict[str, Any]) -> None:
                component = next(item for item in value["components"] if item["name"] == "busybox")
                component["license_expression"] = "GPL-2.0-only"
                component["owner_legal_status"] = None

            gpl, _ = _write_bundle(root, "gpl", profile, missing_gpl_review)
            _, _, findings = _verify_bundle(
                gpl, candidate_sha=CANDIDATE, candidate_tree=TREE, profile=profile
            )
            self.assertIn("image.bundle.unresolved", {value.code for value in findings})

    def test_archive_verifier_rejects_yarn_and_blob_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            good, reference = _write_archive(root, "good", "public-readonly")
            _, findings = _archive_binding(
                good,
                expected_reference=reference,
                profile="public-readonly",
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
            )
            self.assertEqual(findings, [])

            nested, reference = _write_archive(root, "nested", "public-readonly", nested_index=True)
            binding, findings = _archive_binding(
                nested,
                expected_reference=reference,
                profile="public-readonly",
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
            )
            self.assertEqual(findings, [])
            self.assertNotEqual(binding["image_digest"], binding["platform_manifest_digest"])

            yarn, reference = _write_archive(root, "yarn-path", "public-readonly", yarn_path=True)
            with self.assertRaises(EvidenceError) as raised:
                _archive_binding(
                    yarn,
                    expected_reference=reference,
                    profile="public-readonly",
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                )
            self.assertEqual(raised.exception.code, "image.yarn.present")

            yarn_config, reference = _write_archive(
                root, "yarn-config", "public-readonly", yarn_config=True
            )
            _, findings = _archive_binding(
                yarn_config,
                expected_reference=reference,
                profile="public-readonly",
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
            )
            self.assertIn("image.yarn.present", {value.code for value in findings})

            corrupt, reference = _write_archive(
                root, "corrupt", "public-readonly", corrupt_blob=True
            )
            with self.assertRaises(EvidenceError) as raised:
                _archive_binding(
                    corrupt,
                    expected_reference=reference,
                    profile="public-readonly",
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                )
            self.assertEqual(raised.exception.code, "image.oci.hash")

            missing, reference = _write_archive(
                root, "missing", "public-readonly", missing_layer=True
            )
            with self.assertRaises(EvidenceError) as raised:
                _archive_binding(
                    missing,
                    expected_reference=reference,
                    profile="public-readonly",
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                )
            self.assertIn(raised.exception.code, {"image.archive.invalid", "image.oci.hash"})

            malformed, reference = _write_archive(
                root, "malformed", "public-readonly", malformed_layer=True
            )
            with self.assertRaises(EvidenceError) as raised:
                _archive_binding(
                    malformed,
                    expected_reference=reference,
                    profile="public-readonly",
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                )
            self.assertEqual(raised.exception.code, "image.archive.invalid")


if __name__ == "__main__":
    unittest.main()
