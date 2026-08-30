from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify-image-security.sh"
FAKE_JQ = Path(__file__).with_name("fake_jq.py")
ROOT = Path(__file__).parents[3]


class VerifyImageSecurityTests(unittest.TestCase):
    def test_exact_manifest_is_scanned_with_current_and_frozen_databases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            binary_directory = temporary / "bin"
            binary_directory.mkdir()
            shutil.copy2(FAKE_JQ, binary_directory / "jq")
            (binary_directory / "jq").chmod(0o755)
            command_log = temporary / "docker.jsonl"
            socket = temporary / "docker.sock"
            socket.touch()
            manifest = temporary / "digests.json"
            current_cache = temporary / "current"
            frozen_cache = temporary / "frozen"
            output = temporary / "reports"
            for cache, updated_at in (
                (current_cache, "2026-08-23T12:00:00Z"),
                (frozen_cache, "2026-08-22T12:57:22.518776499Z"),
            ):
                (cache / "db").mkdir(parents=True)
                (cache / "db" / "trivy.db").write_bytes(b"fixture-database")
                (cache / "db" / "metadata.json").write_text(
                    json.dumps(
                        {
                            "Version": 2,
                            "NextUpdate": (
                                "2026-08-23T12:57:22.518775968Z"
                                if cache == frozen_cache
                                else "2026-08-24T12:00:00Z"
                            ),
                            "UpdatedAt": updated_at,
                            "DownloadedAt": "2026-08-23T12:10:00Z",
                        }
                    ),
                    encoding="utf-8",
                )

            commit = "1" * 40
            registry = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
            components = ["runtime", "web", "caddy", "grafana", "loki", "tempo"]
            images = {}
            build_paths = {
                "runtime": ("containers/Dockerfile.runtime", "runtime"),
                "web": ("containers/Dockerfile.web", None),
                "caddy": ("containers/Dockerfile.caddy", None),
                "grafana": ("containers/Dockerfile.observability", "grafana"),
                "loki": ("containers/Dockerfile.observability", "loki"),
                "tempo": ("containers/Dockerfile.observability", "tempo"),
            }
            for index, component in enumerate(components, 1):
                digest = f"sha256:{str(index) * 64}"
                images[component] = {
                    "dockerfile": build_paths[component][0],
                    "target": build_paths[component][1],
                    "tag": f"{registry}/{component}:{commit}",
                    "digest": digest,
                    "reference": f"{registry}/{component}@{digest}",
                }
            build_config = ROOT / "infra/single-host/cloudbuild.images.yaml"
            fixture_digests = json.loads(
                (ROOT / "packages/fixture-generator/fixtures/canonical-digests.json").read_text(
                    encoding="utf-8"
                )
            )
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "colortrace-single-host-image-build/v2",
                        "build": {
                            "id": "build-123",
                            "project": "colortrace-test-project",
                            "region": "us-central1",
                            "service_account": (
                                "projects/colortrace-test-project/serviceAccounts/"
                                "ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com"
                            ),
                            "registry": registry,
                            "config_sha256": (
                                "sha256:" + hashlib.sha256(build_config.read_bytes()).hexdigest()
                            ),
                            "create_time": "2026-08-23T12:00:00Z",
                            "finish_time": "2026-08-23T12:10:00Z",
                        },
                        "source": {
                            "commit": commit,
                            "tree": "a" * 40,
                            "date_epoch": 1787486400,
                        },
                        "fixture_manifest_sha256": (
                            "sha256:"
                            + fixture_digests["files"][
                                "runtime/manifests/fixture-runtime-manifest.json"
                            ]
                        ),
                        "images": images,
                    }
                ),
                encoding="utf-8",
            )

            docker = binary_directory / "docker"
            docker.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

arguments = sys.argv[1:]
log = pathlib.Path(os.environ["FAKE_DOCKER_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(arguments) + "\\n")
if arguments[:2] == ["image", "inspect"] or arguments[:1] == ["pull"]:
    raise SystemExit(0)
if arguments[:1] != ["run"]:
    raise SystemExit(2)
if "version" in arguments and "--format" in arguments:
    print(json.dumps({"Version": "0.69.3", "VulnerabilityDB": {"Version": 2}}))
    raise SystemExit(0)
if "--download-db-only" in arguments:
    raise SystemExit(0)
if "--output" in arguments:
    container_output = arguments[arguments.index("--output") + 1]
    report_mount = next(
        value for index, value in enumerate(arguments)
        if arguments[index - 1] == "--volume" and value.endswith(":/reports")
    )
    host_output = pathlib.Path(report_mount.removesuffix(":/reports"))
    report = host_output / pathlib.PurePosixPath(container_output).name
    report.write_text(json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": arguments[-1],
        "Results": [],
    }), encoding="utf-8")
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            docker.chmod(0o755)

            sha256sum = binary_directory / "sha256sum"
            sha256sum.write_text(
                """#!/usr/bin/env python3
import hashlib
import os
import pathlib
import sys

if "--check" in sys.argv[1:]:
    sys.stdin.read()
    state = pathlib.Path(os.environ["FAKE_SHA_CHECK_STATE"])
    count = int(state.read_text()) + 1 if state.exists() else 1
    state.write_text(str(count))
    if os.environ.get("FAKE_FAIL_SECOND_FROZEN_CHECK") == "true" and count == 2:
        raise SystemExit(1)
    raise SystemExit(0)
for value in sys.argv[1:]:
    path = pathlib.Path(value)
    print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {value}")
""",
                encoding="utf-8",
            )
            sha256sum.chmod(0o755)

            environment = {
                **os.environ,
                "COLORTRACE_DOCKER_SOCKET": str(socket),
                "FAKE_DOCKER_LOG": str(command_log),
                "FAKE_SHA_CHECK_STATE": str(temporary / "sha-check-state"),
                "PATH": f"{binary_directory}:{os.environ['PATH']}",
            }
            completed = subprocess.run(
                [SCRIPT, manifest, current_cache, frozen_cache, output],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            bindings = json.loads((output / "scan-bindings.json").read_text())
            self.assertEqual(bindings["schema"], "colortrace-single-host-image-scan/v2")
            self.assertEqual(bindings["result"], "pass")
            self.assertFalse(bindings["vulnerability_ignores"])
            self.assertEqual(set(bindings["images"]), {*components, "prometheus"})
            self.assertEqual(len(bindings["reports"]), 14)
            calls = [json.loads(line) for line in command_log.read_text().splitlines()]
            scan_calls = [call for call in calls if "--output" in call]
            self.assertEqual(len(scan_calls), 14)
            for call in scan_calls:
                self.assertIn("--network", call)
                self.assertIn("none", call)
                self.assertIn("--offline-scan", call)
                self.assertIn("--parallel", call)
                self.assertIn("--severity", call)
                self.assertIn("HIGH,CRITICAL", call)
                self.assertNotIn("--ignorefile", call)
            checksum_lines = (output / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(len(checksum_lines), 18)
            self.assertTrue(any(line.endswith("  current-caddy.json") for line in checksum_lines))
            self.assertTrue(
                any(line.endswith("  frozen-prometheus.json") for line in checksum_lines)
            )

            (temporary / "sha-check-state").unlink()
            tampered_output = temporary / "tampered-reports"
            tampered_environment = {
                **environment,
                "FAKE_FAIL_SECOND_FROZEN_CHECK": "true",
            }
            tampered = subprocess.run(
                [SCRIPT, manifest, current_cache, frozen_cache, tampered_output],
                check=False,
                capture_output=True,
                env=tampered_environment,
                text=True,
            )
            self.assertNotEqual(tampered.returncode, 0)
            self.assertFalse((tampered_output / "scan-bindings.json").exists())


if __name__ == "__main__":
    unittest.main()
