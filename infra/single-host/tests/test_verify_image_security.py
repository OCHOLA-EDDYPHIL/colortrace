from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify-image-security.sh"
FAKE_JQ = Path(__file__).with_name("fake_jq.py")


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
                    json.dumps({"Version": 2, "UpdatedAt": updated_at}),
                    encoding="utf-8",
                )

            commit = "1" * 40
            registry = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
            components = ["runtime", "web", "caddy", "grafana", "loki", "tempo"]
            images = {}
            for index, component in enumerate(components, 1):
                digest = f"sha256:{str(index) * 64}"
                images[component] = {
                    "tag": f"{registry}/{component}:{commit}",
                    "digest": digest,
                    "reference": f"{registry}/{component}@{digest}",
                }
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "source": {"commit": commit, "tree": "a" * 40},
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
import pathlib
import sys

if "--check" in sys.argv[1:]:
    sys.stdin.read()
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
            self.assertEqual(bindings["result"], "pass")
            self.assertFalse(bindings["vulnerability_ignores"])
            self.assertEqual(set(bindings["images"]), {*components, "prometheus"})
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


if __name__ == "__main__":
    unittest.main()
