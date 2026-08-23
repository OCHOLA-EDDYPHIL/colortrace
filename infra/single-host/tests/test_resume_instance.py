from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "resume-instance.sh"


class ResumeInstanceTests(unittest.TestCase):
    def _run(
        self,
        *,
        status: str,
        actual_generation: str,
        expected_generation: str,
        healthy: bool = True,
    ):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            log = temporary / "gcloud.log"
            log.touch()
            counter = temporary / "describe-count"
            fake_gcloud = temporary / "gcloud"
            fake_gcloud.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

log = pathlib.Path(os.environ["FAKE_GCLOUD_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")

if sys.argv[1:4] == ["compute", "instances", "describe"]:
    counter = pathlib.Path(os.environ["FAKE_GCLOUD_COUNTER"])
    count = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
    counter.write_text(str(count + 1), encoding="utf-8")
    status = os.environ["FAKE_GCLOUD_STATUS"] if count == 0 else "RUNNING"
    print(json.dumps({
        "status": status,
        "metadata": {"items": [{
            "key": "colortrace-staging-generation",
            "value": os.environ["FAKE_GCLOUD_GENERATION"],
        }]},
    }))
    raise SystemExit(0)

if sys.argv[1:4] == ["compute", "instances", "start"]:
    raise SystemExit(0)

if sys.argv[1:3] == ["compute", "ssh"]:
    raise SystemExit(0 if os.environ["FAKE_GCLOUD_HEALTHY"] == "true" else 1)

raise SystemExit(2)
""",
                encoding="utf-8",
            )
            fake_gcloud.chmod(0o755)
            fake_jq = temporary / "jq"
            fake_jq.write_text(
                """#!/usr/bin/env python3
import json
import sys

document = json.load(sys.stdin)
expression = sys.argv[-1]
if expression == ".status":
    print(document["status"])
    raise SystemExit(0)
if "colortrace-staging-generation" in expression:
    for item in document["metadata"]["items"]:
        if item["key"] == "colortrace-staging-generation":
            print(item["value"])
            raise SystemExit(0)
raise SystemExit(1)
""",
                encoding="utf-8",
            )
            fake_jq.chmod(0o755)
            environment = {
                **os.environ,
                "FAKE_GCLOUD_LOG": str(log),
                "FAKE_GCLOUD_COUNTER": str(counter),
                "FAKE_GCLOUD_STATUS": status,
                "FAKE_GCLOUD_GENERATION": actual_generation,
                "FAKE_GCLOUD_HEALTHY": "true" if healthy else "false",
                "COLORTRACE_RESUME_ATTEMPTS": "1",
                "COLORTRACE_RESUME_DELAY_SECONDS": "0",
                "PATH": f"{temporary}:{os.environ['PATH']}",
            }
            completed = subprocess.run(
                [
                    str(SCRIPT),
                    "colortrace-test-project",
                    "us-central1-a",
                    "ct-singlehost-vm",
                    expected_generation,
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
            return completed, calls

    def test_matching_stopped_instance_is_started_and_verified(self) -> None:
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["compute", "instances", "describe"],
                ["compute", "instances", "start"],
                ["compute", "instances", "describe"],
                ["compute", "ssh", "ct-singlehost-vm"],
            ],
        )
        ssh_call = calls[-1]
        self.assertIn("--tunnel-through-iap", ssh_call)
        command = ssh_call[ssh_call.index("--command") + 1]
        self.assertIn("/var/lib/colortrace-lifecycle/generation", command)
        self.assertIn("colortrace-auto-stop.timer", command)
        self.assertIn("colortrace-runtime", command)
        self.assertIn("colortrace-web", command)

    def test_generation_mismatch_does_not_start_instance(self) -> None:
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0002",
        )

        self.assertEqual(completed.returncode, 65)
        self.assertEqual(
            [call[:3] for call in calls],
            [["compute", "instances", "describe"]],
        )

    def test_running_instance_is_health_verified(self) -> None:
        completed, calls = self._run(
            status="RUNNING",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["compute", "instances", "describe"],
                ["compute", "ssh", "ct-singlehost-vm"],
            ],
        )

    def test_stale_or_unhealthy_generation_requires_terraform_renewal(self) -> None:
        completed, calls = self._run(
            status="RUNNING",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
            healthy=False,
        )

        self.assertEqual(completed.returncode, 70)
        self.assertIn("new staging_generation", completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["compute", "instances", "describe"],
                ["compute", "ssh", "ct-singlehost-vm"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
