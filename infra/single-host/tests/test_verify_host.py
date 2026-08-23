from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "verify-host.sh"
FAKE_JQ = Path(__file__).with_name("fake_jq.py")


class VerifyHostTests(unittest.TestCase):
    def test_boundary_mcp_and_restart_receipt_are_verified_without_leaking_password(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            binary_directory = temporary / "bin"
            binary_directory.mkdir()
            shutil.copy2(FAKE_JQ, binary_directory / "jq")
            (binary_directory / "jq").chmod(0o755)
            command_log = temporary / "commands.jsonl"
            output = temporary / "verification.json"

            gcloud = binary_directory / "gcloud"
            gcloud.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["gcloud", *sys.argv[1:]]) + "\\n")
if sys.argv[1:4] == ["compute", "instances", "describe"]:
    print(json.dumps({
        "metadata": {"items": [{
            "key": "colortrace-staging-generation",
            "value": "stage-0001",
        }]},
        "status": "RUNNING",
    }))
    raise SystemExit(0)
if sys.argv[1:3] == ["compute", "ssh"]:
    if "--command" in sys.argv and "docker inspect" in sys.argv[sys.argv.index("--command") + 1]:
        print("1" * 40)
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            gcloud.chmod(0o755)

            curl = binary_directory / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

arguments = sys.argv[1:]
if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["curl", *arguments]) + "\\n")

url = arguments[-1]
authenticated = "--netrc-file" in arguments
if "--write-out" in arguments:
    if not authenticated or "--user" in arguments:
        status = "401"
    elif url.endswith("/v1/session"):
        status = "404"
    elif url.endswith("/reset") and "Origin: https://invalid.example" in arguments:
        status = "403"
    elif url.endswith("/reset"):
        status = "415"
    else:
        status = "200"
        if "--dump-header" in arguments:
            path = pathlib.Path(arguments[arguments.index("--dump-header") + 1])
            path.write_text(
                "HTTP/2 200\\r\\n"
                "Referrer-Policy: no-referrer\\r\\n"
                "X-Content-Type-Options: nosniff\\r\\n"
                "X-Frame-Options: DENY\\r\\n\\r\\n",
                encoding="utf-8",
            )
    print(status, end="")
    raise SystemExit(0)

path = pathlib.Path(arguments[arguments.index("--output") + 1])
path.write_text(json.dumps({
    "schema": "colortrace-demo-receipt/v1",
    "run_id": os.environ["FAKE_RUN_ID"],
    "source_commit": "1" * 40,
    "terminal_at": "2026-08-23T18:00:00Z",
    "receipt_sha256": "sha256:" + "2" * 64,
}), encoding="utf-8")
""",
                encoding="utf-8",
            )
            curl.chmod(0o755)

            timeout = binary_directory / "timeout"
            timeout.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["timeout", *sys.argv[1:]]) + "\\n")
raise SystemExit(124)
""",
                encoding="utf-8",
            )
            timeout.chmod(0o755)

            run_id = f"demo-run-{'a' * 32}"
            password = "CorrectHorse42"
            environment = {
                **os.environ,
                "COLORTRACE_ACCESS_PASSWORD": password,
                "COLORTRACE_RESUME_ATTEMPTS": "1",
                "COLORTRACE_RESUME_DELAY_SECONDS": "0",
                "FAKE_COMMAND_LOG": str(command_log),
                "FAKE_RUN_ID": run_id,
                "PATH": f"{binary_directory}:{os.environ['PATH']}",
            }
            completed = subprocess.run(
                [
                    SCRIPT,
                    "https://203-0-113-42.sslip.io",
                    "colortrace",
                    "colortrace-test-project",
                    "us-central1-a",
                    "ct-singlehost-vm",
                    "stage-0001",
                    run_id,
                    output,
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "colortrace-single-host-verification/v1")
            self.assertEqual(report["run_id"], run_id)
            self.assertTrue(all(value == "pass" for value in report["checks"].values()))
            calls = [json.loads(line) for line in command_log.read_text().splitlines()]
            serialized_calls = json.dumps(calls)
            self.assertNotIn(password, serialized_calls)
            self.assertIn("docker restart colortrace-runtime", serialized_calls)
            self.assertIn("colortrace-grafana-mcp catalog", serialized_calls)
            private_port_calls = [call for call in calls if call[0] == "timeout"]
            self.assertEqual(
                sorted(int(call[-1]) for call in private_port_calls),
                [
                    22,
                    80,
                    3000,
                    3100,
                    3200,
                    4318,
                    8080,
                    8443,
                    9090,
                    13000,
                    13100,
                    13200,
                    19090,
                ],
            )
            mcp_calls = [
                call
                for call in calls
                if call[0] == "gcloud"
                and "--command" in call
                and "colortrace-grafana-mcp catalog" in call[call.index("--command") + 1]
            ]
            self.assertEqual(len(mcp_calls), 1)
            subprocess.run(
                ["bash", "-n", "-c", mcp_calls[0][mcp_calls[0].index("--command") + 1]],
                check=True,
            )
            self.assertEqual(
                sum(call[:2] == ["gcloud", "compute"] for call in calls),
                7,
            )


if __name__ == "__main__":
    unittest.main()
