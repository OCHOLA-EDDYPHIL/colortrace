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
        actual_hard_stop_epoch: int | str | None = 2_000_000_000,
        now: int = 1_800_000_000,
        now_sequence: tuple[int, ...] | None = None,
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
    metadata = [{
        "key": "colortrace-staging-generation",
        "value": os.environ["FAKE_GCLOUD_GENERATION"],
    }]
    if os.environ["FAKE_GCLOUD_HARD_STOP"] != "__missing__":
        metadata.append({
            "key": "colortrace-staging-hard-stop-epoch",
            "value": os.environ["FAKE_GCLOUD_HARD_STOP"],
        })
    print(json.dumps({
        "status": status,
        "metadata": {"items": metadata},
    }))
    raise SystemExit(0)

if sys.argv[1:4] == ["compute", "instances", "start"]:
    raise SystemExit(0)

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
if "colortrace-staging-hard-stop-epoch" in expression:
    for item in document["metadata"]["items"]:
        if item["key"] == "colortrace-staging-hard-stop-epoch":
            print(item["value"])
            raise SystemExit(0)
raise SystemExit(1)
""",
                encoding="utf-8",
            )
            fake_jq.chmod(0o755)
            fake_date = temporary / "date"
            fake_date.write_text(
                """#!/usr/bin/env python3
import os
import pathlib
import sys

if sys.argv[1:] == ["+%s"]:
    counter = pathlib.Path(os.environ["FAKE_DATE_COUNTER"])
    count = int(counter.read_text(encoding="utf-8")) if counter.exists() else 0
    counter.write_text(str(count + 1), encoding="utf-8")
    values = os.environ["FAKE_NOW_SEQUENCE"].split(",")
    print(values[min(count, len(values) - 1)])
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            fake_date.chmod(0o755)
            environment = {
                **os.environ,
                "FAKE_GCLOUD_LOG": str(log),
                "FAKE_GCLOUD_COUNTER": str(counter),
                "FAKE_GCLOUD_STATUS": status,
                "FAKE_GCLOUD_GENERATION": actual_generation,
                "FAKE_GCLOUD_HARD_STOP": (
                    "__missing__" if actual_hard_stop_epoch is None else str(actual_hard_stop_epoch)
                ),
                "FAKE_DATE_COUNTER": str(temporary / "date-count"),
                "FAKE_NOW_SEQUENCE": ",".join(str(value) for value in (now_sequence or (now,))),
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

    def test_matching_stopped_instance_is_started_without_broader_authority(self) -> None:
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
            ],
        )
        self.assertNotIn(["compute", "ssh"], [call[:2] for call in calls])

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

    def test_matching_running_instance_requires_only_inspection(self) -> None:
        completed, calls = self._run(
            status="RUNNING",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [["compute", "instances", "describe"]],
        )

    def test_non_resumable_state_is_rejected(self) -> None:
        completed, calls = self._run(
            status="SUSPENDED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
        )

        self.assertEqual(completed.returncode, 69)
        self.assertIn("not in a resumable state", completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [["compute", "instances", "describe"]],
        )

    def test_expired_hard_stop_does_not_start_instance(self) -> None:
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
            actual_hard_stop_epoch=1_800_000_000,
        )

        self.assertEqual(completed.returncode, 65)
        self.assertIn("hard-stop boundary has been reached", completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [["compute", "instances", "describe"]],
        )

    def test_missing_or_malformed_hard_stop_does_not_start_instance(self) -> None:
        for hard_stop_epoch in (None, "not-an-epoch", "9" * 40):
            with self.subTest(hard_stop_epoch=hard_stop_epoch):
                completed, calls = self._run(
                    status="TERMINATED",
                    actual_generation="stage-0001",
                    expected_generation="stage-0001",
                    actual_hard_stop_epoch=hard_stop_epoch,
                )

                self.assertEqual(completed.returncode, 65)
                self.assertIn("hard-stop boundary is missing or invalid", completed.stderr)
                self.assertEqual(
                    [call[:3] for call in calls],
                    [["compute", "instances", "describe"]],
                )

    def test_legacy_zero_sentinel_preserves_resume_behavior(self) -> None:
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
            actual_hard_stop_epoch=0,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["compute", "instances", "describe"],
                ["compute", "instances", "start"],
                ["compute", "instances", "describe"],
            ],
        )

    def test_cutoff_crossed_immediately_before_start_does_not_start_instance(self) -> None:
        hard_stop_epoch = 1_800_000_000
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
            actual_hard_stop_epoch=hard_stop_epoch,
            now_sequence=(hard_stop_epoch - 1, hard_stop_epoch),
        )

        self.assertEqual(completed.returncode, 65)
        self.assertEqual(
            [call[:3] for call in calls],
            [["compute", "instances", "describe"]],
        )

    def test_cutoff_crossed_while_starting_never_reports_success(self) -> None:
        hard_stop_epoch = 1_800_000_000
        completed, calls = self._run(
            status="TERMINATED",
            actual_generation="stage-0001",
            expected_generation="stage-0001",
            actual_hard_stop_epoch=hard_stop_epoch,
            now_sequence=(hard_stop_epoch - 1, hard_stop_epoch - 1, hard_stop_epoch),
        )

        self.assertEqual(completed.returncode, 65)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ["compute", "instances", "describe"],
                ["compute", "instances", "start"],
                ["compute", "instances", "describe"],
            ],
        )


if __name__ == "__main__":
    unittest.main()
