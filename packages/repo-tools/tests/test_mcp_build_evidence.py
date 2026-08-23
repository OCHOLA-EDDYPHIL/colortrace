from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from colortrace_repo.mcp_build_evidence import build_mcp_reproducibility_evidence

CANDIDATE = "a" * 40
TREE = "b" * 40


class McpBuildEvidenceTest(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        binary = b"deterministic mcp-grafana fixture"
        first = root / "first"
        second = root / "second"
        first.write_bytes(binary)
        second.write_bytes(binary)
        lock_path = root / "config" / "grafana-mcp" / "mcp-grafana.lock.json"
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text(
            json.dumps(
                {
                    "binary_sha256": hashlib.sha256(binary).hexdigest(),
                    "schema": "mcp-grafana-runtime-lock/v2",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return first, second, root / "evidence.json"

    def _binding(self, suffix: str = "c") -> dict[str, object]:
        return {
            "archive_sha256": "sha256:" + suffix * 64,
            "config_digest": "sha256:" + suffix * 64,
            "history_sha256": "sha256:" + suffix * 64,
            "layer_digests": ["sha256:" + suffix * 64],
            "layer_diff_ids": ["sha256:" + suffix * 64],
            "platform_manifest_digest": "sha256:" + suffix * 64,
        }

    def test_two_identical_builds_produce_passing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first, second, output = self._fixture(root)

            with mock.patch(
                "colortrace_repo.mcp_build_evidence._archive_binding",
                side_effect=[
                    (self._binding("a"), []),
                    (
                        {
                            **self._binding("a"),
                            "archive_sha256": "sha256:" + "b" * 64,
                        },
                        [],
                    ),
                ],
            ):
                findings = build_mcp_reproducibility_evidence(
                    root,
                    output,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    first_binary=first,
                    second_binary=second,
                    first_archive=root / "first.tar",
                    second_archive=root / "second.tar",
                    first_reference="runtime:first",
                    second_reference="runtime:second",
                )

            self.assertEqual(findings, [])
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["method"], "two-buildx-no-cache-builds")
            self.assertEqual([build["ordinal"] for build in report["builds"]], [1, 2])
            self.assertEqual(
                len({build["binary_sha256"] for build in report["builds"]}),
                1,
            )
            self.assertEqual(
                len({build["image_identity"] for build in report["builds"]}),
                1,
            )

    def test_binary_or_image_difference_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first, second, output = self._fixture(root)
            second.write_bytes(b"different")

            with mock.patch(
                "colortrace_repo.mcp_build_evidence._archive_binding",
                side_effect=[(self._binding("c"), []), (self._binding("d"), [])],
            ):
                findings = build_mcp_reproducibility_evidence(
                    root,
                    output,
                    candidate_sha=CANDIDATE,
                    candidate_tree=TREE,
                    first_binary=first,
                    second_binary=second,
                    first_archive=root / "first.tar",
                    second_archive=root / "second.tar",
                    first_reference="runtime:first",
                    second_reference="runtime:second",
                )

            self.assertEqual(
                {finding.code for finding in findings},
                {"mcp.reproducibility.binary", "mcp.reproducibility.image"},
            )
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "fail")


if __name__ == "__main__":
    unittest.main()
