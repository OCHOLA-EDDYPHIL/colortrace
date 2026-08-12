from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.actions import check_actions
from colortrace_repo.binary_assets import check_binary_assets
from colortrace_repo.generated import compare_generated_trees


class RepositoryChecksTest(unittest.TestCase):
    def test_generated_tree_comparison_is_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            expected = root / "expected"
            actual = root / "actual"
            expected.mkdir()
            actual.mkdir()
            (expected / "client.ts").write_bytes(b"export const value = 1;\n")
            (actual / "client.ts").write_bytes(b"export const value = 1;\n")
            self.assertEqual(compare_generated_trees(root, expected, actual), [])

            (actual / "client.ts").write_bytes(b"export const value = 2;\n")
            codes = {finding.code for finding in compare_generated_trees(root, expected, actual)}
            self.assertEqual(codes, {"generated.content"})

    def test_actions_require_full_commit_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "check.yml"
            workflow.write_text(
                "jobs:\n  check:\n    steps:\n      - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.mutable"}
            )
            workflow.write_text(
                "jobs:\n  check:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
                encoding="utf-8",
            )
            self.assertEqual(check_actions(root), [])

    def test_actions_reject_mutable_flow_style_and_quoted_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "check.yml"
            workflow.write_text(
                'jobs: {check: {steps: [{"uses": "actions/checkout@v4"}]}}\n',
                encoding="utf-8",
            )

            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.mutable"}
            )

            workflow.write_text(
                "jobs: {check: {steps: [{'uses': 'actions/checkout@" + "a" * 40 + "'}]}}\n",
                encoding="utf-8",
            )
            self.assertEqual(check_actions(root), [])

    def test_actions_reject_multiline_and_escaped_uses_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            workflow = workflows / "check.yml"
            cases = (
                "jobs:\n  check:\n    steps:\n      - uses:\n          actions/checkout@v4\n",
                'jobs:\n  check:\n    steps:\n      - "u\\u0073es": actions/checkout@v4\n',
                "jobs:\n  check:\n    steps:\n      - ? uses\n        : actions/checkout@v4\n",
                "jobs:\n  check:\n    steps:\n"
                "      - {\n          uses: actions/checkout@v4\n        }\n",
                "jobs:\n  check:\n    steps:\n"
                "      - uses: &mutable\n          actions/checkout@v4\n",
                "checkout: &mutable actions/checkout@v4\n"
                "jobs:\n  check:\n    steps:\n      - uses: *mutable\n",
            )
            for index, source in enumerate(cases):
                with self.subTest(case=index):
                    workflow.write_text(source, encoding="utf-8")
                    self.assertEqual(
                        {finding.code for finding in check_actions(root)},
                        {"action.ref.mutable"},
                    )

    def test_actions_validate_nested_local_actions_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            local_action = root / ".github" / "actions" / "wrapper"
            workflows.mkdir(parents=True)
            local_action.mkdir(parents=True)
            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: ./.github/actions/wrapper\n",
                encoding="utf-8",
            )
            metadata = local_action / "action.yml"
            metadata.write_text(
                "name: wrapper\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.mutable"}
            )

            metadata.write_text(
                "name: wrapper\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@" + "a" * 40 + "\n",
                encoding="utf-8",
            )
            self.assertEqual(check_actions(root), [])

            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: ./.github/actions/missing\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.local.missing"}
            )

            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: ../outside\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.local.escape"}
            )

    def test_referenced_local_action_is_scanned_in_ignored_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            local_action = root / "dist" / "wrapper"
            workflows.mkdir(parents=True)
            local_action.mkdir(parents=True)
            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: ./dist/wrapper\n",
                encoding="utf-8",
            )
            (local_action / "action.yml").write_text(
                "name: wrapper\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )

            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.mutable"}
            )

    def test_self_repository_action_is_scanned_before_remote_ref_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            action_name = "wrapper@" + "a" * 40
            local_action = root / "dist" / action_name
            workflows.mkdir(parents=True)
            local_action.mkdir(parents=True)
            workflow = workflows / "check.yml"
            metadata = local_action / "action.yml"
            metadata.write_text(
                "name: wrapper\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )

            workflow.write_text(
                "jobs:\n  check:\n    steps:\n      - uses: $/dist/" + action_name + "\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.mutable"}
            )

            workflow.write_text(
                "jobs:\n  check:\n    steps:\n      - uses: $/dist/missing\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.local.missing"}
            )

    def test_windows_style_local_action_path_is_rejected_as_nonportable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            action_name = "evil@" + "a" * 40
            local_action = root / "dist" / action_name
            workflows.mkdir(parents=True)
            local_action.mkdir(parents=True)
            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: '.\\dist\\" + action_name + "'\n",
                encoding="utf-8",
            )
            (local_action / "action.yml").write_text(
                "name: wrapper\nruns:\n  using: composite\n  steps:\n"
                "    - uses: actions/checkout@v4\n",
                encoding="utf-8",
            )

            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.ref.invalid"}
            )

    def test_local_docker_action_requires_external_digest_pinned_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            workflows = root / ".github" / "workflows"
            local_action = root / "docker-action"
            workflows.mkdir(parents=True)
            local_action.mkdir()
            (workflows / "check.yml").write_text(
                "jobs:\n  check:\n    steps:\n      - uses: ./docker-action\n",
                encoding="utf-8",
            )
            metadata = local_action / "action.yml"
            metadata.write_text(
                "name: docker wrapper\nruns:\n  using: docker\n  image: docker://alpine:latest\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.docker.image"}
            )

            metadata.write_text(
                "name: docker wrapper\nruns:\n  using: docker\n  image: Dockerfile\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.docker.image"}
            )

            metadata.write_text(
                "name: docker wrapper\nruns:\n  using: Docker\n  image: docker://alpine:latest\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.docker.image"}
            )

            metadata.write_text(
                "name: docker wrapper\nruns:\n  using: docker\n  image: docker://alpine@sha256:"
                + "a" * 64
                + "\n",
                encoding="utf-8",
            )
            self.assertEqual(check_actions(root), [])

            metadata.unlink()
            linked_metadata = root / "metadata.txt"
            linked_metadata.write_text(
                "name: docker wrapper\nruns:\n  using: docker\n  image: docker://alpine:latest\n",
                encoding="utf-8",
            )
            metadata.symlink_to(Path("..") / "metadata.txt")
            self.assertEqual(
                {finding.code for finding in check_actions(root)}, {"action.docker.image"}
            )

    def test_binary_asset_requires_exact_registry_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "policy").mkdir()
            binary = root / "image.bin"
            binary.write_bytes(b"\x89synthetic\x00binary")
            policy_path = root / "policy" / "binary-assets.json"
            policy_path.write_text(
                json.dumps({"schema_version": 1, "assets": []}), encoding="utf-8"
            )
            codes = {finding.code for finding in check_binary_assets(root)}
            self.assertEqual(codes, {"binary.asset.unregistered"})

            policy_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "assets": [
                            {
                                "license": "CC0-1.0",
                                "path": "image.bin",
                                "provenance": "generated synthetic test asset",
                                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(check_binary_assets(root), [])


if __name__ == "__main__":
    unittest.main()
