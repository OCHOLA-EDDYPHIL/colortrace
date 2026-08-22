from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from colortrace_repo.actions import check_actions
from colortrace_repo.binary_assets import check_binary_assets
from colortrace_repo.cli import main as cli_main
from colortrace_repo.common import is_canonical_spdx
from colortrace_repo.generated import check_generated_manifest, compare_generated_trees

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _copy_generated_policy_fixture(root: Path) -> None:
    paths = (
        "policy/dependency-inventory.json",
        "policy/generated-trees.json",
        "packages/api-client/openapi-ts.config.ts",
        "packages/api-client/package.json",
        "packages/contracts/openapi.json",
        "packages/api/src/colortrace_api/assets/hosted-read-projection-v1.json",
        "pnpm-lock.yaml",
    )
    for path in paths:
        _copy_file(_REPOSITORY_ROOT / path, root / path)
    shutil.copytree(
        _REPOSITORY_ROOT / "packages/api-client/src/generated",
        root / "packages/api-client/src/generated",
    )


def _copy_binary_policy_fixture(root: Path) -> Path:
    policy = root / "policy/binary-assets.json"
    _copy_file(_REPOSITORY_ROOT / "policy/binary-assets.json", policy)
    shutil.copytree(_REPOSITORY_ROOT / "packages/web/evidence", root / "packages/web/evidence")
    document = json.loads(policy.read_text(encoding="utf-8"))
    candidate = next(iter(document["capture_profiles"].values()))["candidate"]
    candidate["commit"] = "b" * 40
    candidate["tree"] = "a" * 40
    for item in document["capture_inputs"].values():
        if item["role"] == "font":
            continue
        item["sha256"] = hashlib.sha256(item["path"].encode()).hexdigest()
    policy.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return policy


def _fake_git_bytes(_root: Path, specification: str) -> bytes | None:
    if specification.endswith("^{tree}"):
        return b"a" * 40 + b"\n"
    _, separator, path = specification.partition(":")
    return path.encode() if separator else None


def _at(document: object, path: tuple[str | int, ...]) -> object:
    current = document
    for key in path:
        current = current[key]  # type: ignore[index]
    return current


def _set(document: object, path: tuple[str | int, ...], value: object) -> None:
    target = _at(document, path[:-1])
    target[path[-1]] = value  # type: ignore[index]


def _cli_findings(root: Path, command: str, option: str, value: str) -> list[dict[str, str]]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        result = cli_main(["--root", str(root), "--format", "json", command, option, value])
    if result != 1:
        raise AssertionError(f"expected policy rejection, got exit code {result}")
    return json.loads(output.getvalue())["findings"]


class RepositoryChecksTest(unittest.TestCase):
    def test_spdx_licenses_must_be_known_and_canonical(self) -> None:
        for value in ("Apache-2.0", "MIT", "Apache-2.0 OR MIT"):
            self.assertTrue(is_canonical_spdx(value))
        for value in (None, "", "apache-2.0", "MadeUp-1.0"):
            self.assertFalse(is_canonical_spdx(value))

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

    def test_generated_policy_binds_inputs_outputs_fixture_and_does_not_run_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _copy_generated_policy_fixture(root)
            policy = root / "policy" / "generated-trees.json"
            original = policy.read_text(encoding="utf-8")
            self.assertEqual(check_generated_manifest(root), [])

            cases = (
                (("trees", 0, "inputs", 0, "sha256"), "0" * 64, "generated.input.mismatch"),
                (("trees", 0, "outputs", 0, "sha256"), "0" * 64, "generated.output.mismatch"),
                (("trees", 0, "license"), "apache-2.0", "generated.license.invalid"),
                (("files", 0, "provenance_pointer"), "#/missing", "generated.provenance.invalid"),
                (("files", 0, "sha256"), "0" * 64, "generated.file.mismatch"),
            )
            for path, value, code in cases:
                with self.subTest(binding=code):
                    document = json.loads(original)
                    _set(document, path, value)
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertIn(
                        code, {finding.code for finding in check_generated_manifest(root)}
                    )

            document = json.loads(original)
            document["trees"][0]["outputs"][:2] = reversed(document["trees"][0]["outputs"][:2])
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "generated.outputs.invalid",
                {finding.code for finding in check_generated_manifest(root)},
            )

            for state in ("owner-approved", "owner-review-required", "prohibited"):
                with self.subTest(review=state):
                    document = json.loads(original)
                    document["trees"][0]["redistribution_review"] = state
                    document["files"][0]["redistribution_review"] = state
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertEqual(check_generated_manifest(root), [])

            document = json.loads(original)
            sentinel = root / "policy-command-executed"
            document["trees"][0]["generation_command"] = f"touch {sentinel}"
            policy.write_text(json.dumps(document), encoding="utf-8")
            codes = {finding.code for finding in check_generated_manifest(root)}
            self.assertIn("generated.command.invalid", codes)
            self.assertFalse(sentinel.exists())

    def test_generated_policy_rejects_unknown_keys_and_symlink_boundaries(self) -> None:
        locations = (
            (),
            ("trees", 0),
            ("trees", 0, "generator"),
            ("trees", 0, "inputs", 0),
            ("trees", 0, "outputs", 0),
            ("files", 0),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _copy_generated_policy_fixture(root)
            policy = root / "policy" / "generated-trees.json"
            original = policy.read_text(encoding="utf-8")
            for location in locations:
                with self.subTest(schema=location):
                    document = json.loads(original)
                    _set(document, location + ("unexpected",), True)
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertNotEqual(check_generated_manifest(root), [])

            for location, key in (
                (("trees", 0), "redistribution_review"),
                (("files", 0), "license"),
            ):
                with self.subTest(missing=(location, key)):
                    document = json.loads(original)
                    _at(document, location).pop(key)  # type: ignore[union-attr]
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertNotEqual(check_generated_manifest(root), [])

        for boundary in ("input", "fixture", "tree", "output"):
            with (
                self.subTest(boundary=boundary),
                tempfile.TemporaryDirectory() as temporary_directory,
            ):
                root = Path(temporary_directory)
                _copy_generated_policy_fixture(root)
                outside = root / "outside"
                outside.write_bytes(b"outside")
                target = (
                    root
                    / {
                        "input": "packages/contracts/openapi.json",
                        "fixture": (
                            "packages/api/src/colortrace_api/assets/hosted-read-projection-v1.json"
                        ),
                        "tree": "packages/api-client/src/generated",
                        "output": "packages/api-client/src/generated/client.gen.ts",
                    }[boundary]
                )
                if boundary == "tree":
                    outside.unlink()
                    outside.mkdir()
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                target.symlink_to(outside, target_is_directory=outside.is_dir())
                codes = {finding.code for finding in check_generated_manifest(root)}
                self.assertTrue(
                    any(code.endswith(("path", "invalid", "symlink")) for code in codes)
                )

    def test_generated_policy_path_never_escapes_or_follows_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repository"
            _copy_generated_policy_fixture(root)
            policy = root / "policy/generated-trees.json"
            inside = root / "policy/generated-source.json"
            outside = base / "outside-generated.json"
            inside.write_bytes(policy.read_bytes())
            outside.write_bytes(policy.read_bytes())

            policy.unlink()
            policy.symlink_to(inside)
            findings = check_generated_manifest(root)
            self.assertEqual(
                [(finding.code, finding.path) for finding in findings],
                [("generated.policy.path", "policy/generated-trees.json")],
            )

            policy.unlink()
            shutil.copy2(inside, policy)
            escape = "../outside-generated.json"
            findings = _cli_findings(root, "generated", "--manifest", escape)
            self.assertEqual(
                [(finding["code"], finding["path"]) for finding in findings],
                [("generated.policy.path", escape)],
            )

            linked = root / "policy/custom-generated.json"
            linked.symlink_to(policy)
            findings = _cli_findings(
                root, "generated", "--manifest", "policy/custom-generated.json"
            )
            self.assertEqual(
                [(finding["code"], finding["path"]) for finding in findings],
                [("generated.policy.path", "policy/custom-generated.json")],
            )

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

    @mock.patch("colortrace_repo.binary_assets._git_bytes", side_effect=_fake_git_bytes)
    def test_binary_asset_requires_exact_registry_entry(self, _history: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            policy = _copy_binary_policy_fixture(root)
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["assets"].pop(0)
            policy.write_text(json.dumps(document), encoding="utf-8")
            codes = {finding.code for finding in check_binary_assets(root)}
            self.assertEqual(codes, {"binary.asset.unregistered", "binary.capture.outputs"})

    @mock.patch("colortrace_repo.binary_assets._git_bytes", side_effect=_fake_git_bytes)
    def test_binary_policy_enforces_exact_schema_license_and_review(
        self, _history: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            policy = _copy_binary_policy_fixture(root)
            original = policy.read_text(encoding="utf-8")
            self.assertEqual(check_binary_assets(root), [])

            locations = (
                (),
                ("assets", 0),
                ("capture_environments", "playwright-1.62.1-noble-dcc5531e"),
                (
                    "capture_environments",
                    "playwright-1.62.1-noble-dcc5531e",
                    "browser",
                ),
                ("capture_inputs", "test-workspace"),
                ("capture_profiles", "source-095792f"),
                ("capture_profiles", "source-095792f", "candidate"),
                ("capture_profiles", "source-095792f", "invocations", 0),
                (
                    "capture_profiles",
                    "source-095792f",
                    "invocations",
                    0,
                    "expected_result",
                ),
            )
            for location in locations:
                with self.subTest(location=location):
                    document = json.loads(original)
                    _set(document, location + ("unexpected",), True)
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertNotEqual(check_binary_assets(root), [])

            document = json.loads(original)
            document["assets"][0]["license"] = "MadeUp-1.0"
            document["assets"][0]["redistribution_review"] = "maybe"
            policy.write_text(json.dumps(document), encoding="utf-8")
            codes = {finding.code for finding in check_binary_assets(root)}
            self.assertTrue({"binary.license.invalid", "binary.redistribution.invalid"} <= codes)

            for key in ("license", "redistribution_review"):
                with self.subTest(missing=key):
                    document = json.loads(original)
                    document["assets"][0].pop(key)
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertIn(
                        "binary.policy.entry",
                        {finding.code for finding in check_binary_assets(root)},
                    )

            for state in ("owner-approved", "owner-review-required", "prohibited"):
                with self.subTest(review=state):
                    document = json.loads(original)
                    document["assets"][0]["redistribution_review"] = state
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertEqual(check_binary_assets(root), [])

    @mock.patch("colortrace_repo.binary_assets._git_bytes", side_effect=_fake_git_bytes)
    def test_binary_policy_enforces_screenshot_capture_bindings(self, _history: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            policy = _copy_binary_policy_fixture(root)
            original = policy.read_text(encoding="utf-8")

            mutations = (
                (
                    ("capture_profiles", "source-095792f", "candidate", "commit"),
                    "a" * 39,
                    "binary.capture.candidate",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "browser",
                        "sha256",
                    ),
                    "a" * 63,
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "fonts",
                        "selected_inputs",
                    ),
                    ["missing-font"],
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "image",
                    ),
                    "mcr.microsoft.com/playwright:latest",
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "image",
                    ),
                    "@sha256:" + "a" * 64,
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "image",
                    ),
                    "image@@sha256:" + "a" * 64,
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "image",
                    ),
                    "example.invalid/image@sha256:" + "a" * 64 + "-suffix",
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "image",
                    ),
                    "example.invalid/image@sha256:" + "A" * 64,
                    "binary.capture.environment",
                ),
                (
                    ("capture_profiles", "source-095792f", "reproducibility"),
                    "point-in-time-only",
                    "binary.capture.reproducibility",
                ),
                (
                    ("capture_profiles", "source-095792f", "invocations", 0, "command"),
                    "",
                    "binary.capture.reproducibility",
                ),
                (
                    (
                        "capture_profiles",
                        "source-095792f",
                        "invocations",
                        0,
                        "environment_variables",
                    ),
                    ["CI=true", "CI=true"],
                    "binary.capture.reproducibility",
                ),
                (
                    (
                        "capture_profiles",
                        "source-095792f",
                        "invocations",
                        0,
                        "environment_variables",
                    ),
                    ["=missing-key"],
                    "binary.capture.reproducibility",
                ),
                (
                    (
                        "capture_profiles",
                        "source-095792f",
                        "invocations",
                        0,
                        "environment_variables",
                    ),
                    ["CI=true", "CI=false"],
                    "binary.capture.reproducibility",
                ),
                (
                    (
                        "capture_profiles",
                        "source-095792f",
                        "invocations",
                        0,
                        "expected_result",
                        "exit_code",
                    ),
                    0,
                    "binary.capture.reproducibility",
                ),
                (
                    ("capture_inputs", "test-workspace", "sha256"),
                    "0" * 63,
                    "binary.capture.input",
                ),
                (
                    ("assets", 0, "capture_profile"),
                    "missing-profile",
                    "binary.capture.reference",
                ),
                (
                    ("assets", 0, "viewport"),
                    "1439x900",
                    "binary.capture.viewport",
                ),
                (
                    (
                        "capture_environments",
                        "playwright-1.62.1-noble-dcc5531e",
                        "render_environment",
                        "network",
                    ),
                    "default",
                    "binary.capture.environment",
                ),
                (
                    (
                        "capture_profiles",
                        "source-095792f",
                        "invocations",
                        0,
                        "capture_outputs",
                        0,
                        "capture_output",
                    ),
                    "path",
                    "binary.capture.outputs",
                ),
            )
            for path, value, code in mutations:
                with self.subTest(code=code):
                    document = json.loads(original)
                    _set(document, path, value)
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertIn(code, {finding.code for finding in check_binary_assets(root)})

            document = json.loads(original)
            profile = document["capture_profiles"]["source-095792f"]
            profile["inputs"] = [
                item
                for item in profile["inputs"]
                if document["capture_inputs"][item]["role"] != "fixture"
            ]
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "binary.capture.inputs",
                {finding.code for finding in check_binary_assets(root)},
            )

            document = json.loads(original)
            document["capture_profiles"]["unused-profile"] = document["capture_profiles"][
                "source-095792f"
            ]
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "binary.capture.unused",
                {finding.code for finding in check_binary_assets(root)},
            )

            document = json.loads(original)
            document["capture_inputs"]["test-workspace"]["sha256"] = "0" * 64
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "binary.capture.input.mismatch",
                {finding.code for finding in check_binary_assets(root)},
            )

            document = json.loads(original)
            document["capture_profiles"]["source-095792f"]["candidate"]["tree"] = "c" * 40
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "binary.capture.candidate",
                {finding.code for finding in check_binary_assets(root)},
            )

            document = json.loads(original)
            document["capture_inputs"]["unused-input"] = document["capture_inputs"]["fixture-api"]
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "binary.capture.input.unused",
                {finding.code for finding in check_binary_assets(root)},
            )

            _history.side_effect = lambda *_arguments: None
            policy.write_text(original, encoding="utf-8")
            self.assertTrue(
                {"binary.capture.candidate", "binary.capture.input.mismatch"}
                <= {finding.code for finding in check_binary_assets(root)}
            )

    @mock.patch("colortrace_repo.binary_assets._git_bytes", side_effect=_fake_git_bytes)
    def test_binary_policy_rejects_symlink_assets(self, _history: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            policy = _copy_binary_policy_fixture(root)
            document = json.loads(policy.read_text(encoding="utf-8"))
            image = root / document["assets"][0]["path"]
            outside = root / "outside.png"
            outside.write_bytes(image.read_bytes())
            image.unlink()
            image.symlink_to(outside)
            codes = {finding.code for finding in check_binary_assets(root)}
            self.assertIn("binary.policy.path", codes)
            self.assertIn("binary.asset.symlink", codes)

    @mock.patch("colortrace_repo.binary_assets._git_bytes", side_effect=_fake_git_bytes)
    def test_binary_policy_path_never_escapes_or_follows_symlinks(
        self, _history: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repository"
            policy = _copy_binary_policy_fixture(root)
            inside = root / "policy/binary-source.json"
            outside = base / "outside-binary.json"
            inside.write_bytes(policy.read_bytes())
            outside.write_bytes(policy.read_bytes())

            policy.unlink()
            policy.symlink_to(inside)
            findings = check_binary_assets(root)
            self.assertEqual(
                [(finding.code, finding.path) for finding in findings],
                [("binary.policy.path", "policy/binary-assets.json")],
            )

            policy.unlink()
            shutil.copy2(inside, policy)
            escape = "../outside-binary.json"
            findings = _cli_findings(root, "binary-assets", "--policy", escape)
            self.assertEqual(
                [(finding["code"], finding["path"]) for finding in findings],
                [("binary.policy.path", escape)],
            )

            linked = root / "policy/custom-binary.json"
            linked.symlink_to(policy)
            findings = _cli_findings(root, "binary-assets", "--policy", "policy/custom-binary.json")
            self.assertEqual(
                [(finding["code"], finding["path"]) for finding in findings],
                [("binary.policy.path", "policy/custom-binary.json")],
            )


if __name__ == "__main__":
    unittest.main()
