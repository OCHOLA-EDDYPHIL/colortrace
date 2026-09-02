from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.actions import check_actions
from colortrace_repo.cli import main as cli_main
from colortrace_repo.common import is_canonical_spdx
from colortrace_repo.generated import check_generated_manifest, compare_generated_trees
from yaml import BaseLoader, load  # type: ignore[import-untyped]

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
        "pnpm-lock.yaml",
    )
    for path in paths:
        _copy_file(_REPOSITORY_ROOT / path, root / path)
    shutil.copytree(
        _REPOSITORY_ROOT / "packages/api-client/src/generated",
        root / "packages/api-client/src/generated",
    )


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
    def test_repository_ci_keeps_quality_manual_and_runner_routes_external(self) -> None:
        workflow_source = (_REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        workflow = load(workflow_source, Loader=BaseLoader)

        triggers = workflow["on"]
        self.assertEqual(triggers["push"]["branches"], ["main"])
        self.assertIn("pull_request", triggers)
        dispatch_inputs = triggers["workflow_dispatch"]["inputs"]
        self.assertEqual(
            dispatch_inputs["final_image_evidence"],
            {
                "description": "Build and seal exact final-image evidence",
                "required": "true",
                "type": "boolean",
                "default": "false",
            },
        )
        image_lane = dispatch_inputs["image_lane"]
        self.assertEqual(image_lane["required"], "true")
        self.assertEqual(image_lane["type"], "choice")
        self.assertEqual(image_lane["default"], "secret")
        self.assertEqual(image_lane["options"], ["secret", "docker"])
        self.assertNotIn("image_runner", workflow_source)

        secret_scan = workflow["jobs"]["secret-scan"]
        self.assertNotIn("if", secret_scan)
        self.assertEqual(
            secret_scan["name"],
            "${{ github.event_name == 'workflow_dispatch' && "
            "(inputs.final_image_evidence && format('Final image evidence - {0}', "
            "inputs.image_lane) || 'Manual secret scan') || 'Secret scan' }}",
        )
        self.assertEqual(
            secret_scan["runs-on"],
            "${{ fromJSON(vars.COLORTRACE_RUNNER_ROUTES)"
            "[github.event_name == 'workflow_dispatch' && inputs.final_image_evidence && "
            "format('final-image-{0}', inputs.image_lane) || 'secret-scan'] }}",
        )
        self.assertEqual(
            secret_scan["env"]["SECURITY_REQUIRE_IMAGES"],
            "${{ github.event_name == 'workflow_dispatch' && "
            "inputs.final_image_evidence && 'true' || 'false' }}",
        )
        self.assertEqual(
            secret_scan["env"]["EVIDENCE_ARTIFACT_PREFIX"],
            "${{ github.event_name == 'workflow_dispatch' && "
            "inputs.final_image_evidence && format('final-image-evidence-{0}', "
            "inputs.image_lane) || 'security-evidence' }}",
        )
        self.assertEqual(
            secret_scan["timeout-minutes"],
            "${{ github.event_name == 'workflow_dispatch' && "
            "inputs.final_image_evidence && 120 || 20 }}",
        )
        secret_steps = {step["name"]: step for step in secret_scan["steps"]}
        self.assertEqual(
            secret_steps["Bootstrap secret scanner"]["if"],
            "${{ env.SECURITY_REQUIRE_IMAGES != 'true' }}",
        )
        self.assertEqual(
            secret_steps["Bootstrap secret scanner"]["run"], "make ensure-gitleaks-image"
        )
        self.assertEqual(secret_steps["Scan repository for secrets"]["run"], "make check-secret")
        self.assertEqual(
            secret_steps["Bootstrap security evidence tools"]["if"],
            "${{ env.SECURITY_REQUIRE_IMAGES == 'true' }}",
        )
        self.assertEqual(
            secret_steps["Produce exact-candidate security evidence"]["if"],
            "${{ env.SECURITY_REQUIRE_IMAGES == 'true' }}",
        )
        self.assertEqual(
            secret_steps["Verify exact-candidate image cleanup"]["if"],
            "${{ always() && env.SECURITY_REQUIRE_IMAGES == 'true' }}",
        )
        evidence_upload = secret_steps["Retain private security evidence"]
        self.assertEqual(
            evidence_upload["if"],
            "${{ always() && env.SECURITY_REQUIRE_IMAGES == 'true' }}",
        )
        self.assertEqual(evidence_upload["with"]["if-no-files-found"], "error")
        self.assertEqual(evidence_upload["with"]["include-hidden-files"], "true")
        self.assertEqual(evidence_upload["with"]["retention-days"], "90")

        quality = workflow["jobs"]["quality"]
        self.assertEqual(
            quality["if"],
            "${{ github.event_name == 'workflow_dispatch' && !inputs.final_image_evidence }}",
        )
        self.assertEqual(
            quality["runs-on"],
            "${{ fromJSON(vars.COLORTRACE_RUNNER_ROUTES).quality }}",
        )
        quality_steps = {step["name"]: step for step in quality["steps"]}
        self.assertEqual(quality_steps["Bootstrap quality tools"]["run"], "make bootstrap-quality")
        self.assertEqual(
            quality_steps["Run independent quality shards"]["run"],
            "make --jobs=2 check-fast check-telemetry",
        )

        physical_runner_labels = (
            "self-hosted",
            "Linux",
            "X64",
            "colortrace-secret",
            "colortrace-docker",
        )
        for job in workflow["jobs"].values():
            runs_on = job["runs-on"]
            self.assertIn("fromJSON(vars.COLORTRACE_RUNNER_ROUTES)", runs_on)
            for label in physical_runner_labels:
                self.assertNotIn(label, runs_on)

        makefile = (_REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn('--env "COLORTRACE_RUNNER_ENVIRONMENT=$(RUNNER_ENVIRONMENT)"', makefile)
        self.assertIn('--env "COLORTRACE_RUNNER_NAME=$(RUNNER_NAME)"', makefile)

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

    def test_generated_policy_binds_inputs_outputs_and_does_not_run_commands(self) -> None:
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
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertEqual(check_generated_manifest(root), [])

            document = json.loads(original)
            document["files"] = [{}]
            policy.write_text(json.dumps(document), encoding="utf-8")
            self.assertIn(
                "generated.file.invalid",
                {finding.code for finding in check_generated_manifest(root)},
            )

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

            for location, key in ((("trees", 0), "redistribution_review"),):
                with self.subTest(missing=(location, key)):
                    document = json.loads(original)
                    _at(document, location).pop(key)  # type: ignore[union-attr]
                    policy.write_text(json.dumps(document), encoding="utf-8")
                    self.assertNotEqual(check_generated_manifest(root), [])

        for boundary in ("input", "tree", "output"):
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


if __name__ == "__main__":
    unittest.main()
