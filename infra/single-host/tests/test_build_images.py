from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[3]
SCRIPT = SOURCE_ROOT / "infra" / "single-host" / "scripts" / "build-images.sh"
BUILD_CONFIG = SOURCE_ROOT / "infra" / "single-host" / "cloudbuild.images.yaml"
RUNTIME_DOCKERFILE = SOURCE_ROOT / "containers/Dockerfile.runtime"
CADDY_DOCKERFILE = SOURCE_ROOT / "containers/Dockerfile.caddy"
OBSERVABILITY_DOCKERFILE = SOURCE_ROOT / "containers/Dockerfile.observability"
DOCKERFILE_FRONTEND = (
    "# syntax=docker/dockerfile:1.7.0@sha256:"
    "dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56"
)
FIXTURE_DIGESTS = (
    SOURCE_ROOT / "packages" / "fixture-generator" / "fixtures" / "canonical-digests.json"
)
FAKE_JQ = Path(__file__).with_name("fake_jq.py")


class BuildImagesTests(unittest.TestCase):
    def test_networked_go_module_resolution_disables_http2_per_command(self) -> None:
        for dockerfile in (
            RUNTIME_DOCKERFILE,
            CADDY_DOCKERFILE,
            OBSERVABILITY_DOCKERFILE,
        ):
            with self.subTest(dockerfile=dockerfile.name):
                contents = dockerfile.read_text(encoding="utf-8")
                self.assertGreater(contents.count("go mod download all"), 0)
                self.assertEqual(
                    contents.count("go mod download all"),
                    contents.count("GODEBUG=http2client=0 go mod download all"),
                )
                self.assertEqual(
                    contents.count("go list -mod=readonly -m all"),
                    contents.count("GODEBUG=http2client=0 go list -mod=readonly -m all"),
                )
                self.assertNotIn("ENV GODEBUG", contents)
                self.assertNotIn("ARG GODEBUG", contents)

        observability = OBSERVABILITY_DOCKERFILE.read_text(encoding="utf-8")
        self.assertEqual(observability.count("go mod tidy"), 1)
        self.assertEqual(
            observability.count("go mod tidy"),
            observability.count("GODEBUG=http2client=0 go mod tidy"),
        )

    def test_checksum_dockerfiles_pin_compatible_frontend(self) -> None:
        checksum_dockerfiles = [
            dockerfile
            for dockerfile in SOURCE_ROOT.glob("containers/Dockerfile*")
            if "ADD --checksum=sha256:" in dockerfile.read_text(encoding="utf-8")
        ]
        self.assertGreater(len(checksum_dockerfiles), 0)
        for dockerfile in checksum_dockerfiles:
            with self.subTest(dockerfile=dockerfile.name):
                contents = dockerfile.read_text(encoding="utf-8")
                self.assertEqual(contents.splitlines()[0], DOCKERFILE_FRONTEND)

    def test_build_config_is_pinned_and_sequential(self) -> None:
        configuration = BUILD_CONFIG.read_text(encoding="utf-8")
        builder = (
            "gcr.io/cloud-builders/docker@sha256:"
            "2e8d40d8e48dc14fab4213d5e532d74f63fd403d9e8d7f6463096a75820286c3"
        )

        self.assertEqual(configuration.count(f"name: {builder}"), 6)
        self.assertEqual(configuration.count("- DOCKER_BUILDKIT=1"), 6)
        self.assertIn("machineType: E2_HIGHCPU_8", configuration)
        self.assertIn("logging: CLOUD_LOGGING_ONLY", configuration)
        self.assertIn("--build-arg=SOURCE_COMMIT=${_SOURCE_COMMIT}", configuration)
        self.assertIn("--build-arg=SOURCE_TREE=${_SOURCE_TREE}", configuration)
        self.assertIn("--build-arg=SOURCE_DATE_EPOCH=${_SOURCE_DATE_EPOCH}", configuration)
        self.assertIn("- runtime\n    name:", configuration)
        self.assertIn("- web\n    name:", configuration)
        self.assertIn("- caddy\n    name:", configuration)
        self.assertIn("- grafana\n    name:", configuration)
        self.assertIn("- loki\n    name:", configuration)
        observability = OBSERVABILITY_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn(
            'org.opencontainers.image.source="https://github.com/OCHOLA-EDDYPHIL/colortrace"',
            observability,
        )

    def _repository(self, temporary: Path) -> tuple[Path, str]:
        repository = temporary / "repository"
        script = repository / "infra" / "single-host" / "scripts" / "build-images.sh"
        config = repository / "infra" / "single-host" / "cloudbuild.images.yaml"
        fixture_digests = (
            repository / "packages" / "fixture-generator" / "fixtures" / "canonical-digests.json"
        )
        script.parent.mkdir(parents=True)
        fixture_digests.parent.mkdir(parents=True)
        shutil.copy2(SCRIPT, script)
        shutil.copy2(BUILD_CONFIG, config)
        shutil.copy2(FIXTURE_DIGESTS, fixture_digests)
        subprocess.run(["git", "init", "--quiet", repository], check=True)
        subprocess.run(
            ["git", "-C", repository, "config", "user.email", "test@example.test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repository, "config", "user.name", "ColorTrace Test"],
            check=True,
        )
        subprocess.run(["git", "-C", repository, "add", "."], check=True)
        subprocess.run(
            ["git", "-C", repository, "commit", "--quiet", "-m", "fixture"],
            check=True,
        )
        commit = subprocess.run(
            ["git", "-C", repository, "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return repository, commit

    def _fake_gcloud(self, temporary: Path, commit: str) -> tuple[Path, Path]:
        binary_directory = temporary / "bin"
        binary_directory.mkdir()
        shutil.copy2(FAKE_JQ, binary_directory / "jq")
        (binary_directory / "jq").chmod(0o755)
        log = temporary / "gcloud.log"
        fake = binary_directory / "gcloud"
        fake.write_text(
            """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

log = pathlib.Path(os.environ["FAKE_GCLOUD_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")

if sys.argv[1:3] == ["builds", "submit"]:
    print("build-123")
    raise SystemExit(0)

if sys.argv[1:3] == ["builds", "describe"]:
    registry = os.environ["FAKE_REGISTRY"]
    commit = os.environ["FAKE_COMMIT"]
    source_tree = os.environ["FAKE_SOURCE_TREE"]
    source_date_epoch = os.environ["FAKE_SOURCE_DATE_EPOCH"]
    source_bucket = os.environ.get(
        "FAKE_SOURCE_BUCKET",
        "colortrace-test-project-ct-singlehost-build-source",
    )
    service_account = os.environ["FAKE_SERVICE_ACCOUNT"]
    substitution_commit = os.environ.get("FAKE_SUBSTITUTION_COMMIT", commit)
    components = ["runtime", "web", "caddy", "grafana", "loki", "tempo"]
    print(json.dumps({
        "id": "build-123",
        "status": "SUCCESS",
        "serviceAccount": service_account,
        "source": {"storageSource": {
            "bucket": source_bucket,
            "object": "source/candidate.tgz",
        }},
        "substitutions": {
            "_REGISTRY": registry,
            "_SOURCE_COMMIT": substitution_commit,
            "_SOURCE_TREE": source_tree,
            "_SOURCE_DATE_EPOCH": source_date_epoch,
        },
        "createTime": "2026-08-23T00:00:00Z",
        "finishTime": "2026-08-23T00:10:00Z",
        "results": {"images": [
            {
                "name": f"{registry}/{component}:{commit}",
                "digest": "sha256:" + str(index + 1) * 64,
            }
            for index, component in enumerate(components)
        ]},
    }))
    raise SystemExit(0)

raise SystemExit(2)
""",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return binary_directory, log

    def _run(
        self,
        repository: Path,
        commit: str,
        binary_directory: Path,
        log: Path,
        output: Path,
        environment_overrides: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        registry_host = "us-central1-docker.pkg.dev"
        repository_head = subprocess.run(
            ["git", "-C", repository, "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source_tree = subprocess.run(
            ["git", "-C", repository, "show", "--no-patch", "--format=%T", repository_head],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source_date_epoch = subprocess.run(
            ["git", "-C", repository, "show", "--no-patch", "--format=%ct", repository_head],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        environment = {
            **os.environ,
            "FAKE_GCLOUD_LOG": str(log),
            "FAKE_REGISTRY": f"{registry_host}/colortrace-test-project/ct-singlehost-images",
            "FAKE_COMMIT": commit,
            "FAKE_SOURCE_TREE": source_tree,
            "FAKE_SOURCE_DATE_EPOCH": source_date_epoch,
            "FAKE_SERVICE_ACCOUNT": (
                "projects/colortrace-test-project/serviceAccounts/"
                "ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com"
            ),
            "PATH": f"{binary_directory}:{os.environ['PATH']}",
        }
        if environment_overrides is not None:
            environment.update(environment_overrides)
        return subprocess.run(
            [
                repository / "infra" / "single-host" / "scripts" / "build-images.sh",
                "colortrace-test-project",
                "us-central1",
                "ct-singlehost",
                commit,
                output,
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )

    def test_clean_head_build_records_exact_digest_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            repository, commit = self._repository(temporary)
            binary_directory, log = self._fake_gcloud(temporary, commit)
            output = temporary / "digests.json"

            completed = self._run(
                repository,
                commit,
                binary_directory,
                log,
                output,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(manifest["schema"], "colortrace-single-host-image-build/v2")
            self.assertEqual(manifest["build"]["id"], "build-123")
            self.assertEqual(manifest["build"]["project"], "colortrace-test-project")
            self.assertEqual(manifest["build"]["region"], "us-central1")
            self.assertRegex(manifest["build"]["config_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(manifest["source"]["commit"], commit)
            self.assertEqual(
                manifest["fixture_manifest_sha256"],
                "sha256:21386db7c4ae2c3119d5532fc75589ddce1e64f7ccdecf61f41415e80f4564a6",
            )
            self.assertEqual(
                set(manifest["images"]),
                {"runtime", "web", "caddy", "grafana", "loki", "tempo"},
            )
            self.assertEqual(
                manifest["images"]["runtime"]["reference"],
                "us-central1-docker.pkg.dev/colortrace-test-project/"
                f"ct-singlehost-images/runtime@sha256:{'1' * 64}",
            )
            self.assertEqual(
                (
                    manifest["images"]["runtime"]["dockerfile"],
                    manifest["images"]["runtime"]["target"],
                ),
                ("containers/Dockerfile.runtime", "runtime"),
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls[0][:2], ["builds", "submit"])
            submitted_snapshot = Path(calls[0][2])
            self.assertNotEqual(submitted_snapshot, repository)
            self.assertFalse(submitted_snapshot.exists())
            self.assertIn(
                str(submitted_snapshot / "infra/single-host/cloudbuild.images.yaml"),
                calls[0],
            )
            self.assertIn(
                "projects/colortrace-test-project/serviceAccounts/"
                "ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com",
                calls[0],
            )
            self.assertIn(
                "gs://colortrace-test-project-ct-singlehost-build-source/source",
                calls[0],
            )
            self.assertEqual(calls[1][:3], ["builds", "describe", "build-123"])

    def test_described_build_identity_must_match_submission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            repository, commit = self._repository(temporary)
            binary_directory, log = self._fake_gcloud(temporary, commit)

            for overrides in (
                {
                    "FAKE_SERVICE_ACCOUNT": (
                        "projects/colortrace-test-project/serviceAccounts/"
                        "different@colortrace-test-project.iam.gserviceaccount.com"
                    )
                },
                {"FAKE_SUBSTITUTION_COMMIT": "0" * 40},
                {"FAKE_SOURCE_BUCKET": "unowned-build-source"},
            ):
                output = temporary / f"mismatch-{len(list(temporary.iterdir()))}.json"
                completed = self._run(
                    repository,
                    commit,
                    binary_directory,
                    log,
                    output,
                    overrides,
                )

                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(output.exists())

    def test_dirty_worktree_is_rejected_before_cloud_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            repository, commit = self._repository(temporary)
            binary_directory, log = self._fake_gcloud(temporary, commit)
            (repository / "dirty.txt").write_text("not committed\n", encoding="utf-8")

            completed = self._run(
                repository,
                commit,
                binary_directory,
                log,
                temporary / "digests.json",
            )

            self.assertEqual(completed.returncode, 66)
            self.assertIn("clean Git worktree", completed.stderr)
            self.assertFalse(log.exists())

    def test_candidate_must_equal_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            repository, commit = self._repository(temporary)
            binary_directory, log = self._fake_gcloud(temporary, commit)

            completed = self._run(
                repository,
                "0" * 40,
                binary_directory,
                log,
                temporary / "digests.json",
            )

            self.assertEqual(completed.returncode, 65)
            self.assertIn("checked-out HEAD", completed.stderr)
            self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
