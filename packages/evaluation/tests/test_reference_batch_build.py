from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[3]


def test_reference_worker_cloud_build_is_pinned_and_provenance_bound() -> None:
    configuration = (
        REPOSITORY_ROOT / "infra/google-batch/cloudbuild.reference-worker.yaml"
    ).read_text(encoding="utf-8")
    builder = (
        "gcr.io/cloud-builders/docker@sha256:"
        "2e8d40d8e48dc14fab4213d5e532d74f63fd403d9e8d7f6463096a75820286c3"
    )
    git_builder = (
        "gcr.io/cloud-builders/git@sha256:"
        "e22d5e335eb04484c86f5255006c5331d26c1372cb609cb0d8d13b564d4addea"
    )

    assert configuration.count(f"name: {builder}") == 1
    assert configuration.count(f"name: {git_builder}") == 1
    assert 'source_commit="${COMMIT_SHA}"' in configuration
    assert "--work-tree=/workspace" in configuration
    assert "write-tree" in configuration
    assert "rev-parse --verify HEAD^{commit}" in configuration
    assert "rev-parse --verify HEAD^{tree}" in configuration
    assert "status --porcelain --untracked-files=all" in configuration
    assert "/workspace/.colortrace-source-commit" in configuration
    assert "/workspace/.colortrace-source-tree" in configuration
    assert "- DOCKER_BUILDKIT=1" in configuration
    assert "--platform=linux/amd64" in configuration
    assert "--target=reference-worker" in configuration
    assert '--build-arg="SOURCE_COMMIT=$$source_commit"' in configuration
    assert '--build-arg="SOURCE_TREE=$$source_tree"' in configuration
    assert '--build-arg="SOURCE_DATE_EPOCH=${_SOURCE_DATE_EPOCH}"' in configuration
    assert '--tag="${_REGISTRY}/reference-worker:$$source_commit"' in configuration
    assert "${_REGISTRY}/reference-worker:${COMMIT_SHA}" in configuration
    assert "_SOURCE_COMMIT" not in configuration
    assert "_SOURCE_TREE" not in configuration


def test_reference_worker_image_contains_the_batch_entrypoint_and_storage_client() -> None:
    dockerfile = (REPOSITORY_ROOT / "containers/Dockerfile.runtime").read_text(encoding="utf-8")
    build = dockerfile.split(" AS reference-worker-build", maxsplit=1)[1].split(
        "\n\nFROM ", maxsplit=1
    )[0]
    image = dockerfile.split(" AS reference-worker\n", maxsplit=1)[1].split(
        "\n\nFROM ", maxsplit=1
    )[0]

    assert build.count("--extra reference-batch") == 2
    assert "import OpenImageIO, PyOpenColorIO, google.cloud.storage" in build
    assert "colortrace-reference-batch-worker --help" in build
    assert 'ENTRYPOINT ["/opt/colortrace/bin/colortrace-reference-batch-worker"]' in image
    assert "USER 65532:65532" in image
    assert "ENV HOME=/work" in image
    assert "COLORTRACE_REFERENCE_EXECUTION_MODE=google-cloud-batch" in image
    assert "COLORTRACE_SOURCE_REVISION=${SOURCE_COMMIT}" in image
    assert "COLORTRACE_SOURCE_TREE=${SOURCE_TREE}" in image
