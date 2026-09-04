from __future__ import annotations

import json
from pathlib import Path

import pytest
from colortrace_api.reference_visuals import (
    REFERENCE_PREVIEW_MANIFEST_PATH,
    REFERENCE_PREVIEW_ROOT,
    ReferencePreviewError,
    load_reference_preview_catalog,
)
from colortrace_fixture import load_reference_media_manifest


def _catalog():
    manifest = load_reference_media_manifest()
    return load_reference_preview_catalog(
        expected_reference_manifest_sha256=manifest.manifest_sha256
    )


def test_reference_previews_are_worker_bound_open_film_pixels() -> None:
    catalog = _catalog()

    assert set(catalog.scenarios) == {
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    }
    for scenario_id, visuals in catalog.scenarios.items():
        assert set(visuals) == {"expected", "observed", "recovered", "diff"}
        assert visuals["expected"].content.startswith(b"\x89PNG\r\n\x1a\n")
        assert visuals["expected"].pixel_evidence is True
        assert visuals["expected"].sha256 == visuals["recovered"].sha256
        assert (
            visuals["expected"].source_canonical_pixel_sha256
            == visuals["recovered"].source_canonical_pixel_sha256
        )
        assert (
            visuals["expected"].source_canonical_pixel_sha256
            != visuals["observed"].source_canonical_pixel_sha256
        )
        assert visuals["diff"].source_relation == "amplified-absolute-display-difference-8x"
        assert visuals["diff"].representation == "open-film-difference-png/v1"
        descriptor = visuals["observed"].descriptor(scenario_id=scenario_id)
        assert descriptor["content_sha256"] == visuals["observed"].sha256
        assert descriptor["pixel_evidence"] is True

    cache = catalog.scenarios["tos-stale-derivative-cache-v1"]
    assert cache["observed"].source_relation == "stale-parent"
    assert cache["observed"].source_artifact_ids != (cache["observed"].served_artifact_id,)


def test_reference_preview_manifest_digest_tampering_fails_closed(tmp_path: Path) -> None:
    document = json.loads(REFERENCE_PREVIEW_MANIFEST_PATH.read_text(encoding="utf-8"))
    document["generator"]["difference_scale"] = 9
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReferencePreviewError, match="manifest-digest-mismatch"):
        load_reference_preview_catalog(
            expected_reference_manifest_sha256=load_reference_media_manifest().manifest_sha256,
            manifest_path=path,
            asset_root=REFERENCE_PREVIEW_ROOT,
        )


def test_reference_preview_manifest_rejects_wrong_reference_binding() -> None:
    with pytest.raises(ReferencePreviewError, match="manifest-invalid"):
        load_reference_preview_catalog(expected_reference_manifest_sha256="sha256:" + "0" * 64)
