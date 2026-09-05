from __future__ import annotations

import hashlib
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


def test_reference_preview_manifest_rejects_self_rehashed_malformed_receipt(
    tmp_path: Path,
) -> None:
    document = json.loads(REFERENCE_PREVIEW_MANIFEST_PATH.read_text(encoding="utf-8"))
    old_receipt_sha256, receipt = next(iter(document["worker_receipts"].items()))
    receipt["pixel_work"] += 1
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    encoded_receipt = json.dumps(
        receipt_body,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    new_receipt_sha256 = f"sha256:{hashlib.sha256(encoded_receipt).hexdigest()}"
    receipt["receipt_sha256"] = new_receipt_sha256
    del document["worker_receipts"][old_receipt_sha256]
    document["worker_receipts"][new_receipt_sha256] = receipt
    for scenario in document["scenarios"].values():
        for visual in scenario["visuals"].values():
            visual["source_receipt_sha256"] = [
                new_receipt_sha256 if value == old_receipt_sha256 else value
                for value in visual["source_receipt_sha256"]
            ]
    manifest_body = {key: value for key, value in document.items() if key != "manifest_sha256"}
    encoded_manifest = json.dumps(
        manifest_body,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    document["manifest_sha256"] = f"sha256:{hashlib.sha256(encoded_manifest).hexdigest()}"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReferencePreviewError, match="receipts-invalid"):
        load_reference_preview_catalog(
            expected_reference_manifest_sha256=load_reference_media_manifest().manifest_sha256,
            manifest_path=path,
            asset_root=REFERENCE_PREVIEW_ROOT,
        )
