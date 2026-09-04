from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np
import OpenImageIO as oiio
import pytest
from colortrace_api.reference_visuals import (
    REFERENCE_PREVIEW_ROOT,
    load_reference_preview_catalog,
)
from colortrace_evaluation import reference_preview_evidence
from colortrace_evaluation.contracts import canonical_json_bytes
from colortrace_evaluation.reference_preview_evidence import (
    ReferencePreviewRefreshError,
    _difference_image,
    _display_image,
    _encode_png,
    refresh_reference_previews,
)
from colortrace_fixture import load_reference_media_manifest


def _copy_previews(tmp_path: Path) -> Path:
    target = tmp_path / "previews"
    shutil.copytree(REFERENCE_PREVIEW_ROOT, target)
    return target


def _asset_bytes(asset_root: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in asset_root.iterdir() if path.is_file()}


def _png_bytes(asset_root: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in asset_root.glob("*.png")}


def _pixel_evidence(asset_root: Path) -> dict[tuple[str, str], str]:
    document = json.loads((asset_root / "manifest.json").read_text(encoding="utf-8"))
    return {
        (scenario_id, kind): visual["source_canonical_pixel_sha256"][0]
        for scenario_id, scenario in document["scenarios"].items()
        for kind, visual in scenario["visuals"].items()
        if kind != "diff"
    }


def _fake_renderer(
    pixels: Mapping[tuple[str, str], str],
    *,
    corrupt_observed: bool = False,
):
    def render(
        job: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
    ) -> dict[str, Any]:
        del source_root, config_root, output_root
        mode = str(job["job_id"]).split("-", maxsplit=1)[0]
        scenario_id = str(job["scenario_id"])
        pixel_digest = pixels[(scenario_id, mode)]
        if corrupt_observed and mode == "observed":
            pixel_digest = "sha256:" + "0" * 64
        output_identity = {
            "source": job["source"]["sha256"],
            "config": job["color"]["config_sha256"],
            "resource": job["color"]["resource_sha256"],
        }
        output_digest = (
            f"sha256:{hashlib.sha256(canonical_json_bytes(output_identity)).hexdigest()}"
        )
        receipt: dict[str, Any] = {
            "schema": "reference-render-receipt/v1",
            "job_id": job["job_id"],
            "scenario_id": scenario_id,
            "incident_class": job["incident_class"],
            "trace_id": job["trace_id"],
            "worker_id": job["worker_id"],
            "artifact_id": job["artifact_id"],
            "source_sha256": job["source"]["sha256"],
            "config_sha256": job["color"]["config_sha256"],
            "resource_sha256": job["color"]["resource_sha256"],
            "effective_generation": job["runtime"]["effective_generation"],
            "cache_key": job["runtime"]["cache_key"],
            "output_relative_path": job["output"]["relative_path"],
            "output_sha256": output_digest,
            "canonical_pixel_sha256": pixel_digest,
            "width": 4096,
            "height": 2160,
            "channels": 3,
            "pixel_work": 8_847_360,
            "bytes_read": job["source"]["byte_length"],
            "bytes_written": 34_000_000,
            "cpu_nanoseconds": 1,
            "wall_nanoseconds": 2,
            "dependencies": {
                "openimageio": "3.1.17.0",
                "opencolorio": "2.5.2",
            },
        }
        receipt["receipt_sha256"] = (
            f"sha256:{hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()}"
        )
        return receipt

    return render


def _asset_builder(asset_root: Path, *, changed: bool = False, mutate_live: bool = False):
    original = _png_bytes(asset_root)

    def build(
        *,
        template: Mapping[str, Any],
        receipts: Mapping[tuple[str, str], Mapping[str, Any]],
        output_root: Path,
        work_root: Path,
    ) -> Mapping[str, bytes]:
        del template, receipts, output_root, work_root
        assets = dict(original)
        if changed:
            assets["config-rollout-drift-observed.png"] = assets[
                "resource-resolution-drift-observed.png"
            ]
        if mutate_live:
            (asset_root / "config-rollout-drift-observed.png").write_bytes(
                assets["resource-resolution-drift-observed.png"]
            )
        return assets

    return build


def test_check_rebuilds_all_pngs_without_writing(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    manifest_path = asset_root / "manifest.json"
    original = _asset_bytes(asset_root)
    pixels = _pixel_evidence(asset_root)

    result = refresh_reference_previews(
        source_root=tmp_path / "unused-source",
        manifest_path=manifest_path,
        asset_root=asset_root,
        renderer=_fake_renderer(pixels),
        asset_builder=_asset_builder(asset_root),
    )

    assert result["schema"] == "reference-preview-generation/v1"
    assert result["mode"] == "check"
    assert result["asset_set_installed"] is False
    assert result["scenario_count"] == 3
    assert result["worker_receipt_count"] == 9
    assert result["png_asset_count"] == 12
    assert result["png_content_changed"] is False
    assert _asset_bytes(asset_root) == original


def test_check_rejects_stale_pngs_without_writing(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    original = _asset_bytes(asset_root)

    with pytest.raises(ReferencePreviewRefreshError, match="reference-preview-assets-stale"):
        refresh_reference_previews(
            source_root=tmp_path / "unused-source",
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
            renderer=_fake_renderer(_pixel_evidence(asset_root)),
            asset_builder=_asset_builder(asset_root, changed=True),
        )

    assert _asset_bytes(asset_root) == original


def test_write_atomically_installs_complete_valid_asset_set(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    original = _asset_bytes(asset_root)

    result = refresh_reference_previews(
        source_root=tmp_path / "unused-source",
        manifest_path=asset_root / "manifest.json",
        asset_root=asset_root,
        write=True,
        renderer=_fake_renderer(_pixel_evidence(asset_root)),
        asset_builder=_asset_builder(asset_root, changed=True),
    )

    assert result["mode"] == "write"
    assert result["asset_set_installed"] is True
    assert result["png_content_changed"] is True
    assert (asset_root / "config-rollout-drift-observed.png").read_bytes() == (
        asset_root / "resource-resolution-drift-observed.png"
    ).read_bytes()
    assert _asset_bytes(asset_root) != original
    catalog = load_reference_preview_catalog(
        expected_reference_manifest_sha256=load_reference_media_manifest().manifest_sha256,
        manifest_path=asset_root / "manifest.json",
        asset_root=asset_root,
    )
    assert catalog.manifest_sha256 == result["preview_manifest_sha256"]


def test_write_rolls_back_complete_asset_set_on_post_install_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset_root = _copy_previews(tmp_path)
    original = _asset_bytes(asset_root)
    calls = 0
    load_catalog = reference_preview_evidence.load_reference_preview_catalog

    def fail_after_exchange(**kwargs: Any):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise RuntimeError("post-install validation failure")
        return load_catalog(**kwargs)

    monkeypatch.setattr(
        reference_preview_evidence,
        "load_reference_preview_catalog",
        fail_after_exchange,
    )

    with pytest.raises(
        ReferencePreviewRefreshError,
        match="reference-preview-install-validation-failed",
    ):
        refresh_reference_previews(
            source_root=tmp_path / "unused-source",
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
            write=True,
            renderer=_fake_renderer(_pixel_evidence(asset_root)),
            asset_builder=_asset_builder(asset_root, changed=True),
        )

    assert _asset_bytes(asset_root) == original


def test_write_rejects_concurrent_target_change(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    original_manifest = (asset_root / "manifest.json").read_bytes()

    with pytest.raises(
        ReferencePreviewRefreshError,
        match="reference-preview-assets-concurrent-change",
    ):
        refresh_reference_previews(
            source_root=tmp_path / "unused-source",
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
            write=True,
            renderer=_fake_renderer(_pixel_evidence(asset_root)),
            asset_builder=_asset_builder(asset_root, mutate_live=True),
        )

    assert (asset_root / "manifest.json").read_bytes() == original_manifest
    assert (asset_root / "config-rollout-drift-observed.png").read_bytes() == (
        asset_root / "resource-resolution-drift-observed.png"
    ).read_bytes()


def test_refresh_rejects_changed_canonical_pixels_without_writing(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    original = _asset_bytes(asset_root)

    with pytest.raises(
        ReferencePreviewRefreshError,
        match="reference-preview-pixel-lineage-changed",
    ):
        refresh_reference_previews(
            source_root=tmp_path / "unused-source",
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
            renderer=_fake_renderer(_pixel_evidence(asset_root), corrupt_observed=True),
            asset_builder=_asset_builder(asset_root),
        )

    assert _asset_bytes(asset_root) == original


def test_check_rejects_receipt_changed_after_self_hash(tmp_path: Path) -> None:
    asset_root = _copy_previews(tmp_path)
    original = _asset_bytes(asset_root)
    render = _fake_renderer(_pixel_evidence(asset_root))

    def tampered_renderer(
        job: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
    ) -> dict[str, Any]:
        receipt = render(
            job,
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
        )
        receipt["wall_nanoseconds"] = 3
        return receipt

    with pytest.raises(
        ReferencePreviewRefreshError,
        match="reference-preview-receipt-job-mismatch",
    ):
        refresh_reference_previews(
            source_root=tmp_path / "unused-source",
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
            renderer=tampered_renderer,
            asset_builder=_asset_builder(asset_root),
        )

    assert _asset_bytes(asset_root) == original


def test_png_encoding_strips_source_metadata_and_is_byte_deterministic(
    tmp_path: Path,
) -> None:
    def image(date_time: str) -> oiio.ImageBuf:
        spec = oiio.ImageSpec(960, 506, 3, oiio.FLOAT)
        spec.attribute("DateTime", date_time)
        result = oiio.ImageBuf(spec)
        assert oiio.ImageBufAlgo.fill(result, (0.25, 0.5, 0.75))
        return result

    first = _encode_png(image("2026:01:01 00:00:00"), tmp_path / "first.png")
    second = _encode_png(image("1999:12:31 23:59:59"), tmp_path / "second.png")

    assert first == second
    decoded = oiio.ImageBuf(str(tmp_path / "first.png"))
    assert (decoded.spec().width, decoded.spec().height, decoded.spec().nchannels) == (
        960,
        506,
        3,
    )
    pixels = decoded.get_pixels(oiio.UINT8)
    assert tuple(pixels[0, 0]) == (64, 128, 191)


def test_display_transform_binds_half_exr_and_preserves_prequantization_boundary(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    path = output_root / "sample.exr"
    source_pixels = np.asarray(
        [[[0.0, 0.0031308, 0.25], [1.0, 2.0, -0.25]]],
        dtype=np.float32,
    )
    spec = oiio.ImageSpec(2, 1, 3, oiio.HALF)
    spec.channelnames = ("R", "G", "B")
    image_output = oiio.ImageOutput.create(str(path))
    assert image_output is not None
    assert image_output.open(str(path), spec)
    assert image_output.write_image(source_pixels)
    image_output.close()
    content = path.read_bytes()
    prequantization_pixels = source_pixels.astype(">f4", copy=False).tobytes(order="C")
    receipt: dict[str, Any] = {
        "output_relative_path": "sample.exr",
        "output_sha256": f"sha256:{hashlib.sha256(content).hexdigest()}",
        "canonical_pixel_sha256": (f"sha256:{hashlib.sha256(prequantization_pixels).hexdigest()}"),
        "width": 2,
        "height": 1,
        "channels": 3,
        "bytes_written": len(content),
    }

    display = _display_image(output_root=output_root, receipt=receipt, width=2, height=1)
    transformed = display.image.get_pixels(oiio.FLOAT)

    assert display.source_decoded_pixel_sha256 != receipt["canonical_pixel_sha256"]
    assert transformed[0, 0, 0] == pytest.approx(0.0)
    assert transformed[0, 0, 1] == pytest.approx(0.0404, abs=0.001)
    assert transformed[0, 0, 2] == pytest.approx(0.537, abs=0.001)
    assert tuple(transformed[0, 1]) == pytest.approx((1.0, 1.0, 0.0))

    receipt["output_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(
        ReferencePreviewRefreshError,
        match="reference-preview-render-output-invalid",
    ):
        _display_image(output_root=output_root, receipt=receipt, width=2, height=1)


def test_difference_is_amplified_after_display_clamp() -> None:
    spec = oiio.ImageSpec(960, 506, 3, oiio.FLOAT)
    expected = oiio.ImageBuf(spec)
    observed = oiio.ImageBuf(spec)
    assert oiio.ImageBufAlgo.fill(expected, (1.0, 0.5, 0.0))
    assert oiio.ImageBufAlgo.fill(observed, (0.0, 0.375, 0.0))

    difference = _difference_image(expected, observed).get_pixels(oiio.UINT8)

    assert tuple(difference[0, 0]) == (255, 255, 0)
