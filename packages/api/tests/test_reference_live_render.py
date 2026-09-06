from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from colortrace_api.reference_live_render import (
    LocalReferenceLiveRenderer,
    ReferenceLiveRenderError,
)
from colortrace_api.reference_visuals import load_reference_preview_catalog
from colortrace_fixture import load_reference_media_manifest

SCENARIO_ID = "tos-resource-resolution-drift-v1"
REQUEST_ID = "123e4567-e89b-12d3-a456-426614174000"
DIGEST = f"sha256:{'a' * 64}"


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _renderer(
    tmp_path: Path,
    *,
    canonical_pixel_sha256: str | None = None,
) -> LocalReferenceLiveRenderer:
    source_root = tmp_path / "source"
    work_root = tmp_path / "work"
    source_root.mkdir()
    work_root.mkdir(mode=0o700)
    expected = load_reference_preview_catalog(
        expected_reference_manifest_sha256=load_reference_media_manifest().manifest_sha256
    ).visual(SCENARIO_ID, "recovered")

    def worker(
        job: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
        execution_identity: Any,
    ) -> dict[str, Any]:
        del source_root, config_root
        output_root.mkdir(parents=True)
        body = {
            "schema": "reference-render-receipt/v2",
            "job_sha256": _digest(job),
            "execution_identity": execution_identity.to_dict(),
            "execution_identity_sha256": execution_identity.sha256,
            "scenario_id": job["scenario_id"],
            "artifact_id": job["artifact_id"],
            "source_sha256": job["source"]["sha256"],
            "output_sha256": DIGEST,
            "canonical_pixel_sha256": (
                canonical_pixel_sha256 or expected.source_canonical_pixel_sha256[0]
            ),
            "dependencies": {"openimageio": "3.1.17.0", "opencolorio": "2.5.2"},
            "wall_nanoseconds": 1,
        }
        return {**body, "receipt_sha256": _digest(body)}

    return LocalReferenceLiveRenderer(
        source_root=source_root,
        work_root=work_root,
        source_revision="b" * 40,
        source_tree="c" * 40,
        runtime_image=f"example.invalid/colortrace/runtime@sha256:{'d' * 64}",
        worker=worker,
        preview_encoder=lambda **_: expected.content,
    )


def _render(renderer: LocalReferenceLiveRenderer) -> Any:
    return renderer.render(
        scenario_id=SCENARIO_ID,
        request_id=REQUEST_ID,
        action_intent={
            "action_intent_id": f"action-intent:{'e' * 64}",
            "derivation_sha256": DIGEST,
        },
        approval={"approval_id": f"reference-approval:{'f' * 64}", "approval_sha256": DIGEST},
    )


def test_live_renderer_binds_fresh_output_and_removes_ephemeral_work(tmp_path: Path) -> None:
    renderer = _renderer(tmp_path)

    result = _render(renderer)

    assert result.document["schema"] == "reference-live-render/v1"
    assert result.document["request_id"] == REQUEST_ID
    assert result.document["output_equivalent"] is True
    assert result.document["visual_content_sha256"] == (
        f"sha256:{hashlib.sha256(result.png).hexdigest()}"
    )
    assert result.document["live_render_sha256"] == _digest(
        {key: value for key, value in result.document.items() if key != "live_render_sha256"}
    )
    assert list((tmp_path / "work").iterdir()) == []


def test_live_renderer_rejects_non_equivalent_canonical_pixels(tmp_path: Path) -> None:
    renderer = _renderer(tmp_path, canonical_pixel_sha256=DIGEST)

    with pytest.raises(ReferenceLiveRenderError, match="reference-live-render-receipt-invalid"):
        _render(renderer)

    assert list((tmp_path / "work").iterdir()) == []


def test_live_renderer_rejects_group_writable_work_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    work_root = tmp_path / "work"
    source_root.mkdir()
    work_root.mkdir(mode=0o770)

    with pytest.raises(
        ReferenceLiveRenderError, match="reference-live-render-configuration-invalid"
    ):
        LocalReferenceLiveRenderer(
            source_root=source_root,
            work_root=work_root,
            source_revision="b" * 40,
            source_tree="c" * 40,
            runtime_image=f"example.invalid/colortrace/runtime@sha256:{'d' * 64}",
        )
