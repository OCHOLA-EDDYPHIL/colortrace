from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import numpy as np
import OpenImageIO as oiio  # type: ignore[import-untyped]
import pytest
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    lut_bytes,
    prepare_worker,
)
from colortrace_simulator.reference_worker import (
    ReferenceExecutionIdentity,
    ReferenceRenderJob,
    ReferenceWorkerError,
    execute_reference_render_job,
    execute_reference_render_job_file,
    load_reference_render_job,
)

HOST_IDENTITY = ReferenceExecutionIdentity(
    mode="host-python-module",
    source_revision="1" * 40,
    source_tree="2" * 40,
    container_image_digest=None,
)

SCENARIOS = (
    ("tos-resource-resolution-drift-v1", "resource-resolution-drift/v1"),
    ("tos-config-rollout-drift-v1", "configuration-rollout-drift/v1"),
    ("tos-stale-derivative-cache-v1", "stale-derivative-cache/v1"),
)
TINY_PIXELS = np.array(
    [
        [[0.0, 0.25, 0.5], [0.75, 1.0, 0.125]],
        [[0.5, 0.25, 0.0], [1.0, 0.75, 0.5]],
    ],
    dtype=np.float32,
)


@dataclass(frozen=True, slots=True)
class RenderCase:
    source_root: Path
    source_path: Path
    config_root: Path
    config_path: Path
    output_root: Path
    job: dict[str, Any]


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _write_tiny_exr(path: Path) -> None:
    path.parent.mkdir(parents=True)
    spec = oiio.ImageSpec(2, 2, 3, oiio.FLOAT)
    spec.channelnames = ["R", "G", "B"]
    spec.attribute("compression", "zip")
    writer = oiio.ImageOutput.create(str(path))
    assert writer is not None
    try:
        assert writer.open(str(path), spec)
        assert writer.write_image(TINY_PIXELS)
    finally:
        writer.close()


def _read_exr(path: Path) -> tuple[Any, Any]:
    reader = oiio.ImageInput.open(str(path))
    assert reader is not None
    try:
        spec = reader.spec()
        pixels = reader.read_image(format=oiio.FLOAT)
    finally:
        reader.close()
    assert pixels is not None
    return spec, pixels


def _make_case(
    tmp_path: Path,
    *,
    scenario_id: str = SCENARIOS[0][0],
    incident_class: str = SCENARIOS[0][1],
    lut_kind: str = "approved",
) -> RenderCase:
    source_root = tmp_path / "source"
    source_path = source_root / "03_2a" / "03_2a_00000.exr"
    _write_tiny_exr(source_path)

    worker = prepare_worker(tmp_path / "runtime", "A", lut_bytes(lut_kind))
    config_root = worker.config_path.parent
    config_root.chmod(0o700)
    output_root = tmp_path / "output"
    job: dict[str, Any] = {
        "schema": "reference-render-job/v1",
        "job_id": "reference-render-00000",
        "scenario_id": scenario_id,
        "incident_class": incident_class,
        "trace_id": "0123456789abcdef0123456789abcdef",
        "worker_id": "worker-A",
        "artifact_id": "frame:03_2a:00000",
        "source": {
            "relative_path": source_path.relative_to(source_root).as_posix(),
            "sha256": _sha256_file(source_path),
            "byte_length": source_path.stat().st_size,
        },
        "color": {
            "config_relative_path": worker.config_path.relative_to(config_root).as_posix(),
            "config_sha256": f"sha256:{worker.config_sha256}",
            "resource_relative_path": worker.lut_path.relative_to(config_root).as_posix(),
            "resource_sha256": f"sha256:{worker.lut_sha256}",
            "input_color_space": "fixture_input",
            "output_color_space": "fixture_output",
        },
        "runtime": {
            "effective_generation": 7,
            "cache_key": "cache:03_2a:00000",
        },
        "output": {"relative_path": "renders/03_2a_00000.exr"},
    }
    return RenderCase(
        source_root=source_root,
        source_path=source_path,
        config_root=config_root,
        config_path=worker.config_path,
        output_root=output_root,
        job=job,
    )


def _execute(case: RenderCase, *, output_root: Path | None = None) -> dict[str, Any]:
    return execute_reference_render_job(
        case.job,
        source_root=case.source_root,
        config_root=case.config_root,
        output_root=case.output_root if output_root is None else output_root,
        execution_identity=HOST_IDENTITY,
    )


@pytest.mark.parametrize(("scenario_id", "incident_class"), SCENARIOS)
def test_registered_scenarios_execute_real_tiny_exr_round_trip(
    tmp_path: Path,
    scenario_id: str,
    incident_class: str,
) -> None:
    case = _make_case(
        tmp_path,
        scenario_id=scenario_id,
        incident_class=incident_class,
    )

    receipt = _execute(case)

    output_path = case.output_root / cast(dict[str, str], case.job["output"])["relative_path"]
    spec, pixels = _read_exr(output_path)
    assert receipt["schema"] == "reference-render-receipt/v2"
    assert receipt["job_sha256"] == _canonical_digest(
        ReferenceRenderJob.from_mapping(case.job).to_dict()
    )
    assert receipt["execution_identity"] == HOST_IDENTITY.to_dict()
    assert receipt["execution_identity_sha256"] == HOST_IDENTITY.sha256
    assert receipt["scenario_id"] == scenario_id
    assert receipt["incident_class"] == incident_class
    assert receipt["input_color_space"] == "fixture_input"
    assert receipt["output_color_space"] == "fixture_output"
    assert receipt["output_sha256"] == _sha256_file(output_path)
    assert receipt["canonical_pixel_sha256"] == _sha256_bytes(
        TINY_PIXELS.astype(">f4", copy=False).tobytes(order="C")
    )
    assert receipt["width"] == spec.width == 2
    assert receipt["height"] == spec.height == 2
    assert receipt["channels"] == spec.nchannels == 3
    assert receipt["pixel_work"] == 4
    np.testing.assert_array_equal(pixels, TINY_PIXELS)


def test_repeated_render_has_deterministic_output_and_valid_receipt_digest(
    tmp_path: Path,
) -> None:
    case = _make_case(tmp_path)

    first = _execute(case, output_root=tmp_path / "output-first")
    second = _execute(case, output_root=tmp_path / "output-second")

    variable_fields = {"cpu_nanoseconds", "wall_nanoseconds", "receipt_sha256"}
    assert {key: value for key, value in first.items() if key not in variable_fields} == {
        key: value for key, value in second.items() if key not in variable_fields
    }
    assert first["output_sha256"] == second["output_sha256"]
    assert first["canonical_pixel_sha256"] == second["canonical_pixel_sha256"]
    for receipt in (first, second):
        body = dict(receipt)
        receipt_sha256 = cast(str, body.pop("receipt_sha256"))
        assert receipt_sha256 == _canonical_digest(body)
    first_path = tmp_path / "output-first" / "renders" / "03_2a_00000.exr"
    second_path = tmp_path / "output-second" / "renders" / "03_2a_00000.exr"
    for path in (first_path, second_path):
        reader = oiio.ImageInput.open(str(path))
        assert reader is not None
        try:
            assert reader.spec().get_string_attribute("DateTime") == "1970:01:01 00:00:00"
        finally:
            reader.close()


def test_worker_applies_non_identity_ocio_transform(tmp_path: Path) -> None:
    case = _make_case(tmp_path, lut_kind="shadowed")

    receipt = _execute(case)

    output_path = case.output_root / cast(dict[str, str], case.job["output"])["relative_path"]
    _spec, pixels = _read_exr(output_path)
    assert not np.array_equal(pixels, TINY_PIXELS.astype(np.float16).astype(np.float32))
    assert receipt["canonical_pixel_sha256"] != _sha256_bytes(
        TINY_PIXELS.astype(">f4", copy=False).tobytes(order="C")
    )


@pytest.mark.parametrize(
    ("target", "expected_code"),
    [
        ("source", "reference-source-digest-mismatch"),
        ("config", "render-config-digest-mismatch"),
    ],
)
def test_source_and_config_tampering_fail_closed(
    tmp_path: Path,
    target: str,
    expected_code: str,
) -> None:
    case = _make_case(tmp_path)
    path = case.source_path if target == "source" else case.config_path
    payload = bytearray(path.read_bytes())
    payload[-1] ^= 1
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)

    with pytest.raises(ReferenceWorkerError) as raised:
        _execute(case)

    assert raised.value.code == expected_code
    assert not (case.output_root / "renders" / "03_2a_00000.exr").exists()


@pytest.mark.parametrize(
    ("section", "field", "unsafe_path"),
    [
        ("source", "relative_path", "../escape.exr"),
        ("color", "config_relative_path", "/etc/passwd"),
        ("color", "resource_relative_path", "luts/../../escape.cube"),
        ("output", "relative_path", "../escape.exr"),
    ],
)
def test_unsafe_job_paths_are_rejected(
    tmp_path: Path,
    section: str,
    field: str,
    unsafe_path: str,
) -> None:
    job = deepcopy(_make_case(tmp_path).job)
    cast(dict[str, Any], job[section])[field] = unsafe_path

    with pytest.raises(ReferenceWorkerError) as raised:
        ReferenceRenderJob.from_mapping(job)

    assert raised.value.code == "reference-job-invalid"


def test_output_symlink_cannot_escape_output_root(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    case.output_root.mkdir()
    (case.output_root / "renders").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReferenceWorkerError) as raised:
        _execute(case)

    assert raised.value.code == "reference-output-invalid"
    assert not (outside / "03_2a_00000.exr").exists()


def test_nested_output_symlink_cannot_create_directories_outside_root(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    case.output_root.mkdir()
    (case.output_root / "redirect").symlink_to(outside, target_is_directory=True)
    cast(dict[str, Any], case.job["output"])["relative_path"] = "redirect/escaped/03_2a_00000.exr"

    with pytest.raises(ReferenceWorkerError) as raised:
        _execute(case)

    assert raised.value.code == "reference-output-invalid"
    assert not (outside / "escaped").exists()


@pytest.mark.parametrize("root_kind", ("source", "config", "output"))
def test_worker_rejects_root_beneath_symlinked_parent(
    tmp_path: Path,
    root_kind: str,
) -> None:
    case = _make_case(tmp_path / "case")
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    escaped_root = linked_parent / root_kind
    if root_kind != "output":
        source = case.source_root if root_kind == "source" else case.config_root
        source.rename(real_parent / root_kind)

    roots = {
        "source_root": escaped_root if root_kind == "source" else case.source_root,
        "config_root": escaped_root if root_kind == "config" else case.config_root,
        "output_root": escaped_root if root_kind == "output" else case.output_root,
    }
    with pytest.raises(ReferenceWorkerError) as raised:
        execute_reference_render_job(
            case.job,
            **roots,
            execution_identity=HOST_IDENTITY,
        )

    assert raised.value.code == "reference-root-unsafe"


def test_expanded_configuration_scenario_alias_is_rejected(tmp_path: Path) -> None:
    job = _make_case(tmp_path).job
    job["scenario_id"] = "tos-configuration-rollout-drift-v1"

    with pytest.raises(ReferenceWorkerError) as raised:
        ReferenceRenderJob.from_mapping(job)

    assert raised.value.code == "reference-job-invalid"


def test_scenario_and_incident_class_must_match(tmp_path: Path) -> None:
    job = _make_case(tmp_path).job
    job["incident_class"] = "stale-derivative-cache/v1"

    with pytest.raises(ReferenceWorkerError) as raised:
        ReferenceRenderJob.from_mapping(job)

    assert raised.value.code == "reference-job-invalid"


def test_file_entrypoint_writes_content_bound_receipt(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(case.job), encoding="utf-8")

    receipt = execute_reference_render_job_file(
        job_path.resolve(),
        source_root=case.source_root,
        config_root=case.config_root,
        output_root=case.output_root,
        receipt_relative_path="receipts/result.json",
        execution_identity=HOST_IDENTITY,
    )

    persisted = json.loads(
        (case.output_root / "receipts" / "result.json").read_text(encoding="utf-8")
    )
    assert persisted == receipt


def test_job_file_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    job_path = tmp_path / "job.json"
    job_path.write_text('{"schema":"reference-render-job/v1","schema":"duplicate"}')

    with pytest.raises(ReferenceWorkerError) as raised:
        load_reference_render_job(job_path.resolve())

    assert raised.value.code == "reference-job-file-invalid"


@pytest.mark.parametrize(
    "identity",
    (
        {
            "mode": "host-python-module",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
        },
        {
            "mode": "host-python-module",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "container_image_digest": "sha256:" + "3" * 64,
        },
        {
            "mode": "container",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "container_image_digest": None,
        },
        {
            "mode": "container",
            "source_revision": "not-a-git-object",
            "source_tree": "2" * 40,
            "container_image_digest": "sha256:" + "3" * 64,
        },
    ),
)
def test_execution_identity_rejects_missing_or_dishonest_bindings(
    identity: Mapping[str, Any],
) -> None:
    with pytest.raises(ReferenceWorkerError) as raised:
        ReferenceExecutionIdentity.from_mapping(identity)

    assert raised.value.code == "reference-execution-identity-invalid"


def test_container_execution_identity_requires_and_preserves_pinned_digest() -> None:
    identity = ReferenceExecutionIdentity.from_mapping(
        {
            "mode": "container",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "container_image_digest": "sha256:" + "3" * 64,
        }
    )

    assert identity.container_image_digest == "sha256:" + "3" * 64
    assert identity.sha256 == _canonical_digest(identity.to_dict())
