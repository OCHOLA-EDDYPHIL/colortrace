from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import time
from argparse import ArgumentParser
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import OpenImageIO as oiio
import PyOpenColorIO as ocio  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]

from .renderer import RendererError, VerifiedPrivateConfigRoot

REFERENCE_JOB_SCHEMA = Path(__file__).parent / "schemas" / "reference-render-job-v1.schema.json"
REFERENCE_RECEIPT_SCHEMA = (
    Path(__file__).parent / "schemas" / "reference-render-receipt-v2.schema.json"
)
OPENIMAGEIO_VERSION = "3.1.17.0"
OPENCOLORIO_VERSION = "2.5.2"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE = re.compile(r"^[0-9a-f]{32}$")
_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
_MAX_JOB_BYTES = 65_536

IncidentClass = Literal[
    "resource-resolution-drift/v1",
    "configuration-rollout-drift/v1",
    "stale-derivative-cache/v1",
]
ExecutionMode = Literal[
    "host-python-module",
    "container",
    "google-cloud-batch",
    "injected-worker-callable",
]
_SCENARIO_CLASSES: Mapping[str, IncidentClass] = {
    "tos-resource-resolution-drift-v1": "resource-resolution-drift/v1",
    "tos-config-rollout-drift-v1": "configuration-rollout-drift/v1",
    "tos-stale-derivative-cache-v1": "stale-derivative-cache/v1",
}


class ReferenceWorkerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReferenceExecutionIdentity:
    mode: ExecutionMode
    source_revision: str
    source_tree: str
    container_image_digest: str | None

    def __post_init__(self) -> None:
        if (
            self.mode
            not in {
                "host-python-module",
                "container",
                "google-cloud-batch",
                "injected-worker-callable",
            }
            or not isinstance(self.source_revision, str)
            or _GIT_OBJECT.fullmatch(self.source_revision) is None
            or not isinstance(self.source_tree, str)
            or _GIT_OBJECT.fullmatch(self.source_tree) is None
            or (
                self.container_image_digest is not None
                and (
                    not isinstance(self.container_image_digest, str)
                    or _DIGEST.fullmatch(self.container_image_digest) is None
                )
            )
            or (
                self.mode in {"container", "google-cloud-batch"}
                and self.container_image_digest is None
            )
            or (
                self.mode in {"host-python-module", "injected-worker-callable"}
                and self.container_image_digest is not None
            )
        ):
            raise ReferenceWorkerError("reference-execution-identity-invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceExecutionIdentity:
        if set(value) != {
            "mode",
            "source_revision",
            "source_tree",
            "container_image_digest",
        }:
            raise ReferenceWorkerError("reference-execution-identity-invalid")
        mode = value.get("mode")
        source_revision = value.get("source_revision")
        source_tree = value.get("source_tree")
        container_image_digest = value.get("container_image_digest")
        return cls(
            mode=cast(ExecutionMode, mode),
            source_revision=cast(str, source_revision),
            source_tree=cast(str, source_tree),
            container_image_digest=cast(str | None, container_image_digest),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "source_revision": self.source_revision,
            "source_tree": self.source_tree,
            "container_image_digest": self.container_image_digest,
        }

    @property
    def sha256(self) -> str:
        return f"sha256:{hashlib.sha256(_canonical_json_bytes(self.to_dict())).hexdigest()}"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = child
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON token: {value}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _relative(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ReferenceWorkerError("reference-job-path-invalid")
    return path


def _safe_root(root: Path, *, create: bool = False) -> Path:
    absolute = root if root.is_absolute() else Path.cwd() / root
    if ".." in absolute.parts or absolute.is_symlink():
        raise ReferenceWorkerError("reference-root-unsafe")
    resolved = absolute.resolve(strict=False)
    if (
        resolved != absolute.absolute()
        or resolved == Path(resolved.anchor)
        or len(resolved.parts) < 3
    ):
        raise ReferenceWorkerError("reference-root-unsafe")
    try:
        if create:
            resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = resolved.lstat()
    except OSError as error:
        raise ReferenceWorkerError("reference-root-unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReferenceWorkerError("reference-root-unsafe")
    return resolved


def _open_output_parent(root: Path, relative: Path, *, error_code: str) -> int:
    try:
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise ReferenceWorkerError(error_code) from error
    try:
        for part in relative.parent.parts:
            try:
                os.mkdir(part, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = child_fd
    except OSError as error:
        os.close(directory_fd)
        raise ReferenceWorkerError(error_code) from error
    return directory_fd


def _directory_entry_present(directory_fd: int, name: str, *, error_code: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReferenceWorkerError(error_code) from error
    return True


def _safe_input(root: Path, relative: Path) -> Path:
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise ReferenceWorkerError("reference-input-unavailable") from error
    if (
        candidate != resolved
        or candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ReferenceWorkerError("reference-input-unsafe")
    return resolved


@dataclass(frozen=True, slots=True)
class ReferenceRenderJob:
    job_id: str
    scenario_id: str
    incident_class: IncidentClass
    trace_id: str
    worker_id: str
    artifact_id: str
    source_relative_path: str
    source_sha256: str
    source_bytes: int
    config_relative_path: str
    config_sha256: str
    resource_relative_path: str
    resource_sha256: str
    input_color_space: str
    output_color_space: str
    effective_generation: int
    cache_key: str | None
    output_relative_path: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceRenderJob:
        try:
            schema = json.loads(REFERENCE_JOB_SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(dict(value))
            source = cast(Mapping[str, Any], value["source"])
            color = cast(Mapping[str, Any], value["color"])
            runtime = cast(Mapping[str, Any], value["runtime"])
            output = cast(Mapping[str, Any], value["output"])
            job = cls(
                job_id=cast(str, value["job_id"]),
                scenario_id=cast(str, value["scenario_id"]),
                incident_class=cast(IncidentClass, value["incident_class"]),
                trace_id=cast(str, value["trace_id"]),
                worker_id=cast(str, value["worker_id"]),
                artifact_id=cast(str, value["artifact_id"]),
                source_relative_path=cast(str, source["relative_path"]),
                source_sha256=cast(str, source["sha256"]),
                source_bytes=cast(int, source["byte_length"]),
                config_relative_path=cast(str, color["config_relative_path"]),
                config_sha256=cast(str, color["config_sha256"]),
                resource_relative_path=cast(str, color["resource_relative_path"]),
                resource_sha256=cast(str, color["resource_sha256"]),
                input_color_space=cast(str, color["input_color_space"]),
                output_color_space=cast(str, color["output_color_space"]),
                effective_generation=cast(int, runtime["effective_generation"]),
                cache_key=cast(str | None, runtime["cache_key"]),
                output_relative_path=cast(str, output["relative_path"]),
            )
        except (OSError, KeyError, TypeError, ValidationError, ValueError) as error:
            raise ReferenceWorkerError("reference-job-invalid") from error
        fields = (
            job.job_id,
            job.scenario_id,
            job.worker_id,
            job.artifact_id,
            job.input_color_space,
            job.output_color_space,
        )
        if (
            any(_IDENTIFIER.fullmatch(field) is None for field in fields)
            or _TRACE.fullmatch(job.trace_id) is None
            or _DIGEST.fullmatch(job.source_sha256) is None
            or _DIGEST.fullmatch(job.config_sha256) is None
            or _DIGEST.fullmatch(job.resource_sha256) is None
            or _SCENARIO_CLASSES.get(job.scenario_id) != job.incident_class
        ):
            raise ReferenceWorkerError("reference-job-invalid")
        _relative(job.source_relative_path)
        _relative(job.config_relative_path)
        _relative(job.resource_relative_path)
        _relative(job.output_relative_path)
        return job

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reference-render-job/v1",
            "job_id": self.job_id,
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class,
            "trace_id": self.trace_id,
            "worker_id": self.worker_id,
            "artifact_id": self.artifact_id,
            "source": {
                "relative_path": self.source_relative_path,
                "sha256": self.source_sha256,
                "byte_length": self.source_bytes,
            },
            "color": {
                "config_relative_path": self.config_relative_path,
                "config_sha256": self.config_sha256,
                "resource_relative_path": self.resource_relative_path,
                "resource_sha256": self.resource_sha256,
                "input_color_space": self.input_color_space,
                "output_color_space": self.output_color_space,
            },
            "runtime": {
                "effective_generation": self.effective_generation,
                "cache_key": self.cache_key,
            },
            "output": {"relative_path": self.output_relative_path},
        }


def _dependency_versions() -> dict[str, str]:
    oiio_version = oiio.VERSION_STRING
    ocio_version = cast(str, ocio.__version__)
    if oiio_version != OPENIMAGEIO_VERSION:
        raise ReferenceWorkerError("reference-openimageio-version-mismatch")
    if ocio_version != OPENCOLORIO_VERSION:
        raise ReferenceWorkerError("reference-opencolorio-version-mismatch")
    return {"openimageio": oiio_version, "opencolorio": ocio_version}


def load_reference_render_job(path: Path) -> ReferenceRenderJob:
    try:
        metadata = path.lstat()
        if (
            not path.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_JOB_BYTES
        ):
            raise ReferenceWorkerError("reference-job-file-invalid")
        value = json.loads(
            path.read_bytes().decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except ReferenceWorkerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReferenceWorkerError("reference-job-file-invalid") from error
    if not isinstance(value, Mapping):
        raise ReferenceWorkerError("reference-job-file-invalid")
    return ReferenceRenderJob.from_mapping(value)


def execute_reference_render_job(
    value: ReferenceRenderJob | Mapping[str, Any],
    *,
    source_root: Path,
    config_root: Path,
    output_root: Path,
    execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
) -> dict[str, Any]:
    job = value if isinstance(value, ReferenceRenderJob) else ReferenceRenderJob.from_mapping(value)
    identity = (
        execution_identity
        if isinstance(execution_identity, ReferenceExecutionIdentity)
        else ReferenceExecutionIdentity.from_mapping(execution_identity)
    )
    if identity.mode == "injected-worker-callable":
        raise ReferenceWorkerError("reference-execution-identity-invalid")
    source_base = _safe_root(source_root)
    config_base = _safe_root(config_root)
    output_base = _safe_root(output_root, create=True)
    source = _safe_input(source_base, _relative(job.source_relative_path))
    if source.stat().st_size != job.source_bytes or _sha256_file(source) != job.source_sha256:
        raise ReferenceWorkerError("reference-source-digest-mismatch")
    config_path = _safe_input(config_base, _relative(job.config_relative_path))
    resource_path = _safe_input(config_base, _relative(job.resource_relative_path))
    try:
        verified = VerifiedPrivateConfigRoot.verify(
            root=config_base,
            config_path=config_path,
            lut_path=resource_path,
            expected_config_sha256=job.config_sha256,
            expected_resource_sha256=job.resource_sha256,
        )
    except RendererError as error:
        raise ReferenceWorkerError(error.code) from error
    versions = _dependency_versions()
    output_relative = _relative(job.output_relative_path)
    output = output_base / output_relative
    output_parent_fd = _open_output_parent(
        output_base,
        output_relative,
        error_code="reference-output-invalid",
    )
    try:
        if _directory_entry_present(
            output_parent_fd,
            output.name,
            error_code="reference-output-invalid",
        ):
            raise ReferenceWorkerError("reference-output-invalid")
    except ReferenceWorkerError:
        os.close(output_parent_fd)
        raise

    wall_started = time.monotonic_ns()
    cpu_started = time.process_time_ns()
    temporary: Path | None = None
    image_input: Any = None
    image_output: Any = None
    try:
        image_input = oiio.ImageInput.open(str(source))
        if image_input is None:
            raise ReferenceWorkerError("reference-exr-open-failed")
        spec = image_input.spec()
        if spec.width < 1 or spec.height < 1 or spec.nchannels not in {3, 4}:
            raise ReferenceWorkerError("reference-exr-layout-invalid")
        pixels = image_input.read_image(format=oiio.FLOAT)
        if pixels is None:
            raise ReferenceWorkerError("reference-exr-read-failed")
        configuration = ocio.Config.CreateFromFile(str(verified.config_path))
        configuration.validate()
        processor = configuration.getProcessor(job.input_color_space, job.output_color_space)
        cpu = processor.getDefaultCPUProcessor()
        if spec.nchannels == 3:
            cpu.applyRGB(pixels)
        else:
            cpu.applyRGBA(pixels)
        pixel_bytes = pixels.astype(">f4", copy=False).tobytes(order="C")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".part.exr", dir=output.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        output_spec = oiio.ImageSpec(spec.width, spec.height, spec.nchannels, oiio.HALF)
        output_spec.channelnames = tuple(spec.channelnames)
        output_spec.attribute("compression", "zip")
        output_spec.attribute("oiio:ColorSpace", job.output_color_space)
        output_spec.attribute("DateTime", "1970:01:01 00:00:00")
        image_output = oiio.ImageOutput.create(str(temporary))
        if image_output is None or not image_output.open(str(temporary), output_spec):
            raise ReferenceWorkerError("reference-exr-output-open-failed")
        if not image_output.write_image(pixels):
            raise ReferenceWorkerError("reference-exr-write-failed")
        image_output.close()
        image_output = None
        os.chmod(temporary, 0o600)
        try:
            os.link(
                temporary,
                output.name,
                dst_dir_fd=output_parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise ReferenceWorkerError("reference-output-invalid") from error
        temporary.unlink()
        temporary = None
    except ReferenceWorkerError:
        raise
    except Exception as error:
        raise ReferenceWorkerError("reference-render-failed") from error
    finally:
        if image_input is not None:
            image_input.close()
        if image_output is not None:
            image_output.close()
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(output_parent_fd)

    receipt_body: dict[str, Any] = {
        "schema": "reference-render-receipt/v2",
        "job_sha256": (
            f"sha256:{hashlib.sha256(_canonical_json_bytes(job.to_dict())).hexdigest()}"
        ),
        "execution_identity": identity.to_dict(),
        "execution_identity_sha256": identity.sha256,
        "job_id": job.job_id,
        "scenario_id": job.scenario_id,
        "incident_class": job.incident_class,
        "trace_id": job.trace_id,
        "worker_id": job.worker_id,
        "artifact_id": job.artifact_id,
        "source_sha256": job.source_sha256,
        "config_sha256": job.config_sha256,
        "resource_sha256": job.resource_sha256,
        "input_color_space": job.input_color_space,
        "output_color_space": job.output_color_space,
        "effective_generation": job.effective_generation,
        "cache_key": job.cache_key,
        "output_relative_path": output_relative.as_posix(),
        "output_sha256": _sha256_file(output),
        "canonical_pixel_sha256": f"sha256:{hashlib.sha256(pixel_bytes).hexdigest()}",
        "width": spec.width,
        "height": spec.height,
        "channels": spec.nchannels,
        "pixel_work": spec.width * spec.height,
        "bytes_read": job.source_bytes,
        "bytes_written": output.stat().st_size,
        "cpu_nanoseconds": max(0, time.process_time_ns() - cpu_started),
        "wall_nanoseconds": max(0, time.monotonic_ns() - wall_started),
        "dependencies": versions,
    }
    receipt_body["receipt_sha256"] = (
        f"sha256:{hashlib.sha256(_canonical_json_bytes(receipt_body)).hexdigest()}"
    )
    try:
        schema = json.loads(REFERENCE_RECEIPT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(receipt_body)
    except (OSError, ValidationError, ValueError) as error:
        raise ReferenceWorkerError("reference-receipt-invalid") from error
    return receipt_body


def execute_reference_render_job_file(
    job_path: Path,
    *,
    source_root: Path,
    config_root: Path,
    output_root: Path,
    receipt_relative_path: str,
    execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
) -> dict[str, Any]:
    job = load_reference_render_job(job_path)
    receipt = execute_reference_render_job(
        job,
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
        execution_identity=execution_identity,
    )
    root = _safe_root(output_root)
    relative = _relative(receipt_relative_path)
    target = root / relative
    target_parent_fd = _open_output_parent(
        root,
        relative,
        error_code="reference-receipt-output-invalid",
    )
    temporary: Path | None = None
    try:
        if _directory_entry_present(
            target_parent_fd,
            target.name,
            error_code="reference-receipt-output-invalid",
        ):
            raise ReferenceWorkerError("reference-receipt-output-invalid")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".part", dir=target.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output:
            output.write(_canonical_json_bytes(receipt) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.link(
                temporary,
                target.name,
                dst_dir_fd=target_parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise ReferenceWorkerError("reference-receipt-output-invalid") from error
        temporary.unlink()
        temporary = None
    except ReferenceWorkerError:
        raise
    except OSError as error:
        raise ReferenceWorkerError("reference-receipt-write-failed") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        os.close(target_parent_fd)
    return receipt


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-worker")
    parser.add_argument("--job", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--config-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--receipt-relative-path", default="receipt.json")
    parser.add_argument(
        "--execution-mode",
        choices=("host-python-module", "container"),
        default=os.environ.get("COLORTRACE_REFERENCE_EXECUTION_MODE"),
        required=os.environ.get("COLORTRACE_REFERENCE_EXECUTION_MODE") is None,
    )
    parser.add_argument(
        "--source-revision",
        default=os.environ.get("COLORTRACE_SOURCE_REVISION"),
        required=os.environ.get("COLORTRACE_SOURCE_REVISION") is None,
    )
    parser.add_argument(
        "--source-tree",
        default=os.environ.get("COLORTRACE_SOURCE_TREE"),
        required=os.environ.get("COLORTRACE_SOURCE_TREE") is None,
    )
    parser.add_argument(
        "--container-image-digest",
        default=os.environ.get("COLORTRACE_CONTAINER_IMAGE_DIGEST"),
    )
    arguments = parser.parse_args()
    try:
        execution_identity = ReferenceExecutionIdentity.from_mapping(
            {
                "mode": arguments.execution_mode,
                "source_revision": arguments.source_revision,
                "source_tree": arguments.source_tree,
                "container_image_digest": arguments.container_image_digest,
            }
        )
        receipt = execute_reference_render_job_file(
            arguments.job,
            source_root=arguments.source_root,
            config_root=arguments.config_root,
            output_root=arguments.output_root,
            receipt_relative_path=arguments.receipt_relative_path,
            execution_identity=execution_identity,
        )
    except ReferenceWorkerError as error:
        print(error.code, file=sys.stderr)
        raise SystemExit(2) from error
    print(_canonical_json_bytes(receipt).decode("utf-8"))


__all__ = [
    "ExecutionMode",
    "IncidentClass",
    "OPENIMAGEIO_VERSION",
    "OPENCOLORIO_VERSION",
    "ReferenceExecutionIdentity",
    "ReferenceRenderJob",
    "ReferenceWorkerError",
    "execute_reference_render_job",
    "execute_reference_render_job_file",
    "load_reference_render_job",
    "main",
]


if __name__ == "__main__":
    main()
