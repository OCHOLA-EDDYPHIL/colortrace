from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .contracts import prefixed_sha256, validate_schema

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class CleanupError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: bytes


class CleanupTransport(Protocol):
    def request(self, method: str, path: str, credential: str) -> HttpResult: ...


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise CleanupError("redirect-refused")


class HttpsCleanupTransport:
    def __init__(self, origin: str) -> None:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise CleanupError("grafana-origin-invalid")
        self._origin = f"https://{parsed.hostname}"
        self._opener = build_opener(_RejectRedirects())

    def request(self, method: str, path: str, credential: str) -> HttpResult:
        if method not in {"GET", "DELETE"} or not path.startswith("/api/"):
            raise CleanupError("request-boundary-invalid")
        request = Request(
            self._origin + path,
            method=method,
            headers={"Accept": "application/json", "Authorization": f"Bearer {credential}"},
        )
        try:
            with self._opener.open(request, timeout=15) as response:
                status = response.status
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            status = error.code
            body = error.read(_MAX_RESPONSE_BYTES + 1)
        except (OSError, URLError) as error:
            raise CleanupError("transport-error") from error
        if len(body) > _MAX_RESPONSE_BYTES:
            raise CleanupError("response-oversized")
        return HttpResult(status=status, body=body)


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _credential(path: Path) -> str:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat(follow_symlinks=False)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
    ):
        raise CleanupError("credential-file-policy")
    value = resolved.read_text(encoding="ascii").strip()
    if not value or "\n" in value or "\r" in value:
        raise CleanupError("credential-value-invalid")
    return value


def _object(body: bytes, *, code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CleanupError(code) from error
    if not isinstance(value, Mapping):
        raise CleanupError(code)
    return value


def cleanup_grafana_resources(
    *,
    grafana_url: str,
    viewer_token_file: Path,
    editor_token_file: Path,
    folder_uid: str,
    rule_uid: str,
    transport: CleanupTransport | None = None,
) -> dict[str, Any]:
    if _IDENTIFIER.fullmatch(folder_uid) is None or _IDENTIFIER.fullmatch(rule_uid) is None:
        raise CleanupError("resource-identifier-invalid")
    if folder_uid == rule_uid:
        raise CleanupError("resource-identifiers-not-distinct")
    viewer = _credential(viewer_token_file)
    editor = _credential(editor_token_file)
    client = transport or HttpsCleanupTransport(grafana_url)
    rule_path = f"/api/v1/provisioning/alert-rules/{quote(rule_uid, safe='')}"
    folder_path = f"/api/folders/{quote(folder_uid, safe='')}"
    receipts: list[dict[str, Any]] = []
    started_at = _timestamp()

    def call(
        method: str,
        path: str,
        credential: str,
        expected: set[int],
    ) -> HttpResult:
        try:
            result = client.request(method, path, credential)
        except CleanupError:
            raise
        except Exception as error:
            raise CleanupError("transport-error") from error
        receipts.append(
            {
                "method": method,
                "path": path,
                "status": result.status,
                "response_bytes": len(result.body),
                "response_sha256": f"sha256:{hashlib.sha256(result.body).hexdigest()}",
            }
        )
        if result.status not in expected:
            raise CleanupError(f"unexpected-http-{result.status}")
        return result

    failure_code: str | None = None
    try:
        rule = call("GET", rule_path, viewer, {200, 404})
        if rule.status == 200:
            rule_value = _object(rule.body, code="rule-response-invalid")
            if rule_value.get("uid") != rule_uid or rule_value.get("isPaused") is not True:
                raise CleanupError("rule-identity-or-state-invalid")
        folder = call("GET", folder_path, viewer, {200, 404})
        if folder.status == 200:
            folder_value = _object(folder.body, code="folder-response-invalid")
            if folder_value.get("uid") != folder_uid:
                raise CleanupError("folder-identity-invalid")
        if rule.status == 200:
            call("DELETE", rule_path, editor, {200, 202, 204})
        call("GET", rule_path, viewer, {404})
        if folder.status == 200:
            call("DELETE", folder_path, editor, {200, 202, 204})
        call("GET", folder_path, viewer, {404})
    except CleanupError as error:
        failure_code = str(error) or "cleanup-failed"

    body: dict[str, Any] = {
        "schema": "reliability-grafana-cleanup/v1",
        "started_at": started_at,
        "finished_at": _timestamp(),
        "folder_uid": folder_uid,
        "rule_uid": rule_uid,
        "direct_uid_reads_only": True,
        "global_notification_routing_mutations": 0,
        "cleanup_complete": failure_code is None,
        "failure_code": failure_code,
        "requests": receipts,
    }
    evidence = {**body, "sha256": prefixed_sha256(body)}
    validate_schema("reliability-grafana-cleanup-v1.schema.json", evidence)
    return evidence


__all__ = [
    "CleanupError",
    "CleanupTransport",
    "HttpResult",
    "HttpsCleanupTransport",
    "cleanup_grafana_resources",
]
