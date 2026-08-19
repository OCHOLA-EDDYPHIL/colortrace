from __future__ import annotations

import json
from pathlib import Path

from colortrace_evaluation.grafana_cleanup import HttpResult, cleanup_grafana_resources

FOLDER = "ct-evaluation-folder"
RULE = "ct-evaluation-rule"
RULE_PATH = f"/api/v1/provisioning/alert-rules/{RULE}"
FOLDER_PATH = f"/api/folders/{FOLDER}"


class FakeTransport:
    def __init__(self, responses: list[tuple[str, str, int, bytes]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, str]] = []

    def request(self, method: str, path: str, credential: str) -> HttpResult:
        expected_method, expected_path, status, body = self.responses.pop(0)
        assert (method, path) == (expected_method, expected_path)
        self.calls.append((method, path, credential))
        return HttpResult(status=status, body=body)


def credentials(tmp_path: Path) -> tuple[Path, Path]:
    viewer = tmp_path / "viewer.token"
    editor = tmp_path / "editor.token"
    viewer.write_text("viewer-private", encoding="ascii")
    editor.write_text("editor-private", encoding="ascii")
    viewer.chmod(0o600)
    editor.chmod(0o600)
    return viewer, editor


def encoded(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def test_cleanup_uses_only_exact_uids_and_proves_absence(tmp_path: Path) -> None:
    viewer, editor = credentials(tmp_path)
    transport = FakeTransport(
        [
            ("GET", RULE_PATH, 200, encoded({"uid": RULE, "isPaused": True})),
            ("GET", FOLDER_PATH, 200, encoded({"uid": FOLDER})),
            ("DELETE", RULE_PATH, 204, b""),
            ("GET", RULE_PATH, 404, b""),
            ("DELETE", FOLDER_PATH, 200, b"{}"),
            ("GET", FOLDER_PATH, 404, b""),
        ]
    )
    result = cleanup_grafana_resources(
        grafana_url="https://example.invalid",
        viewer_token_file=viewer,
        editor_token_file=editor,
        folder_uid=FOLDER,
        rule_uid=RULE,
        transport=transport,
    )
    assert result["cleanup_complete"] is True
    assert result["failure_code"] is None
    assert result["direct_uid_reads_only"] is True
    assert result["global_notification_routing_mutations"] == 0
    assert [item[1] for item in transport.calls] == [
        RULE_PATH,
        FOLDER_PATH,
        RULE_PATH,
        RULE_PATH,
        FOLDER_PATH,
        FOLDER_PATH,
    ]
    serialized = json.dumps(result)
    assert "viewer-private" not in serialized
    assert "editor-private" not in serialized
    assert all(
        "notification" not in item[1] and "alertmanager" not in item[1] for item in transport.calls
    )
    assert not transport.responses


def test_cleanup_retains_partial_failure_after_rule_is_removed(tmp_path: Path) -> None:
    viewer, editor = credentials(tmp_path)
    transport = FakeTransport(
        [
            ("GET", RULE_PATH, 200, encoded({"uid": RULE, "isPaused": True})),
            ("GET", FOLDER_PATH, 200, encoded({"uid": FOLDER})),
            ("DELETE", RULE_PATH, 204, b""),
            ("GET", RULE_PATH, 404, b""),
            ("DELETE", FOLDER_PATH, 503, b"unavailable"),
        ]
    )
    result = cleanup_grafana_resources(
        grafana_url="https://example.invalid",
        viewer_token_file=viewer,
        editor_token_file=editor,
        folder_uid=FOLDER,
        rule_uid=RULE,
        transport=transport,
    )
    assert result["cleanup_complete"] is False
    assert result["failure_code"] == "unexpected-http-503"
    assert result["requests"][-2]["status"] == 404
    assert result["requests"][-1]["status"] == 503
    assert not transport.responses


def test_cleanup_proves_resources_already_absent_without_deletes(tmp_path: Path) -> None:
    viewer, editor = credentials(tmp_path)
    transport = FakeTransport(
        [
            ("GET", RULE_PATH, 404, b""),
            ("GET", FOLDER_PATH, 404, b""),
            ("GET", RULE_PATH, 404, b""),
            ("GET", FOLDER_PATH, 404, b""),
        ]
    )
    result = cleanup_grafana_resources(
        grafana_url="https://example.invalid",
        viewer_token_file=viewer,
        editor_token_file=editor,
        folder_uid=FOLDER,
        rule_uid=RULE,
        transport=transport,
    )
    assert result["cleanup_complete"] is True
    assert all(request["method"] == "GET" for request in result["requests"])
    assert all(request["status"] == 404 for request in result["requests"])
    assert not transport.responses


def test_cleanup_refuses_unpaused_or_mismatched_resources(tmp_path: Path) -> None:
    viewer, editor = credentials(tmp_path)
    transport = FakeTransport(
        [("GET", RULE_PATH, 200, encoded({"uid": "unrelated", "isPaused": False}))]
    )
    result = cleanup_grafana_resources(
        grafana_url="https://example.invalid",
        viewer_token_file=viewer,
        editor_token_file=editor,
        folder_uid=FOLDER,
        rule_uid=RULE,
        transport=transport,
    )
    assert result["cleanup_complete"] is False
    assert result["failure_code"] == "rule-identity-or-state-invalid"
    assert [call[:2] for call in transport.calls] == [("GET", RULE_PATH)]
    assert not transport.responses
