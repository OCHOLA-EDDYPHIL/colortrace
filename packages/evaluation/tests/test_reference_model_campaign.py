from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from colortrace_evaluation import reference_model_campaign
from colortrace_evaluation.contracts import strict_json_file
from colortrace_evaluation.reference_campaign import ReferenceCampaignError


class _FakeReceiptSet:
    def to_dict(self) -> dict[str, object]:
        return {"schema": "test-receipts"}


def test_cli_journals_each_attempt_before_writing_final_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipts_path = tmp_path / "receipts.json"
    campaign_path = tmp_path / "campaign.json"
    journal_path = tmp_path / "receipts.json.attempts"

    async def fake_run(
        project_id: str,
        *,
        receipt_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> _FakeReceiptSet:
        assert project_id == "test-project"
        assert receipt_callback is not None
        receipt_callback({"case_id": "case-001", "outcome": "accepted-query"})
        assert strict_json_file(journal_path / "001.json") == {
            "case_id": "case-001",
            "outcome": "accepted-query",
        }
        assert not receipts_path.exists()
        assert not campaign_path.exists()
        return _FakeReceiptSet()

    monkeypatch.setattr(
        reference_model_campaign,
        "run_recorded_reference_campaign",
        lambda _receipts: {"passed": True},
    )

    monkeypatch.setattr(reference_model_campaign, "_run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "colortrace-reference-model-campaign",
            "--project-id",
            "test-project",
            "--receipt-set-output",
            str(receipts_path),
            "--campaign-report-output",
            str(campaign_path),
        ],
    )

    reference_model_campaign.main()

    assert json.loads(receipts_path.read_text()) == {"schema": "test-receipts"}
    assert json.loads(campaign_path.read_text()) == {"passed": True}


def test_cli_preserves_journal_and_aggregate_when_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipts_path = tmp_path / "receipts.json"
    campaign_path = tmp_path / "campaign.json"
    journal_path = tmp_path / "receipts.json.attempts"

    async def fake_run(
        _project_id: str,
        *,
        receipt_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> _FakeReceiptSet:
        assert receipt_callback is not None
        receipt_callback({"case_id": "case-001", "outcome": "domain-rejection"})
        return _FakeReceiptSet()

    def fail_verification(_receipts: object) -> dict[str, object]:
        assert receipts_path.exists()
        raise ReferenceCampaignError("verification-failed")

    monkeypatch.setattr(reference_model_campaign, "_run", fake_run)
    monkeypatch.setattr(
        reference_model_campaign,
        "run_recorded_reference_campaign",
        fail_verification,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "colortrace-reference-model-campaign",
            "--project-id",
            "test-project",
            "--receipt-set-output",
            str(receipts_path),
            "--campaign-report-output",
            str(campaign_path),
        ],
    )

    with pytest.raises(SystemExit) as caught:
        reference_model_campaign.main()

    assert caught.value.code == 2
    assert strict_json_file(receipts_path) == {"schema": "test-receipts"}
    assert strict_json_file(journal_path / "001.json") == {
        "case_id": "case-001",
        "outcome": "domain-rejection",
    }
    assert not campaign_path.exists()


def test_cli_attempt_journal_is_exclusive(tmp_path: Path) -> None:
    journal_path = tmp_path / "attempts"
    reference_model_campaign._prepare_attempt_journal(journal_path)

    with pytest.raises(ValueError, match="output-exists"):
        reference_model_campaign._prepare_attempt_journal(journal_path)


@pytest.mark.parametrize("campaign_relative", ("receipts.json/child.json", "."))
def test_cli_rejects_overlapping_output_topology_before_model_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    campaign_relative: str,
) -> None:
    receipts_path = tmp_path / "receipts.json"
    campaign_path = tmp_path / campaign_relative
    invoked = False

    async def forbidden_run(*_args: object, **_kwargs: object) -> _FakeReceiptSet:
        nonlocal invoked
        invoked = True
        return _FakeReceiptSet()

    monkeypatch.setattr(reference_model_campaign, "_run", forbidden_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "colortrace-reference-model-campaign",
            "--project-id",
            "test-project",
            "--receipt-set-output",
            str(receipts_path),
            "--campaign-report-output",
            str(campaign_path),
        ],
    )

    with pytest.raises(SystemExit) as caught:
        reference_model_campaign.main()

    assert caught.value.code == 2
    assert invoked is False
    assert not receipts_path.exists()
    assert not receipts_path.with_name("receipts.json.attempts").exists()
