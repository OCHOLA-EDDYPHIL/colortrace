from __future__ import annotations

import asyncio
import sys
from argparse import ArgumentParser
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from colortrace_investigation import AdkVertexGateway, ModelFailure

from .contracts import ContractError, canonical_json_bytes, write_exclusive
from .reference_campaign import (
    RecordedSelectionReceiptSet,
    ReferenceCampaignError,
    record_reference_model_selections,
    run_recorded_reference_campaign,
    sealed_reference_holdouts,
)


async def _run(
    project_id: str,
    *,
    receipt_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> RecordedSelectionReceiptSet:
    corpus = sealed_reference_holdouts()
    receipts = await record_reference_model_selections(
        model=AdkVertexGateway(project_id=project_id),
        corpus=corpus,
        receipt_callback=receipt_callback,
    )
    return receipts


def _prepare_attempt_journal(path: Path) -> Callable[[Mapping[str, Any]], None]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ContractError("output-exists") from error
    except OSError as error:
        raise ContractError("attempt-journal-create-failed") from error
    attempt_number = 0

    def persist(receipt: Mapping[str, Any]) -> None:
        nonlocal attempt_number
        attempt_number += 1
        write_exclusive(path / f"{attempt_number:03d}.json", receipt)

    return persist


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-model-campaign")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--receipt-set-output", required=True, type=Path)
    parser.add_argument("--campaign-report-output", required=True, type=Path)
    arguments = parser.parse_args()
    receipt_path = arguments.receipt_set_output.resolve(strict=False)
    campaign_path = arguments.campaign_report_output.resolve(strict=False)
    journal_path = receipt_path.with_name(f"{receipt_path.name}.attempts")
    paths = (receipt_path, campaign_path, journal_path)
    overlaps = any(
        left == right or left in right.parents or right in left.parents
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    )
    if overlaps or receipt_path.exists() or campaign_path.exists() or journal_path.exists():
        print("reference-recorded-selection-output-exists", file=sys.stderr)
        raise SystemExit(2)
    try:
        receipt_callback = _prepare_attempt_journal(journal_path)
        receipts = asyncio.run(_run(arguments.project_id, receipt_callback=receipt_callback))
        write_exclusive(receipt_path, receipts.to_dict())
        campaign = run_recorded_reference_campaign(receipts)
        write_exclusive(campaign_path, campaign)
    except (ContractError, ModelFailure, ReferenceCampaignError) as error:
        code = getattr(error, "code", str(error))
        print(code, file=sys.stderr)
        raise SystemExit(2) from error
    print(canonical_json_bytes(campaign).decode("utf-8"))
    if not campaign["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
