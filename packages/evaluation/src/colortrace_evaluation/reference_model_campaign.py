from __future__ import annotations

import asyncio
import sys
from argparse import ArgumentParser
from pathlib import Path

from colortrace_investigation import AdkVertexGateway, ModelFailure

from .contracts import ContractError, canonical_json_bytes, write_exclusive
from .reference_campaign import (
    ReferenceCampaignError,
    record_reference_model_selections,
    run_recorded_reference_campaign,
    sealed_reference_holdouts,
)


async def _run(project_id: str) -> tuple[dict[str, object], dict[str, object]]:
    corpus = sealed_reference_holdouts()
    receipts = await record_reference_model_selections(
        model=AdkVertexGateway(project_id=project_id),
        corpus=corpus,
    )
    return receipts.to_dict(), run_recorded_reference_campaign(receipts, corpus)


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-model-campaign")
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--receipt-set-output", required=True, type=Path)
    parser.add_argument("--campaign-report-output", required=True, type=Path)
    arguments = parser.parse_args()
    receipt_path = arguments.receipt_set_output.resolve(strict=False)
    campaign_path = arguments.campaign_report_output.resolve(strict=False)
    if receipt_path == campaign_path or receipt_path.exists() or campaign_path.exists():
        print("reference-recorded-selection-output-exists", file=sys.stderr)
        raise SystemExit(2)
    try:
        receipts, campaign = asyncio.run(_run(arguments.project_id))
        write_exclusive(receipt_path, receipts)
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
