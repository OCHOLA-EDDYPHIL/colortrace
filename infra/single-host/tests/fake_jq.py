#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


def _arguments() -> tuple[bool, bool, dict[str, str], dict[str, list[Any]], list[str]]:
    raw = False
    null_input = False
    values: dict[str, str] = {}
    files: dict[str, list[Any]] = {}
    positional: list[str] = []
    index = 1
    while index < len(sys.argv):
        value = sys.argv[index]
        if value in {"-e", "-r", "-er", "-re"}:
            raw = raw or "r" in value
            index += 1
        elif value == "-n":
            null_input = True
            index += 1
        elif value == "--arg":
            values[sys.argv[index + 1]] = sys.argv[index + 2]
            index += 3
        elif value == "--slurpfile":
            files[sys.argv[index + 1]] = [
                json.loads(Path(sys.argv[index + 2]).read_text(encoding="utf-8"))
            ]
            index += 3
        else:
            positional.append(value)
            index += 1
    return raw, null_input, values, files, positional


def _build_manifest(document: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    components = ("runtime", "web", "caddy", "grafana", "loki", "tempo")
    build_paths: dict[str, tuple[str, str | None]] = {
        "runtime": ("Dockerfile.runtime", "runtime"),
        "web": ("Dockerfile.web", None),
        "caddy": ("Dockerfile.caddy", None),
        "grafana": ("Dockerfile.observability", "grafana"),
        "loki": ("Dockerfile.observability", "loki"),
        "tempo": ("Dockerfile.observability", "tempo"),
    }
    if (
        document.get("id") != values["build_id"]
        or document.get("status") != "SUCCESS"
        or document.get("serviceAccount") != values["service_account"]
        or document.get("substitutions", {}).get("_REGISTRY") != values["registry"]
        or document.get("substitutions", {}).get("_SOURCE_COMMIT") != values["source_commit"]
        or document.get("substitutions", {}).get("_SOURCE_TREE") != values["source_tree"]
        or document.get("substitutions", {}).get("_SOURCE_DATE_EPOCH")
        != values["source_date_epoch"]
    ):
        raise ValueError
    images: dict[str, dict[str, str]] = {}
    for component in components:
        tag = f"{values['registry']}/{component}:{values['source_commit']}"
        matches = [value for value in document["results"]["images"] if value["name"] == tag]
        if len(matches) != 1 or re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]["digest"]) is None:
            raise ValueError
        digest = matches[0]["digest"]
        images[component] = {
            "dockerfile": build_paths[component][0],
            "target": build_paths[component][1],
            "tag": tag,
            "digest": digest,
            "reference": f"{values['registry']}/{component}@{digest}",
        }
    return {
        "schema": "colortrace-single-host-image-build/v2",
        "build": {
            "id": values["build_id"],
            "project": values["project_id"],
            "region": values["region"],
            "service_account": values["service_account"],
            "registry": values["registry"],
            "config_sha256": values["build_config_sha256"],
            "create_time": document.get("createTime"),
            "finish_time": document.get("finishTime"),
        },
        "source": {
            "commit": values["source_commit"],
            "tree": values["source_tree"],
            "date_epoch": int(values["source_date_epoch"]),
        },
        "fixture_manifest_sha256": values["fixture_manifest_sha256"],
        "images": images,
    }


def main() -> int:
    raw, null_input, values, files, positional = _arguments()
    expression = positional[0]
    document = None
    if not null_input:
        document = json.loads(
            Path(positional[1]).read_text(encoding="utf-8")
            if len(positional) == 2
            else sys.stdin.read()
        )

    try:
        if "def image_result" in expression:
            result: Any = _build_manifest(document, values)
        elif expression == ".status":
            result = document["status"]
        elif "colortrace-staging-generation" in expression:
            result = next(
                item["value"]
                for item in document["metadata"]["items"]
                if item["key"] == "colortrace-staging-generation"
            )
        elif expression == ".source.commit":
            result = document["source"]["commit"]
        elif expression == ".source_commit":
            result = document["source_commit"]
        elif expression == '.files["runtime/manifests/fixture-runtime-manifest.json"]':
            result = document["files"]["runtime/manifests/fixture-runtime-manifest.json"]
        elif expression.startswith(".images[$component]."):
            result = document["images"][values["component"]][expression.rsplit(".", 1)[1]]
        elif expression == ".upstream.prometheus.index_digest":
            result = document["upstream"]["prometheus"]["index_digest"]
        elif "colortrace-single-host-image-build/v2" in expression:
            result = (
                document["schema"] == "colortrace-single-host-image-build/v2"
                and re.fullmatch(r"[0-9a-f]{40}", document["source"]["commit"]) is not None
                and re.fullmatch(r"[0-9a-f]{40}", document["source"]["tree"]) is not None
                and sorted(document["images"])
                == ["caddy", "grafana", "loki", "runtime", "tempo", "web"]
            )
        elif '.UpdatedAt == "2026-08-22' in expression:
            result = (
                document.get("Version") == 2
                and document.get("UpdatedAt") == "2026-08-22T12:57:22.518776499Z"
                and document.get("NextUpdate") == "2026-08-23T12:57:22.518775968Z"
                and isinstance(document.get("DownloadedAt"), str)
                and bool(document["DownloadedAt"])
            )
        elif ".UpdatedAt | type" in expression:
            result = document.get("Version") == 2 and isinstance(document.get("UpdatedAt"), str)
        elif ".Results | type" in expression:
            result = isinstance(document.get("Results"), list) and not any(
                vulnerability
                for item in document["Results"]
                for vulnerability in item.get("Vulnerabilities") or []
            )
        elif "$before[0]" in expression:
            result = (
                document.get("schema") == "colortrace-demo-receipt/v1"
                and document == files["before"][0]
            )
        elif "colortrace-demo-receipt/v1" in expression:
            result = (
                document.get("schema") == "colortrace-demo-receipt/v1"
                and document.get("run_id") == values["run_id"]
                and re.fullmatch(r"[0-9a-f]{40}", document.get("source_commit", "")) is not None
                and re.fullmatch(r"sha256:[0-9a-f]{64}", document.get("receipt_sha256", ""))
                is not None
                and bool(document.get("terminal_at"))
            )
        elif "colortrace-single-host-image-scan/v1" in expression:
            build = files["build"][0]
            images = dict(build["images"])
            images["prometheus"] = {
                "reference": values["prometheus_reference"],
                "upstream": files["observability"][0]["upstream"]["prometheus"],
            }
            result = {
                "schema": "colortrace-single-host-image-scan/v1",
                "source": build["source"],
                "scanner_image": values["scanner_image"],
                "databases": {
                    "current": {"content_sha256": values["current_database_sha256"]},
                    "frozen": {
                        "image": values["frozen_database_image"],
                        "content_sha256": values["frozen_database_sha256"],
                    },
                },
                "images": images,
                "severities": ["HIGH", "CRITICAL"],
                "vulnerability_ignores": False,
                "result": "pass",
            }
        elif "colortrace-single-host-verification/v1" in expression:
            receipt = files["receipt"][0]
            result = {
                "schema": "colortrace-single-host-verification/v1",
                "checked_at": values["checked_at"],
                "public_url": values["public_url"],
                "instance": {
                    "project": values["project"],
                    "zone": values["zone"],
                    "name": values["instance"],
                },
                "staging_generation": values["generation"],
                "source_commit": receipt["source_commit"],
                "run_id": receipt["run_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "checks": {
                    "tls": "pass",
                    "access_gate": "pass",
                    "malformed_request": "pass",
                    "wrong_origin": "pass",
                    "general_api_private": "pass",
                    "runtime_health_after_restart": "pass",
                    "runtime_image_binding": "pass",
                    "grafana_mcp_inventory_after_restart": "pass",
                    "receipt_persistence_after_restart": "pass",
                },
            }
        else:
            raise ValueError
    except (KeyError, StopIteration, TypeError, ValueError):
        return 1

    if result is False or result is None:
        return 1
    if raw and isinstance(result, str):
        print(result)
    else:
        print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
