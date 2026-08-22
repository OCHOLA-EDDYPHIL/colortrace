from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from colortrace_repo.actions import check_actions
from colortrace_repo.ai_policy import check_ai_policy
from colortrace_repo.binary_assets import check_binary_assets
from colortrace_repo.common import Finding, sorted_findings
from colortrace_repo.contracts import check_contracts
from colortrace_repo.dependencies import check_dependencies
from colortrace_repo.deployment import check_deployment
from colortrace_repo.distribution import check_distribution_wheels, check_package_metadata
from colortrace_repo.final_image_evidence import (
    ImageEvidenceInput,
    build_final_image_evidence,
)
from colortrace_repo.generated import check_generated_manifest, compare_generated_trees
from colortrace_repo.security_evidence import (
    finalize_security_evidence,
    prepare_security_evidence,
)


def _path(root: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _unresolved_path(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        dest="command_root",
        metavar="PATH",
        help="repository root (may also be passed before the subcommand)",
    )
    parser.add_argument(
        "--format",
        dest="command_format",
        choices=("text", "json"),
        help="diagnostic output format",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="colortrace-repo")
    parser.add_argument("--root", default=".", metavar="PATH", help="repository root")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    subparsers = parser.add_subparsers(dest="command", required=True)

    contracts = subparsers.add_parser("contracts", help="validate repository contracts")
    _add_common_arguments(contracts)
    contracts.add_argument(
        "--directory",
        metavar="PATH",
        help="contract directory (default: packages/contracts)",
    )

    generated = subparsers.add_parser(
        "generated", help="compare generated output with its tracked tree"
    )
    _add_common_arguments(generated)
    generated.add_argument("--expected", metavar="PATH", help="tracked generated tree")
    generated.add_argument("--actual", metavar="PATH", help="freshly generated candidate tree")
    generated.add_argument(
        "--manifest",
        metavar="PATH",
        help="tree-pair manifest (default: policy/generated-trees.json)",
    )

    dependencies = subparsers.add_parser(
        "dependencies", help="validate dependency licenses and provenance"
    )
    _add_common_arguments(dependencies)
    dependencies.add_argument("--policy", metavar="PATH", help="dependency policy JSON")
    dependencies.add_argument("--inventory", metavar="PATH", help="license inventory JSON")

    ai_policy = subparsers.add_parser("ai-policy", help="validate the runtime AI boundary")
    _add_common_arguments(ai_policy)
    ai_policy.add_argument("--policy", metavar="PATH", help="AI boundary policy JSON")

    actions = subparsers.add_parser("actions", help="validate immutable action references")
    _add_common_arguments(actions)

    binaries = subparsers.add_parser(
        "binary-assets", help="validate registered binary asset provenance"
    )
    _add_common_arguments(binaries)
    binaries.add_argument("--policy", metavar="PATH", help="binary asset policy JSON")

    deployment = subparsers.add_parser(
        "deployment", help="validate immutable Google Cloud deployment sources"
    )
    _add_common_arguments(deployment)

    distribution = subparsers.add_parser(
        "distribution", help="validate first-party license metadata"
    )
    _add_common_arguments(distribution)

    distribution_wheels = subparsers.add_parser(
        "distribution-wheels", help="verify first-party wheel license payloads"
    )
    _add_common_arguments(distribution_wheels)
    distribution_wheels.add_argument("--directory", required=True, metavar="PATH")

    security_prepare = subparsers.add_parser(
        "security-prepare", help="create deterministic security evidence inputs"
    )
    _add_common_arguments(security_prepare)
    security_prepare.add_argument("--output", required=True, metavar="PATH")

    security_finalize = subparsers.add_parser(
        "security-finalize", help="seal exact-candidate security evidence"
    )
    _add_common_arguments(security_finalize)
    security_finalize.add_argument("--output", required=True, metavar="PATH")
    security_finalize.add_argument("--candidate-sha", required=True)
    security_finalize.add_argument("--candidate-tree", required=True)
    security_finalize.add_argument("--scanner-image", required=True)
    security_finalize.add_argument("--scanner-metadata", required=True)
    security_finalize.add_argument("--secret-scanner-image", required=True)

    image_evidence = subparsers.add_parser(
        "image-evidence", help="verify and enrich exact final-image evidence"
    )
    _add_common_arguments(image_evidence)
    image_evidence.add_argument("--output", required=True, metavar="PATH")
    image_evidence.add_argument("--candidate-sha", required=True)
    image_evidence.add_argument("--candidate-tree", required=True)
    image_evidence.add_argument("--scanner-image", required=True)
    for name in ("runtime", "hosted-runtime", "web"):
        image_evidence.add_argument(f"--{name}-archive", required=True, metavar="PATH")
        image_evidence.add_argument(f"--{name}-bundle", required=True, metavar="PATH")
        image_evidence.add_argument(f"--{name}-sbom", required=True, metavar="PATH")
        image_evidence.add_argument(f"--{name}-reference", required=True)

    check = subparsers.add_parser("check", help="run every repository policy check")
    _add_common_arguments(check)
    return parser


def _run(args: argparse.Namespace, root: Path) -> list[Finding]:
    if args.command == "contracts":
        return check_contracts(root, _path(root, args.directory))
    if args.command == "generated":
        if args.actual is not None:
            expected = args.expected or "packages/api-client/src/generated"
            return compare_generated_trees(root, _path(root, expected), _path(root, args.actual))  # type: ignore[arg-type]
        if args.expected is not None:
            return [
                Finding(
                    args.expected,
                    "generated.arguments",
                    "--expected requires --actual",
                )
            ]
        manifest = _unresolved_path(root, args.manifest) if args.manifest is not None else None
        return check_generated_manifest(root, manifest)
    if args.command == "dependencies":
        return check_dependencies(
            root,
            _path(root, args.policy),
            _path(root, args.inventory),
        )
    if args.command == "ai-policy":
        return check_ai_policy(root, _path(root, args.policy))
    if args.command == "actions":
        return check_actions(root)
    if args.command == "binary-assets":
        policy = _unresolved_path(root, args.policy) if args.policy is not None else None
        return check_binary_assets(root, policy)
    if args.command == "deployment":
        return check_deployment(root)
    if args.command == "distribution":
        return check_package_metadata(root)
    if args.command == "distribution-wheels":
        return check_distribution_wheels(
            root,
            _unresolved_path(root, args.directory),
        )
    if args.command == "security-prepare":
        return prepare_security_evidence(root, _path(root, args.output))  # type: ignore[arg-type]
    if args.command == "security-finalize":
        return finalize_security_evidence(
            root,
            _path(root, args.output),  # type: ignore[arg-type]
            candidate_sha=args.candidate_sha,
            candidate_tree=args.candidate_tree,
            scanner_image=args.scanner_image,
            scanner_metadata=args.scanner_metadata,
            secret_scanner_image=args.secret_scanner_image,
        )
    if args.command == "image-evidence":
        images = tuple(
            ImageEvidenceInput(
                name=name,
                archive=_unresolved_path(root, getattr(args, name.replace("-", "_") + "_archive")),
                bundle=_unresolved_path(root, getattr(args, name.replace("-", "_") + "_bundle")),
                raw_sbom=_unresolved_path(root, getattr(args, name.replace("-", "_") + "_sbom")),
                expected_reference=getattr(args, name.replace("-", "_") + "_reference"),
            )
            for name in ("runtime", "hosted-runtime", "web")
        )
        return build_final_image_evidence(
            root,
            _path(root, args.output),  # type: ignore[arg-type]
            candidate_sha=args.candidate_sha,
            candidate_tree=args.candidate_tree,
            scanner_image=args.scanner_image,
            images=images,
        )
    if args.command == "check":
        findings: list[Finding] = []
        findings.extend(check_contracts(root))
        findings.extend(check_generated_manifest(root))
        findings.extend(check_dependencies(root))
        findings.extend(check_ai_policy(root))
        findings.extend(check_actions(root))
        findings.extend(check_binary_assets(root))
        findings.extend(check_deployment(root))
        findings.extend(check_package_metadata(root))
        return sorted_findings(findings)
    raise AssertionError(f"unhandled command {args.command!r}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root_value = args.command_root if args.command_root is not None else args.root
    output_format = args.command_format if args.command_format is not None else args.format
    root = Path(root_value).resolve()
    findings = sorted_findings(_run(args, root))
    if output_format == "json":
        json.dump(
            {
                "command": args.command,
                "findings": [finding.as_dict() for finding in findings],
                "ok": not findings,
            },
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
    elif findings:
        for finding in findings:
            print(finding.render(), file=sys.stderr)
    else:
        print(f"colortrace-repo {args.command}: ok")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
