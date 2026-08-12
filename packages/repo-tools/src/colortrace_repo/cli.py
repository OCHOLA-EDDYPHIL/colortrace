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
from colortrace_repo.generated import check_generated_manifest, compare_generated_trees


def _path(root: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


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
        return check_generated_manifest(root, _path(root, args.manifest))
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
        return check_binary_assets(root, _path(root, args.policy))
    if args.command == "check":
        findings: list[Finding] = []
        findings.extend(check_contracts(root))
        findings.extend(check_generated_manifest(root))
        findings.extend(check_dependencies(root))
        findings.extend(check_ai_policy(root))
        findings.extend(check_actions(root))
        findings.extend(check_binary_assets(root))
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
