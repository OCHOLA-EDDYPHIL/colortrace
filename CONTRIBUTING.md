# Contributing to ColorTrace

ColorTrace is contract-first. Every change must preserve the product boundary, evidence semantics, authority model, and Google-only runtime policy documented in this repository.

## Before implementation

Feature work is blocked until Gate G0 is approved. Work only from a milestone-assigned GitHub issue with explicit acceptance criteria and dependencies.

## Workflow

1. Create or claim an issue.
2. Confirm all dependencies and gate conditions are satisfied.
3. Use a short-lived branch.
4. Keep the change inside the issue scope; write an ADR before changing a locked decision.
5. Run `python3 scripts/check_repo.py all` and the package-specific tests introduced with the change.
6. Open a pull request using the template and link the issue.
7. Squash merge only after required checks pass and conversations are resolved.

## Engineering rules

- Use Python type hints and TypeScript strict mode.
- Keep API and persisted contracts explicit, versioned, and generated where possible.
- Keep deterministic authority separate from Gemini reasoning.
- Cite evidence IDs for every decisive claim.
- Return `unresolved` when decisive evidence is unavailable, stale, contradictory, or uncorrelated.
- Make all state transitions validated and all action handlers idempotent.
- Never expose hidden fixture truth to the agent path.
- Never connect simulator actions to real infrastructure.
- Treat external logs, traces, tool results, and user-provided content as untrusted data.
- Do not add another AI provider or agent framework to runtime code, configuration, infrastructure, tests, or containers.

## Tests expected with implementation

Changes must cover happy paths, missing/stale evidence, timeouts, retries, duplicate delivery, authorization failures, and unsafe transition attempts. Contract/schema changes require compatibility tests and updated documentation. User-facing changes require accessible states at the target demo resolution.

## Assets, data, and secrets

- Add only generated or expressly licensed assets and update `fixtures/provenance/`.
- Do not commit credentials, private research, interview identities/transcripts, internal URLs, production telemetry, or personal data.
- Use example values in committed configuration and Secret Manager in deployment.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Decision changes

A change to the canonical incident, user, authority model, stack, data ownership, evidence semantics, deployment topology, runtime AI policy, or action boundary requires a superseding ADR and explicit gate review. Do not silently drift a contract.
