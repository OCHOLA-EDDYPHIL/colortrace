# Contributing to ColorTrace

Start work from a GitHub issue and keep each pull request focused on one purpose. Use a short-lived
branch, preserve accepted issue boundaries, and resolve review conversations before merging.

Do not commit credentials, private data, proprietary material, internal URLs, or unlicensed assets.
Report security-sensitive defects privately rather than opening a public issue.

By contributing, you agree that your contribution is licensed under Apache License 2.0 and that you
will follow the project Code of Conduct.

## Development setup

Install Docker and GNU Make. The repository builds its pinned development tool image and stores
reproducible caches under `.cache/`.

```sh
make bootstrap
make check-fast
```

Use `make check` before a change is ready for review. It adds the telemetry integration and secret
scan to the fast suite. `make check-bootstrap` verifies the full setup from a clean local clone.

Do not replace pinned tool, package, image, archive, or provider versions with floating references.
Update the applicable lock, provenance, license, generated-tree, and security policy in the same
change.

## Core invariants

Preserve these boundaries:

- All scenarios and media are generated fixtures. Runtime bundles must not contain the offline
  oracle.
- Gemini and other model output is non-authoritative. Deterministic validators own facts, scope,
  plan bindings, and action admission.
- Only a human can approve a bound action and close a recovery.
- The action executor can mutate only the local simulator and can consume one exact authorization.
- Idempotency keys bind full mutation requests. Replays must return the original result, and changed
  requests must fail closed.
- A terminal receipt is immutable. Reset restores the authored scenario but does not change the
  prior receipt.
- Grafana MCP stays read-only, uses `stdio`, and accepts only cataloged queries.
- The hosted edge exposes only the application and demo facade behind TLS and the access gate.
  Grafana, observability services, metadata, health routes, and general APIs remain private.

Add tests for authorization failure, stale bindings, retries, response loss, restart recovery,
concurrency, and malformed input when a change touches those paths.

## Contracts and generated files

Treat checked-in schemas, OpenAPI documents, lockfiles, policy files, and generated clients as
canonical contracts. Update the source contract first. Then run:

```sh
make generate
make check-contract
make check-generated
```

Do not edit generated clients or generated fixture artifacts by hand. Use `make generate-fixture`
for the canonical local fixture. Keep the generated runtime bundle under `.cache/`; keep the offline
oracle separate from any runtime or image context.

When a change affects the browser workflow, run the web unit tests and the Playwright suite in the
pinned environment. Check both the desktop and small-viewport layouts, keyboard flow, reduced
motion, accessible names, and fail-closed recovery states.

```sh
pnpm --filter @colortrace/web test
pnpm --filter @colortrace/web test:browser
```

## Hosted infrastructure changes

The active gated topology is `infra/single-host`. The `infra/staging` module is a separate
distributed design and is not interchangeable with the single-host profile.

An infrastructure change must preserve the build-to-scan-to-admission digest chain, immutable image
references, the dedicated network, public-port limits, IAP and OS Login access, service-account and
operator separation, the custom Vertex prediction role, the metadata firewall, secret-version
binding, persistent state, strict cost-estimate admission, and the fail-closed seven-day lifecycle.
Run:

```sh
make check-terraform
```

Never apply Terraform from a dirty worktree. Keep backend configuration, variable files, plans,
cloud identifiers, hosted addresses, credentials, and verification receipts outside tracked files.

## Documentation and diagrams

Document only behavior that exists in the same revision. Keep environment-specific values and
operational records in private artifacts.

The single-host diagram has three synchronized forms:

- `docs/architecture/single-host.mmd` is the Mermaid source.
- `docs/architecture/single-host.drawio` is the editable draw.io source.
- `docs/architecture/single-host.svg` is the rendered repository image.

If the topology changes, update all three files in one change. Preserve the same components, trust
boundaries, arrows, and connection labels in each form. Inspect the SVG after export and validate
both XML files before review.

## Change hygiene

- Keep unrelated local changes intact.
- Use `.cache/` for private reports and generated operator files.
- Do not add assistant-specific instructions or local workflow state to the repository.
- Review staged content for secrets, private endpoints, private identifiers, and transient status
  language before each commit.
