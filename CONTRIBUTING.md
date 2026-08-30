# Contributing to ColorTrace

Start from a GitHub issue and keep each pull request focused on one purpose. Use a short-lived
branch, preserve the accepted product and safety boundaries, and resolve review conversations
before merging.

Do not commit credentials, private data, internal URLs, proprietary material, or unlicensed
assets. Report security-sensitive defects through the private channel described in
[SECURITY.md](SECURITY.md).

By contributing, you agree that your contribution is licensed under Apache License 2.0 and that
you will follow the project Code of Conduct.

## Development setup

Install Docker and GNU Make. The repository builds a pinned development toolchain and stores local
caches under `.cache/`.

```sh
make bootstrap
make check-fast
```

Run `make check` before a change is ready for review. Use `make check-bootstrap` when a change
affects first-time setup.

Keep tool, package, image, archive, and provider versions pinned. Update the related lock,
provenance, license, generated-tree, and policy files in the same change.

## Product and authority invariants

Preserve these boundaries:

- All scenarios and media are generated fixtures. Runtime bundles do not contain the offline
  oracle.
- Gemini and other model output is advisory. Deterministic validators own the facts, scope, plan,
  and action admission.
- Only a human can approve a bound recovery and confirm closure.
- The executor can change only the local simulator and can consume one exact authorization.
- Retries return the original mutation result. A changed request with the same identity fails
  closed.
- A terminal receipt is immutable. Reset restores the authored scenario without changing the
  prior receipt.
- Grafana MCP uses `stdio`, stays read-only, and accepts only cataloged queries.
- The hosted edge exposes only the application and demo facade. Runtime administration,
  observability services, metadata, and health routes remain private.

When a change touches these paths, add focused tests for the relevant failure, stale-data, retry,
response-loss, restart, concurrency, and malformed-input behavior.

## Contracts and generated files

Checked-in schemas, OpenAPI documents, lockfiles, policy files, and generated clients are
contracts. Update the source contract first, then run:

```sh
make generate
make check-contract
make check-generated
```

Do not edit generated clients or fixture artifacts by hand. Use `make generate-fixture` for the
canonical local fixture. Keep generated runtime bundles under `.cache/`, with the offline oracle
outside every runtime and image context.

For browser changes, run the web unit and Playwright suites. These commands run on the host and
require the Node 24.19.0 and pnpm 11.21.0 versions declared in `package.json`, installed workspace
dependencies, and Playwright's Chromium browser. Check desktop and small-viewport layouts,
keyboard flow, reduced motion, accessible names, and fail-closed recovery states.

```sh
pnpm --filter @colortrace/web test
pnpm --filter @colortrace/web test:browser
```

## Container definitions

The six definitions in [`containers`](containers) have one job each:

| Definition | Role |
| --- | --- |
| `Dockerfile.dev` | Pinned development, quality, and security tools. |
| `Dockerfile.demo` | Network-isolated command-line demonstration. |
| `Dockerfile.runtime` | Single-host API, recovery workflow, and Grafana MCP process. |
| `Dockerfile.web` | React application and its small web server. |
| `Dockerfile.caddy` | TLS and access-control edge. |
| `Dockerfile.observability` | Separate Grafana, Loki, and Tempo build targets. |

All six builds use the repository root as their context because they copy files from several
packages and policy directories. Select a definition explicitly:

```sh
docker build --file containers/Dockerfile.web .
```

Each definition has an adjacent `.dockerignore` file that limits its inputs. Keep that file aligned
with the definition when inputs change. Do not move package code into `containers` to make a build
look self-contained.

## Single-host infrastructure

The active gated topology is `infra/single-host`. An infrastructure change must preserve the
dedicated network, one public TLS port, IAP and OS Login access, separate operator identities, the
restricted Vertex prediction role, the metadata firewall, immutable image admission, persistent
state, cost-estimate check, and fail-closed seven-day lifecycle.

Run:

```sh
make check-terraform
```

Never apply Terraform from a dirty worktree. Keep backend settings, variable files, plans, cloud
identifiers, hosted addresses, credentials, and operator reports outside tracked files.

## Documentation and diagrams

Document only behavior that exists in the same revision. Use concise language and keep private or
environment-specific values out of the repository.

Graphviz `.dot` files in `docs/architecture` are the editable sources for the product and system
diagrams. Update the matching SVG in the same change and inspect the rendered result.

## Change hygiene

- Keep unrelated local changes intact.
- Use `.cache/` for generated operator files and private reports.
- Do not add assistant-specific instructions or local workflow state to the repository.
- Review staged content for secrets, private endpoints, private identifiers, and temporary status
  language before each commit.
