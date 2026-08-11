# ColorTrace

> Evidence-backed color-pipeline incident response with Gemini, Google ADK, and Grafana MCP.

ColorTrace is a focused incident-response system for VFX color pipelines. It investigates a technically successful render that disagrees with an approved reference, correlates operational evidence through Grafana, deterministically proves the color-resource divergence and affected scope, and lets a VFX pipeline TD approve simulator-only recovery.

## Canonical incident

Two workers use the same nominal `config.ocio` and identical config hash. One resolves a stale or shadowed external LUT because its runtime context or search path differs. All jobs succeed, but only work using the affected transform differs from the declared approved reference. A safe job on the implicated worker proves that worker identity alone is not the scope rule.

## Authority model

- **Grafana** is the operational evidence plane for metrics, logs, traces, and alerts.
- **Gemini via Google ADK** is a bounded investigator and planner, never an evidence source or authority.
- **Deterministic validators** decide resource divergence, reference agreement, lineage, and affected scope.
- **The pipeline TD** approves or rejects an exact, versioned response plan and closes the incident.
- **The simulator adapter** is the only action target in the hackathon release.

Missing decisive evidence fails closed as `unresolved`; ColorTrace never guesses a cause or executes an unapproved action.

## Product loop

1. A real Grafana alert opens an incident.
2. The worker queries Grafana through the official OSS `grafana/mcp-grafana` server.
3. Gemini proposes bounded hypotheses and tool requests with evidence citations.
4. Deterministic validators compare runtime color state, image output, and lineage.
5. The workspace shows confirmed, inferred, rejected, and unresolved claims plus affected and verified-safe work.
6. A human reviews an immutable response-plan version.
7. The simulator quarantines the synthetic worker state and rerenders only approved targets.
8. New Grafana evidence and deterministic checks verify recovery; a human closes the incident.

## Architecture

```text
Browser -> Next.js web -> FastAPI API -> Cloud SQL / Cloud Storage / Cloud Tasks
                                             |
                                             v
                              private Cloud Run ADK worker
                                  |                    |
                              Vertex AI        mcp-grafana (stdio)
                                                       |
                                                       v
                                            Grafana Cloud evidence

Simulator -> telemetry/artifacts -> Grafana Cloud / Cloud Storage
Approved plan -> simulator-only action adapter -> recovery telemetry -> verification
```

Production is intentionally locked to separate Cloud Run web, API, worker, and simulator services; Cloud SQL PostgreSQL; Cloud Storage; Cloud Tasks; Artifact Registry; Secret Manager; and Google Identity Platform/OIDC.

## Repository map

- `apps/` — web, API, investigation worker, and deterministic simulator boundaries
- `packages/` — contracts, domain models, validators, and telemetry helpers
- `infra/` — Terraform and Grafana provisioning
- `fixtures/` — generated fixture contract and provenance ledger
- `docs/` — product, architecture, ADR, security, validation, and submission contracts
- `scripts/` — repository policy checks; no product implementation

## Current status

Repository initialization and roadmap only. Product behavior must not be implemented until the M0 feasibility work and **Gate G0** approve the concept and lock scope.

## Safety and compliance boundaries

- Submitted runtime AI is Vertex AI/Gemini only, orchestrated only with Google ADK.
- Grafana MCP is private, authenticated, read-only, least-privilege, and not internet-exposed.
- Logs and tool results are untrusted data, never instructions.
- Evidence is append-only and large artifacts are immutable by digest.
- Approval binds plan hash, incident version, targets, and acknowledged unresolved items; edits invalidate approval.
- Actions are idempotent, simulator-only, and cannot reach production infrastructure.
- Fixtures use procedurally generated or expressly licensed assets with recorded provenance.

See [the product contract](docs/product/product-contract.md), [system architecture](docs/architecture/system.md), [threat model](docs/security/threat-model.md), and [acceptance matrix](docs/validation/acceptance-matrix.md).

## Development

The initial workspace contains policy and structure rather than product code.

```bash
python3 scripts/check_repo.py all
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Planning uses GitHub milestones and issues; there is intentionally no GitHub Project board.

## License

Apache-2.0. Fixture assets and dependencies require separate provenance and compatibility checks before public release.
