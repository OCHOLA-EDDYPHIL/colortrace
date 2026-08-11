# Deployment architecture

## Locked Google Cloud topology

- Cloud Run: separate `web`, `api`, `worker`, and `simulator` services
- Cloud SQL for PostgreSQL: canonical incidents, evidence metadata, claims, plans, approvals, actions, and audit ledger
- Cloud Storage: digest-addressed images, manifests, diffs, and large evidence artifacts
- Cloud Tasks: bounded asynchronous investigation, execution, and verification delivery
- Vertex AI: pinned stable Gemini Flash model
- Artifact Registry: versioned service images
- Secret Manager: Grafana token, database credentials where needed, signing/configuration secrets
- Identity Platform/OIDC: operator identity and authenticated mutation path
- Grafana Cloud: Metrics, Loki, Tempo, Alerting; optional IRM projection

## Service exposure

| Service | Exposure | Authentication |
|---|---|---|
| web | public | read-only public view; OIDC for operator controls |
| API reads | public, rate-limited | public prepared-demo reads; OIDC for non-public data |
| API mutations | public endpoint | valid OIDC identity and authorization policy |
| worker | private | Cloud Tasks OIDC service identity/audience |
| simulator | private | authorized API/worker service identity plus approved command |
| MCP server | no network listener initially | stdio child of worker; Grafana service-account token outbound |

## Persistence boundaries

PostgreSQL is canonical for workflow state and metadata. Storage objects are immutable and named or verified by digest; database rows reference them. Grafana is canonical for operational observations but not incident approval state. IRM, if added, mirrors incident state and never becomes an authority dependency.

## Cloud Tasks contract

Tasks use stable names/idempotency keys, signed/OIDC-authenticated delivery, expected aggregate version, payload digest, short processing endpoint, bounded retry/dead-letter policy, and durable attempt records. Duplicate delivery returns the prior outcome. No task payload contains credentials or large artifacts.

## Networking and secrets

Use least-privilege service accounts per service, private database connectivity, constrained egress where practical, Secret Manager references rather than environment literals, and redaction at ingress and logging boundaries. The MCP process receives only the read-only Grafana credential and an allow-listed tool configuration.

## Environments

Local, test, and hosted demo environments use distinct projects/datasets/tokens and synthetic data. Terraform defines hosted infrastructure; manual console changes are documented and eliminated before release candidate. No paid resource is provisioned during repository initialization.

## Public-readiness conditions

Before making the repository public: purge secrets/private research, verify history, resolve licenses and asset provenance, pin dependencies/images, reproduce the fixture and deployment from clean instructions, scan SBOM and endpoints for disallowed AI providers, and confirm no internal URLs or production identifiers exist.

## Disaster and rollback behavior

Deploy immutable image revisions and retain the judged revision. Schema migrations are forward-safe and tested against rollback constraints. A failed deploy routes no action traffic until health and authorization tests pass. Post-submission changes are limited to catastrophic security/availability fixes and are documented.
