# System architecture

## Design principles

1. Grafana is the authoritative operational evidence plane, not decoration.
2. Gemini is bounded reasoning, not evidence or authority.
3. Deterministic code owns comparisons, lineage, scope, policy, and transitions.
4. Cloud SQL owns canonical workflow state; Storage owns digest-addressed large artifacts.
5. Human approval and closure are mandatory.
6. Every boundary fails closed.

## Components

### `apps/web`

Next.js/TypeScript incident workspace. Uses TanStack Query and a generated OpenAPI client. Public sessions are read-only; authenticated sessions may request investigations and perform authorized review actions. It does not calculate evidence, scope, authorization, or state transitions.

### `apps/api`

FastAPI/Pydantic control and read API. Verifies OIDC identities, validates expected versions and transitions, owns plan approval records, signs Cloud Tasks requests, serves artifact metadata, and emits audit events. SQLAlchemy 2 and Alembic govern PostgreSQL persistence.

### `apps/worker`

Private Cloud Run task handler. Runs Google ADK with pinned Vertex AI Gemini Flash, starts pinned official `mcp-grafana` as a private stdio subprocess, applies tool/query allow-lists and budgets, records invocation provenance, calls deterministic validators, and commits response packets idempotently.

### `apps/simulator`

Deterministic synthetic render/color environment and action target. It creates the shadowed-LUT fixture, emits telemetry, materializes artifacts, accepts only typed approved commands, and cannot address external infrastructure.

### Packages

- `contracts`: checked OpenAPI description and generated TypeScript client.
- `domain`: versioned incident, evidence, claim, plan, action, and audit schemas.
- `validators`: OCIO/resource, image/reference, lineage, scope, and recovery policies.
- `telemetry`: correlation IDs and OpenTelemetry conventions shared across services.

## Evidence path

```text
simulated job
  -> metrics/logs/traces/alert -> Grafana Cloud
  -> read-only mcp-grafana tools -> worker observation envelope
  -> immutable evidence record + digest
  -> bounded hypotheses
  -> deterministic validator inputs
  -> confirmed/rejected/unresolved claims
  -> response packet
```

The worker never receives the fixture oracle. Any decisive operational fact bypassing Grafana is a G0 failure. Large manifests and images are referenced by immutable digest and fetched from authorized Cloud Storage locations only when required by a deterministic tool.

## Control path

```text
web -> API -> Cloud SQL transaction -> Cloud Tasks -> private worker
web -> API approval -> immutable plan/approval -> simulator command adapter
simulator -> new telemetry/artifacts -> worker verification -> API -> human closure
```

Cloud Tasks uses OIDC to invoke private endpoints. Handlers check audience, service identity, stable task key, expected incident version, and payload digest before work.

## Trust boundaries

- Unauthenticated internet to public read-only web/API
- Authenticated operator to mutation API
- API to Cloud SQL, Storage, Tasks, and Secret Manager
- Cloud Tasks to private worker/simulator endpoints
- Worker to Vertex AI and private stdio MCP child process
- MCP process to Grafana Cloud using least-privilege service account
- Simulator-generated data to telemetry and artifact stores

Logs, trace attributes, image metadata, alert labels, MCP output, and model output remain untrusted even after authentication. They are validated, bounded, escaped, and never interpreted as executable instructions.

## Availability behavior

Cloud Run cold starts, Grafana propagation delay, MCP/Vertex timeouts, duplicate Cloud Tasks delivery, and partial telemetry are expected failure modes. Retries are bounded and idempotent. Deadline exhaustion yields a durable unresolved result rather than a diagnosis.

## Deployment topology

Production uses separate Cloud Run web, API, worker, and simulator services. Local development may compose equivalent processes but may not collapse trust boundaries in deployed code. See `deployment.md`.
