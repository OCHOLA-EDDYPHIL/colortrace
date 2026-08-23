# ADR 0011: Use one isolated host for the gated workflow

## Status

Accepted. This decision supersedes ADR 0006 for the gated profile.

It replaces the earlier requirement to use Cloud SQL PostgreSQL, Cloud Storage artifacts, and
Cloud Tasks as canonical workflow state. It also supersedes the distributed hosted topology in
`infra/staging` for this profile. That module remains separate groundwork; its state, network,
identities, and resources must not be combined with `infra/single-host`.

## Context

The complete workflow needs a browser UI, durable facade, local simulator, Vertex AI, pinned
Grafana MCP process, and correlated logs, metrics, and traces. It also needs a small private
operating boundary that powers off automatically while retaining state.

A distributed layout adds identity exchanges, managed-database migration, several network
boundaries, and independent lifecycle controls without strengthening the authority claim for the
canonical generated scenario. One isolated host preserves the required component boundaries and
provides a smaller restart and recovery path.

## Decision

Use `infra/single-host` as the only gated hosted profile.

The module creates a dedicated VPC and subnet, fixed external address, Shielded Compute Engine VM,
30 GiB persistent balanced boot disk, private Artifact Registry repository, separate runtime and
builder service accounts, and one Secret Manager secret container for the access verifier. The
host service account receives a custom role containing only `aiplatform.endpoints.predict`, plus
repository-scoped image read and secret-scoped verifier read access.

Cloud Build produces six private digest-addressed images: runtime, web, Caddy, Grafana, Loki, and
Tempo. Prometheus is pulled directly from Docker Hub at the digest pinned in the observability lock.
Before VM admission, the build manifest, seven-image scan binding, and admission object form one
SHA-256-linked chain. Terraform accepts only that canonical object and binds its component hashes
to VM metadata. Live verification recomputes the admission binding and compares it with VM metadata
and every running image.

The VM runs Docker Compose across two networks:

- Caddy joins `edge` and `internal`, terminates public TLS, enforces the shared access-code gate,
  and provides internal TLS and OTLP routes.
- The web container joins only `edge`.
- The runtime, Grafana, Prometheus, Loki, and Tempo join only `internal`.
- The runtime starts Grafana MCP over `stdio`; MCP reaches Grafana over internal TLS with a
  viewer-scoped token.

Only TCP 443 is open to the internet. SSH is available only through IAP TCP forwarding and OS
Login. Grafana and the observability backends also bind diagnostic ports to host loopback. The edge
routes only the application and `/v1/demo` paths and rejects other public API paths.

Among containers, only the runtime's fixed address may reach the metadata server. It uses the
attached VM identity for Vertex prediction. The deployment has ordinary outbound internet access
for Google APIs and identity endpoints, Artifact Registry, Docker Hub, ACME, and Debian package
mirrors; it does not enforce a general egress allowlist.

The owner/deployer applies Terraform, performs builds and host verification, and manually stops the
VM. Its `operator_member` receives Cloud Build editor and Service Usage Consumer at project scope,
plus exact-builder `serviceAccountUser` for builds. For SSH it receives only the required project
list/lookups, exact-VM OS Admin, exact-VM IAP restricted to port 22, and exact-host
`serviceAccountUser`. Terraform and stop powers are held separately.

The same owner may impersonate one externally created resume service account. Token Creator is
bound only on that service account, and the module grants the service account only exact-VM
`compute.instances.get` and `compute.instances.start`. It cannot stop the VM or run SSH-based host
verification. This is least-privilege IAM separation within one owner-controlled project, not
organizational separation. Browser users receive only the shared access gate.

SQLite files and the simulator filesystem on the persistent boot disk are canonical application
state for this profile. Caddy certificate state, Grafana state, and telemetry state are also on the
disk. The profile does not use Cloud SQL, Cloud Storage artifact publication, or Cloud Tasks for
the workflow. The GCS backend stores Terraform state only.

Startup atomically records the first activation time for a lifecycle generation before it verifies
a persistent systemd power-off timer. The deadline is exactly seven days later. Stops and restarts
do not reset it. Expired, malformed, incomplete, or interrupted lifecycle state powers off instead
of serving. A new interval requires an explicit generation change through Terraform. Required host
package versions are recorded per generation and checked on later starts.

VM admission also requires a complete recorded seven-day estimate that is positive, at or below
the configured ceiling, and strictly below USD 100. The estimate includes compute, retained disk
and address, model calls, image build and storage, logging, secrets, state storage, and expected
network charges. It is not an enforced billing cap.

## Consequences

The topology has fewer moving parts and one durable restart boundary. It can exercise
response-loss replay, runtime restart, receipt persistence, scenario reset, and host resume without
a managed database or cross-service task transport.

The topology is not highly available. The VM and boot disk are shared failure domains, and the
disk is one retained copy rather than a backup. The access code is a shared outer gate and does not
provide individual application identities. The public address accepts TLS traffic from the
internet, although application routes require the gate.

Auto-stop limits VM runtime but does not delete or stop charges for the disk, address, registry,
secret, state bucket, or other retained services. Billing data can lag and budget alerts do not
stop resources. The unrestricted outbound path and host administrator boundary remain explicit
limitations.

This profile remains limited to the generated scenario and simulator. It is not a production media
deployment. A future distributed topology requires a separate decision, migration design, identity
review, and state-transfer plan.

The authoritative topology is shown in
[`docs/architecture/single-host.svg`](../architecture/single-host.svg). Operator procedures are in
[`docs/operations/single-host.md`](../operations/single-host.md).
