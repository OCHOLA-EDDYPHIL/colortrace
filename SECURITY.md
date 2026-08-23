# Security policy

## Report a vulnerability

Report vulnerabilities through the private channel that supplied repository or hosted access. Do
not open a public issue containing exploit details, credentials, sensitive logs, proprietary
material, or personal data. The maintainer will preserve the report in a draft GitHub security
advisory and can invite the reporter there when continued private coordination is useful.

Include the affected revision, impact, minimal reproduction, and suggested mitigation. Do not test
systems or data that you do not own or have explicit authorization to assess.

## Supported security boundary

ColorTrace operates only on generated fixtures and a local simulator. It does not need access to a
production color pipeline, media store, or customer data. Do not add such access to either operating
profile.

The local demonstration runs without a network and without cloud credentials. The gated hosted
profile uses the topology described in
[`docs/architecture/single-host.svg`](docs/architecture/single-host.svg). Its controls are specific
to that topology.

## Hosted ingress and access

- The VPC firewall permits public traffic only on TCP 443.
- Caddy is configured to obtain a public certificate through ACME, terminate TLS, and require HTTP
  Basic authentication before serving the application or proxying a demo request.
- Caddy removes the inbound `Authorization` header before proxying a request.
- Only `/v1/demo` and `/v1/demo/*` reach the runtime from the public listener. Other `/v1/*` paths
  return `404` at the edge.
- Runtime health routes and general API routes are not routed directly to the public listener.
- SSH is limited to IAP TCP forwarding for the exact VM and destination port 22. OS Login supplies
  the owner/deployer's `operator_member` identity on that VM.
  Project SSH keys and the serial console are disabled for the VM.

The shared access code is an outer gate, not an individual user identity, account-recovery system,
or audit identity. Share it only through an approved private channel. Use a private browser session
on a shared device and close the session when work is complete.

## Internal service boundary

Caddy joins the `edge` and `internal` Docker networks. The web container joins only `edge`; the
runtime, Grafana, Prometheus, Loki, and Tempo join only `internal`. Caddy proxies public application
traffic over those private Docker networks. It also supplies internal TLS endpoints for Grafana and
the runtime and an internal HTTP OTLP endpoint for the three telemetry backends.

Grafana, Prometheus, Loki, and Tempo also bind selected diagnostic ports to host loopback. The
public listener does not expose the Grafana UI, Grafana API, observability backends, OTLP routes, or
loopback diagnostics. Caddy's certificate state, application state, simulator state, receipts,
Grafana state, and telemetry state live on the persistent boot disk.

The runtime starts the pinned Grafana MCP binary as a local `stdio` process. The adapter permits
only the read-only tool catalog in `config/grafana-mcp/query-catalog.json`. It reaches Grafana over
internal TLS with a viewer-scoped service-account token. Grafana queries Prometheus, Loki, and Tempo
over the internal Docker network. Write tools are disabled.

Containers use read-only root filesystems where supported, drop Linux capabilities, and set
`no-new-privileges`. Caddy adds only `NET_BIND_SERVICE`. Writable service state is mounted from the
persistent disk, and container logs use bounded rotation.

## Cloud identity, operators, and metadata

The owner/deployer uses `operator_member` and is responsible for reviewed applies, builds, host
verification, and manual VM stops. Terraform authority and stop permission are held outside this
module. The module grants Cloud Build editor and Service Usage Consumer at project scope, plus
`serviceAccountUser` on the exact builder service account. For SSH, it grants a custom project role
containing only `compute.instances.list` and `compute.projects.get`, OS Admin on the exact VM, IAP
access on the exact VM restricted to destination port 22, and `serviceAccountUser` on the exact host
service account.

The owner controls a dedicated resume service account created outside the module and may impersonate
it through `CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT`. Token Creator is granted to the owner only
on that resume service account. The module grants the resume service account only
`compute.instances.get` and `compute.instances.start` on the exact VM. It cannot stop the VM, use
SSH, run host verification, or apply Terraform. This is least-privilege separation between IAM
principals under one owner, not organizational separation. A browser user receives only the shared
web gate credentials.

The VM has a dedicated runtime service account. Its custom project role contains only
`aiplatform.endpoints.predict`. Repository-level Artifact Registry access permits image pulls, and
secret-level access permits reading the access-verifier secret. The runtime identity has no
project-wide logging or monitoring role and uses no stored service-account key.

Among application containers, only the runtime's fixed internal address may reach the metadata
server. Startup recreates and verifies the `DOCKER-USER` allow rule for that address followed by a
deny rule for other containers. The runtime uses short-lived Google credentials for Vertex
prediction. Host root and the Docker daemon remain inside the VM trust boundary and can administer
these controls.

The deployment has normal outbound internet access; it does not implement a general egress
allowlist. Startup and operation depend on Google APIs and identity endpoints, Artifact Registry,
the pinned Prometheus image on Docker Hub, ACME, and Debian package mirrors. Compromise of the host
or privileged Docker access is outside the container-to-container isolation claim.

## Secret handling

The owner/deployer creates the access code outside Terraform. Secret Manager stores only its bcrypt
verifier. Terraform binds one numeric secret version into the VM startup contract. At boot, the
startup script uses the VM identity to retrieve that version and writes a restricted Caddy
configuration containing the verifier; Caddy does not call the metadata server or Secret Manager.
The plaintext access code must not appear in Terraform state, shell history, command arguments,
logs, screenshots, or tracked files.

The host generates the Grafana administrator password and viewer token on its persistent disk with
restricted permissions. The runtime copies the viewer token from a read-only mount into a
runtime-private `tmpfs` before it starts MCP. Do not print, download, or reuse either Grafana
credential.

Browser session storage can contain a run reference, idempotency keys, and an approval nonce. The
nonce is cleared after action admission. It must not appear in a URL or log. Treat a browser profile
that contains an active run as private operator state.

## Model and action authority

Gemini can select and order only cataloged read queries. The investigation policy limits time,
calls, tool attempts, concurrency, tokens, result size, and evidence window. Provider arguments
come from the catalog, not model text. The adapter redacts credential fields and unapproved labels
before returning data to the model.

Model prose is not evidence and has no action authority. Deterministic code validates the evidence,
scope, plan, target, versions, and digests; the response-plan service creates the action. A human
must provide the one-time nonce, exact approval phrase, and displayed bindings. The service can
consume that authority for one simulator action only. Closure requires bound post-action checks and
a separate human confirmation.

If proof is incomplete, inconsistent, stale, unavailable, or over budget, the workflow stops
without an action. If an action result is uncertain, the service does not assume success.

## Supply-chain and admission controls

Cloud Build produces private, digest-addressed runtime, web, Caddy, Grafana, Loki, and Tempo images
from one clean source commit with a dedicated builder identity. Prometheus is not copied into
Artifact Registry; the host pulls the digest pinned in
`config/observability/images.lock.json` from Docker Hub.

`infra/single-host/scripts/build-images.sh` records the build, source, fixture, and six private
image identities. `verify-image-security.sh` scans those images and the pinned Prometheus image
against current and frozen vulnerability databases with no HIGH or CRITICAL ignore list, then
writes a checksum-covered scan binding. Database metadata is restricted to `Version`, `NextUpdate`,
`UpdatedAt`, and `DownloadedAt`, with version 2 and the frozen schedule pinned.
`admission-binding.py prepare` verifies both artifacts and creates the only artifact variable object
accepted by Terraform. Terraform binds its canonical SHA-256 and the component digests into VM
metadata; host verification compares that chain with all seven live containers and invokes the
packaged `colortrace_grafana_mcp.cli` module for the live MCP catalog probe. Keep manifests, scan
reports, variable files, and verification reports in `.cache/` or another private artifact store.

The boot disk is created from one exact Debian image. On the first activation of a lifecycle
generation, startup installs its required Debian packages and records the complete installed
package inventory. Later starts of that generation require the recorded inventory to match.
Package repositories are an outbound dependency, and a new generation can resolve newer package
versions.

## Lifecycle, cost, and retained state

Startup atomically records one lifecycle generation and its activation time before it verifies a
persistent systemd power-off timer. The deadline is exactly 168 hours after that generation's
activation. A manual stop does not pause the interval. Expired, malformed, incomplete, or
interrupted lifecycle state causes startup to power off instead of serving the application. Only a
reviewed Terraform apply followed by the first valid boot of a new generation starts a new
interval.

Terraform admits the VM only when the recorded complete seven-day estimate is positive, no greater
than the configured ceiling, and strictly below USD 100. This is an input check, not a live billing
cap. Billing data can lag, budget alerts do not stop resources, and VM power-off does not stop
charges for the persistent disk, external address, Artifact Registry, Secret Manager, state bucket,
or other retained resources.

The persistent boot disk is one durable copy, not a backup. It is protected from Terraform destroy
by `prevent_destroy`, but project administrators and infrastructure failures remain capable of data
loss. Export any required private records through an approved storage process.

## Containment and credential rotation

The owner/deployer should stop the VM first if credential disclosure or host compromise is
suspected. A stopped VM retains its persistent disk and prevents the application from serving
traffic; continuing storage and address charges remain possible.

For an access-code rotation, stop the VM, create a new bcrypt verifier, add a new Secret Manager
version, update `access_secret_version`, and apply the reviewed Terraform plan. Start the same valid
lifecycle generation with the narrow resume identity, then verify the host with the verification
owner/deployer. Confirm the new gate before disabling an older secret version. Do not reuse the old
code.

If a Grafana administrator password, viewer token, runtime identity, or host state may be exposed,
do not copy state into a replacement host. Keep the instance stopped and inspect it through the
authorized IAP and OS Login path. Recreate the controlled environment from immutable inputs after
you understand the exposure.
