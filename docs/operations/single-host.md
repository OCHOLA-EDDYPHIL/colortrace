# Single-host operations

This runbook operates the gated ColorTrace profile in `infra/single-host`. Keep cloud-specific
values, credentials, Terraform plans, image manifests, scan reports, admission files, outputs, and
workflow receipts outside the repository.

The commands use `CT_` environment variables for private operator values. Set them only in the
current shell. Do not put them in a tracked script or shell profile.

## Roles

Keep these authorities distinct:

| Role | Authority and task |
| --- | --- |
| Owner/deployer (`operator_member`) | Owns the Terraform credentials, reviews and applies plans, submits builds, creates secret versions, uses exact-VM IAP and OS Login for host verification, and manually stops the VM. Terraform and stop powers are held outside this module. |
| Resume service account (`resume_member`) | Is impersonated by the owner for resume only. The module grants it only `compute.instances.get` and `compute.instances.start` on the exact retained VM. It cannot stop the VM, use SSH, verify the host, or apply Terraform. |
| Browser user | Receives the shared access username and code and uses only the gated browser workflow. |

The two cloud identities are distinct IAM principals controlled by one owner; they do not represent
organizational separation or independent approval. The owner impersonates the resume service
account only for the guarded start command and removes impersonation before host verification.

The module grants `operator_member` Cloud Build editor and Service Usage Consumer at project scope,
plus `serviceAccountUser` on the exact builder service account. For SSH it grants a custom project
role containing only `compute.instances.list` and `compute.projects.get`, OS Admin on the exact VM,
IAP on the exact VM conditioned on destination port 22, and `serviceAccountUser` on the exact host
service account.

## Safety rules

- Use a clean checkout of the exact source revision that will run.
- Use a dedicated Terraform state prefix and single-host resource prefix.
- Do not reuse resources, networks, state, or names from `infra/staging`.
- Review every plan before applying it.
- Keep `enable_instance` false until every immutable input is available.
- Deploy only the generated admission binding; do not hand-copy image references into Terraform.
- Put no plaintext access code, bcrypt verifier, hosted address, cloud identifier, or receipt in
  Git.
- Use only generated fixture data. Do not connect the host to a production media system.

## Required tools and access

Install Docker, GNU Make, Git, `gcloud`, `jq`, `curl`, `sha256sum`, and the Terraform version declared
in `infra/single-host/versions.tf`. Configure `gcloud` and Application Default Credentials for the
owner/deployer. Do not create or download a key for the resume service account.

The project must permit the APIs declared in `infra/single-host/services.tf`, including
`iamcredentials.googleapis.com` for keyless resume-service-account impersonation. The
owner/deployer must be able to create the declared resources and IAM bindings. Create a private
cache directory for all generated operator artifacts:

```sh
install -d -m 0700 .cache/single-host
```

## Select the immutable source

Start from a clean checkout:

```sh
test -z "$(git status --porcelain=v1 --untracked-files=all)"
export CT_CANDIDATE_COMMIT="$(git rev-parse HEAD)"
export CT_CANDIDATE_TREE="$(git show --no-patch --format=%T "$CT_CANDIDATE_COMMIT")"
```

Run the repository's complete check suite before creating cloud resources:

```sh
make bootstrap
make check
```

## Create the Terraform backend

Choose an unused bucket name and a private project. Create the state bucket once, enforce uniform
bucket-level access and public-access prevention, and enable object versioning.

```sh
export CT_PROJECT="your-private-project"
export CT_STATE_BUCKET="your-private-state-bucket"

gcloud storage buckets create "gs://$CT_STATE_BUCKET" \
  --project="$CT_PROJECT" \
  --location=us-central1 \
  --uniform-bucket-level-access \
  --public-access-prevention
gcloud storage buckets update "gs://$CT_STATE_BUCKET" --versioning

terraform -chdir=infra/single-host init \
  -reconfigure \
  -input=false \
  -backend-config="bucket=$CT_STATE_BUCKET" \
  -backend-config="prefix=colortrace/single-host"
```

Protect the bucket like other private project state. Terraform state contains internal addresses,
resource names, and secret-version references.

## Define operators and create the foundation

Choose a unique resource prefix, an available zone in `us-central1`, and the owner/deployer IAM
member. Reserve an account ID for one dedicated resume service account that will remain outside the
module.

```sh
export CT_PREFIX="your-single-host-prefix"
export CT_ZONE="your-us-central1-zone"
export CT_OPERATOR_MEMBER="user:your-owner-deployer"
export CT_RESUME_ACCOUNT_ID="your-resume-operator"
export CT_RESUME_ACCOUNT="$CT_RESUME_ACCOUNT_ID@$CT_PROJECT.iam.gserviceaccount.com"
export CT_RESUME_MEMBER="serviceAccount:$CT_RESUME_ACCOUNT"
export CT_OPERATOR_TFVARS=.cache/single-host/operator.tfvars.json

jq -n \
  --arg project_id "$CT_PROJECT" \
  --arg resource_prefix "$CT_PREFIX" \
  --arg zone "$CT_ZONE" \
  --arg operator_member "$CT_OPERATOR_MEMBER" \
  --arg resume_member "$CT_RESUME_MEMBER" \
  '{
    project_id: $project_id,
    region: "us-central1",
    zone: $zone,
    resource_prefix: $resource_prefix,
    operator_member: $operator_member,
    resume_member: $resume_member,
    enable_instance: false
  }' >"$CT_OPERATOR_TFVARS"
chmod 0600 "$CT_OPERATOR_TFVARS"

terraform -chdir=infra/single-host plan \
  -var-file="../../$CT_OPERATOR_TFVARS" \
  -out=../../.cache/single-host/foundation.tfplan
terraform -chdir=infra/single-host apply ../../.cache/single-host/foundation.tfplan
```

The foundation creates the dedicated network, runtime and builder service accounts, image
repository, access-verifier secret container, and required service bindings. It does not create the
VM, disk, external address, or externally managed resume service account.

After the foundation has enabled the required IAM API, create the resume service account. Grant the
owner Token Creator only on that service account so `gcloud` can impersonate it without a key. Do
not grant Token Creator at project scope.

```sh
gcloud iam service-accounts create "$CT_RESUME_ACCOUNT_ID" \
  --project="$CT_PROJECT" \
  --display-name="ColorTrace guarded resume"
gcloud iam service-accounts add-iam-policy-binding "$CT_RESUME_ACCOUNT" \
  --project="$CT_PROJECT" \
  --member="$CT_OPERATOR_MEMBER" \
  --role=roles/iam.serviceAccountTokenCreator
```

Inspect `terraform -chdir=infra/single-host output -json resource_inventory` after applying. Confirm
that the network, subnetwork, secret container, repository, and service accounts use the selected
prefix. Confirm that the instance, disk, and public address are absent.

## Build, scan, and bind the images

Use the owner/deployer's `operator_member` identity for the build. The build script rejects a dirty
worktree or a commit other than checked-out `HEAD`. It submits an archive of that commit with the
dedicated builder identity and writes a private v2 manifest containing the exact source, build,
fixture, and six private image digests.

```sh
gcloud auth configure-docker us-central1-docker.pkg.dev --quiet

export CT_BUILD_MANIFEST="$(
  infra/single-host/scripts/build-images.sh \
    "$CT_PROJECT" us-central1 "$CT_PREFIX" "$CT_CANDIDATE_COMMIT"
)"
```

Scan the six private images and the pinned upstream Prometheus image against both the current and
pinned frozen vulnerability databases. The command writes individual reports, a checksum file,
and `scan-bindings.json`; it fails on any HIGH or CRITICAL finding. Database metadata must contain
exactly `Version`, `NextUpdate`, `UpdatedAt`, and `DownloadedAt`, with version 2 and the pinned
frozen update schedule.

```sh
export CT_SCAN_BINDING="$(
  infra/single-host/scripts/verify-image-security.sh \
    "$CT_BUILD_MANIFEST" \
    .cache/single-host/trivy-current \
    .cache/single-host/trivy-frozen \
    .cache/single-host/image-scan
)"
```

Create the only artifact variable object accepted by Terraform. The helper validates the build
manifest, scan evidence and checksums, observability lock, scanner and database identities, source
tree, fixture digest, registry, and all seven image references before writing the binding.

```sh
export CT_ADMISSION_TFVARS=.cache/single-host/admission.tfvars.json

python3 infra/single-host/scripts/admission-binding.py prepare \
  "$CT_BUILD_MANIFEST" \
  "$CT_SCAN_BINDING" \
  "$CT_ADMISSION_TFVARS"
```

Do not edit the generated admission file. Changing any bound value invalidates its canonical
digest.

## Create the access-verifier version

Generate a high-entropy 8-128 character URL-safe access code with an approved secret-generation
method and keep the plaintext in a private password manager. Extract the Caddy binary from the
admitted build. Its password command reads the code twice without echo and writes only the bcrypt
verifier.

```sh
export CT_ACCESS_SECRET="$CT_PREFIX-access-hash"
export CT_CADDY_IMAGE="$(jq -er '.images.caddy.reference' "$CT_BUILD_MANIFEST")"
umask 077

CT_CADDY_CONTAINER="$(docker create "$CT_CADDY_IMAGE")"
docker cp "$CT_CADDY_CONTAINER:/usr/bin/caddy" .cache/single-host/caddy
docker rm "$CT_CADDY_CONTAINER" >/dev/null
chmod 0700 .cache/single-host/caddy
.cache/single-host/caddy hash-password --algorithm bcrypt \
  >.cache/single-host/access-hash
chmod 0600 .cache/single-host/access-hash

export CT_ACCESS_SECRET_VERSION="$(
  gcloud secrets versions add "$CT_ACCESS_SECRET" \
    --project="$CT_PROJECT" \
    --data-file=.cache/single-host/access-hash \
    --format='value(name)' \
    | awk -F/ '{print $NF}'
)"
```

Confirm that `CT_ACCESS_SECRET_VERSION` is one positive integer. Do not use `latest`; VM admission
requires one immutable numeric version.

## Review cost and define the lifecycle

Prepare a conservative estimate for the complete seven-day use of the project resources. Include
the VM, 30 GiB persistent balanced disk, attached external address, Vertex predictions, Cloud Build,
Artifact Registry storage and transfer, logging, Secret Manager storage and access, Terraform state
bucket, network traffic, and any taxes or project-specific charges. Include charges incurred before
the VM starts and charges that continue while it is stopped.

The estimate must be positive, no greater than `cost_ceiling_usd`, and strictly below USD 100.
Terraform checks the recorded number but does not enforce actual billing. Billing reports can lag,
and budget alerts do not stop resources.

Resolve one exact Debian 12 boot image. Use a new 8-32 character lowercase pre-acceptance lifecycle
generation while performing deployment, restart, browser, and stop-resume testing. Its clock is a
test window, not the final accepted window. Set the shared non-secret username and record the
reviewed estimate in a separate lifecycle file:

```sh
export CT_BOOT_IMAGE_NAME="$(
  gcloud compute images describe-from-family debian-12 \
    --project=debian-cloud \
    --format='value(name)'
)"
export CT_BOOT_IMAGE="projects/debian-cloud/global/images/$CT_BOOT_IMAGE_NAME"
export CT_GENERATION="your-preaccept-generation"
export CT_ACCESS_USERNAME="colortrace"
export CT_ESTIMATED_SEVEN_DAY_COST="your-reviewed-number-below-100"
export CT_LIFECYCLE_TFVARS=.cache/single-host/lifecycle.tfvars.json

jq -n \
  --arg generation "$CT_GENERATION" \
  --arg access_secret_version "$CT_ACCESS_SECRET_VERSION" \
  --arg access_username "$CT_ACCESS_USERNAME" \
  --arg boot_image "$CT_BOOT_IMAGE" \
  --argjson estimated_cost "$CT_ESTIMATED_SEVEN_DAY_COST" \
  '{
    enable_instance: true,
    staging_generation: $generation,
    access_secret_version: $access_secret_version,
    access_username: $access_username,
    boot_image: $boot_image,
    estimated_seven_day_cost_usd: $estimated_cost,
    cost_ceiling_usd: 100
  }' >"$CT_LIFECYCLE_TFVARS"
chmod 0600 "$CT_LIFECYCLE_TFVARS"
```

## Admit the host

Plan with the operator, generated artifact, and lifecycle files as three distinct inputs:

```sh
terraform -chdir=infra/single-host plan \
  -var-file="../../$CT_OPERATOR_TFVARS" \
  -var-file="../../$CT_ADMISSION_TFVARS" \
  -var-file="../../$CT_LIFECYCLE_TFVARS" \
  -out=../../.cache/single-host/admission.tfplan
terraform -chdir=infra/single-host apply ../../.cache/single-host/admission.tfplan
```

Before applying, confirm the fixed machine and disk sizes, exact boot image, generated artifact
binding hash, seven image digests, selected secret version, source bindings, one public TCP port,
exact-VM IAP on port 22, exact-VM OS Login, the restricted project-inspection role, exact service
account bindings, distinct operator identities, selected generation, and recorded cost estimate.

Save the non-secret outputs in the private operator directory and derive the public URL and exact
instance name from those outputs rather than reconstructing them:

```sh
export CT_OUTPUTS=.cache/single-host/terraform-outputs.json
terraform -chdir=infra/single-host output -json >"$CT_OUTPUTS"
chmod 0600 "$CT_OUTPUTS"

export CT_PUBLIC_URL="$(jq -er '.deployment_contract.value.public_url' "$CT_OUTPUTS")"
export CT_INSTANCE="$(jq -er '.resume_identity.value.instance' "$CT_OUTPUTS")"
```

Retain `deployment_contract`, `resource_inventory`, and `resume_identity` privately. Their hashes
and identities are inputs to later verification even though they contain no access code.

## Run the state-changing host verification

Run this command as the owner/deployer's `operator_member` identity while the VM is already running.
It never starts the VM. The facade must be reset-ready: either no run is active or an existing run
is terminal and can be reset. An unresolved active run makes verification fail closed.

`verify-host.sh` creates and completes a fresh canonical workflow in under 120 seconds, retrieves
all four visuals and its receipt, restarts the runtime, checks receipt persistence and the live MCP
catalog, compares all live images and metadata with the generated admission binding, verifies the
metadata firewall and route boundary, then resets the simulator. The created run remains terminal
and its immutable receipt remains retrievable. This command changes simulator and facade state; do
not use it as a passive health check. The live MCP probe invokes the packaged
`colortrace_grafana_mcp.cli` Python module inside the runtime image.

Enter the access code only through the environment for the process and choose an explicit private
report path:

```sh
read -r -s -p 'Access code: ' COLORTRACE_ACCESS_PASSWORD
export COLORTRACE_ACCESS_PASSWORD
infra/single-host/scripts/verify-host.sh \
  "$CT_PUBLIC_URL" \
  "$CT_ACCESS_USERNAME" \
  "$CT_PROJECT" \
  "$CT_ZONE" \
  "$CT_INSTANCE" \
  "$CT_GENERATION" \
  "$CT_ADMISSION_TFVARS" \
  .cache/single-host/host-verification.json
unset COLORTRACE_ACCESS_PASSWORD
```

The command prints the report path. The report includes private environment identities; keep it
outside Git. A workflow receipt proves one workflow. This report additionally proves the admitted
host, live images, routes, restart, MCP, persistence, and reset boundary.

## Use the browser workflow

Open `CT_PUBLIC_URL` in a private browser session and enter the access username and code. Confirm
that an anonymous request receives `401`. Use the browser workflow in this order:

1. Select **Investigate with Gemini + Grafana**.
2. Review the expected, observed, and difference images and the returned scope and technical proof.
3. Retype the one-time nonce and exact approval phrase, then confirm the bound action.
4. Review the recovered image and safe-output digest, then confirm closure.
5. Record the displayed run ID and receipt digest in private operator records. The browser has no
   receipt-download control; retrieve `/v1/demo/runs/<run-id>/receipt` through an authenticated
   request if the full JSON is required.
6. Select **Reset for another run** only after the receipt identity has been recorded.

Do not reuse an approval nonce or start another run before reset completes. If the browser loses a
start, approval, closure, or reset response, reload the page. The client reuses the stored
idempotency key or recovers the active run. Do not create a replacement request with changed fields.

## Stop and resume with separate principals

The module does not grant stop permission. The owner/deployer uses separately held project
authority to stop the exact VM and retain its disk:

```sh
gcloud compute instances stop "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --quiet
```

To resume, impersonate the dedicated service account and run only the guarded start command:

```sh
export CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="$CT_RESUME_ACCOUNT"
infra/single-host/scripts/resume-instance.sh \
  "$CT_PROJECT" "$CT_ZONE" "$CT_INSTANCE" "$CT_GENERATION"
unset CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
```

The resume script compares the requested generation with VM metadata, starts a terminated VM, and
polls only until Compute Engine reports `RUNNING`. It does not use SSH, validate application health,
or run the host verifier. Startup independently validates the on-disk lifecycle and powers off on
an expired or invalid state.

After the resume command returns and impersonation is unset, run the state-changing host
verification command as the owner/deployer's `operator_member` identity. Do not grant the resume
service account the owner/deployer's permissions or use the owner credentials directly for the
guarded start step.

## Start the final accepted lifecycle window

Complete the deployment, restart, browser, and stop-resume acceptance checks with the
pre-acceptance generation. At the acceptance boundary, choose a new generation that has never been
activated and write a separate final lifecycle variable file. Changing the Terraform value alone
does not define the activation time; the first valid boot after the apply atomically records it.

```sh
export CT_FINAL_GENERATION="your-final-accepted-generation"
export CT_FINAL_LIFECYCLE_TFVARS=.cache/single-host/lifecycle-final.tfvars.json

jq --arg generation "$CT_FINAL_GENERATION" \
  '.staging_generation = $generation' \
  "$CT_LIFECYCLE_TFVARS" >"$CT_FINAL_LIFECYCLE_TFVARS"
chmod 0600 "$CT_FINAL_LIFECYCLE_TFVARS"

terraform -chdir=infra/single-host plan \
  -var-file="../../$CT_OPERATOR_TFVARS" \
  -var-file="../../$CT_ADMISSION_TFVARS" \
  -var-file="../../$CT_FINAL_LIFECYCLE_TFVARS" \
  -out=../../.cache/single-host/final-acceptance.tfplan
terraform -chdir=infra/single-host apply \
  ../../.cache/single-host/final-acceptance.tfplan

terraform -chdir=infra/single-host output -json >"$CT_OUTPUTS"
chmod 0600 "$CT_OUTPUTS"
export CT_GENERATION="$CT_FINAL_GENERATION"
```

Force one stop and guarded resume after the apply so startup activates the final generation at this
boundary. Use the owner/deployer for the stop and the impersonated resume service account only for
the start:

```sh
gcloud compute instances stop "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --quiet

export CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="$CT_RESUME_ACCOUNT"
infra/single-host/scripts/resume-instance.sh \
  "$CT_PROJECT" "$CT_ZONE" "$CT_INSTANCE" "$CT_GENERATION"
unset CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
```

Rerun host verification as the owner/deployer and keep this report as the final acceptance report:

```sh
read -r -s -p 'Access code: ' COLORTRACE_ACCESS_PASSWORD
export COLORTRACE_ACCESS_PASSWORD
infra/single-host/scripts/verify-host.sh \
  "$CT_PUBLIC_URL" \
  "$CT_ACCESS_USERNAME" \
  "$CT_PROJECT" \
  "$CT_ZONE" \
  "$CT_INSTANCE" \
  "$CT_GENERATION" \
  "$CT_ADMISSION_TFVARS" \
  .cache/single-host/final-host-verification.json
unset COLORTRACE_ACCESS_PASSWORD
```

The verifier checks the active generation and timer. Record their exact values in a separate
private acceptance artifact and verify that the deadline is 604800 seconds after activation:

```sh
export CT_FINAL_LIFECYCLE_RECORD=.cache/single-host/final-lifecycle-window.txt

gcloud compute ssh "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --tunnel-through-iap \
  --command='set -eu
generation=$(sudo --non-interactive cat /var/lib/colortrace-lifecycle/current/generation)
activated_at=$(sudo --non-interactive cat /var/lib/colortrace-lifecycle/current/activated-at)
timer_deadline=$(sudo --non-interactive systemctl show --timestamp=unix \
  colortrace-auto-stop.timer --property=NextElapseUSecRealtime --value)
deadline=$(date --date="$timer_deadline" +%s)
test "$deadline" -eq "$((activated_at + 604800))"
printf "generation=%s\nactivated_at_epoch=%s\ndeadline_epoch=%s\n" \
  "$generation" "$activated_at" "$deadline"' \
  >"$CT_FINAL_LIFECYCLE_RECORD"
chmod 0600 "$CT_FINAL_LIFECYCLE_RECORD"
grep -Fqx "generation=$CT_GENERATION" "$CT_FINAL_LIFECYCLE_RECORD"
```

Retain the final Terraform outputs, verification report, and lifecycle-window record together. The
168-hour interval begins at the recorded activation epoch, not when browser testing finishes or an
acceptance note is written.

## Lifecycle behavior

The first valid boot for a generation atomically records its generation and activation timestamp,
then creates and verifies a persistent systemd power-off timer for exactly 168 hours after that
timestamp. Startup serves no application if generation-state activation or timer verification
fails. It also records the installed Debian package inventory for the generation.

A manual stop does not pause or reset the interval. A later start keeps the original activation
time, validates the package inventory, rebuilds the container metadata rules, and recreates the
timer for the original deadline. After expiry, startup powers the VM off again.

A reviewed Terraform apply with a different generation is required for a new seven-day interval.
The following valid start atomically activates the new generation and retains the older generation
records. Malformed, partially written, unexpectedly linked, or otherwise inconsistent lifecycle
state fails closed even if metadata names a new generation. Do not delete or rewrite lifecycle
records to force startup; preserve the disk for inspection and make an explicit recovery or
recreation decision.

Power-off does not remove the persistent disk, fixed address, image repository, secret versions,
Terraform state, facade database, simulator state, receipts, Caddy state, Grafana state, or
telemetry. Those resources can continue to incur charges. The disk is one retained copy, not a
backup, and removing it is a separate destructive operation.

## Recover an unhealthy service

Use the owner/deployer's IAP and OS Login access for host inspection. Do not open a new firewall
port:

```sh
gcloud compute ssh "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --tunnel-through-iap \
  --command='sudo --non-interactive docker compose --file /srv/colortrace/config/compose.yaml ps'
```

If only the runtime needs a controlled restart:

```sh
gcloud compute ssh "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --tunnel-through-iap \
  --command='sudo --non-interactive docker restart colortrace-runtime'
```

The facade reconciles a stored mutation after the simulator worker becomes available. A known
failure becomes terminal. An unknown action outcome stays uncertain and does not permit a new
action. Reload the browser to recover stored state. Run the full host verifier only when a fresh,
state-changing workflow and reset are appropriate.

Do not delete SQLite files, simulator publications, lifecycle records, Caddy state, Grafana state,
or telemetry directories to clear an error. Preserve the disk for inspection. Use the UI reset only
for a terminal workflow; it restores the authored scenario and preserves the prior receipt.
