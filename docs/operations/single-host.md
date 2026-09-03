# Single-host operations

This runbook creates and operates the gated ColorTrace profile in `infra/single-host`. It uses one
Compute Engine VM, one persistent boot disk, and one public TLS endpoint.

Keep all cloud values, credentials, plans, build records, scan reports, host reports, and workflow
receipts outside the repository. The examples store private files under `.cache/single-host` and
use `CT_` environment variables in the current shell.

## Operator roles

Keep these authorities separate:

| Role | Task |
| --- | --- |
| Owner/deployer (`operator_member`) | Review and apply Terraform plans, submit builds, create secret versions, verify the host through IAP and OS Login, and stop the VM. |
| Resume service account (`resume_member`) | Read and start the exact retained VM. It cannot stop the VM, use SSH, verify the host, or apply Terraform. |
| Browser user | Use the shared access gate and the ColorTrace browser workflow. |

The owner controls both cloud identities. The separation limits credentials and permissions; it is
not independent organizational approval.

## Safety rules

- Use a clean checkout of the source revision that will run.
- Use a dedicated Terraform state prefix, resource prefix, and build-source bucket.
- Never use the Terraform state bucket for Cloud Build source.
- Review every saved Terraform plan before you apply it.
- Keep `enable_instance` false until the build, scans, secret version, boot image, and cost estimate
  are ready.
- Use only the generated fixture. Do not connect the host to production media or customer data.
- Keep access codes, bcrypt verifiers, cloud identifiers, hosted addresses, and receipts out of
  tracked files.

## Install tools and prepare access

Use a Linux AMD64 operator host with:

- Bash, Git, Docker Engine, GNU Make, and core utilities
- Python 3, OpenSSH, `gcloud`, `jq`, `curl`, `tar`, `awk`, and `sha256sum`
- the Terraform version declared in `infra/single-host/versions.tf`

The operator needs non-root access to the Docker Unix socket. Configure `gcloud` and Application
Default Credentials for the owner/deployer. Do not create a key for the resume service account.

The Google Cloud project must permit the APIs declared in
`infra/single-host/services.tf`. Create the private work directory:

```sh
install -d -m 0700 .cache/single-host
```

## Select the source revision

Start from a clean checkout and save the checked-out revision:

```sh
test -z "$(git status --porcelain=v1 --untracked-files=all)"
export CT_CANDIDATE_COMMIT="$(git rev-parse HEAD)"
```

Run the repository checks before you create cloud resources:

```sh
make bootstrap
make check
```

## Create the Terraform backend

Choose an unused private bucket. Enable uniform access, public-access prevention, and object
versioning.

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

Protect this bucket as private infrastructure state.

## Create the foundation

Choose one unique 4-21 character resource prefix that starts with a lowercase letter, contains only
lowercase letters, numbers, and hyphens, and ends with a letter or number. Select an available
`us-central1` zone and the owner/deployer IAM member. Reserve an account ID for the resume identity.

```sh
export CT_PREFIX="ct-singlehost"
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

The foundation creates the network, runtime and builder identities, image repository,
short-retention build-source bucket, access-secret container, and required service bindings. It
does not create the VM, disk, or public address.

Inspect the inventory:

```sh
terraform -chdir=infra/single-host output -json resource_inventory \
  >.cache/single-host/foundation-inventory.json
chmod 0600 .cache/single-host/foundation-inventory.json
```

Confirm that every item uses the selected project and prefix. Confirm that the instance, disk, and
public address are absent. Confirm that the build-source bucket differs from the state bucket.

Create the resume service account after the IAM API is available. Give the owner Token Creator on
this account only.

```sh
gcloud iam service-accounts create "$CT_RESUME_ACCOUNT_ID" \
  --project="$CT_PROJECT" \
  --display-name="ColorTrace guarded resume"
gcloud iam service-accounts add-iam-policy-binding "$CT_RESUME_ACCOUNT" \
  --project="$CT_PROJECT" \
  --member="$CT_OPERATOR_MEMBER" \
  --role=roles/iam.serviceAccountTokenCreator
```

Do not grant Token Creator at project scope.

## Build, scan, and bind images

Use the owner/deployer identity. The build script rejects a dirty worktree and a source revision
that does not match `HEAD`. It builds the runtime, web, and Caddy images from their definitions in
`containers`, plus Grafana, Loki, Prometheus, and Tempo from four targets in
`Dockerfile.observability`.

```sh
gcloud auth configure-docker us-central1-docker.pkg.dev --quiet

export CT_BUILD_MANIFEST="$(
  infra/single-host/scripts/build-images.sh \
    "$CT_PROJECT" us-central1 "$CT_PREFIX" "$CT_CANDIDATE_COMMIT"
)"
```

Scan all seven private images. The script checks each image with both the current and pinned
scanner databases and stops on a HIGH or CRITICAL finding.

```sh
export CT_SCAN_BINDING="$(
  infra/single-host/scripts/verify-image-security.sh \
    "$CT_BUILD_MANIFEST" \
    .cache/single-host/trivy-current \
    .cache/single-host/trivy-frozen \
    .cache/single-host/image-scan
)"
```

Create the only artifact variable file accepted by Terraform:

```sh
export CT_ADMISSION_TFVARS=.cache/single-host/admission.tfvars.json

python3 infra/single-host/scripts/admission-binding.py prepare \
  "$CT_BUILD_MANIFEST" \
  "$CT_SCAN_BINDING" \
  "$CT_ADMISSION_TFVARS"
chmod 0600 "$CT_ADMISSION_TFVARS"
```

Do not edit this generated file.

## Create the access verifier

Generate a high-entropy, 8-128 character URL-safe access code. Keep the plaintext in a private
password manager. Extract Caddy from the admitted image and enter the code twice at its private
prompt. Store only the bcrypt verifier in Secret Manager.

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

Confirm that `CT_ACCESS_SECRET_VERSION` is one positive integer. Do not use `latest`.

## Set cost and lifecycle inputs

Prepare a conservative estimate for the complete seven-day period. Include the VM, 30 GiB disk,
external address, Vertex predictions, Cloud Build, Artifact Registry, logging, Secret Manager,
state storage, network traffic, and project-specific taxes or charges. Include charges that
continue while the VM is stopped.

The estimate must be positive, no greater than `cost_ceiling_usd`, and less than USD 100. The
Terraform check is not a live billing cap. Keep a private limit for the number of new workflows
and stop admitting new runs when that allowance is reached.

Resolve one exact Debian 12 boot image. Choose a new 8-32 character lowercase lifecycle
generation.

```sh
export CT_BOOT_IMAGE_NAME="$(
  gcloud compute images describe-from-family debian-12 \
    --project=debian-cloud \
    --format='value(name)'
)"
export CT_BOOT_IMAGE="projects/debian-cloud/global/images/$CT_BOOT_IMAGE_NAME"
export CT_GENERATION="your-lifecycle-generation"
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

Create a saved plan from the operator, artifact, and lifecycle inputs:

```sh
terraform -chdir=infra/single-host plan \
  -var-file="../../$CT_OPERATOR_TFVARS" \
  -var-file="../../$CT_ADMISSION_TFVARS" \
  -var-file="../../$CT_LIFECYCLE_TFVARS" \
  -out=../../.cache/single-host/host.tfplan
```

Before you apply the plan, confirm:

- one `e2-standard-2` VM and one 30 GiB persistent balanced disk
- the selected Debian image, generation, secret version, and cost estimate
- one public TCP port: 443
- IAP and OS Login access for the exact VM
- separate owner/deployer and resume identities
- the generated image and scan binding
- no unexpected replacement or unrelated resource

Apply the reviewed plan:

```sh
terraform -chdir=infra/single-host apply ../../.cache/single-host/host.tfplan
```

Save the non-secret outputs in the private directory and derive the URL and instance name from
them:

```sh
export CT_OUTPUTS=.cache/single-host/terraform-outputs.json
terraform -chdir=infra/single-host output -json >"$CT_OUTPUTS"
chmod 0600 "$CT_OUTPUTS"

export CT_PUBLIC_URL="$(jq -er '.deployment_contract.value.public_url' "$CT_OUTPUTS")"
export CT_INSTANCE="$(jq -er '.resume_identity.value.instance' "$CT_OUTPUTS")"
```

## Verify the deployed host

Run host verification as the owner/deployer while the VM is running. The facade must have no
active run, or it must have a terminal run that can be reset.

This command first rejects and safely replays one plan, then resets it. It next approves and closes
one canonical recovery, retrieves the visuals and receipt, restarts the runtime, checks retained
state, the live MCP catalog, routes, and metadata boundaries, and resets again. It changes
simulator state. Do not use it as a passive health check.

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

Keep the report private.

## Use the browser workflow

Open `CT_PUBLIC_URL` in a private browser session. Enter the access username and code. Confirm that
an anonymous request receives `401`.

1. Select **Investigate the color fault**.
2. Compare the expected, observed, and difference images.
3. Review the diagnosis, four affected outputs, three protected assets, and five commands.
4. Expand **Technical proof and provenance** only when low-level details are needed.
5. Retype the one-time nonce and approval phrase, confirm the checkbox, and select
   **Approve recovery action**. Use **Reject plan** when the scope is not correct.
6. Review the recovered image and the protected-output result.
7. Confirm the closure checkbox and select **Verify and close recovery**.
8. Retain the receipt privately when an operator record is required.
9. Select **Reset for another run** before you start a new run.

Never bind the one-time review code or request identity to changed fields. If the browser loses a
start, decision, closure, or reset response, reload the page and let the client reconcile the run
or retry the exact request.

## Stop and resume the VM

The owner/deployer stops the VM with separately held project authority:

```sh
gcloud compute instances stop "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --quiet
```

Use only the resume service account for the guarded start:

```sh
export CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT="$CT_RESUME_ACCOUNT"
infra/single-host/scripts/resume-instance.sh \
  "$CT_PROJECT" "$CT_ZONE" "$CT_INSTANCE" "$CT_GENERATION"
unset CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
```

The resume script checks the requested generation, starts a terminated VM, and waits until Compute
Engine reports `RUNNING`. It does not use SSH or validate application health. Remove impersonation
before you inspect or verify the host.

## Start a new seven-day generation

A manual stop does not pause the active seven-day interval. Start a new interval only with a
reviewed Terraform change and a generation that has never been activated.

```sh
export CT_GENERATION="your-new-lifecycle-generation"
export CT_NEW_LIFECYCLE_TFVARS=.cache/single-host/lifecycle-new.tfvars.json

jq --arg generation "$CT_GENERATION" \
  '.staging_generation = $generation' \
  "$CT_LIFECYCLE_TFVARS" >"$CT_NEW_LIFECYCLE_TFVARS"
chmod 0600 "$CT_NEW_LIFECYCLE_TFVARS"

gcloud compute instances stop "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --quiet
test "$(gcloud compute instances describe "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --format='value(status)')" = TERMINATED

terraform -chdir=infra/single-host plan \
  -var-file="../../$CT_OPERATOR_TFVARS" \
  -var-file="../../$CT_ADMISSION_TFVARS" \
  -var-file="../../$CT_NEW_LIFECYCLE_TFVARS" \
  -out=../../.cache/single-host/lifecycle-new.tfplan
```

The VM and disk must not be replaced. The plan must update the generation through instance
metadata. Apply only the reviewed plan:

```sh
terraform -chdir=infra/single-host apply \
  ../../.cache/single-host/lifecycle-new.tfplan

test "$(gcloud compute instances describe "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --format='value(status)')" = TERMINATED
```

Stop the host before planning so new candidate metadata is never attached to a VM that is still
running the previous containers. Confirm that it remains stopped after the single in-place update,
then use the guarded resume command. The first valid boot records the new activation time and
creates the 168-hour power-off timer.

## Recover an unhealthy service

Use IAP and OS Login. Do not open another firewall port.

Inspect the container state:

```sh
gcloud compute ssh "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --tunnel-through-iap \
  --command='if sudo --non-interactive docker compose version >/dev/null 2>&1; then
    sudo --non-interactive docker compose --file /srv/colortrace/config/compose.yaml ps
  else
    sudo --non-interactive docker-compose --file /srv/colortrace/config/compose.yaml ps
  fi'
```

Restart only the runtime when the fault is limited to that service:

```sh
gcloud compute ssh "$CT_INSTANCE" \
  --project="$CT_PROJECT" \
  --zone="$CT_ZONE" \
  --tunnel-through-iap \
  --command='sudo --non-interactive docker restart colortrace-runtime'
```

Reload the browser after the service returns. The facade reconciles stored mutations. A known
failure becomes terminal. An unknown action outcome stays uncertain and does not permit another
action.

Do not delete SQLite files, simulator publications, lifecycle records, Caddy state, Grafana state,
or telemetry directories to clear an error. Use the UI reset only for a terminal run. Reset
restores the authored scenario and keeps the prior receipt.

## Contain a suspected compromise

Stop the VM first. A stopped VM retains its disk and prevents the application from serving, but
storage and address charges can continue.

Do not copy state from a suspected host into a replacement environment. Preserve the disk for
inspection through the authorized IAP and OS Login path.

For an access-code rotation:

1. Stop the VM.
2. Create a new bcrypt verifier and Secret Manager version.
3. Update `access_secret_version` in the private lifecycle input.
4. Review and apply the Terraform plan.
5. Resume the same valid generation with the resume identity.
6. Confirm the new gate before you disable the old secret version.

If a Grafana credential, runtime identity, or host state may be exposed, keep the VM stopped until
you understand the exposure. Recreate the environment from immutable inputs when needed.

## Lifecycle behavior

The first valid boot of a generation records its activation time and creates a power-off timer for
168 hours later. Startup serves no application when lifecycle activation or timer verification
fails. Later starts keep the original activation time and recreate the timer for the original
deadline.

Expired, malformed, incomplete, or unexpectedly linked lifecycle state fails closed. Do not edit
the lifecycle records to force a start.

Power-off does not remove the disk, address, image repository, secret versions, Terraform state,
application database, simulator state, receipts, Caddy state, Grafana state, or telemetry. Those
resources can continue to incur charges. The persistent disk is one retained copy, not a backup.
