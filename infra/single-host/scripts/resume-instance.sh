#!/usr/bin/env bash
set -Eeuo pipefail

if test "$#" -ne 4; then
  printf 'usage: %s PROJECT ZONE INSTANCE EXPECTED_GENERATION\n' "$0" >&2
  exit 64
fi

readonly project_id=$1
readonly zone=$2
readonly instance=$3
readonly expected_generation=$4
readonly attempts=${COLORTRACE_RESUME_ATTEMPTS:-60}
readonly delay_seconds=${COLORTRACE_RESUME_DELAY_SECONDS:-5}

[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ "$zone" =~ ^us-central1-[abcf]$ ]] || exit 64
[[ "$instance" =~ ^[a-z][a-z0-9-]{2,61}[a-z0-9]$ ]] || exit 64
[[ "$expected_generation" =~ ^[a-z0-9][a-z0-9-]{6,30}[a-z0-9]$ ]] || exit 64
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || exit 64
[[ "$delay_seconds" =~ ^[0-9]+$ ]] || exit 64

command -v gcloud >/dev/null
command -v jq >/dev/null

describe_instance() {
  gcloud compute instances describe "$instance" \
    --project "$project_id" \
    --zone "$zone" \
    --format=json
}

readonly health_check='test -d /srv/colortrace/app
test -s /var/lib/colortrace-lifecycle/generation
test "$(cat /var/lib/colortrace-lifecycle/generation)" = "$1"
activated_at=$(cat /var/lib/colortrace-lifecycle/activated-at)
case "$activated_at" in ""|*[!0-9]*) exit 1 ;; esac
test "$((activated_at + 604800))" -gt "$(date +%s)"
systemctl is-active --quiet colortrace-auto-stop.timer
test "$(docker inspect --format={{.State.Health.Status}} colortrace-runtime)" = healthy
test "$(docker inspect --format={{.State.Health.Status}} colortrace-web)" = healthy'

verify_instance() {
  gcloud compute ssh "$instance" \
    --project "$project_id" \
    --zone "$zone" \
    --tunnel-through-iap \
    --quiet \
    --command "sudo --non-interactive /bin/bash -ceu '$health_check' colortrace-resume '$expected_generation'"
}

description=$(describe_instance)
actual_generation=$(printf '%s' "$description" \
  | jq -er '.metadata.items[] | select(.key == "colortrace-staging-generation") | .value')
if test "$actual_generation" != "$expected_generation"; then
  printf 'The deployed lifecycle generation does not match the expected value.\n' >&2
  exit 65
fi

status=$(printf '%s' "$description" | jq -er '.status')
case "$status" in
  RUNNING)
    ;;
  TERMINATED)
    gcloud compute instances start "$instance" \
      --project "$project_id" \
      --zone "$zone" \
      --quiet
    description=$(describe_instance)
    ;;
  *)
    printf 'The instance is not in a resumable state: %s\n' "$status" >&2
    exit 69
    ;;
esac

for ((attempt = 1; attempt <= attempts; attempt++)); do
  status=$(printf '%s' "$description" | jq -er '.status')
  case "$status" in
    RUNNING)
      if verify_instance; then
        exit 0
      fi
      ;;
    PROVISIONING|REPAIRING|STAGING|STOPPING|TERMINATED)
      ;;
    *)
      printf 'The instance entered a non-resumable state: %s\n' "$status" >&2
      exit 69
      ;;
  esac

  if test "$attempt" -lt "$attempts"; then
    sleep "$delay_seconds"
    description=$(describe_instance)
  fi
done

printf '%s\n' \
  'The instance did not become healthy for the expected lifecycle generation; apply Terraform with a new staging_generation first.' >&2
exit 70
