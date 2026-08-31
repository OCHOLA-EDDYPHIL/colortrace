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
readonly max_unix_epoch=253402300799

[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ "$zone" =~ ^us-central1-[abcf]$ ]] || exit 64
[[ "$instance" =~ ^[a-z][a-z0-9-]{2,61}[a-z0-9]$ ]] || exit 64
[[ "$expected_generation" =~ ^[a-z0-9][a-z0-9-]{6,30}[a-z0-9]$ ]] || exit 64
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || exit 64
[[ "$delay_seconds" =~ ^[0-9]+$ ]] || exit 64

command -v gcloud >/dev/null
command -v jq >/dev/null
command -v date >/dev/null

describe_instance() {
  gcloud compute instances describe "$instance" \
    --project "$project_id" \
    --zone "$zone" \
    --format=json
}

description=$(describe_instance)
actual_generation=$(printf '%s' "$description" \
  | jq -er '.metadata.items[] | select(.key == "colortrace-staging-generation") | .value')
if test "$actual_generation" != "$expected_generation"; then
  printf 'The deployed lifecycle generation does not match the expected value.\n' >&2
  exit 65
fi

actual_hard_stop_epoch=$(printf '%s' "$description" \
  | jq -er '.metadata.items[] | select(.key == "colortrace-staging-hard-stop-epoch") | .value') || {
  printf 'The deployed absolute hard-stop boundary is missing or invalid.\n' >&2
  exit 65
}
case "$actual_hard_stop_epoch" in
  ''|*[!0-9]*)
    printf 'The deployed absolute hard-stop boundary is missing or invalid.\n' >&2
    exit 65
    ;;
esac
if ! test "$actual_hard_stop_epoch" -le "$max_unix_epoch" 2>/dev/null; then
  printf 'The deployed absolute hard-stop boundary is missing or invalid.\n' >&2
  exit 65
fi

require_open_hard_stop() {
  local now
  if test "$actual_hard_stop_epoch" -eq 0; then
    return 0
  fi
  now=$(date +%s)
  case "$now" in
    ''|*[!0-9]*) exit 70 ;;
  esac
  if test "$now" -ge "$actual_hard_stop_epoch"; then
    printf 'The deployed absolute hard-stop boundary has been reached.\n' >&2
    exit 65
  fi
}

require_open_hard_stop

status=$(printf '%s' "$description" | jq -er '.status')
case "$status" in
  RUNNING)
    ;;
  TERMINATED)
    require_open_hard_stop
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
  require_open_hard_stop
  status=$(printf '%s' "$description" | jq -er '.status')
  case "$status" in
    RUNNING)
      exit 0
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
  'The instance did not reach RUNNING for the expected lifecycle generation; apply Terraform with a new staging_generation first.' >&2
exit 70
