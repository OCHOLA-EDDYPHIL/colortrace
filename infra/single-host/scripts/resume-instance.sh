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

[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ "$zone" =~ ^us-central1-[abcf]$ ]] || exit 64
[[ "$instance" =~ ^[a-z][a-z0-9-]{2,61}[a-z0-9]$ ]] || exit 64
[[ "$expected_generation" =~ ^[a-z0-9][a-z0-9-]{6,30}[a-z0-9]$ ]] || exit 64

command -v gcloud >/dev/null
command -v jq >/dev/null

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

status=$(printf '%s' "$description" | jq -er '.status')
case "$status" in
  RUNNING)
    exit 0
    ;;
  TERMINATED)
    gcloud compute instances start "$instance" \
      --project "$project_id" \
      --zone "$zone" \
      --quiet
    ;;
  *)
    printf 'The instance is not in a resumable state: %s\n' "$status" >&2
    exit 69
    ;;
esac

resumed=$(describe_instance)
if test "$(printf '%s' "$resumed" | jq -er '.status')" != RUNNING; then
  printf 'The instance did not reach RUNNING.\n' >&2
  exit 70
fi
