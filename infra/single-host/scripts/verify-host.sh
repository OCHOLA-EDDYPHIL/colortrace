#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if test "$#" -lt 7 || test "$#" -gt 8; then
  printf '%s\n' \
    "usage: $0 PUBLIC_URL ACCESS_USERNAME PROJECT ZONE INSTANCE GENERATION ADMISSION_TFVARS [OUTPUT]" >&2
  exit 64
fi

readonly public_url=$1
readonly access_username=$2
readonly project_id=$3
readonly zone=$4
readonly instance=$5
readonly expected_generation=$6
readonly admission_tfvars=$7
readonly access_password=${COLORTRACE_ACCESS_PASSWORD:-}
unset COLORTRACE_ACCESS_PASSWORD
readonly script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
readonly admission_helper="$script_dir/admission-binding.py"
readonly contract_helper="$script_dir/demo-verification.py"
readonly output=${8:-"$repository_root/.cache/single-host/host-verification.json"}

[[ "$public_url" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 64
[[ "$access_username" =~ ^[a-z][a-z0-9_-]{2,31}$ ]] || exit 64
[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ "$zone" =~ ^us-central1-[abcf]$ ]] || exit 64
[[ "$instance" =~ ^[a-z][a-z0-9-]{2,61}[a-z0-9]$ ]] || exit 64
[[ "$expected_generation" =~ ^[a-z0-9][a-z0-9-]{6,30}[a-z0-9]$ ]] || exit 64
[[ "$access_password" =~ ^[A-Za-z0-9._~-]{8,128}$ ]] || {
  printf 'COLORTRACE_ACCESS_PASSWORD must contain 8-128 URL-safe characters\n' >&2
  exit 64
}

command -v curl >/dev/null
command -v gcloud >/dev/null
command -v grep >/dev/null
command -v python3 >/dev/null
command -v timeout >/dev/null
test -f "$admission_tfvars"
test -x "$admission_helper"
test -x "$contract_helper"

readonly public_host=${public_url#https://}
readonly verification_root=$(mktemp -d)
cleanup() {
  rm -r -- "$verification_root"
}
trap cleanup EXIT

readonly artifact_binding="$verification_root/artifact-binding.json"
python3 "$admission_helper" validate-admission \
  "$admission_tfvars" "$artifact_binding"

readonly netrc="$verification_root/access.netrc"
printf 'machine %s\nlogin %s\npassword %s\n' \
  "$public_host" "$access_username" "$access_password" >"$netrc"
chmod 0600 "$netrc"

request_status() {
  local authentication=$1
  shift
  local arguments=(
    --silent
    --show-error
    --connect-timeout 10
    --max-time 30
    --max-redirs 0
    --proto '=https'
    --output /dev/null
    --write-out '%{http_code}'
  )
  if test "$authentication" = authenticated; then
    arguments+=(--netrc-file "$netrc")
  fi
  curl "${arguments[@]}" "$@"
}

post_json() {
  local expected_status=$1
  local path=$2
  local request=$3
  local response=$4
  local status
  status=$(curl \
    --fail-with-body \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 115 \
    --max-redirs 0 \
    --proto '=https' \
    --netrc-file "$netrc" \
    --request POST \
    --header 'Content-Type: application/json' \
    --header "Origin: $public_url" \
    --header 'Sec-Fetch-Site: same-origin' \
    --data-binary "@$request" \
    --output "$response" \
    --write-out '%{http_code}' \
    "$public_url$path")
  test "$status" = "$expected_status"
}

post_start() {
  local request=$1
  local response=$2
  curl \
    --silent \
    --show-error \
    --connect-timeout 10 \
    --max-time 115 \
    --max-redirs 0 \
    --proto '=https' \
    --netrc-file "$netrc" \
    --request POST \
    --header 'Content-Type: application/json' \
    --header "Origin: $public_url" \
    --header 'Sec-Fetch-Site: same-origin' \
    --data-binary "@$request" \
    --output "$response" \
    --write-out '%{http_code}' \
    "$public_url/v1/demo/runs"
}

get_json() {
  local path=$1
  local output_path=$2
  curl --fail --silent --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --max-redirs 0 \
    --proto '=https' \
    --netrc-file "$netrc" \
    --output "$output_path" \
    "$public_url$path"
}

get_visual() {
  local path=$1
  local output_path=$2
  curl --fail --silent --show-error \
    --connect-timeout 10 \
    --max-time 30 \
    --max-redirs 0 \
    --proto '=https' \
    --netrc-file "$netrc" \
    --output "$output_path" \
    --write-out '%{content_type}' \
    "$public_url$path"
}

readonly instance_description="$verification_root/instance.json"
gcloud compute instances describe "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --format=json >"$instance_description"
python3 "$contract_helper" verify-instance-metadata \
  "$instance_description" "$artifact_binding" "$expected_generation"

host_ready=false
for _ in $(seq 1 60); do
  if test "$(request_status authenticated "$public_url/" 2>/dev/null || true)" = 200; then
    host_ready=true
    break
  fi
  sleep 5
done
test "$host_ready" = true

test "$(request_status anonymous "$public_url/")" = 401
test "$(request_status anonymous --user 'colortrace-invalid:invalid' "$public_url/")" = 401

readonly response_headers="$verification_root/headers"
test "$(request_status authenticated --dump-header "$response_headers" "$public_url/")" = 200
grep -Eiq '^Referrer-Policy:[[:space:]]*no-referrer([[:space:]]|\r)*$' "$response_headers"
grep -Eiq '^X-Content-Type-Options:[[:space:]]*nosniff([[:space:]]|\r)*$' "$response_headers"
grep -Eiq '^X-Frame-Options:[[:space:]]*DENY([[:space:]]|\r)*$' "$response_headers"

test "$(request_status authenticated "$public_url/v1/session")" = 404
readonly nonexistent_run='demo-run-00000000000000000000000000000000'
test "$(request_status authenticated \
  --request POST \
  --data '{}' \
  "$public_url/v1/demo/runs/$nonexistent_run/reset")" = 415
test "$(request_status authenticated \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://invalid.example' \
  --header 'Sec-Fetch-Site: cross-site' \
  --data '{}' \
  "$public_url/v1/demo/runs/$nonexistent_run/reset")" = 403

readonly -a private_tcp_ports=(
  22
  80
  3000
  3100
  3200
  4318
  8080
  8443
  9090
  13000
  13100
  13200
  19090
)
probe_private_port() {
  local port=$1
  if timeout --signal=TERM 4 \
    bash -c 'exec 3<>"/dev/tcp/${1}/${2}"' \
    colortrace-public-port-probe "$public_host" "$port" \
    >/dev/null 2>&1; then
    printf 'Private TCP port %s is reachable through the public hostname.\n' \
      "$port" >&2
    return 1
  fi
}

private_port_probe_pids=()
for private_tcp_port in "${private_tcp_ports[@]}"; do
  probe_private_port "$private_tcp_port" &
  private_port_probe_pids+=("$!")
done
private_port_boundary_status=0
for private_port_probe_pid in "${private_port_probe_pids[@]}"; do
  if ! wait "$private_port_probe_pid"; then
    private_port_boundary_status=1
  fi
done
test "$private_port_boundary_status" -eq 0

readonly start_request="$verification_root/start-request.json"
readonly started_run="$verification_root/started-run.json"
readonly approval_request="$verification_root/approval-request.json"
readonly approved_run="$verification_root/approved-run.json"
readonly closure_request="$verification_root/closure-request.json"
readonly closed_run="$verification_root/closed-run.json"
readonly receipt_before="$verification_root/receipt-before.json"
readonly workflow_summary="$verification_root/workflow-summary.json"

python3 "$contract_helper" new-start "$start_request"
workflow_start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
start_status=$(post_start "$start_request" "$started_run")
if test "$start_status" = 409; then
  previous_run_id=$(python3 "$contract_helper" conflict-run-id "$started_run")
  previous_run="$verification_root/previous-run.json"
  previous_reset_request="$verification_root/previous-reset-request.json"
  previous_reset_result="$verification_root/previous-reset-result.json"
  get_json "/v1/demo/runs/$previous_run_id" "$previous_run"
  test "$(python3 "$contract_helper" prepare-reset \
    "$previous_run" "$previous_reset_request")" = "$previous_run_id"
  post_json 200 "/v1/demo/runs/$previous_run_id/reset" \
    "$previous_reset_request" "$previous_reset_result"
  python3 "$contract_helper" verify-reset "$previous_reset_result" "$previous_run"
  python3 "$contract_helper" new-start "$start_request"
  workflow_start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
  start_status=$(post_start "$start_request" "$started_run")
fi
test "$start_status" = 201
run_id=$(python3 "$contract_helper" prepare-approval \
  "$started_run" "$approval_request")
post_json 200 "/v1/demo/runs/$run_id/approve" \
  "$approval_request" "$approved_run"
python3 "$contract_helper" prepare-closure \
  "$approved_run" "$closure_request"
post_json 200 "/v1/demo/runs/$run_id/close" \
  "$closure_request" "$closed_run"
get_json "/v1/demo/runs/$run_id/receipt" "$receipt_before"
readonly visual_directory="$verification_root/visuals"
install -d -m 0700 "$visual_directory"
for visual_kind in diff expected observed recovered; do
  test "$(get_visual "/v1/demo/runs/$run_id/visuals/$visual_kind" \
    "$visual_directory/$visual_kind.png")" = image/png
done
workflow_finish_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
workflow_elapsed_ms=$(((workflow_finish_ns - workflow_start_ns) / 1000000))
python3 "$contract_helper" verify-contract \
  "$closed_run" \
  "$receipt_before" \
  "$artifact_binding" \
  "$public_url" \
  "$expected_generation" \
  "$workflow_elapsed_ms" \
  "$visual_directory" \
  "$workflow_summary"

gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command 'sudo --non-interactive docker restart colortrace-runtime >/dev/null'

readonly remote_check="$verification_root/remote-check.sh"
python3 "$contract_helper" remote-script \
  "$artifact_binding" "$expected_generation" "$remote_check"
remote_result=$(gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command "$(cat "$remote_check")")
test "$remote_result" = colortrace-live-binding-ok

readonly mcp_probe="$verification_root/mcp-probe.sh"
python3 "$contract_helper" mcp-script "$workflow_summary" "$mcp_probe"
gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command "$(cat "$mcp_probe")"

readonly receipt_after_restart="$verification_root/receipt-after-restart.json"
get_json "/v1/demo/runs/$run_id/receipt" "$receipt_after_restart"
cmp --silent "$receipt_before" "$receipt_after_restart"

readonly reset_request="$verification_root/reset-request.json"
readonly reset_result="$verification_root/reset-result.json"
test "$(python3 "$contract_helper" prepare-reset \
  "$closed_run" "$reset_request")" = "$run_id"
post_json 200 "/v1/demo/runs/$run_id/reset" "$reset_request" "$reset_result"
python3 "$contract_helper" verify-reset "$reset_result" "$closed_run"
readonly receipt_after_reset="$verification_root/receipt-after-reset.json"
get_json "/v1/demo/runs/$run_id/receipt" "$receipt_after_reset"
cmp --silent "$receipt_before" "$receipt_after_reset"

python3 "$contract_helper" write-report \
  "$workflow_summary" \
  "$artifact_binding" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "$public_url" \
  "$project_id" \
  "$zone" \
  "$instance" \
  "$expected_generation" \
  "$output"
printf '%s\n' "$output"
