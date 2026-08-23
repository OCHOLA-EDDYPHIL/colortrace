#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if test "$#" -lt 7 || test "$#" -gt 8; then
  printf '%s\n' \
    "usage: $0 PUBLIC_URL ACCESS_USERNAME PROJECT ZONE INSTANCE GENERATION RUN_ID [OUTPUT]" >&2
  exit 64
fi

readonly public_url=$1
readonly access_username=$2
readonly project_id=$3
readonly zone=$4
readonly instance=$5
readonly expected_generation=$6
readonly run_id=$7
readonly access_password=${COLORTRACE_ACCESS_PASSWORD:-}
unset COLORTRACE_ACCESS_PASSWORD
readonly script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
readonly resume_script="$script_dir/resume-instance.sh"
readonly output=${8:-"$repository_root/.cache/single-host/host-verification-$run_id.json"}

[[ "$public_url" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || exit 64
[[ "$access_username" =~ ^[a-z][a-z0-9_-]{2,31}$ ]] || exit 64
[[ "$run_id" =~ ^demo-run-[0-9a-f]{32}$ ]] || exit 64
[[ "$access_password" =~ ^[A-Za-z0-9._~-]{8,128}$ ]] || {
  printf 'COLORTRACE_ACCESS_PASSWORD must contain 8-128 URL-safe characters\n' >&2
  exit 64
}

command -v curl >/dev/null
command -v gcloud >/dev/null
command -v jq >/dev/null
command -v sha256sum >/dev/null
command -v timeout >/dev/null
test -x "$resume_script"

readonly public_host=${public_url#https://}
readonly verification_root=$(mktemp -d)
output_tmp=''
cleanup() {
  if test -n "$output_tmp"; then
    rm -f -- "$output_tmp"
  fi
  rm -r -- "$verification_root"
}
trap cleanup EXIT

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

"$resume_script" \
  "$project_id" "$zone" "$instance" "$expected_generation"

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

readonly receipt_before="$verification_root/receipt-before.json"
curl --fail --silent --show-error \
  --connect-timeout 10 \
  --max-time 30 \
  --max-redirs 0 \
  --proto '=https' \
  --netrc-file "$netrc" \
  --output "$receipt_before" \
  "$public_url/v1/demo/runs/$run_id/receipt"
jq -e --arg run_id "$run_id" '
  .schema == "colortrace-demo-receipt/v1"
  and .run_id == $run_id
  and (.source_commit | type == "string" and test("^[0-9a-f]{40}$"))
  and (.receipt_sha256 | type == "string" and test("^sha256:[0-9a-f]{64}$"))
  and (.terminal_at | type == "string" and length > 0)
' "$receipt_before" >/dev/null

gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command 'sudo --non-interactive docker restart colortrace-runtime >/dev/null'

"$resume_script" \
  "$project_id" "$zone" "$instance" "$expected_generation"

readonly expected_source_commit=$(jq -er '.source_commit' "$receipt_before")
deployed_source_commit=$(gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command \
    'sudo --non-interactive docker inspect --format='\''{{ index .Config.Labels "org.opencontainers.image.revision" }}'\'' colortrace-runtime')
test "$deployed_source_commit" = "$expected_source_commit"

readonly mcp_probe_command='set -eu
probe=/tmp/colortrace-hosted-mcp-inventory.json
cleanup() {
  sudo --non-interactive docker exec colortrace-runtime \
    rm -f "$probe" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \
  /opt/colortrace/bin/colortrace-grafana-mcp catalog \
  --grafana-url https://grafana.internal:8443 \
  --token-file /var/run/colortrace-private/grafana-viewer-token \
  --tls-ca-file /etc/colortrace/caddy-root.crt \
  --binary /usr/local/bin/mcp-grafana \
  --lock /opt/colortrace-config/grafana-mcp/mcp-grafana.lock.json \
  --catalog /opt/colortrace-config/grafana-mcp/query-catalog.json \
  --output "$probe"
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \
  /opt/colortrace/bin/python -c '\''import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["schema"] == "grafana-mcp-tool-inventory/v1"
assert value["selected_tools"]'\'' \
  "$probe"'
gcloud compute ssh "$instance" \
  --project "$project_id" \
  --zone "$zone" \
  --tunnel-through-iap \
  --quiet \
  --command "$mcp_probe_command"

readonly receipt_after="$verification_root/receipt-after.json"
curl --fail --silent --show-error \
  --connect-timeout 10 \
  --max-time 30 \
  --max-redirs 0 \
  --proto '=https' \
  --netrc-file "$netrc" \
  --output "$receipt_after" \
  "$public_url/v1/demo/runs/$run_id/receipt"
jq -e --slurpfile before "$receipt_before" '
  .schema == "colortrace-demo-receipt/v1"
  and . == $before[0]
' "$receipt_after" >/dev/null

output_directory=$(dirname -- "$output")
install -d -m 0700 "$output_directory"
output_tmp=$(mktemp "$output_directory/.host-verification.XXXXXX")
jq -n \
  --slurpfile receipt "$receipt_after" \
  --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg public_url "$public_url" \
  --arg project "$project_id" \
  --arg zone "$zone" \
  --arg instance "$instance" \
  --arg generation "$expected_generation" \
  '{
    schema: "colortrace-single-host-verification/v1",
    checked_at: $checked_at,
    public_url: $public_url,
    instance: {project: $project, zone: $zone, name: $instance},
    staging_generation: $generation,
    source_commit: $receipt[0].source_commit,
    run_id: $receipt[0].run_id,
    receipt_sha256: $receipt[0].receipt_sha256,
    checks: {
      tls: "pass",
      access_gate: "pass",
      malformed_request: "pass",
      wrong_origin: "pass",
      general_api_private: "pass",
      non_https_public_tcp: "pass",
      runtime_health_after_restart: "pass",
      runtime_image_binding: "pass",
      grafana_mcp_inventory_after_restart: "pass",
      receipt_persistence_after_restart: "pass"
    }
  }' >"$output_tmp"
chmod 0600 "$output_tmp"
mv "$output_tmp" "$output"
output_tmp=''
printf '%s\n' "$output"
