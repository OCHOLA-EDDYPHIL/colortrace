#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if test "$#" -ne 4; then
  printf 'usage: %s DIGEST_MANIFEST CURRENT_CACHE FROZEN_CACHE OUTPUT_DIRECTORY\n' "$0" >&2
  exit 64
fi

readonly script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly repository_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)
readonly observability_lock="$repository_root/config/observability/images.lock.json"
readonly admission_helper="$script_dir/admission-binding.py"
readonly trivy_image='aquasec/trivy@sha256:'\
'bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c'
readonly frozen_database_image='ghcr.io/aquasecurity/trivy-db@sha256:'\
'67136d9c032b639278e256601e29b8af0ff4ed28e66d859e4cac692f7c1deef6'
readonly frozen_database_sha256='eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314'
readonly docker_socket=${COLORTRACE_DOCKER_SOCKET:-/var/run/docker.sock}

command -v docker >/dev/null
command -v jq >/dev/null
command -v python3 >/dev/null
command -v realpath >/dev/null
command -v sha256sum >/dev/null
command -v stat >/dev/null
test -f "$1"
test -f "$observability_lock"
test -x "$admission_helper"
test -e "$docker_socket"
install -d -m 0700 "$2" "$3" "$4"
readonly manifest=$(realpath "$1")
readonly current_cache=$(realpath "$2")
readonly frozen_cache=$(realpath "$3")
readonly output_directory=$(realpath "$4")
for path in "$manifest" "$current_cache" "$frozen_cache" "$output_directory" "$docker_socket"; do
  case "$path" in
    *$'\n'*|*:*) exit 64 ;;
  esac
done
test "$current_cache" != "$frozen_cache"
test "$current_cache" != "$output_directory"
test "$frozen_cache" != "$output_directory"
docker pull "$trivy_image" >/dev/null
docker image inspect "$trivy_image" >/dev/null

python3 "$admission_helper" validate-build "$manifest"
readonly source_commit=$(jq -er '.source.commit' "$manifest")
readonly tag_pattern="^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9_./-]+:${source_commit}$"

readonly components=(runtime web caddy grafana loki prometheus tempo)
declare -A references
for component in "${components[@]}"; do
  tag=$(jq -er --arg component "$component" '.images[$component].tag' "$manifest")
  digest=$(jq -er --arg component "$component" '.images[$component].digest' "$manifest")
  reference=$(jq -er --arg component "$component" '.images[$component].reference' "$manifest")
  [[ "$tag" =~ $tag_pattern ]] || exit 65
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 65
  test "$reference" = "${tag%:*}@$digest" || exit 65
  references[$component]=$reference
done

for component in "${components[@]}"; do
  docker pull "${references[$component]}" >/dev/null
  docker image inspect "${references[$component]}" >/dev/null
done

readonly host_uid=$(id -u)
readonly host_gid=$(id -g)
readonly socket_gid=$(stat -c '%g' "$docker_socket")

download_database() {
  local cache=$1
  shift
  docker run --rm --pull=never \
    --user "$host_uid:$host_gid" \
    --volume "$cache:/trivy-cache" \
    "$trivy_image" image \
    --cache-dir /trivy-cache \
    --download-db-only \
    --skip-java-db-update \
    --skip-version-check \
    "$@"
}

download_database "$current_cache"
if ! test -s "$frozen_cache/db/trivy.db"; then
  download_database "$frozen_cache" --db-repository "$frozen_database_image"
fi

validate_databases() {
  test -s "$current_cache/db/trivy.db"
  test -s "$current_cache/db/metadata.json"
  test -s "$frozen_cache/db/trivy.db"
  test -s "$frozen_cache/db/metadata.json"
  printf '%s  %s\n' "$frozen_database_sha256" "$frozen_cache/db/trivy.db" \
    | sha256sum --check --status
  jq -e '.Version == 2 and (.UpdatedAt | type == "string")' \
    "$current_cache/db/metadata.json" >/dev/null
  jq -e '
    .Version == 2
    and .UpdatedAt == "2026-08-22T12:57:22.518776499Z"
    and .NextUpdate == "2026-08-23T12:57:22.518775968Z"
    and (.DownloadedAt | type == "string")
    and (.DownloadedAt | length > 0)
  ' \
    "$frozen_cache/db/metadata.json" >/dev/null
}

validate_databases
docker run --rm --network none --pull=never \
  --user "$host_uid:$host_gid" \
  --volume "$current_cache:/trivy-cache:ro" \
  "$trivy_image" --cache-dir /trivy-cache version --format json \
  >"$output_directory/scanner.json"

scan_image() {
  local database_name=$1
  local cache=$2
  local component=$3
  local reference=$4
  local report="$output_directory/$database_name-$component.json"
  docker run --rm --network none --pull=never \
    --user "$host_uid:$host_gid" \
    --group-add "$socket_gid" \
    --volume "$docker_socket:/var/run/docker.sock" \
    --volume "$cache:/trivy-cache" \
    --volume "$output_directory:/reports" \
    "$trivy_image" image \
    --cache-dir /trivy-cache \
    --image-src docker \
    --offline-scan \
    --parallel 1 \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --ignore-unfixed=false \
    --skip-db-update \
    --skip-java-db-update \
    --skip-version-check \
    --format json \
    --output "/reports/$database_name-$component.json" \
    "$reference"
  jq -e '
    (.Results | type == "array")
    and ([.Results[]?.Vulnerabilities[]?] | length == 0)
  ' "$report" >/dev/null
}

for component in "${components[@]}"; do
  scan_image current "$current_cache" "$component" "${references[$component]}"
  scan_image frozen "$frozen_cache" "$component" "${references[$component]}"
done

validate_databases
install -m 0600 "$current_cache/db/metadata.json" \
  "$output_directory/current-db-metadata.json"
install -m 0600 "$frozen_cache/db/metadata.json" \
  "$output_directory/frozen-db-metadata.json"
current_database_sha256=$(sha256sum "$current_cache/db/trivy.db" | cut -d ' ' -f 1)
python3 "$admission_helper" record-scan \
  "$manifest" \
  "$observability_lock" \
  "$output_directory" \
  "sha256:$current_database_sha256" \
  "sha256:$frozen_database_sha256"
printf '%s\n' "$output_directory/scan-bindings.json"
