#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if test "$#" -lt 4 || test "$#" -gt 5; then
  printf 'usage: %s PROJECT REGION RESOURCE_PREFIX CANDIDATE_COMMIT [OUTPUT]\n' "$0" >&2
  exit 64
fi

readonly project_id=$1
readonly region=$2
readonly resource_prefix=$3
readonly candidate_commit=$4
readonly script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly repository_root=$(git -C "$script_dir/../../.." rev-parse --show-toplevel)
readonly output=${5:-"$repository_root/.cache/single-host/image-digests-$candidate_commit.json"}

[[ "$project_id" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || exit 64
[[ "$region" == us-central1 ]] || exit 64
[[ "$resource_prefix" =~ ^[a-z][a-z0-9-]{2,19}[a-z0-9]$ ]] || exit 64
[[ "$candidate_commit" =~ ^[0-9a-f]{40}$ ]] || exit 64

command -v gcloud >/dev/null
command -v git >/dev/null
command -v jq >/dev/null
command -v tar >/dev/null
test -f "$repository_root/infra/single-host/cloudbuild.images.yaml"

actual_head=$(git -C "$repository_root" rev-parse --verify HEAD)
if test "$actual_head" != "$candidate_commit"; then
  printf 'candidate commit is not the checked-out HEAD\n' >&2
  exit 65
fi
if test -n "$(git -C "$repository_root" status --porcelain=v1 --untracked-files=all)"; then
  printf 'image builds require a clean Git worktree\n' >&2
  exit 66
fi

source_tree=$(git -C "$repository_root" show --no-patch --format=%T "$candidate_commit")
source_date_epoch=$(git -C "$repository_root" show --no-patch --format=%ct "$candidate_commit")
[[ "$source_tree" =~ ^[0-9a-f]{40}$ ]] || exit 65
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || exit 65

readonly registry="$region-docker.pkg.dev/$project_id/$resource_prefix-images"
readonly builder_service_account="projects/$project_id/serviceAccounts/$resource_prefix-builder@$project_id.iam.gserviceaccount.com"
readonly snapshot_root=$(mktemp -d)
manifest_tmp=''
cleanup() {
  if test -n "$manifest_tmp"; then
    rm -f -- "$manifest_tmp"
  fi
  if test -d "$snapshot_root"; then
    rm -r -- "$snapshot_root"
  fi
}
trap cleanup EXIT

git -C "$repository_root" archive --format=tar "$candidate_commit" \
  | tar --extract --file=- --directory "$snapshot_root"
readonly build_config="$snapshot_root/infra/single-host/cloudbuild.images.yaml"
test -f "$build_config"

build_id=$(gcloud builds submit "$snapshot_root" \
  --project "$project_id" \
  --region "$region" \
  --config "$build_config" \
  --service-account "$builder_service_account" \
  --substitutions "_REGISTRY=$registry,_SOURCE_COMMIT=$candidate_commit,_SOURCE_TREE=$source_tree,_SOURCE_DATE_EPOCH=$source_date_epoch" \
  --format='value(id)' \
  --quiet)
[[ "$build_id" =~ ^[A-Za-z0-9-]+$ ]] || {
  printf 'Cloud Build did not return one valid build identifier\n' >&2
  exit 70
}

build_result=$(gcloud builds describe "$build_id" \
  --project "$project_id" \
  --region "$region" \
  --format=json)

output_directory=$(dirname -- "$output")
mkdir -p "$output_directory"
manifest_tmp=$(mktemp "$output_directory/.image-digests.XXXXXX")

printf '%s' "$build_result" | jq -e \
  --arg build_id "$build_id" \
  --arg project_id "$project_id" \
  --arg region "$region" \
  --arg registry "$registry" \
  --arg service_account "$builder_service_account" \
  --arg source_commit "$candidate_commit" \
  --arg source_tree "$source_tree" \
  --arg source_date_epoch "$source_date_epoch" \
  '
    def image_result($component):
      ($registry + "/" + $component + ":" + $source_commit) as $expected_tag
      | [.results.images[]? | select(.name == $expected_tag)] as $matches
      | if ($matches | length) != 1 then
          error("missing unique result for " + $component)
        elif ($matches[0].digest | test("^sha256:[0-9a-f]{64}$") | not) then
          error("invalid digest for " + $component)
        else
          {
            tag: $expected_tag,
            digest: $matches[0].digest,
            reference: ($registry + "/" + $component + "@" + $matches[0].digest)
          }
        end;
    if .id != $build_id then
      error("described build identifier does not match")
    elif .status != "SUCCESS" then
      error("build did not succeed: " + (.status // "missing"))
    else
      . as $build
      | {
          schema_version: 1,
          build: {
            id: $build_id,
            project: $project_id,
            region: $region,
            service_account: $service_account,
            create_time: ($build.createTime // null),
            finish_time: ($build.finishTime // null)
          },
          source: {
            commit: $source_commit,
            tree: $source_tree,
            date_epoch: ($source_date_epoch | tonumber)
          },
          images: {
            runtime: ($build | image_result("runtime")),
            web: ($build | image_result("web")),
            caddy: ($build | image_result("caddy")),
            grafana: ($build | image_result("grafana")),
            loki: ($build | image_result("loki")),
            tempo: ($build | image_result("tempo"))
          }
        }
    end
  ' >"$manifest_tmp"

chmod 0644 "$manifest_tmp"
mv "$manifest_tmp" "$output"
manifest_tmp=''
printf '%s\n' "$output"
