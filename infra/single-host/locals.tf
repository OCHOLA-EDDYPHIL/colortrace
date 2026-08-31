locals {
  labels = {
    application = "colortrace"
    environment = "staging"
    managed_by  = "terraform"
    topology    = "single-host"
  }

  staging_lifetime_hours    = 168
  subnet_cidr               = "10.72.0.0/28"
  iap_tcp_source_range      = "35.235.240.0/20"
  registry_host             = "${var.region}-docker.pkg.dev"
  expected_registry         = "${local.registry_host}/${var.project_id}/${var.resource_prefix}-images"
  expected_prometheus_image = "docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
  trivy_image               = "aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
  frozen_database_image     = "ghcr.io/aquasecurity/trivy-db@sha256:67136d9c032b639278e256601e29b8af0ff4ed28e66d859e4cac692f7c1deef6"
  frozen_database_sha256    = "sha256:eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314"
  frozen_database_time      = "2026-08-22T12:57:22.518776499Z"
  build_config_sha256       = "sha256:${filesha256("${path.module}/cloudbuild.images.yaml")}"
  observability_lock_sha256 = "sha256:${filesha256(
    "${path.module}/../../config/observability/images.lock.json"
  )}"
  fixture_manifest_sha256 = "sha256:${jsondecode(file(
    "${path.module}/../../packages/fixture-generator/fixtures/canonical-digests.json"
  )).files["runtime/manifests/fixture-runtime-manifest.json"]}"
  private_components = toset([
    "runtime",
    "web",
    "caddy",
    "grafana",
    "loki",
    "tempo",
  ])

  workload_inputs_complete = (
    var.operator_member != null
    && var.resume_member != null
    && var.resume_member != var.operator_member
    && var.staging_generation != null
    && var.access_secret_version != null
    && var.boot_image != null
    && var.estimated_seven_day_cost_usd != null
    && var.deployment_artifact_binding != null
    && var.deployment_artifact_binding_sha256 != null
  )

  artifact_binding_is_valid = try(
    var.deployment_artifact_binding.schema == "colortrace-single-host-admission/v1"
    && var.deployment_artifact_binding_sha256 == "sha256:${sha256(jsonencode(var.deployment_artifact_binding))}"
    && var.deployment_artifact_binding.build.project == var.project_id
    && var.deployment_artifact_binding.build.region == var.region
    && var.deployment_artifact_binding.build.registry == local.expected_registry
    && var.deployment_artifact_binding.build.service_account == "projects/${var.project_id}/serviceAccounts/${var.resource_prefix}-builder@${var.project_id}.iam.gserviceaccount.com"
    && var.deployment_artifact_binding.build.config_sha256 == local.build_config_sha256
    && var.deployment_artifact_binding.observability_lock_sha256 == local.observability_lock_sha256
    && can(timecmp(var.deployment_artifact_binding.build.create_time, var.deployment_artifact_binding.build.finish_time))
    && timecmp(var.deployment_artifact_binding.build.create_time, var.deployment_artifact_binding.build.finish_time) <= 0
    && var.deployment_artifact_binding.fixture_manifest_sha256 == local.fixture_manifest_sha256
    && alltrue([
      for component in local.private_components :
      startswith(
        var.deployment_artifact_binding.images[component],
        "${local.expected_registry}/${component}@sha256:",
      )
      && length(var.deployment_artifact_binding.images[component]) == length("${local.expected_registry}/${component}@sha256:") + 64
    ])
    && var.deployment_artifact_binding.images.prometheus == local.expected_prometheus_image
    && var.deployment_artifact_binding.scanner.image == local.trivy_image
    && can(timecmp(
      var.deployment_artifact_binding.scanner.databases.current.updated_at,
      var.deployment_artifact_binding.scanner.databases.current.updated_at,
    ))
    && var.deployment_artifact_binding.scanner.databases.frozen.image == local.frozen_database_image
    && var.deployment_artifact_binding.scanner.databases.frozen.content_sha256 == local.frozen_database_sha256
    && var.deployment_artifact_binding.scanner.databases.frozen.updated_at == local.frozen_database_time,
    false,
  )

  private_images_in_owned_registry = try(alltrue([
    for component in local.private_components :
    startswith(var.deployment_artifact_binding.images[component], "${local.expected_registry}/${component}@sha256:")
  ]), false)

  estimated_cost_is_bounded = try(
    var.estimated_seven_day_cost_usd > 0
    && var.estimated_seven_day_cost_usd < 100
    && var.estimated_seven_day_cost_usd <= var.cost_ceiling_usd,
    false,
  )

  placeholder_digest = "sha256:${join("", [for _ in range(64) : "0"])}"
  boot_image         = coalesce(var.boot_image, "projects/debian-cloud/global/images/debian-12-00000000")
  runtime_image      = try(var.deployment_artifact_binding.images.runtime, "invalid.local/colortrace/runtime@${local.placeholder_digest}")
  web_image          = try(var.deployment_artifact_binding.images.web, "invalid.local/colortrace/web@${local.placeholder_digest}")
  caddy_image        = try(var.deployment_artifact_binding.images.caddy, "invalid.local/colortrace/caddy@${local.placeholder_digest}")
  grafana_image      = try(var.deployment_artifact_binding.images.grafana, "invalid.local/colortrace/grafana@${local.placeholder_digest}")
  loki_image         = try(var.deployment_artifact_binding.images.loki, "invalid.local/colortrace/loki@${local.placeholder_digest}")
  prometheus_image   = try(var.deployment_artifact_binding.images.prometheus, "invalid.local/colortrace/prometheus@${local.placeholder_digest}")
  tempo_image        = try(var.deployment_artifact_binding.images.tempo, "invalid.local/colortrace/tempo@${local.placeholder_digest}")
  candidate_commit   = try(var.deployment_artifact_binding.source.commit, join("", [for _ in range(40) : "0"]))
  candidate_tree     = try(var.deployment_artifact_binding.source.tree, join("", [for _ in range(40) : "0"]))
  staging_generation = coalesce(var.staging_generation, "unbound")
  staging_hard_stop_epoch = coalesce(
    var.staging_hard_stop_epoch,
    0,
  )
  fixture_bundle_sha256 = try(
    var.deployment_artifact_binding.fixture_manifest_sha256,
    local.placeholder_digest,
  )
  deployment_artifact_binding_sha256 = coalesce(
    var.deployment_artifact_binding_sha256,
    local.placeholder_digest,
  )
  build_manifest_sha256 = try(
    var.deployment_artifact_binding.build_manifest_sha256,
    local.placeholder_digest,
  )
  scan_binding_sha256 = try(
    var.deployment_artifact_binding.scan_binding_sha256,
    local.placeholder_digest,
  )
  scanner_version_sha256 = try(
    var.deployment_artifact_binding.scanner.version_sha256,
    local.placeholder_digest,
  )
  scan_report_set_sha256 = try(
    var.deployment_artifact_binding.scanner.report_set_sha256,
    local.placeholder_digest,
  )
  runtime_build_binding_json = "${jsonencode({
    schema        = "colortrace-runtime-build-binding/v1"
    source_commit = local.candidate_commit
    source_tree   = local.candidate_tree
  })}\n"
  runtime_build_binding_sha256 = "sha256:${sha256(local.runtime_build_binding_json)}"
  public_hostname              = var.enable_instance ? "${replace(google_compute_address.public[0].address, ".", "-")}.sslip.io" : "invalid.example"
  public_url                   = "https://${local.public_hostname}"
}

check "instance_admission" {
  assert {
    condition = (
      !var.enable_instance
      || (
        local.workload_inputs_complete
        && local.artifact_binding_is_valid
        && local.private_images_in_owned_registry
        && local.estimated_cost_is_bounded
      )
    )
    error_message = "VM admission requires the operator identity, generation, immutable secret and boot image, one canonical checked build-and-scan artifact binding, and a seven-day estimate below USD 100 and no greater than the configured ceiling."
  }
}

check "isolated_network_identity" {
  assert {
    condition = (
      google_compute_network.single_host.name != "ct-p114-0821a-network"
      && google_compute_subnetwork.single_host.ip_cidr_range != "10.71.0.0/24"
    )
    error_message = "The single-host deployment must not reuse the reserved network or address range."
  }
}
