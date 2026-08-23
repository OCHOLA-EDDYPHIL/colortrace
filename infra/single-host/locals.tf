locals {
  labels = {
    application = "colortrace"
    environment = "staging"
    managed_by  = "terraform"
    topology    = "single-host"
  }

  staging_lifetime_hours = 168
  subnet_cidr            = "10.72.0.0/28"
  iap_tcp_source_range   = "35.235.240.0/20"
  registry_host          = "${var.region}-docker.pkg.dev"

  workload_inputs_complete = alltrue([
    for value in [
      var.operator_member,
      var.staging_generation,
      var.access_secret_version,
      var.candidate_commit,
      var.candidate_tree,
      var.boot_image,
      var.runtime_image,
      var.web_image,
      var.caddy_image,
      var.lgtm_image,
    ] : value != null
  ])

  private_images_in_owned_registry = alltrue([
    for image in [var.runtime_image, var.web_image] :
    image == null || startswith(
      image,
      "${local.registry_host}/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/",
    )
  ])

  estimated_cost_is_bounded = try(
    var.estimated_seven_day_cost_usd > 0
    && var.estimated_seven_day_cost_usd <= var.cost_ceiling_usd,
    false,
  )

  placeholder_digest = "sha256:${join("", [for _ in range(64) : "0"])}"
  boot_image         = coalesce(var.boot_image, "projects/debian-cloud/global/images/debian-12-00000000")
  runtime_image      = coalesce(var.runtime_image, "invalid.local/colortrace/runtime@${local.placeholder_digest}")
  web_image          = coalesce(var.web_image, "invalid.local/colortrace/web@${local.placeholder_digest}")
  caddy_image        = coalesce(var.caddy_image, "invalid.local/colortrace/caddy@${local.placeholder_digest}")
  lgtm_image         = coalesce(var.lgtm_image, "invalid.local/colortrace/lgtm@${local.placeholder_digest}")
}

check "instance_admission" {
  assert {
    condition = (
      !var.enable_instance
      || (
        local.workload_inputs_complete
        && local.private_images_in_owned_registry
        && local.estimated_cost_is_bounded
      )
    )
    error_message = "VM admission requires the operator identity, generation, immutable secret version, source bindings, exact boot image, digest-addressed workload images, owned runtime and web images, and a bounded seven-day cost estimate."
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
