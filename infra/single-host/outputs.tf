output "resource_inventory" {
  description = "Non-secret inventory for the isolated single-host deployment."
  value = {
    network              = google_compute_network.single_host.id
    subnetwork           = google_compute_subnetwork.single_host.id
    subnetwork_cidr      = google_compute_subnetwork.single_host.ip_cidr_range
    service_account      = google_service_account.host.email
    builder_account      = google_service_account.builder.email
    access_secret        = google_secret_manager_secret.access_gate.id
    artifact_repository  = google_artifact_registry_repository.images.id
    enabled_services     = sort(keys(google_project_service.required))
    public_address       = var.enable_instance ? google_compute_address.public[0].address : null
    instance             = var.enable_instance ? google_compute_instance.host[0].id : null
    persistent_disk      = var.enable_instance ? google_compute_disk.boot[0].id : null
    operator_iam_roles   = sort(keys(google_project_iam_member.operator))
    operator_build_roles = sort(keys(google_project_iam_member.operator_build))
    host_iam_roles       = sort(keys(google_project_iam_member.host))
    artifact_reader      = var.enable_instance ? google_artifact_registry_repository_iam_member.host_reader[0].id : null
  }
}

output "image_build_identity" {
  description = "Non-secret identity and registry path used by the immutable image build command."
  value = {
    project         = var.project_id
    region          = var.region
    registry        = "${local.registry_host}/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
    service_account = google_service_account.builder.email
  }
}

output "deployment_contract" {
  description = "Non-secret immutable and lifecycle bindings for the admitted host."
  value = var.enable_instance ? {
    candidate_commit      = var.candidate_commit
    candidate_tree        = var.candidate_tree
    machine_type          = var.machine_type
    disk_size_gb          = var.boot_disk_size_gb
    disk_type             = google_compute_disk.boot[0].type
    boot_image            = var.boot_image
    generation            = var.staging_generation
    lifetime_hours        = local.staging_lifetime_hours
    estimated_cost_usd    = var.estimated_seven_day_cost_usd
    cost_ceiling_usd      = var.cost_ceiling_usd
    public_tcp_ports      = [443]
    ssh_source_range      = local.iap_tcp_source_range
    public_hostname       = local.public_hostname
    public_url            = local.public_url
    access_secret_version = var.access_secret_version
    images = {
      caddy      = var.caddy_image
      grafana    = var.grafana_image
      loki       = var.loki_image
      prometheus = var.prometheus_image
      runtime    = var.runtime_image
      tempo      = var.tempo_image
      web        = var.web_image
    }
    fixture_bundle_sha256 = var.fixture_bundle_sha256
  } : null
}

output "resume_identity" {
  description = "Exact non-secret identity required by the guarded resume command."
  value = var.enable_instance ? {
    project    = var.project_id
    zone       = var.zone
    instance   = google_compute_instance.host[0].name
    generation = var.staging_generation
  } : null
}
