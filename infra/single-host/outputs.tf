output "resource_inventory" {
  description = "Non-secret inventory for the isolated single-host deployment."
  value = {
    network             = google_compute_network.single_host.id
    subnetwork          = google_compute_subnetwork.single_host.id
    subnetwork_cidr     = google_compute_subnetwork.single_host.ip_cidr_range
    service_account     = google_service_account.host.email
    builder_account     = google_service_account.builder.email
    access_secret       = google_secret_manager_secret.access_gate.id
    artifact_repository = google_artifact_registry_repository.images.id
    build_source_bucket = google_storage_bucket.build_source.name
    enabled_services    = sort(keys(google_project_service.required))
    public_address      = var.enable_instance ? google_compute_address.public[0].address : null
    instance            = var.enable_instance ? google_compute_instance.host[0].id : null
    persistent_disk     = var.enable_instance ? google_compute_disk.boot[0].id : null
    operator_iam_roles = var.enable_instance ? sort([
      google_project_iam_custom_role.operator_project_inspector[0].id,
      google_compute_instance_iam_member.operator_os_admin[0].role,
      google_iap_tunnel_instance_iam_member.operator_iap_ssh[0].role,
      google_service_account_iam_member.operator_host[0].role,
    ]) : []
    operator_build_roles = sort(keys(google_project_iam_member.operator_build))
    operator_build_source_roles = sort(
      keys(google_storage_bucket_iam_member.operator_build_source)
    )
    operator_artifact_reader = (
      var.operator_member == null ? null : {
        member     = google_artifact_registry_repository_iam_member.operator_reader[0].member
        repository = google_artifact_registry_repository.images.repository_id
        role       = google_artifact_registry_repository_iam_member.operator_reader[0].role
      }
    )
    host_iam_roles = (
      var.enable_instance ? [google_project_iam_custom_role.vertex_predictor[0].id] : []
    )
    resume_instance_start_role = (
      var.enable_instance ? google_project_iam_custom_role.resume_instance_starter[0].id : null
    )
    host_prediction_role = (
      var.enable_instance ? google_project_iam_custom_role.vertex_predictor[0].id : null
    )
    artifact_reader = var.enable_instance ? google_artifact_registry_repository_iam_member.host_reader[0].id : null
  }
}

output "image_build_identity" {
  description = "Non-secret identity and registry path used by the immutable image build command."
  value = {
    project         = var.project_id
    region          = var.region
    registry        = "${local.registry_host}/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
    service_account = google_service_account.builder.email
    source_staging  = "gs://${google_storage_bucket.build_source.name}/source"
  }
}

output "deployment_contract" {
  description = "Non-secret immutable and lifecycle bindings for the admitted host."
  value = var.enable_instance ? {
    candidate_commit      = local.candidate_commit
    candidate_tree        = local.candidate_tree
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
      caddy      = local.caddy_image
      grafana    = local.grafana_image
      loki       = local.loki_image
      prometheus = local.prometheus_image
      runtime    = local.runtime_image
      tempo      = local.tempo_image
      web        = local.web_image
    }
    fixture_bundle_sha256 = local.fixture_bundle_sha256
    artifact_hashes = {
      deployment_artifact_binding_sha256 = local.deployment_artifact_binding_sha256
      build_manifest_sha256              = local.build_manifest_sha256
      observability_lock_sha256          = local.observability_lock_sha256
      scan_binding_sha256                = local.scan_binding_sha256
      scan_report_set_sha256             = local.scan_report_set_sha256
      scanner_version_sha256             = local.scanner_version_sha256
      runtime_build_binding_sha256       = local.runtime_build_binding_sha256
    }
    scanner = var.deployment_artifact_binding.scanner
  } : null
}

output "resume_identity" {
  description = "Exact non-secret identity required by the guarded resume command."
  value = var.enable_instance ? {
    member                  = var.resume_member
    project                 = var.project_id
    zone                    = var.zone
    instance                = google_compute_instance.host[0].name
    generation              = var.staging_generation
    artifact_binding_sha256 = local.deployment_artifact_binding_sha256
  } : null
}
