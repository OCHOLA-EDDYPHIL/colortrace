locals {
  caddyfile = templatefile("${path.module}/templates/Caddyfile.tftpl", {
    access_username = var.access_username
    public_hostname = local.public_hostname
  })
  compose_yaml = templatefile("${path.module}/templates/compose.yaml.tftpl", {
    caddy_image           = local.caddy_image
    candidate_commit      = local.candidate_commit
    candidate_tree        = local.candidate_tree
    fixture_bundle_path   = var.fixture_bundle_path
    fixture_bundle_sha256 = local.fixture_bundle_sha256
    grafana_image         = local.grafana_image
    loki_image            = local.loki_image
    project_id            = var.project_id
    prometheus_image      = local.prometheus_image
    public_url            = local.public_url
    runtime_image         = local.runtime_image
    staging_generation    = local.staging_generation
    tempo_image           = local.tempo_image
    web_image             = local.web_image
  })
}

resource "google_compute_disk" "boot" {
  count = var.enable_instance ? 1 : 0

  project = var.project_id
  name    = "${var.resource_prefix}-boot"
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.boot_disk_size_gb
  image   = local.boot_image
  labels  = local.labels

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_instance" "host" {
  count = var.enable_instance ? 1 : 0

  project                   = var.project_id
  name                      = "${var.resource_prefix}-vm"
  zone                      = var.zone
  machine_type              = var.machine_type
  allow_stopping_for_update = true
  can_ip_forward            = false
  deletion_protection       = false
  tags = [
    "${var.resource_prefix}-iap-ssh",
    "${var.resource_prefix}-public",
  ]
  labels = local.labels

  boot_disk {
    source      = google_compute_disk.boot[0].id
    auto_delete = false
    mode        = "READ_WRITE"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.single_host.id

    access_config {
      nat_ip       = google_compute_address.public[0].address
      network_tier = "PREMIUM"
    }
  }

  service_account {
    email  = google_service_account.host.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys                  = "TRUE"
    colortrace-artifact-binding-sha256      = local.deployment_artifact_binding_sha256
    colortrace-build-manifest-sha256        = local.build_manifest_sha256
    colortrace-candidate-commit             = local.candidate_commit
    colortrace-candidate-tree               = local.candidate_tree
    colortrace-fixture-manifest-sha256      = local.fixture_bundle_sha256
    colortrace-observability-lock-sha256    = local.observability_lock_sha256
    colortrace-runtime-build-binding-sha256 = local.runtime_build_binding_sha256
    colortrace-scan-binding-sha256          = local.scan_binding_sha256
    colortrace-scan-report-set-sha256       = local.scan_report_set_sha256
    colortrace-scanner-version-sha256       = local.scanner_version_sha256
    colortrace-staging-generation           = local.staging_generation
    enable-oslogin                          = "TRUE"
    serial-port-enable                      = "FALSE"
  }

  metadata_startup_script = templatefile("${path.module}/templates/startup.sh.tftpl", {
    access_secret_id           = google_secret_manager_secret.access_gate.secret_id
    access_secret_version      = coalesce(var.access_secret_version, "MISSING")
    caddyfile_base64           = base64encode(local.caddyfile)
    compose_yaml_base64        = base64encode(local.compose_yaml)
    grafana_alerting_base64    = filebase64("${path.module}/../../config/telemetry/grafana-alerting.yaml")
    grafana_datasources_base64 = filebase64("${path.module}/../../config/observability/grafana-datasources.yaml")
    loki_config_base64         = filebase64("${path.module}/../../config/observability/loki.yaml")
    prometheus_config_base64   = filebase64("${path.module}/../../config/observability/prometheus.yaml")
    tempo_config_base64        = filebase64("${path.module}/../../config/observability/tempo.yaml")
    project_id                 = var.project_id
    region                     = var.region
    registry_host              = local.registry_host
    staging_generation         = coalesce(var.staging_generation, "unbound")
    staging_lifetime_hours     = local.staging_lifetime_hours
  })

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    provisioning_model  = "STANDARD"
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  lifecycle {
    precondition {
      condition = (
        local.workload_inputs_complete
        && local.artifact_binding_is_valid
        && local.private_images_in_owned_registry
        && local.estimated_cost_is_bounded
      )
      error_message = "The VM cannot be created until every admission input passes."
    }
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.host_reader,
    google_project_iam_member.host_vertex_predictor,
    google_project_iam_member.operator,
    google_secret_manager_secret_iam_member.host_access_gate,
  ]
}
