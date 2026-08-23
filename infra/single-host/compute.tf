locals {
  compose_yaml = templatefile("${path.module}/templates/compose.yaml.tftpl", {
    caddy_image         = local.caddy_image
    fixture_bundle_path = var.fixture_bundle_path
    lgtm_image          = local.lgtm_image
    runtime_image       = local.runtime_image
    web_image           = local.web_image
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
    block-project-ssh-keys        = "TRUE"
    colortrace-candidate-commit   = coalesce(var.candidate_commit, "unbound")
    colortrace-candidate-tree     = coalesce(var.candidate_tree, "unbound")
    colortrace-staging-generation = coalesce(var.staging_generation, "unbound")
    enable-oslogin                = "TRUE"
    serial-port-enable            = "FALSE"
  }

  metadata_startup_script = templatefile("${path.module}/templates/startup.sh.tftpl", {
    access_secret_id      = google_secret_manager_secret.access_gate.secret_id
    access_secret_version = coalesce(var.access_secret_version, "MISSING")
    caddyfile_base64 = base64encode(templatefile("${path.module}/templates/Caddyfile.tftpl", {
      access_username = var.access_username
      public_hostname = "${replace(google_compute_address.public[0].address, ".", "-")}.sslip.io"
    }))
    compose_yaml_base64    = base64encode(local.compose_yaml)
    project_id             = var.project_id
    region                 = var.region
    registry_host          = local.registry_host
    staging_generation     = coalesce(var.staging_generation, "unbound")
    staging_lifetime_hours = local.staging_lifetime_hours
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
        && local.private_images_in_owned_registry
        && local.estimated_cost_is_bounded
      )
      error_message = "The VM cannot be created until every admission input passes."
    }
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.host_reader,
    google_project_iam_member.host,
    google_project_iam_member.operator,
    google_secret_manager_secret_iam_member.host_access_gate,
  ]
}
