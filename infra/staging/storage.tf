resource "google_artifact_registry_repository" "runtime" {
  project       = var.project_id
  location      = var.region
  repository_id = "${var.resource_prefix}-runtime"
  description   = "Immutable ColorTrace staging runtime images."
  format        = "DOCKER"
  mode          = "STANDARD_REPOSITORY"
  labels        = local.labels

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"

    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s"
    }
  }

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"

    most_recent_versions {
      keep_count = 4
    }
  }

  depends_on = [google_project_service.required["artifactregistry.googleapis.com"]]
}

resource "google_storage_bucket" "artifacts" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.resource_prefix}-artifacts"
  location                    = upper(var.region)
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = local.labels

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age        = 7
      with_state = "ARCHIVED"
    }
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age        = 14
      with_state = "ANY"
    }
  }
}

resource "google_storage_bucket_iam_member" "simulator_writer" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectUser"
  member = google_service_account.service["simulator"].member
}

resource "google_storage_bucket_iam_member" "worker_reader" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.service["worker"].member
}

resource "google_artifact_registry_repository_iam_member" "deployment_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.runtime.location
  repository = google_artifact_registry_repository.runtime.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.service["deployment"].member
}

resource "google_secret_manager_secret" "grafana_viewer" {
  project   = var.project_id
  secret_id = "${var.resource_prefix}-grafana-viewer"
  labels    = local.labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_iam_member" "worker_grafana" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.grafana_viewer.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.service["worker"].member
}
