resource "google_secret_manager_secret" "access_gate" {
  project   = var.project_id
  secret_id = "${var.resource_prefix}-access-hash"
  labels    = local.labels

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  depends_on = [google_project_service.required["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_iam_member" "host_access_gate" {
  count = var.enable_instance ? 1 : 0

  project   = var.project_id
  secret_id = google_secret_manager_secret.access_gate.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.host.member
}
