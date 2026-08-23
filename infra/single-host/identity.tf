resource "google_service_account" "host" {
  project      = var.project_id
  account_id   = "${var.resource_prefix}-vm"
  display_name = "ColorTrace single-host runtime"
  description  = "Dedicated runtime identity for the isolated ColorTrace staging host."

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

locals {
  host_project_roles = toset([
    "roles/aiplatform.user",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ])

  operator_project_roles = toset([
    "roles/compute.osAdminLogin",
    "roles/iap.tunnelResourceAccessor",
  ])
}

resource "google_project_iam_member" "host" {
  for_each = var.enable_instance ? local.host_project_roles : toset([])

  project = var.project_id
  role    = each.key
  member  = google_service_account.host.member
}

resource "google_project_iam_member" "operator" {
  for_each = var.enable_instance ? local.operator_project_roles : toset([])

  project = var.project_id
  role    = each.key
  member  = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_artifact_registry_repository_iam_member" "host_reader" {
  count = var.enable_instance ? 1 : 0

  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.host.member
}
