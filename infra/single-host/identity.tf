resource "google_service_account" "host" {
  project      = var.project_id
  account_id   = "${var.resource_prefix}-vm"
  display_name = "ColorTrace single-host runtime"
  description  = "Dedicated runtime identity for the isolated ColorTrace staging host."

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

resource "google_service_account" "builder" {
  project      = var.project_id
  account_id   = "${var.resource_prefix}-builder"
  display_name = "ColorTrace single-host image builder"
  description  = "Dedicated Cloud Build identity for immutable ColorTrace staging images."

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

locals {
  host_project_roles = toset([
    "roles/aiplatform.user",
  ])

  operator_project_roles = toset([
    "roles/compute.osAdminLogin",
    "roles/iap.tunnelResourceAccessor",
  ])

  operator_build_project_roles = toset([
    "roles/cloudbuild.builds.editor",
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

resource "google_project_iam_member" "builder_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.builder.member
}

resource "google_project_iam_member" "operator_build" {
  for_each = var.operator_member == null ? toset([]) : local.operator_build_project_roles

  project = var.project_id
  role    = each.key
  member  = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_service_account_iam_member" "operator_build" {
  count = var.operator_member == null ? 0 : 1

  service_account_id = google_service_account.builder.name
  role               = "roles/iam.serviceAccountUser"
  member             = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_artifact_registry_repository_iam_member" "host_reader" {
  count = var.enable_instance ? 1 : 0

  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = google_service_account.host.member
}

resource "google_artifact_registry_repository_iam_member" "builder_writer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.builder.member
}
