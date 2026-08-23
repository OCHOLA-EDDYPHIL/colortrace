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
  operator_build_project_roles = toset([
    "roles/cloudbuild.builds.editor",
    "roles/serviceusage.serviceUsageConsumer",
  ])
}

resource "google_project_iam_custom_role" "vertex_predictor" {
  count = var.enable_instance ? 1 : 0

  project     = var.project_id
  role_id     = "${replace(var.resource_prefix, "-", "_")}_vertex_predictor"
  title       = "ColorTrace Vertex prediction"
  description = "Allows only hosted Vertex prediction for the single-host runtime."
  permissions = ["aiplatform.endpoints.predict"]
  stage       = "GA"

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

resource "google_project_iam_member" "host_vertex_predictor" {
  count = var.enable_instance ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.vertex_predictor[0].id
  member  = google_service_account.host.member
}

resource "google_project_iam_custom_role" "operator_project_inspector" {
  count = var.enable_instance ? 1 : 0

  project     = var.project_id
  role_id     = "${replace(var.resource_prefix, "-", "_")}_project_inspector"
  title       = "ColorTrace project inspection"
  description = "Allows only the project and instance-list lookups required by the guarded gcloud SSH workflow."
  permissions = [
    "compute.instances.list",
    "compute.projects.get",
  ]
  stage = "GA"

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

resource "google_project_iam_member" "operator_project_inspector" {
  count = var.enable_instance ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.operator_project_inspector[0].id
  member  = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_compute_instance_iam_member" "operator_os_admin" {
  count = var.enable_instance ? 1 : 0

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.host[0].name
  role          = "roles/compute.osAdminLogin"
  member        = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_iap_tunnel_instance_iam_member" "operator_iap_ssh" {
  count = var.enable_instance ? 1 : 0

  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.host[0].name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = coalesce(var.operator_member, "user:invalid@example.invalid")

  condition {
    title       = "${var.resource_prefix}-iap-ssh-only"
    description = "Restricts the exact-instance IAP tunnel to SSH."
    expression  = "destination.port == 22"
  }
}

resource "google_service_account_iam_member" "operator_host" {
  count = var.enable_instance ? 1 : 0

  service_account_id = google_service_account.host.name
  role               = "roles/iam.serviceAccountUser"
  member             = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_project_iam_custom_role" "resume_instance_starter" {
  count = var.enable_instance ? 1 : 0

  project     = var.project_id
  role_id     = "${replace(var.resource_prefix, "-", "_")}_instance_starter"
  title       = "ColorTrace instance start"
  description = "Allows the guarded operator workflow to inspect and start the single staging VM."
  permissions = [
    "compute.instances.get",
    "compute.instances.start",
  ]
  stage = "GA"

  depends_on = [google_project_service.required["iam.googleapis.com"]]
}

resource "google_compute_instance_iam_member" "resume_instance_starter" {
  count = var.enable_instance ? 1 : 0

  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.host[0].name
  role          = google_project_iam_custom_role.resume_instance_starter[0].id
  member        = coalesce(var.resume_member, "user:invalid@example.invalid")
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

resource "google_artifact_registry_repository_iam_member" "operator_reader" {
  count = var.operator_member == null ? 0 : 1

  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.reader"
  member     = coalesce(var.operator_member, "user:invalid@example.invalid")
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
