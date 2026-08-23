resource "google_storage_bucket" "build_source" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.resource_prefix}-build-source"
  location                    = var.region
  storage_class               = "STANDARD"
  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.labels

  lifecycle_rule {
    action {
      type = "Delete"
    }

    condition {
      age = 1
    }
  }

  depends_on = [google_project_service.required["storage.googleapis.com"]]
}

locals {
  operator_build_source_roles = toset([
    "roles/storage.legacyBucketReader",
    "roles/storage.objectCreator",
  ])
}

resource "google_storage_bucket_iam_member" "operator_build_source" {
  for_each = var.operator_member == null ? toset([]) : local.operator_build_source_roles

  bucket = google_storage_bucket.build_source.name
  role   = each.key
  member = coalesce(var.operator_member, "user:invalid@example.invalid")
}

resource "google_storage_bucket_iam_member" "builder_build_source" {
  bucket = google_storage_bucket.build_source.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.builder.member
}
