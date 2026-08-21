resource "google_sql_database_instance" "workflow" {
  project             = var.project_id
  name                = "${var.resource_prefix}-postgres"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = false

  settings {
    tier              = "db-f1-micro"
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"
    disk_type         = "PD_HDD"
    disk_size         = 10
    disk_autoresize   = false

    backup_configuration {
      enabled                        = false
      point_in_time_recovery_enabled = false
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }

    insights_config {
      query_insights_enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"
    }

    password_validation_policy {
      min_length                  = 20
      complexity                  = "COMPLEXITY_DEFAULT"
      reuse_interval              = 4
      disallow_username_substring = true
      enable_password_policy      = true
    }

    user_labels = local.labels
  }

  depends_on = [google_project_service.required["sqladmin.googleapis.com"]]
}

resource "google_sql_database" "workflow" {
  project  = var.project_id
  name     = "colortrace"
  instance = google_sql_database_instance.workflow.name
}

locals {
  database_identities = toset(["api", "migration", "simulator", "worker"])
}

resource "google_sql_user" "iam" {
  for_each = local.database_identities

  project  = var.project_id
  instance = google_sql_database_instance.workflow.name
  name     = trimsuffix(google_service_account.service[each.key].email, ".gserviceaccount.com")
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}
