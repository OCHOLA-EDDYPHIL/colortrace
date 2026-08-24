locals {
  run_services = {
    api = {
      arguments   = ["api-readonly"]
      concurrency = 10
      ingress     = "INGRESS_TRAFFIC_ALL"
      port        = 8080
      timeout     = "60s"
    }
    web = {
      arguments   = []
      concurrency = 40
      ingress     = "INGRESS_TRAFFIC_ALL"
      port        = 8080
      timeout     = "30s"
    }
  }

  selected_run_services = {
    for name, configuration in local.run_services : name => configuration
    if contains(var.workload_services, name)
  }

  database_roles = {
    migration = google_sql_user.iam["migration"].name
    reader    = google_sql_user.iam["api"].name
    runtime   = google_sql_user.iam["worker"].name
  }

  hosted_database_environment = {
    COLORTRACE_CLOUD_SQL_DATABASE      = google_sql_database.workflow.name
    COLORTRACE_CLOUD_SQL_INSTANCE      = google_sql_database_instance.workflow.connection_name
    COLORTRACE_POSTGRES_MIGRATION_ROLE = local.database_roles.migration
    COLORTRACE_POSTGRES_API_ROLE       = local.database_roles.reader
    COLORTRACE_POSTGRES_RUNTIME_ROLE   = local.database_roles.runtime
  }

  database_jobs = merge(
    var.database_bootstrap_secret_version == null ? {} : { bootstrap = {} },
    var.enable_database_migration_job ? { migrate-seed = {} } : {},
  )
}

data "google_cloud_run_v2_service" "api" {
  count = contains(var.workload_services, "web") ? 1 : 0

  project  = var.project_id
  name     = "${var.resource_prefix}-api"
  location = var.region
}

resource "google_cloud_run_v2_service" "service" {
  for_each = local.selected_run_services

  project             = var.project_id
  name                = "${var.resource_prefix}-${each.key}"
  location            = var.region
  ingress             = each.value.ingress
  deletion_protection = false
  labels              = local.labels

  template {
    service_account                  = google_service_account.service[each.key].email
    timeout                          = each.value.timeout
    max_instance_request_concurrency = each.value.concurrency
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    labels                           = local.labels

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    dynamic "vpc_access" {
      for_each = each.key == "api" ? [1] : []

      content {
        egress = "PRIVATE_RANGES_ONLY"

        network_interfaces {
          network    = google_compute_network.staging.name
          subnetwork = google_compute_subnetwork.staging.name
        }
      }
    }

    containers {
      image = each.key == "web" ? local.web_image : local.runtime_image
      args  = length(each.value.arguments) == 0 ? null : each.value.arguments

      ports {
        container_port = each.value.port
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 2
        failure_threshold     = 30

        http_get {
          path = each.key == "web" ? "/" : "/health/startup"
        }
      }

      liveness_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 10
        failure_threshold     = 3

        http_get {
          path = each.key == "web" ? "/" : "/health/live"
        }
      }

      dynamic "env" {
        for_each = each.key == "web" ? {} : local.candidate_environment

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = each.key == "web" ? {
          COLORTRACE_API_AUDIENCE = data.google_cloud_run_v2_service.api[0].uri
          COLORTRACE_API_ORIGIN   = data.google_cloud_run_v2_service.api[0].uri
        } : {}

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = each.key == "api" ? {
          COLORTRACE_BIND_HOST = "0.0.0.0"
        } : {}

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = each.key == "api" ? local.hosted_database_environment : {}

        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !local.database_job_requested
      error_message = "Database preparation jobs must be removed before any workload is admitted."
    }

    precondition {
      condition     = local.workload_bindings_complete
      error_message = "Every immutable workload and identity binding must be supplied before Cloud Run deployment."
    }

    precondition {
      condition     = strcontains(each.key == "web" ? local.web_image : local.runtime_image, "@sha256:")
      error_message = "Cloud Run images must use immutable SHA-256 digest references."
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_service_networking_connection.private_services,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  for_each = contains(var.workload_services, "web") ? toset(["web"]) : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service[each.key].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "web_api" {
  for_each = contains(var.workload_services, "web") ? toset(["api"]) : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service[each.key].name
  role     = "roles/run.invoker"
  member   = google_service_account.service["web"].member
}

resource "google_cloud_run_v2_job" "database" {
  for_each = local.database_jobs

  project             = var.project_id
  name                = "${var.resource_prefix}-${each.key}"
  location            = var.region
  deletion_protection = false
  labels              = local.labels

  template {
    parallelism = 1
    task_count  = 1

    template {
      service_account       = google_service_account.service["migration"].email
      timeout               = "300s"
      max_retries           = 0
      execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"

        network_interfaces {
          network    = google_compute_network.staging.name
          subnetwork = google_compute_subnetwork.staging.name
        }
      }

      containers {
        image = local.runtime_image
        args  = [each.key]

        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }

        dynamic "env" {
          for_each = merge(local.candidate_environment, local.hosted_database_environment)

          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "env" {
          for_each = each.key == "bootstrap" ? {
            COLORTRACE_POSTGRES_ADMIN_PASSWORD_FILE   = "/run/colortrace-private/postgres-admin"
            COLORTRACE_POSTGRES_ADMIN_PASSWORD_SOURCE = "/var/run/secrets/colortrace/postgres-admin"
            COLORTRACE_POSTGRES_ADMIN_USER            = "postgres"
          } : {}

          content {
            name  = env.key
            value = env.value
          }
        }

        dynamic "volume_mounts" {
          for_each = each.key == "bootstrap" ? [1] : []

          content {
            name       = "postgres-bootstrap"
            mount_path = "/var/run/secrets/colortrace"
          }
        }
      }

      dynamic "volumes" {
        for_each = each.key == "bootstrap" ? [1] : []

        content {
          name = "postgres-bootstrap"

          secret {
            secret       = google_secret_manager_secret.postgres_bootstrap.secret_id
            default_mode = 292

            items {
              version = coalesce(var.database_bootstrap_secret_version, "0")
              path    = "postgres-admin"
              mode    = 292
            }
          }
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = length(var.workload_services) == 0 && length(local.database_jobs) == 1
      error_message = "Exactly one database preparation stage may exist, with no admitted workloads."
    }

    precondition {
      condition     = local.database_job_bindings_complete
      error_message = "Every immutable candidate and runtime binding is required before a database job is created."
    }

    precondition {
      condition     = strcontains(local.runtime_image, "@sha256:")
      error_message = "Database jobs require an immutable SHA-256 runtime image."
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_secret_manager_secret_iam_member.migration_bootstrap,
    google_service_networking_connection.private_services,
    google_sql_user.iam,
  ]
}
