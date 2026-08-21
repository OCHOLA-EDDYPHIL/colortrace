locals {
  run_services = {
    api = {
      command     = ["colortrace-api"]
      concurrency = 10
      ingress     = "INGRESS_TRAFFIC_ALL"
      port        = 8080
      timeout     = "60s"
    }
    simulator = {
      command     = ["colortrace-simulator-service"]
      concurrency = 1
      ingress     = "INGRESS_TRAFFIC_INTERNAL_ONLY"
      port        = 8080
      timeout     = "180s"
    }
    web = {
      command     = []
      concurrency = 40
      ingress     = "INGRESS_TRAFFIC_ALL"
      port        = 8080
      timeout     = "30s"
    }
    worker = {
      command     = ["colortrace-worker-service"]
      concurrency = 1
      ingress     = "INGRESS_TRAFFIC_INTERNAL_ONLY"
      port        = 8080
      timeout     = "180s"
    }
  }
}

resource "google_cloud_run_v2_service" "service" {
  for_each = var.deploy_workloads ? local.run_services : {}

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

    containers {
      image   = each.key == "web" ? local.web_image : local.runtime_image
      command = length(each.value.command) == 0 ? null : each.value.command

      ports {
        container_port = each.value.port
      }

      resources {
        limits = {
          cpu    = each.key == "worker" ? "2" : "1"
          memory = each.key == "worker" ? "1Gi" : "512Mi"
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
          path = "/health/startup"
        }
      }

      liveness_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 10
        failure_threshold     = 3

        http_get {
          path = "/health/live"
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
        for_each = each.key == "api" ? {
          COLORTRACE_OIDC_AUDIENCE = coalesce(var.oidc_audience, "unbound")
          COLORTRACE_OIDC_ISSUER   = coalesce(var.oidc_issuer, "unbound")
          COLORTRACE_OIDC_JWKS_URI = coalesce(var.oidc_jwks_uri, "unbound")
        } : {}

        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = each.key == "worker" ? { COLORTRACE_GRAFANA_TOKEN = coalesce(var.grafana_secret_version, "0") } : {}

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.grafana_viewer.secret_id
              version = env.value
            }
          }
        }
      }

      dynamic "volume_mounts" {
        for_each = contains(["api", "simulator", "worker"], each.key) ? [1] : []

        content {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }
    }

    dynamic "volumes" {
      for_each = contains(["api", "simulator", "worker"], each.key) ? [1] : []

      content {
        name = "cloudsql"

        cloud_sql_instance {
          instances = [google_sql_database_instance.workflow.connection_name]
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = strcontains(each.key == "web" ? local.web_image : local.runtime_image, "@sha256:")
      error_message = "Cloud Run images must use immutable SHA-256 digest references."
    }
  }

  depends_on = [
    google_project_service.required["run.googleapis.com"],
    google_secret_manager_secret_iam_member.worker_grafana,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  for_each = var.deploy_workloads ? toset(["api", "web"]) : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service[each.key].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "task_private" {
  for_each = var.deploy_workloads ? toset(["simulator", "worker"]) : toset([])

  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.service[each.key].name
  role     = "roles/run.invoker"
  member   = google_service_account.service["task"].member
}
