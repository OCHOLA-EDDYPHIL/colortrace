locals {
  service_accounts = {
    api = {
      display_name = "ColorTrace staging API"
    }
    deployment = {
      display_name = "ColorTrace staging deployment"
    }
    migration = {
      display_name = "ColorTrace staging database migration"
    }
    simulator = {
      display_name = "ColorTrace staging simulator"
    }
    task = {
      display_name = "ColorTrace staging task delivery"
    }
    web = {
      display_name = "ColorTrace staging web"
    }
    worker = {
      display_name = "ColorTrace staging worker"
    }
  }
}

resource "google_service_account" "service" {
  for_each = local.service_accounts

  project      = var.project_id
  account_id   = "${var.resource_prefix}-${each.key}"
  display_name = each.value.display_name
  description  = "Dedicated ${each.key} identity for ColorTrace staging."

  depends_on = [google_project_service.required]
}

locals {
  project_roles = {
    api        = toset(["roles/logging.logWriter"])
    deployment = toset([])
    migration  = toset(["roles/logging.logWriter"])
    simulator  = toset(["roles/logging.logWriter"])
    task       = toset([])
    web = toset([
      "roles/logging.logWriter",
    ])
    worker = toset([
      "roles/aiplatform.user",
      "roles/logging.logWriter",
    ])
  }

  project_role_bindings = merge([
    for identity, roles in local.project_roles : {
      for role in roles : "${identity}:${role}" => {
        identity = identity
        role     = role
      }
    }
  ]...)
}

locals {
  cloud_sql_identities = toset(["api", "migration", "simulator", "worker"])
  cloud_sql_roles      = toset(["roles/cloudsql.client", "roles/cloudsql.instanceUser"])
  cloud_sql_role_bindings = {
    for binding in setproduct(local.cloud_sql_identities, local.cloud_sql_roles) :
    "${binding[0]}:${binding[1]}" => {
      identity = binding[0]
      role     = binding[1]
    }
  }
}

resource "google_project_iam_member" "cloud_sql_runtime" {
  for_each = local.cloud_sql_role_bindings

  project = var.project_id
  role    = each.value.role
  member  = google_service_account.service[each.value.identity].member

  condition {
    title       = "colortrace_staging_sql_instance"
    description = "Restrict runtime database connection authority to the owned staging instance."
    expression  = "resource.name == 'projects/${var.project_id}/instances/${google_sql_database_instance.workflow.name}'"
  }
}

resource "google_project_iam_member" "deployment_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = google_service_account.service["deployment"].member

  condition {
    title       = "colortrace_staging_run_resources"
    description = "Restrict deployment authority to ColorTrace staging services and jobs."
    expression  = "resource.name.startsWith('projects/${var.project_id}/locations/${var.region}/services/${var.resource_prefix}-') || resource.name.startsWith('projects/${var.project_id}/locations/${var.region}/jobs/${var.resource_prefix}-')"
  }
}

resource "google_project_iam_member" "service_roles" {
  for_each = local.project_role_bindings

  project = var.project_id
  role    = each.value.role
  member  = google_service_account.service[each.value.identity].member
}

resource "google_service_account_iam_member" "api_task_actor" {
  service_account_id = google_service_account.service["task"].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.service["api"].member
}

resource "google_service_account_iam_member" "deployment_runtime_actor" {
  for_each = toset(["api", "migration", "simulator", "web", "worker"])

  service_account_id = google_service_account.service[each.key].name
  role               = "roles/iam.serviceAccountUser"
  member             = google_service_account.service["deployment"].member
}

data "google_project" "current" {
  project_id = var.project_id
}

resource "google_service_account_iam_member" "tasks_token_creator" {
  service_account_id = google_service_account.service["task"].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudtasks.iam.gserviceaccount.com"

  depends_on = [google_project_service.required["cloudtasks.googleapis.com"]]
}
