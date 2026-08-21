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
    api = toset([
      "roles/cloudsql.client",
      "roles/cloudsql.instanceUser",
      "roles/logging.logWriter",
    ])
    deployment = toset([
      "roles/run.admin",
    ])
    migration = toset([
      "roles/cloudsql.client",
      "roles/cloudsql.instanceUser",
      "roles/logging.logWriter",
    ])
    simulator = toset([
      "roles/cloudsql.client",
      "roles/cloudsql.instanceUser",
      "roles/logging.logWriter",
    ])
    task = toset([])
    web = toset([
      "roles/logging.logWriter",
    ])
    worker = toset([
      "roles/aiplatform.user",
      "roles/cloudsql.client",
      "roles/cloudsql.instanceUser",
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
  for_each = toset(["api", "simulator", "web", "worker"])

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
