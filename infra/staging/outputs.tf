output "resource_inventory" {
  description = "Non-secret inventory for exact deployment evidence."
  value = {
    artifact_repository = google_artifact_registry_repository.runtime.id
    artifact_bucket     = google_storage_bucket.artifacts.id
    cloud_sql_instance  = google_sql_database_instance.workflow.connection_name
    database            = google_sql_database.workflow.name
    grafana_secret      = google_secret_manager_secret.grafana_viewer.id
    network             = google_compute_network.staging.id
    subnetwork          = google_compute_subnetwork.staging.id
    queues = {
      simulator = google_cloud_tasks_queue.simulator.id
      worker    = google_cloud_tasks_queue.worker.id
    }
    service_accounts = {
      for key, account in google_service_account.service : key => account.email
    }
    services = {
      for key, service in google_cloud_run_v2_service.service : key => {
        name = service.name
        uri  = service.uri
      }
    }
  }
}

output "candidate_bindings" {
  description = "Exact non-secret bindings for deployed workload evidence."
  value = var.deploy_workloads ? {
    commit         = var.candidate_commit
    tree           = var.candidate_tree
    runtime_image  = local.runtime_image
    web_image      = local.web_image
    configuration  = var.configuration_sha256
    fixture        = var.fixture_sha256
    model_profile  = var.model_profile_sha256
    policy         = var.policy_sha256
    grafana_secret = "${google_secret_manager_secret.grafana_viewer.id}/versions/${coalesce(var.grafana_secret_version, "0")}"
  } : null
}
