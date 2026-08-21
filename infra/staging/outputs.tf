output "resource_inventory" {
  description = "Non-secret inventory for exact deployment evidence."
  value = {
    artifact_repository = google_artifact_registry_repository.runtime.id
    artifact_bucket     = google_storage_bucket.artifacts.id
    cloud_sql_instance  = google_sql_database_instance.workflow.connection_name
    database            = google_sql_database.workflow.name
    network             = google_compute_network.staging.id
    subnetwork          = google_compute_subnetwork.staging.id
    private_address     = google_compute_global_address.private_services.id
    private_connection  = google_service_networking_connection.private_services.peering
    enabled_services    = sort(keys(google_project_service.required))
    database_users = {
      for key, user in google_sql_user.iam : key => user.name
    }
    secrets = {
      grafana_viewer             = google_secret_manager_secret.grafana_viewer.id
      postgres_bootstrap         = google_secret_manager_secret.postgres_bootstrap.id
      postgres_bootstrap_version = var.database_bootstrap_secret_version
    }
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
    jobs = {
      for key, job in google_cloud_run_v2_job.database : key => job.name
    }
    iam = {
      cloud_sql       = sort([for binding in google_project_iam_member.cloud_sql_runtime : binding.id])
      project         = sort([for binding in google_project_iam_member.service_roles : binding.id])
      run_admin       = google_project_iam_member.deployment_run_admin.id
      actors          = sort([for binding in google_service_account_iam_member.deployment_runtime_actor : binding.id])
      bootstrap       = sort([for binding in google_secret_manager_secret_iam_member.migration_bootstrap : binding.id])
      artifact_writer = google_artifact_registry_repository_iam_member.deployment_writer.id
      run_invokers = sort(concat(
        [for binding in google_cloud_run_v2_service_iam_member.public : binding.id],
        [for binding in google_cloud_run_v2_service_iam_member.web_api : binding.id],
      ))
    }
  }
}

output "candidate_bindings" {
  description = "Exact non-secret bindings for deployed workload evidence."
  value = length(var.workload_services) > 0 || local.database_job_requested ? {
    commit        = var.candidate_commit
    tree          = var.candidate_tree
    runtime_image = local.runtime_image
    web_image     = contains(var.workload_services, "web") ? local.web_image : null
    configuration = var.configuration_sha256
    fixture       = var.fixture_sha256
    model_profile = var.model_profile_sha256
    policy        = var.policy_sha256
    operator_oidc = {
      deployed          = false
      issuer            = null
      audience          = null
      jwks_uri          = null
      mutations_exposed = false
    }
    grafana_mcp = {
      deployed              = false
      public                = false
      viewer_secret_version = null
      secret_accessors      = []
    }
    api_origin    = contains(var.workload_services, "web") ? data.google_cloud_run_v2_service.api[0].uri : null
    services      = sort(tolist(var.workload_services))
    database_jobs = sort(keys(google_cloud_run_v2_job.database))
  } : null
}
