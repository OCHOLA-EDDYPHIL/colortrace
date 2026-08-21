mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }

  mock_data "google_cloud_run_v2_service" {
    defaults = {
      name = "ct-stg-t0001-api"
      uri  = "https://ct-stg-t0001-api.example.run.app"
    }
  }
}

run "foundation_is_bounded" {
  command = plan

  variables {
    project_id      = "colortrace-test-project"
    resource_prefix = "ct-stg-t0001"
  }

  assert {
    condition     = length(google_cloud_run_v2_service.service) == 0
    error_message = "Cloud Run workloads must remain absent until exact bindings are supplied."
  }

  assert {
    condition     = google_sql_database_instance.workflow.settings[0].tier == "db-f1-micro"
    error_message = "Staging must use the bounded shared-core database tier."
  }

  assert {
    condition     = google_storage_bucket.artifacts.public_access_prevention == "enforced"
    error_message = "The artifact bucket must prohibit public access."
  }

  assert {
    condition     = google_storage_bucket.artifacts.force_destroy
    error_message = "The staging artifact bucket must support complete owned-resource cleanup."
  }

  assert {
    condition     = google_storage_bucket.artifacts.soft_delete_policy[0].retention_duration_seconds == 0
    error_message = "The staging artifact bucket must not retain soft-deleted temporary evidence after cleanup."
  }

  assert {
    condition     = google_sql_database_instance.workflow.settings[0].ip_configuration[0].ipv4_enabled == false
    error_message = "Cloud SQL must not receive a public IP address."
  }

}

run "workloads_require_every_binding" {
  command = plan

  variables {
    project_id           = "colortrace-test-project"
    resource_prefix      = "ct-stg-t0001"
    workload_services    = ["api"]
    runtime_image_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image_digest     = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  }

  expect_failures = [
    check.complete_workload_bindings,
    google_cloud_run_v2_service.service,
  ]
}

run "api_can_be_admitted_before_the_web_proxy" {
  command = plan

  variables {
    project_id           = "colortrace-test-project"
    resource_prefix      = "ct-stg-t0001"
    workload_services    = ["api"]
    candidate_commit     = "1111111111111111111111111111111111111111"
    candidate_tree       = "2222222222222222222222222222222222222222"
    runtime_image_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    configuration_sha256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256       = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256 = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256        = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  assert {
    condition     = toset(keys(google_cloud_run_v2_service.service)) == toset(["api"])
    error_message = "The API must be independently deployable before its exact URI is bound to the web proxy."
  }

  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.public) == 0
    error_message = "The API-only stage must not grant unauthenticated invocation."
  }
}

run "workload_isolation_is_explicit" {
  command = plan

  variables {
    project_id           = "colortrace-test-project"
    resource_prefix      = "ct-stg-t0001"
    workload_services    = ["api", "web"]
    candidate_commit     = "1111111111111111111111111111111111111111"
    candidate_tree       = "2222222222222222222222222222222222222222"
    runtime_image_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image_digest     = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    configuration_sha256 = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256       = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256 = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256        = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  assert {
    condition     = google_cloud_run_v2_service.service["web"].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "The read-only web service must accept intended public ingress."
  }

  assert {
    condition     = google_cloud_run_v2_service.service["api"].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "The API transport must accept the authenticated web proxy while remaining IAM-protected."
  }


  assert {
    condition     = toset(keys(google_cloud_run_v2_service_iam_member.public)) == toset(["web"])
    error_message = "Only the web service may grant unauthenticated Cloud Run invocation."
  }

  assert {
    condition     = toset(keys(google_cloud_run_v2_service_iam_member.web_api)) == toset(["api"])
    error_message = "The web identity invocation grant must target only the API."
  }

  assert {
    condition     = alltrue([for service in google_cloud_run_v2_service.service : service.template[0].scaling[0].min_instance_count == 0])
    error_message = "Every service must scale to zero."
  }

  assert {
    condition     = alltrue([for service in google_cloud_run_v2_service.service : service.template[0].scaling[0].max_instance_count == 1])
    error_message = "Every staging service must have a one-instance ceiling."
  }

  assert {
    condition     = google_cloud_run_v2_service.service["api"].template[0].vpc_access[0].egress == "PRIVATE_RANGES_ONLY"
    error_message = "The hosted API must use direct private-range VPC egress for Cloud SQL."
  }

  assert {
    condition     = alltrue([for service in google_cloud_run_v2_service.service : strcontains(service.template[0].containers[0].image, "@sha256:")])
    error_message = "Every deployed image must be digest-addressed."
  }

  assert {
    condition = (
      google_cloud_run_v2_service.service["web"].template[0].containers[0].startup_probe[0].http_get[0].path == "/"
      && google_cloud_run_v2_service.service["web"].template[0].containers[0].liveness_probe[0].http_get[0].path == "/"
      && google_cloud_run_v2_service.service["api"].template[0].containers[0].startup_probe[0].http_get[0].path == "/health/startup"
      && google_cloud_run_v2_service.service["api"].template[0].containers[0].liveness_probe[0].http_get[0].path == "/health/live"
    )
    error_message = "Only the private API may expose diagnostic health paths; public web probes must use the intended read surface."
  }

  assert {
    condition = (
      output.candidate_bindings.operator_oidc.deployed == false
      && output.candidate_bindings.operator_oidc.issuer == null
      && output.candidate_bindings.operator_oidc.audience == null
      && output.candidate_bindings.operator_oidc.jwks_uri == null
      && output.candidate_bindings.operator_oidc.mutations_exposed == false
    )
    error_message = "The provisional read-only topology must bind operator OIDC as absent and expose no mutations."
  }

  assert {
    condition = (
      output.candidate_bindings.grafana_mcp.deployed == false
      && output.candidate_bindings.grafana_mcp.public == false
      && output.candidate_bindings.grafana_mcp.viewer_secret_version == null
      && length(output.candidate_bindings.grafana_mcp.secret_accessors) == 0
    )
    error_message = "The provisional API/web topology must bind Grafana MCP as absent, private, and credential-free."
  }

  assert {
    condition = (
      length([
        for env in google_cloud_run_v2_service.service["web"].template[0].containers[0].env : env
        if contains(["COLORTRACE_API_AUDIENCE", "COLORTRACE_API_ORIGIN"], env.name)
      ]) == 2
      && alltrue([
        for env in google_cloud_run_v2_service.service["web"].template[0].containers[0].env :
        env.value == "https://ct-stg-t0001-api.example.run.app"
        if contains(["COLORTRACE_API_AUDIENCE", "COLORTRACE_API_ORIGIN"], env.name)
      ])
    )
    error_message = "The public proxy must bind its origin and audience to the managed API service lookup."
  }
}

run "database_bootstrap_is_private_single_attempt_and_digest_bound" {
  command = plan

  variables {
    project_id                        = "colortrace-test-project"
    resource_prefix                   = "ct-stg-t0001"
    database_bootstrap_secret_version = "1"
    candidate_commit                  = "1111111111111111111111111111111111111111"
    candidate_tree                    = "2222222222222222222222222222222222222222"
    runtime_image_digest              = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    configuration_sha256              = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256                    = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256              = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256                     = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  assert {
    condition     = toset(keys(google_cloud_run_v2_job.database)) == toset(["bootstrap"])
    error_message = "The bootstrap stage may create only its private job."
  }

  assert {
    condition     = alltrue([for job in google_cloud_run_v2_job.database : job.template[0].task_count == 1 && job.template[0].template[0].max_retries == 0])
    error_message = "Every database preparation job must run one task without platform retries."
  }

  assert {
    condition     = alltrue([for job in google_cloud_run_v2_job.database : strcontains(job.template[0].template[0].containers[0].image, "@sha256:")])
    error_message = "Every database preparation job must use the exact runtime digest."
  }

  assert {
    condition     = length(google_cloud_run_v2_service.service) == 0
    error_message = "Database preparation must complete before API admission."
  }
}


run "database_migration_is_private_single_attempt_and_digest_bound" {
  command = plan

  variables {
    project_id                    = "colortrace-test-project"
    resource_prefix               = "ct-stg-t0001"
    enable_database_migration_job = true
    candidate_commit              = "1111111111111111111111111111111111111111"
    candidate_tree                = "2222222222222222222222222222222222222222"
    runtime_image_digest          = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    configuration_sha256          = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256                = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256          = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256                 = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  assert {
    condition     = toset(keys(google_cloud_run_v2_job.database)) == toset(["migrate-seed"])
    error_message = "The migration stage may create only its private job."
  }

  assert {
    condition     = google_cloud_run_v2_job.database["migrate-seed"].template[0].task_count == 1 && google_cloud_run_v2_job.database["migrate-seed"].template[0].template[0].max_retries == 0
    error_message = "The migration job must run one task without platform retries."
  }

  assert {
    condition     = length(google_cloud_run_v2_service.service) == 0
    error_message = "Migration must complete before API admission."
  }
}


run "database_stages_cannot_overlap" {
  command = plan

  variables {
    project_id                        = "colortrace-test-project"
    resource_prefix                   = "ct-stg-t0001"
    enable_database_migration_job     = true
    database_bootstrap_secret_version = "1"
    candidate_commit                  = "1111111111111111111111111111111111111111"
    candidate_tree                    = "2222222222222222222222222222222222222222"
    runtime_image_digest              = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    configuration_sha256              = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256                    = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256              = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256                     = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  expect_failures = [
    check.database_stage_isolation,
    google_cloud_run_v2_job.database["bootstrap"],
    google_cloud_run_v2_job.database["migrate-seed"],
  ]
}


run "database_jobs_cannot_overlap_workloads" {
  command = plan

  variables {
    project_id                    = "colortrace-test-project"
    resource_prefix               = "ct-stg-t0001"
    workload_services             = ["api"]
    enable_database_migration_job = true
    candidate_commit              = "1111111111111111111111111111111111111111"
    candidate_tree                = "2222222222222222222222222222222222222222"
    runtime_image_digest          = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    configuration_sha256          = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256                = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256          = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256                 = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  }

  expect_failures = [
    check.database_stage_isolation,
    google_cloud_run_v2_job.database["migrate-seed"],
    google_cloud_run_v2_service.service["api"],
  ]
}
