mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}

run "foundation_is_bounded" {
  command = plan

  variables {
    project_id = "colortrace-test-project"
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
}

run "workloads_require_every_binding" {
  command = plan

  variables {
    project_id           = "colortrace-test-project"
    deploy_workloads     = true
    runtime_image_digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image_digest     = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  }

  expect_failures = [check.complete_workload_bindings]
}

run "workload_isolation_is_explicit" {
  command = plan

  variables {
    project_id             = "colortrace-test-project"
    deploy_workloads       = true
    candidate_commit       = "1111111111111111111111111111111111111111"
    candidate_tree         = "2222222222222222222222222222222222222222"
    runtime_image_digest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image_digest       = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    configuration_sha256   = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    fixture_sha256         = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
    model_profile_sha256   = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
    policy_sha256          = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
    grafana_secret_version = "1"
    oidc_issuer            = "https://identity.example.test"
    oidc_audience          = "colortrace-api"
    oidc_jwks_uri          = "https://identity.example.test/.well-known/jwks.json"
  }

  assert {
    condition     = google_cloud_run_v2_service.service["web"].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "The read-only web service must accept intended public ingress."
  }

  assert {
    condition     = google_cloud_run_v2_service.service["api"].ingress == "INGRESS_TRAFFIC_ALL"
    error_message = "The API must expose public reads while enforcing mutation authorization in-app."
  }

  assert {
    condition     = google_cloud_run_v2_service.service["worker"].ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY"
    error_message = "The worker must remain private."
  }

  assert {
    condition     = google_cloud_run_v2_service.service["simulator"].ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY"
    error_message = "The simulator must remain private."
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
    condition     = alltrue([for service in google_cloud_run_v2_service.service : strcontains(service.template[0].containers[0].image, "@sha256:")])
    error_message = "Every deployed image must be digest-addressed."
  }
}
