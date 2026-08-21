locals {
  labels = {
    application = "colortrace"
    environment = "staging"
    managed_by  = "terraform"
  }

  required_workload_bindings = [
    var.candidate_commit,
    var.candidate_tree,
    var.runtime_image_digest,
    var.web_image_digest,
    var.configuration_sha256,
    var.fixture_sha256,
    var.model_profile_sha256,
    var.policy_sha256,
    var.grafana_secret_version,
    var.oidc_issuer,
    var.oidc_audience,
    var.oidc_jwks_uri,
  ]

  runtime_image = var.deploy_workloads ? "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runtime.repository_id}/runtime@${coalesce(var.runtime_image_digest, "unbound")}" : null
  web_image     = var.deploy_workloads ? "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runtime.repository_id}/web@${coalesce(var.web_image_digest, "unbound")}" : null

  candidate_environment = {
    COLORTRACE_CANDIDATE_COMMIT     = coalesce(var.candidate_commit, "unbound")
    COLORTRACE_CANDIDATE_TREE       = coalesce(var.candidate_tree, "unbound")
    COLORTRACE_CONFIGURATION_SHA256 = coalesce(var.configuration_sha256, "unbound")
    COLORTRACE_FIXTURE_SHA256       = coalesce(var.fixture_sha256, "unbound")
    COLORTRACE_MODEL_PROFILE_SHA256 = coalesce(var.model_profile_sha256, "unbound")
    COLORTRACE_POLICY_SHA256        = coalesce(var.policy_sha256, "unbound")
  }
}

check "complete_workload_bindings" {
  assert {
    condition = !var.deploy_workloads || alltrue([
      for value in local.required_workload_bindings : value != null
    ])
    error_message = "All immutable workload and identity bindings are required before Cloud Run deployment."
  }
}
