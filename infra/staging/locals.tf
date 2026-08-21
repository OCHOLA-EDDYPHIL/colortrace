locals {
  labels = {
    application = "colortrace"
    environment = "staging"
    managed_by  = "terraform"
  }

  base_workload_bindings = [
    var.candidate_commit,
    var.candidate_tree,
    var.configuration_sha256,
    var.fixture_sha256,
    var.model_profile_sha256,
    var.policy_sha256,
    var.oidc_issuer,
    var.oidc_audience,
    var.oidc_jwks_uri,
  ]

  runtime_image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runtime.repository_id}/runtime@${coalesce(var.runtime_image_digest, "sha256:0000000000000000000000000000000000000000000000000000000000000000")}"
  web_image     = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.runtime.repository_id}/web@${coalesce(var.web_image_digest, "sha256:0000000000000000000000000000000000000000000000000000000000000000")}"

  workload_bindings_complete = (
    alltrue([for value in local.base_workload_bindings : value != null])
    && (
      length(setintersection(var.workload_services, toset(["api", "simulator", "worker"]))) == 0
      || var.runtime_image_digest != null
    )
    && (!contains(var.workload_services, "web") || (
      var.web_image_digest != null && var.api_origin != null
    ))
    && (!contains(var.workload_services, "worker") || (
      var.grafana_secret_version != null && var.grafana_url != null
    ))
  )

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
    condition     = length(var.workload_services) == 0 || local.workload_bindings_complete
    error_message = "All immutable workload and identity bindings are required before Cloud Run deployment."
  }
}
