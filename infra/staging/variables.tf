variable "project_id" {
  description = "Google Cloud project that owns the staging resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project identifier."
  }
}

variable "region" {
  description = "Single Google Cloud region for all regional resources."
  type        = string
  default     = "us-central1"

  validation {
    condition     = contains(["us-central1", "us-east1", "us-west1"], var.region)
    error_message = "region must be one of the preflighted staging regions."
  }
}

variable "resource_prefix" {
  description = "Unique deterministic prefix for resources owned by one deployment."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,17}[a-z0-9]$", var.resource_prefix))
    error_message = "resource_prefix must be a lowercase 4-19 character prefix that fits every service-account identifier."
  }
}

variable "workload_services" {
  description = "Explicit Cloud Run service set admitted after its immutable bindings and runtime exist."
  type        = set(string)
  default     = []

  validation {
    condition = (
      length(setsubtract(var.workload_services, toset(["api", "web"]))) == 0
      && (!contains(var.workload_services, "web") || contains(var.workload_services, "api"))
    )
    error_message = "The provisional lane may deploy only api and web; web requires api."
  }
}

variable "enable_database_migration_job" {
  description = "Create the private exact-image migration and synthetic-seed job before API admission."
  type        = bool
  default     = false
}

variable "database_bootstrap_secret_version" {
  description = "Temporary numeric Secret Manager version used only by the private database bootstrap job."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.database_bootstrap_secret_version == null || can(regex("^[1-9][0-9]*$", var.database_bootstrap_secret_version))
    error_message = "database_bootstrap_secret_version must be an immutable numeric version."
  }
}

variable "candidate_commit" {
  description = "Exact source commit embedded in the deployed workload binding."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.candidate_commit == null || can(regex("^[0-9a-f]{40}$", var.candidate_commit))
    error_message = "candidate_commit must be a full lowercase Git commit."
  }
}

variable "candidate_tree" {
  description = "Exact source tree embedded in the deployed workload binding."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.candidate_tree == null || can(regex("^[0-9a-f]{40}$", var.candidate_tree))
    error_message = "candidate_tree must be a full lowercase Git tree."
  }
}

variable "runtime_image_digest" {
  description = "Digest of the API, worker, and simulator runtime image."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.runtime_image_digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.runtime_image_digest))
    error_message = "runtime_image_digest must be a SHA-256 image digest."
  }
}

variable "web_image_digest" {
  description = "Digest of the read-only web image."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.web_image_digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.web_image_digest))
    error_message = "web_image_digest must be a SHA-256 image digest."
  }
}

variable "configuration_sha256" {
  description = "Digest of the normalized deployment configuration."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.configuration_sha256 == null || can(regex("^sha256:[0-9a-f]{64}$", var.configuration_sha256))
    error_message = "configuration_sha256 must be a prefixed SHA-256 digest."
  }
}

variable "fixture_sha256" {
  description = "Digest binding for the deployed synthetic fixture."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.fixture_sha256 == null || can(regex("^sha256:[0-9a-f]{64}$", var.fixture_sha256))
    error_message = "fixture_sha256 must be a prefixed SHA-256 digest."
  }
}

variable "model_profile_sha256" {
  description = "Digest binding for the investigation model profile."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.model_profile_sha256 == null || can(regex("^sha256:[0-9a-f]{64}$", var.model_profile_sha256))
    error_message = "model_profile_sha256 must be a prefixed SHA-256 digest."
  }
}

variable "policy_sha256" {
  description = "Digest binding for the deployed policy set."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.policy_sha256 == null || can(regex("^sha256:[0-9a-f]{64}$", var.policy_sha256))
    error_message = "policy_sha256 must be a prefixed SHA-256 digest."
  }
}

variable "grafana_secret_version" {
  description = "Existing Secret Manager version containing the Viewer token."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.grafana_secret_version == null || can(regex("^[1-9][0-9]*$", var.grafana_secret_version))
    error_message = "grafana_secret_version must be an immutable numeric version."
  }
}

variable "grafana_url" {
  description = "Exact Grafana Cloud origin used by the private MCP subprocess."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.grafana_url == null || can(regex("^https://[^/?#]+/?$", var.grafana_url))
    error_message = "grafana_url must be one HTTPS origin without credentials, path, query, or fragment."
  }
}
