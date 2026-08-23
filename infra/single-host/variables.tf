variable "project_id" {
  description = "Google Cloud project that owns the isolated single-host resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project identifier."
  }
}

variable "region" {
  description = "Google Cloud region for the single-host deployment."
  type        = string
  default     = "us-central1"

  validation {
    condition     = var.region == "us-central1"
    error_message = "The single-host deployment is preflighted only for us-central1."
  }
}

variable "zone" {
  description = "Available us-central1 zone selected immediately before deployment."
  type        = string
  default     = "us-central1-a"

  validation {
    condition = contains([
      "us-central1-a",
      "us-central1-b",
      "us-central1-c",
      "us-central1-f",
    ], var.zone)
    error_message = "zone must be one of the preflighted us-central1 zones."
  }
}

variable "resource_prefix" {
  description = "Unique prefix for resources owned by this deployment."
  type        = string
  default     = "ct-singlehost"

  validation {
    condition = (
      can(regex("^[a-z][a-z0-9-]{2,19}[a-z0-9]$", var.resource_prefix))
      && !startswith(var.resource_prefix, "ct-p114")
    )
    error_message = "resource_prefix must be a lowercase 4-21 character prefix and must not use the reserved ct-p114 namespace."
  }
}

variable "enable_instance" {
  description = "Admit the VM only after every immutable deployment input is supplied."
  type        = bool
  default     = false
}

variable "operator_member" {
  description = "Deployment IAM member that may build images and use IAP TCP forwarding and OS Login on the VM."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.operator_member == null
      || can(regex("^(user|group|serviceAccount):[^[:space:]]+$", var.operator_member))
    )
    error_message = "operator_member must be a user, group, or serviceAccount IAM member."
  }
}

variable "resume_member" {
  description = "Separate least-privilege IAM member that may only inspect and start the staging VM."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.resume_member == null
      || can(regex("^(user|group|serviceAccount):[^[:space:]]+$", var.resume_member))
    )
    error_message = "resume_member must be a user, group, or serviceAccount IAM member."
  }

  validation {
    condition     = var.resume_member == null || var.resume_member != var.operator_member
    error_message = "resume_member must be separate from operator_member."
  }
}

variable "machine_type" {
  description = "Fixed bounded machine type for the single-host deployment."
  type        = string
  default     = "e2-standard-2"

  validation {
    condition     = var.machine_type == "e2-standard-2"
    error_message = "machine_type must remain e2-standard-2."
  }
}

variable "boot_disk_size_gb" {
  description = "Persistent balanced boot disk size for application and observability state."
  type        = number
  default     = 30

  validation {
    condition     = var.boot_disk_size_gb == 30
    error_message = "boot_disk_size_gb must remain 30 GiB."
  }
}

variable "boot_image" {
  description = "Exact Debian 12 image resource used to create the persistent boot disk."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.boot_image == null
      || can(regex("^projects/debian-cloud/global/images/debian-12-bookworm-v[0-9]{8}$", var.boot_image))
    )
    error_message = "boot_image must identify one exact Debian 12 image, not an image family."
  }
}

variable "estimated_seven_day_cost_usd" {
  description = "Operator estimate for the complete seven-day deployment before the VM is admitted."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition     = var.estimated_seven_day_cost_usd == null || var.estimated_seven_day_cost_usd > 0
    error_message = "estimated_seven_day_cost_usd must be positive when supplied."
  }
}

variable "cost_ceiling_usd" {
  description = "Configured comparison ceiling; the estimate must also remain strictly below USD 100."
  type        = number
  default     = 100

  validation {
    condition     = var.cost_ceiling_usd > 0 && var.cost_ceiling_usd <= 100
    error_message = "cost_ceiling_usd must be greater than zero and no more than USD 100."
  }
}

variable "staging_generation" {
  description = "Operator-selected generation that starts one new seven-day lifecycle when changed."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.staging_generation == null
      || can(regex("^[a-z0-9][a-z0-9-]{6,30}[a-z0-9]$", var.staging_generation))
    )
    error_message = "staging_generation must be an 8-32 character lowercase identifier."
  }
}

variable "access_secret_version" {
  description = "Immutable numeric version of the Secret Manager value that contains one Caddy bcrypt hash."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.access_secret_version == null || can(regex("^[1-9][0-9]*$", var.access_secret_version))
    error_message = "access_secret_version must be an immutable numeric version."
  }
}

variable "access_username" {
  description = "Non-secret username paired with the access-code bcrypt hash."
  type        = string
  default     = "colortrace"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]{2,31}$", var.access_username))
    error_message = "access_username must be a simple lowercase account name."
  }
}

variable "deployment_artifact_binding" {
  description = "One checked build-and-scan admission binding from which every deployed artifact identity is derived."
  type = object({
    schema                    = string
    build_manifest_sha256     = string
    scan_binding_sha256       = string
    observability_lock_sha256 = string
    build = object({
      id              = string
      project         = string
      region          = string
      service_account = string
      registry        = string
      config_sha256   = string
      create_time     = string
      finish_time     = string
    })
    source = object({
      commit     = string
      tree       = string
      date_epoch = number
    })
    fixture_manifest_sha256 = string
    images = object({
      runtime    = string
      web        = string
      caddy      = string
      grafana    = string
      loki       = string
      prometheus = string
      tempo      = string
    })
    scanner = object({
      image          = string
      version_sha256 = string
      databases = object({
        current = object({
          content_sha256  = string
          metadata_sha256 = string
          updated_at      = string
        })
        frozen = object({
          image           = string
          content_sha256  = string
          metadata_sha256 = string
          updated_at      = string
        })
      })
      report_set_sha256 = string
    })
  })
  default  = null
  nullable = true

  validation {
    condition = var.deployment_artifact_binding == null || try(
      var.deployment_artifact_binding.schema == "colortrace-single-host-admission/v1"
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.build_manifest_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scan_binding_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.observability_lock_sha256))
      && can(regex("^[A-Za-z0-9-]+$", var.deployment_artifact_binding.build.id))
      && can(regex("^[0-9a-f]{40}$", var.deployment_artifact_binding.source.commit))
      && can(regex("^[0-9a-f]{40}$", var.deployment_artifact_binding.source.tree))
      && var.deployment_artifact_binding.source.date_epoch > 0
      && floor(var.deployment_artifact_binding.source.date_epoch) == var.deployment_artifact_binding.source.date_epoch
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.build.config_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.fixture_manifest_sha256))
      && alltrue([
        for image in values(var.deployment_artifact_binding.images) :
        can(regex("^[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9_./-]+@sha256:[0-9a-f]{64}$", image))
      ])
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.databases.current.content_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.version_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.databases.current.metadata_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.databases.frozen.content_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.databases.frozen.metadata_sha256))
      && can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding.scanner.report_set_sha256)),
      false,
    )
    error_message = "deployment_artifact_binding must use the exact admission schema with complete immutable source, build, image, scanner, database, fixture, and report digests."
  }
}

variable "deployment_artifact_binding_sha256" {
  description = "Canonical SHA-256 of deployment_artifact_binding, as emitted by the admission helper."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.deployment_artifact_binding_sha256 == null
      || can(regex("^sha256:[0-9a-f]{64}$", var.deployment_artifact_binding_sha256))
    )
    error_message = "deployment_artifact_binding_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "fixture_bundle_path" {
  description = "Absolute in-image path to the synthetic fixture bundle used by the runtime."
  type        = string
  default     = "/opt/colortrace/fixture"

  validation {
    condition = (
      startswith(var.fixture_bundle_path, "/")
      && !strcontains(var.fixture_bundle_path, "..")
      && !strcontains(var.fixture_bundle_path, "//")
    )
    error_message = "fixture_bundle_path must be a normalized absolute path."
  }
}
