mock_provider "google" {
  mock_resource "google_compute_address" {
    defaults = {
      address = "203.0.113.42"
    }
  }

  mock_resource "google_service_account" {
    defaults = {
      email  = "ct-singlehost-vm@colortrace-test-project.iam.gserviceaccount.com"
      member = "serviceAccount:ct-singlehost-vm@colortrace-test-project.iam.gserviceaccount.com"
      name   = "projects/colortrace-test-project/serviceAccounts/ct-singlehost-vm@colortrace-test-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  project_id              = "colortrace-test-project"
  staging_hard_stop_epoch = 1900000000
  deployment_artifact_binding = {
    schema                    = "colortrace-single-host-admission/v1"
    build_manifest_sha256     = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    scan_binding_sha256       = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    observability_lock_sha256 = "sha256:ca5a0f510defc4728d17e4bac2c8d17b4a1e43ff88419cf542ae922d4abd0df9"
    build = {
      id              = "build-123"
      project         = "colortrace-test-project"
      region          = "us-central1"
      service_account = "projects/colortrace-test-project/serviceAccounts/ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com"
      registry        = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
      config_sha256   = "sha256:883c8a57f8e094e01fe1d66da41bdf2eb025939b537a5b0a003510adb9722dd0"
      create_time     = "2026-08-23T01:00:00Z"
      finish_time     = "2026-08-23T01:10:00Z"
    }
    source = {
      commit     = "1111111111111111111111111111111111111111"
      tree       = "2222222222222222222222222222222222222222"
      date_epoch = 1787446800
    }
    fixture_manifest_sha256 = "sha256:21386db7c4ae2c3119d5532fc75589ddce1e64f7ccdecf61f41415e80f4564a6"
    images = {
      runtime    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333"
      web        = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/web@sha256:4444444444444444444444444444444444444444444444444444444444444444"
      caddy      = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/caddy@sha256:5555555555555555555555555555555555555555555555555555555555555555"
      grafana    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/grafana@sha256:6666666666666666666666666666666666666666666666666666666666666666"
      loki       = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/loki@sha256:7777777777777777777777777777777777777777777777777777777777777777"
      prometheus = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/prometheus@sha256:8888888888888888888888888888888888888888888888888888888888888888"
      tempo      = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/tempo@sha256:9999999999999999999999999999999999999999999999999999999999999999"
    }
    scanner = {
      image          = "aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
      version_sha256 = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      databases = {
        current = {
          content_sha256  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
          metadata_sha256 = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
          updated_at      = "2026-08-23T00:00:00Z"
        }
        frozen = {
          image           = "ghcr.io/aquasecurity/trivy-db@sha256:67136d9c032b639278e256601e29b8af0ff4ed28e66d859e4cac692f7c1deef6"
          content_sha256  = "sha256:eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314"
          metadata_sha256 = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
          updated_at      = "2026-08-22T12:57:22.518776499Z"
        }
      }
      report_set_sha256 = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
    }
  }
  deployment_artifact_binding_sha256 = "sha256:daee9e9ddca5a2a62be24368e22f8ac5a40e84f22f1b9a9ff4689d9b0751827b"
}

run "foundation_has_no_billable_host" {
  command = plan

  variables {
    deployment_artifact_binding        = null
    deployment_artifact_binding_sha256 = null
  }

  assert {
    condition     = length(google_compute_instance.host) == 0
    error_message = "The VM must remain absent until all admission inputs are supplied."
  }

  assert {
    condition = (
      length(google_compute_disk.boot) == 0
      && length(google_compute_address.public) == 0
    )
    error_message = "The persistent disk and address must remain absent before VM admission."
  }

  assert {
    condition = (
      length(google_project_iam_member.host_vertex_predictor) == 0
      && length(google_project_iam_custom_role.vertex_predictor) == 0
      && length(google_project_iam_member.operator_project_inspector) == 0
      && length(google_project_iam_custom_role.operator_project_inspector) == 0
      && length(google_compute_instance_iam_member.operator_os_admin) == 0
      && length(google_iap_tunnel_instance_iam_member.operator_iap_ssh) == 0
      && length(google_service_account_iam_member.operator_host) == 0
      && length(google_compute_instance_iam_member.resume_instance_starter) == 0
      && length(google_project_iam_custom_role.resume_instance_starter) == 0
      && length(google_project_iam_member.operator_build) == 0
      && length(google_service_account_iam_member.operator_build) == 0
      && length(google_artifact_registry_repository_iam_member.operator_reader) == 0
      && length(google_storage_bucket_iam_member.operator_build_source) == 0
      && length(google_secret_manager_secret_iam_member.host_access_gate) == 0
    )
    error_message = "Runtime and operator authority must remain absent before VM admission."
  }

  assert {
    condition = (
      google_compute_network.single_host.name == "ct-singlehost-network"
      && google_compute_subnetwork.single_host.ip_cidr_range == "10.72.0.0/28"
    )
    error_message = "The module must use its dedicated network and subnet."
  }

  assert {
    condition     = google_secret_manager_secret.access_gate.secret_id == "ct-singlehost-access-hash"
    error_message = "The access-code verifier must have a dedicated Secret Manager container."
  }

  assert {
    condition = (
      google_artifact_registry_repository.images.repository_id == "ct-singlehost-images"
      && google_storage_bucket.build_source.name == "colortrace-test-project-ct-singlehost-build-source"
      && google_storage_bucket.build_source.public_access_prevention == "enforced"
      && google_storage_bucket.build_source.uniform_bucket_level_access
      && google_storage_bucket_iam_member.builder_build_source.role == "roles/storage.objectViewer"
      && strcontains(file("${path.module}/build-source.tf"), "member = google_service_account.builder.member")
      && google_service_account.builder.account_id == "ct-singlehost-builder"
      && google_artifact_registry_repository_iam_member.builder_writer.role == "roles/artifactregistry.writer"
      && google_project_iam_member.builder_logs.role == "roles/logging.logWriter"
      && contains(keys(google_project_service.required), "cloudbuild.googleapis.com")
      && contains(keys(google_project_service.required), "storage.googleapis.com")
      && !contains(keys(google_project_service.required), "monitoring.googleapis.com")
    )
    error_message = "Private images must have a dedicated repository, builder identity, and minimal build services."
  }

  assert {
    condition     = strcontains(file("${path.module}/compute.tf"), "prevent_destroy = true")
    error_message = "The retained boot disk must be protected from Terraform destruction."
  }
}

run "image_builder_precedes_host_admission" {
  command = plan

  variables {
    operator_member                    = "user:operator@example.test"
    deployment_artifact_binding        = null
    deployment_artifact_binding_sha256 = null
  }

  assert {
    condition = (
      length(google_compute_instance.host) == 0
      && toset(keys(google_project_iam_member.operator_build)) == toset([
        "roles/cloudbuild.builds.editor",
        "roles/serviceusage.serviceUsageConsumer",
      ])
      && google_service_account_iam_member.operator_build[0].role == "roles/iam.serviceAccountUser"
      && google_service_account_iam_member.operator_build[0].member == "user:operator@example.test"
      && google_artifact_registry_repository_iam_member.operator_reader[0].role == "roles/artifactregistry.reader"
      && google_artifact_registry_repository_iam_member.operator_reader[0].member == "user:operator@example.test"
      && toset(keys(google_storage_bucket_iam_member.operator_build_source)) == toset([
        "roles/storage.legacyBucketReader",
        "roles/storage.objectCreator",
      ])
      && alltrue([
        for binding in google_storage_bucket_iam_member.operator_build_source :
        binding.bucket == "colortrace-test-project-ct-singlehost-build-source"
        && binding.member == "user:operator@example.test"
      ])
      && output.resource_inventory.operator_artifact_reader.member == "user:operator@example.test"
      && output.resource_inventory.operator_artifact_reader.repository == "ct-singlehost-images"
      && output.resource_inventory.operator_artifact_reader.role == "roles/artifactregistry.reader"
      && output.image_build_identity.registry == "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
      && output.image_build_identity.source_staging == "gs://colortrace-test-project-ct-singlehost-build-source/source"
    )
    error_message = "The operator must be able to build immutable images without admitting the VM."
  }
}

run "instance_requires_complete_admission_inputs" {
  command = plan

  variables {
    enable_instance         = true
    staging_hard_stop_epoch = null
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "boot_image_family_is_rejected" {
  command = plan

  variables {
    boot_image = "projects/debian-cloud/global/images/family/debian-12"
  }

  expect_failures = [var.boot_image]
}

run "non_positive_hard_stop_is_rejected" {
  command = plan

  variables {
    staging_hard_stop_epoch = 0
  }

  expect_failures = [var.staging_hard_stop_epoch]
}

run "overflowing_hard_stop_is_rejected" {
  command = plan

  variables {
    staging_hard_stop_epoch = 253402300800
  }

  expect_failures = [var.staging_hard_stop_epoch]
}

run "artifact_hash_mismatch_is_rejected" {
  command = plan

  variables {
    enable_instance                    = true
    operator_member                    = "user:operator@example.test"
    staging_generation                 = "stage-0001"
    access_secret_version              = "7"
    boot_image                         = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd       = 24
    deployment_artifact_binding_sha256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "cost_at_hard_ceiling_is_rejected" {
  command = plan

  variables {
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    resume_member                = "serviceAccount:resume@example.test"
    staging_generation           = "stage-0001"
    access_secret_version        = "7"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 100
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "cost_above_configured_ceiling_is_rejected" {
  command = plan

  variables {
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    staging_generation           = "stage-0001"
    access_secret_version        = "7"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 24
    cost_ceiling_usd             = 23
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "reserved_network_namespace_is_rejected" {
  command = plan

  variables {
    resource_prefix = "ct-p114-0821a"
  }

  expect_failures = [var.resource_prefix]
}

run "resume_principal_must_be_separate" {
  command = plan

  variables {
    operator_member = "user:operator@example.test"
    resume_member   = "user:operator@example.test"
  }

  expect_failures = [var.resume_member]
}

run "bounded_single_host_is_admitted" {
  command = apply

  variables {
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    resume_member                = "serviceAccount:resume@example.test"
    staging_generation           = "stage-0001"
    access_secret_version        = "7"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 24
  }

  assert {
    condition = (
      local.artifact_binding_is_valid
      && local.private_images_in_owned_registry
      && local.estimated_cost_is_bounded
      && google_compute_instance.host[0].machine_type == "e2-standard-2"
      && google_compute_disk.boot[0].type == "pd-balanced"
      && google_compute_disk.boot[0].size == 30
      && google_compute_disk.boot[0].image == "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
      && google_compute_instance.host[0].boot_disk[0].auto_delete == false
      && !strcontains(file("${path.module}/compute.tf"), "termination_time")
    )
    error_message = "The host must use the checked binding, bounded machine, and retained 30 GiB balanced disk."
  }

  assert {
    condition = (
      google_compute_instance.host[0].service_account[0].email == google_service_account.host.email
      && google_compute_instance.host[0].metadata["enable-oslogin"] == "TRUE"
      && google_compute_instance.host[0].metadata["block-project-ssh-keys"] == "TRUE"
      && google_compute_instance.host[0].metadata["serial-port-enable"] == "FALSE"
      && google_compute_instance.host[0].metadata["colortrace-staging-hard-stop-epoch"] == "1900000000"
      && google_compute_instance.host[0].metadata["colortrace-artifact-binding-sha256"] == "sha256:daee9e9ddca5a2a62be24368e22f8ac5a40e84f22f1b9a9ff4689d9b0751827b"
      && google_compute_instance.host[0].metadata["colortrace-build-manifest-sha256"] == "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      && google_compute_instance.host[0].metadata["colortrace-scan-binding-sha256"] == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      && google_compute_instance.host[0].metadata["colortrace-runtime-build-binding-sha256"] == "sha256:94dcf637a46182cd88090369a68dd2295a43df1fcb1e0d3ce885cd8d62debbba"
      && google_compute_instance.host[0].metadata["colortrace-scanner-version-sha256"] == "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      && google_compute_instance.host[0].metadata["colortrace-scan-report-set-sha256"] == "sha256:8888888888888888888888888888888888888888888888888888888888888888"
    )
    error_message = "The host must expose its hardened identity and complete admission hash chain in metadata."
  }

  assert {
    condition = (
      google_compute_instance.host[0].shielded_instance_config[0].enable_secure_boot
      && google_compute_instance.host[0].shielded_instance_config[0].enable_vtpm
      && google_compute_instance.host[0].shielded_instance_config[0].enable_integrity_monitoring
    )
    error_message = "Every Shielded VM control must remain enabled."
  }

  assert {
    condition = (
      toset(google_compute_firewall.public_https.source_ranges) == toset(["0.0.0.0/0"])
      && one(google_compute_firewall.public_https.allow).protocol == "tcp"
      && toset(one(google_compute_firewall.public_https.allow).ports) == toset(["443"])
      && toset(google_compute_firewall.iap_ssh.source_ranges) == toset(["35.235.240.0/20"])
      && toset(one(google_compute_firewall.iap_ssh.allow).ports) == toset(["22"])
    )
    error_message = "Only HTTPS may be public, and SSH must be restricted to IAP TCP forwarding."
  }

  assert {
    condition = (
      toset(google_project_iam_custom_role.operator_project_inspector[0].permissions) == toset([
        "compute.instances.list",
        "compute.projects.get",
      ])
      && google_project_iam_member.operator_project_inspector[0].role == google_project_iam_custom_role.operator_project_inspector[0].id
      && google_compute_instance_iam_member.operator_os_admin[0].role == "roles/compute.osAdminLogin"
      && google_compute_instance_iam_member.operator_os_admin[0].member == "user:operator@example.test"
      && google_compute_instance_iam_member.operator_os_admin[0].instance_name == google_compute_instance.host[0].name
      && google_iap_tunnel_instance_iam_member.operator_iap_ssh[0].role == "roles/iap.tunnelResourceAccessor"
      && google_iap_tunnel_instance_iam_member.operator_iap_ssh[0].member == "user:operator@example.test"
      && google_iap_tunnel_instance_iam_member.operator_iap_ssh[0].instance == google_compute_instance.host[0].name
      && one(google_iap_tunnel_instance_iam_member.operator_iap_ssh[0].condition).expression == "destination.port == 22"
      && google_service_account_iam_member.operator_host[0].service_account_id == google_service_account.host.name
      && google_service_account_iam_member.operator_host[0].role == "roles/iam.serviceAccountUser"
      && google_service_account_iam_member.operator_host[0].member == "user:operator@example.test"
      && toset(google_project_iam_custom_role.vertex_predictor[0].permissions) == toset(["aiplatform.endpoints.predict"])
      && google_project_iam_member.host_vertex_predictor[0].role == google_project_iam_custom_role.vertex_predictor[0].id
      && toset(google_project_iam_custom_role.resume_instance_starter[0].permissions) == toset([
        "compute.instances.get",
        "compute.instances.start",
      ])
      && google_compute_instance_iam_member.resume_instance_starter[0].role == google_project_iam_custom_role.resume_instance_starter[0].id
      && google_compute_instance_iam_member.resume_instance_starter[0].member == "serviceAccount:resume@example.test"
      && google_compute_instance_iam_member.resume_instance_starter[0].member != "user:operator@example.test"
      && google_compute_instance_iam_member.resume_instance_starter[0].instance_name == google_compute_instance.host[0].name
      && toset(keys(google_project_iam_member.operator_build)) == toset([
        "roles/cloudbuild.builds.editor",
        "roles/serviceusage.serviceUsageConsumer",
      ])
      && google_service_account_iam_member.operator_build[0].role == "roles/iam.serviceAccountUser"
      && google_artifact_registry_repository_iam_member.operator_reader[0].role == "roles/artifactregistry.reader"
      && google_artifact_registry_repository_iam_member.operator_reader[0].member == "user:operator@example.test"
      && google_secret_manager_secret_iam_member.host_access_gate[0].role == "roles/secretmanager.secretAccessor"
      && google_artifact_registry_repository_iam_member.host_reader[0].role == "roles/artifactregistry.reader"
      && !strcontains(file("${path.module}/identity.tf"), "roles/aiplatform.user")
    )
    error_message = "The operator and VM must receive only their exact declared custom and access roles."
  }

  assert {
    condition = (
      google_compute_instance.host[0].metadata["startup-script"] == local.startup_script
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "STAGING_LIFETIME_HOURS='168'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "STAGING_HARD_STOP_EPOCH='1900000000'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "if test \"$hard_stop_now\" -ge \"$STAGING_HARD_STOP_EPOCH\"")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "test \"$STAGING_HARD_STOP_EPOCH\" -ne 0")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "test \"$STAGING_HARD_STOP_EPOCH\" -lt \"$deadline\"")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "APT_AUTOMATIC_TIMERS='apt-daily.timer apt-daily-upgrade.timer'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "APT_AUTOMATIC_SERVICES='apt-daily.service apt-daily-upgrade.service'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "APT_SERVICE_QUIESCE_ATTEMPTS=180")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl mask $APT_AUTOMATIC_UNITS")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl stop $APT_AUTOMATIC_TIMERS")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl show \"$unit\" --property=ActiveState --value")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "test \"$apt_services_inactive\" = true || lifecycle_error")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl is-enabled \"$unit\"")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl is-active \"$unit\"")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "test \"$enabled_state\" = masked || lifecycle_error")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "test \"$active_state\" = inactive || lifecycle_error")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "freeze_automatic_apt\n\nread_record_value()")
      && !strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl mask --now")
      && !strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl mask --runtime")
      && !strcontains(google_compute_instance.host[0].metadata["startup-script"], "systemctl stop $APT_AUTOMATIC_UNITS")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "secretmanager.googleapis.com")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "ACCESS_SECRET_VERSION='7'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "access_hash=$(printf")
      && !strcontains(file("${path.module}/compute.tf"), "metadata_startup_script")
    )
    error_message = "The startup contract must freeze automatic apt, schedule the seven-day stop, and fetch, never embed, the access verifier."
  }

  assert {
    condition = (
      strcontains(local.compose_yaml, "COLORTRACE_DEMO_MODE: \"canonical\"")
      && strcontains(local.compose_yaml, "COLORTRACE_SOURCE_COMMIT: \"1111111111111111111111111111111111111111\"")
      && strcontains(local.compose_yaml, "COLORTRACE_SOURCE_TREE: \"2222222222222222222222222222222222222222\"")
      && strcontains(local.compose_yaml, "COLORTRACE_FIXTURE_BUNDLE_SHA256: \"sha256:21386db7c4ae2c3119d5532fc75589ddce1e64f7ccdecf61f41415e80f4564a6\"")
      && strcontains(local.compose_yaml, "COLORTRACE_RUNTIME_IMAGE: \"us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333\"")
      && strcontains(local.compose_yaml, "COLORTRACE_PUBLIC_URL: \"https://203-0-113-42.sslip.io\"")
      && strcontains(local.compose_yaml, "COLORTRACE_VERTEX_PROJECT_ID: \"colortrace-test-project\"")
      && strcontains(local.compose_yaml, "COLORTRACE_VERTEX_LOCATION: \"global\"")
      && strcontains(local.compose_yaml, "COLORTRACE_OIDC_AUDIENCE: \"https://runtime.internal:8443\"")
      && length(regexall("restart: \"no\"", local.compose_yaml)) == 7
      && !strcontains(local.compose_yaml, "restart: unless-stopped")
    )
    error_message = "The runtime must receive all immutable canonical-demo and identity bindings."
  }

  assert {
    condition = (
      strcontains(local.compose_yaml, "/run/colortrace-private:size=64k,uid=65532,gid=65532,mode=0700")
      && strcontains(local.compose_yaml, "COLORTRACE_GRAFANA_TOKEN_FILE: \"/run/colortrace-private/grafana-viewer-token\"")
      && !strcontains(local.compose_yaml, "/var/run/colortrace-private")
      && strcontains(local.compose_yaml, "http://127.0.0.1:8080/health/startup")
      && !strcontains(local.compose_yaml, "COLORTRACE_API_ORIGIN")
      && !strcontains(local.compose_yaml, "COLORTRACE_API_AUDIENCE")
      && strcontains(local.compose_yaml, "COLORTRACE_GRAFANA_URL: \"https://grafana.internal:8443\"")
      && strcontains(local.compose_yaml, "COLORTRACE_GRAFANA_CA_FILE: \"/etc/colortrace/caddy-root.crt\"")
      && length(regexall("/srv/colortrace/config/caddy-root.crt:/etc/colortrace/caddy-root.crt:ro", local.compose_yaml)) == 1
      && strcontains(local.compose_yaml, "ipv4_address: 172.30.0.2")
      && strcontains(local.compose_yaml, "ipv4_address: 172.30.0.10")
      && strcontains(local.compose_yaml, "subnet: 172.30.0.0/24")
      && strcontains(local.compose_yaml, "ip_range: 172.30.0.128/25")
      && strcontains(local.compose_yaml, "    dns:\n      - 8.8.8.8")
      && !strcontains(local.compose_yaml, "NODE_EXTRA_CA_CERTS")
      && strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_ENDPOINT: \"http://otel.internal:4318\"")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
      && strcontains(local.compose_yaml, "GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS: \"prometheus,loki,tempo\"")
      && strcontains(local.compose_yaml, "image: us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/grafana@sha256:6666666666666666666666666666666666666666666666666666666666666666")
      && strcontains(local.compose_yaml, "image: us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/prometheus@sha256:8888888888888888888888888888888888888888888888888888888888888888")
      && !strcontains(local.compose_yaml, "otel-lgtm")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "chown -R 65532:65532 \"$ROOT_DIR/caddy-config\" \"$ROOT_DIR/caddy-data\"")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "grafana-datasources.yaml")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "/api/datasources/uid/$datasource_uid/health")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "/api/datasources/proxy/uid/prometheus/api/v1/query")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "/api/datasources/proxy/uid/loki/loki/api/v1/query")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "/api/datasources/proxy/uid/tempo/api/search")
      && strcontains(file("${path.module}/../../config/observability/tempo.yaml"), "mcp_server:\n    enabled: true")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "backends_ready")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "configure_container_metadata_boundary")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "compose down --remove-orphans")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "--remove-orphans grafana loki prometheus tempo caddy")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "RUNTIME_CONTAINER_IP='172.30.0.10'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "METADATA_IP='169.254.169.254'")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "--insert DOCKER-USER 1")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "--jump ACCEPT")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "--jump DROP")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "65532:65532:400")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "target=Path(\"/run/colortrace-private/grafana-viewer-token\")")
      && !strcontains(google_compute_instance.host[0].metadata["startup-script"], "/var/run/colortrace-private")
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "hmac.compare_digest(source.read_bytes(), target.read_bytes())")
      && strcontains(local.caddyfile, "http://otel.internal:4318")
      && strcontains(local.caddyfile, "rewrite * /api/v1/otlp/v1/metrics")
      && strcontains(local.caddyfile, "rewrite * /otlp/v1/logs")
      && strcontains(local.caddyfile, "reverse_proxy tempo:4318")
      && strcontains(local.caddyfile, "https://grafana.internal:8443")
      && strcontains(local.caddyfile, "https://runtime.internal:8443")
      && !strcontains(local.caddyfile, "https://grafana.internal {")
      && !strcontains(local.caddyfile, "https://runtime.internal {")
      && strcontains(local.caddyfile, "@public_api path /v1/demo /v1/demo/* /v1/benchmarks/reference-suite")
      && strcontains(local.caddyfile, "reverse_proxy @public_api runtime:8080")
      && !strcontains(local.caddyfile, "/v1/benchmarks/*")
      && strcontains(local.caddyfile, "@other_api path /v1/*")
      && strcontains(local.caddyfile, "respond @other_api 404")
      && length(regexall("header_up -Authorization", local.caddyfile)) == 2
      && length(regexall("bind 172.30.0.2", local.caddyfile)) == 3
    )
    error_message = "The deployment must preserve the private runtime, observability, metadata-boundary, and proxy contracts."
  }

  assert {
    condition = (
      output.deployment_contract.public_tcp_ports == [443]
      && output.deployment_contract.lifetime_hours == 168
      && output.deployment_contract.hard_stop_epoch == 1900000000
      && output.staging_hard_stop_epoch == 1900000000
      && output.deployment_contract.estimated_cost_usd == 24
      && output.deployment_contract.public_url == "https://203-0-113-42.sslip.io"
      && output.deployment_contract.artifact_hashes.deployment_artifact_binding_sha256 == "sha256:daee9e9ddca5a2a62be24368e22f8ac5a40e84f22f1b9a9ff4689d9b0751827b"
      && output.deployment_contract.artifact_hashes.runtime_build_binding_sha256 == "sha256:94dcf637a46182cd88090369a68dd2295a43df1fcb1e0d3ce885cd8d62debbba"
      && output.deployment_contract.scanner.image == local.trivy_image
      && output.resume_identity.artifact_binding_sha256 == "sha256:daee9e9ddca5a2a62be24368e22f8ac5a40e84f22f1b9a9ff4689d9b0751827b"
      && output.resume_identity.member == "serviceAccount:resume@example.test"
    )
    error_message = "The deployment output must preserve its bounded lifecycle and complete artifact hash contract."
  }
}

run "omitted_hard_stop_preserves_rolling_lifecycle" {
  command = plan

  variables {
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    resume_member                = "serviceAccount:resume@example.test"
    staging_generation           = "stage-0001"
    staging_hard_stop_epoch      = null
    access_secret_version        = "7"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 24
  }

  assert {
    condition = (
      length(google_compute_instance.host) == 1
      && google_compute_instance.host[0].metadata["colortrace-staging-hard-stop-epoch"] == "0"
      && strcontains(google_compute_instance.host[0].metadata["startup-script"], "STAGING_HARD_STOP_EPOCH='0'")
      && output.deployment_contract.hard_stop_epoch == null
      && output.staging_hard_stop_epoch == 0
    )
    error_message = "Omitting the absolute cutoff must preserve the existing rolling 168-hour lifecycle."
  }
}
