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
    }
  }
}

run "foundation_has_no_billable_host" {
  command = plan

  variables {
    project_id = "colortrace-test-project"
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
      length(google_project_iam_member.host) == 0
      && length(google_project_iam_member.operator) == 0
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
    condition     = google_artifact_registry_repository.images.repository_id == "ct-singlehost-images"
    error_message = "Private application images must have a dedicated repository."
  }
}

run "instance_requires_complete_admission_inputs" {
  command = plan

  variables {
    project_id      = "colortrace-test-project"
    enable_instance = true
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "bounded_single_host_is_admitted" {
  command = apply

  variables {
    project_id                   = "colortrace-test-project"
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    staging_generation           = "stage-0001"
    access_secret_version        = "7"
    candidate_commit             = "1111111111111111111111111111111111111111"
    candidate_tree               = "2222222222222222222222222222222222222222"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-20260801"
    estimated_seven_day_cost_usd = 24
    runtime_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image                    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/web@sha256:4444444444444444444444444444444444444444444444444444444444444444"
    caddy_image                  = "docker.io/library/caddy@sha256:5555555555555555555555555555555555555555555555555555555555555555"
    lgtm_image                   = "docker.io/grafana/otel-lgtm@sha256:6666666666666666666666666666666666666666666666666666666666666666"
  }

  assert {
    condition = (
      google_compute_instance.host[0].machine_type == "e2-standard-2"
      && google_compute_disk.boot[0].type == "pd-balanced"
      && google_compute_disk.boot[0].size == 30
      && google_compute_disk.boot[0].image == "projects/debian-cloud/global/images/debian-12-20260801"
      && google_compute_instance.host[0].boot_disk[0].auto_delete == false
    )
    error_message = "The host must use the bounded machine and persistent 30 GiB balanced disk."
  }

  assert {
    condition = (
      google_compute_instance.host[0].service_account[0].email == google_service_account.host.email
      && google_compute_instance.host[0].metadata["enable-oslogin"] == "TRUE"
      && google_compute_instance.host[0].metadata["block-project-ssh-keys"] == "TRUE"
      && google_compute_instance.host[0].metadata["serial-port-enable"] == "FALSE"
    )
    error_message = "The host must use its dedicated service account and hardened OS Login metadata."
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
      toset(keys(google_project_iam_member.operator)) == toset([
        "roles/compute.osAdminLogin",
        "roles/iap.tunnelResourceAccessor",
      ])
      && google_secret_manager_secret_iam_member.host_access_gate[0].role == "roles/secretmanager.secretAccessor"
      && google_artifact_registry_repository_iam_member.host_reader[0].role == "roles/artifactregistry.reader"
    )
    error_message = "The operator and VM must receive only the declared access roles."
  }

  assert {
    condition = (
      strcontains(google_compute_instance.host[0].metadata_startup_script, "STAGING_LIFETIME_HOURS='168'")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "secretmanager.googleapis.com")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "ACCESS_SECRET_VERSION='7'")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "access_hash=$(printf")
    )
    error_message = "The startup contract must schedule the seven-day stop and fetch, never embed, the access verifier."
  }

  assert {
    condition = (
      output.deployment_contract.public_tcp_ports == [443]
      && output.deployment_contract.lifetime_hours == 168
      && output.deployment_contract.estimated_cost_usd == 24
      && output.deployment_contract.public_url == "https://203-0-113-42.sslip.io"
    )
    error_message = "The deployment output must preserve its bounded public and lifecycle contract."
  }
}

run "cost_above_ceiling_is_rejected" {
  command = plan

  variables {
    project_id                   = "colortrace-test-project"
    enable_instance              = true
    operator_member              = "user:operator@example.test"
    staging_generation           = "stage-0001"
    access_secret_version        = "7"
    candidate_commit             = "1111111111111111111111111111111111111111"
    candidate_tree               = "2222222222222222222222222222222222222222"
    boot_image                   = "projects/debian-cloud/global/images/debian-12-20260801"
    estimated_seven_day_cost_usd = 101
    runtime_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image                    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/web@sha256:4444444444444444444444444444444444444444444444444444444444444444"
    caddy_image                  = "docker.io/library/caddy@sha256:5555555555555555555555555555555555555555555555555555555555555555"
    lgtm_image                   = "docker.io/grafana/otel-lgtm@sha256:6666666666666666666666666666666666666666666666666666666666666666"
  }

  expect_failures = [
    check.instance_admission,
    google_compute_instance.host,
  ]
}

run "reserved_network_namespace_is_rejected" {
  command = plan

  variables {
    project_id      = "colortrace-test-project"
    resource_prefix = "ct-p114-0821a"
  }

  expect_failures = [var.resource_prefix]
}
