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
      && length(google_project_iam_member.operator_build) == 0
      && length(google_service_account_iam_member.operator_build) == 0
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
      && google_service_account.builder.account_id == "ct-singlehost-builder"
      && google_artifact_registry_repository_iam_member.builder_writer.role == "roles/artifactregistry.writer"
      && google_project_iam_member.builder_logs.role == "roles/logging.logWriter"
      && contains(keys(google_project_service.required), "cloudbuild.googleapis.com")
      && !contains(keys(google_project_service.required), "monitoring.googleapis.com")
    )
    error_message = "Private images must have a dedicated repository, builder identity, and minimal build services."
  }
}

run "image_builder_precedes_host_admission" {
  command = plan

  variables {
    project_id      = "colortrace-test-project"
    operator_member = "user:operator@example.test"
  }

  assert {
    condition = (
      length(google_compute_instance.host) == 0
      && toset(keys(google_project_iam_member.operator_build)) == toset([
        "roles/cloudbuild.builds.editor",
      ])
      && google_service_account_iam_member.operator_build[0].role == "roles/iam.serviceAccountUser"
      && google_service_account_iam_member.operator_build[0].member == "user:operator@example.test"
      && output.image_build_identity.registry == "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
    )
    error_message = "The operator must be able to build immutable images without admitting the VM."
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

run "boot_image_family_is_rejected" {
  command = plan

  variables {
    project_id = "colortrace-test-project"
    boot_image = "projects/debian-cloud/global/images/family/debian-12"
  }

  expect_failures = [var.boot_image]
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
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 24
    runtime_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image                    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/web@sha256:4444444444444444444444444444444444444444444444444444444444444444"
    caddy_image                  = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/caddy@sha256:5555555555555555555555555555555555555555555555555555555555555555"
    grafana_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/grafana@sha256:6666666666666666666666666666666666666666666666666666666666666666"
    loki_image                   = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/loki@sha256:7777777777777777777777777777777777777777777777777777777777777777"
    prometheus_image             = "docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
    tempo_image                  = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/tempo@sha256:9999999999999999999999999999999999999999999999999999999999999999"
    fixture_bundle_sha256        = "sha256:a9c5234acee64294b149e8e6ee761c7e2799999476943766ae856ec54eac7061"
  }

  assert {
    condition = (
      google_compute_instance.host[0].machine_type == "e2-standard-2"
      && google_compute_disk.boot[0].type == "pd-balanced"
      && google_compute_disk.boot[0].size == 30
      && google_compute_disk.boot[0].image == "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
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
      && toset(keys(google_project_iam_member.host)) == toset(["roles/aiplatform.user"])
      && toset(keys(google_project_iam_member.operator_build)) == toset(["roles/cloudbuild.builds.editor"])
      && google_service_account_iam_member.operator_build[0].role == "roles/iam.serviceAccountUser"
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
      strcontains(local.compose_yaml, "COLORTRACE_DEMO_MODE: \"canonical\"")
      && strcontains(local.compose_yaml, "COLORTRACE_SOURCE_COMMIT: \"1111111111111111111111111111111111111111\"")
      && strcontains(local.compose_yaml, "COLORTRACE_SOURCE_TREE: \"2222222222222222222222222222222222222222\"")
      && strcontains(local.compose_yaml, "COLORTRACE_FIXTURE_BUNDLE_SHA256: \"sha256:a9c5234acee64294b149e8e6ee761c7e2799999476943766ae856ec54eac7061\"")
      && strcontains(local.compose_yaml, "COLORTRACE_RUNTIME_IMAGE: \"us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333\"")
      && strcontains(local.compose_yaml, "COLORTRACE_PUBLIC_URL: \"https://203-0-113-42.sslip.io\"")
      && strcontains(local.compose_yaml, "COLORTRACE_VERTEX_PROJECT_ID: \"colortrace-test-project\"")
      && strcontains(local.compose_yaml, "COLORTRACE_VERTEX_LOCATION: \"global\"")
      && strcontains(local.compose_yaml, "COLORTRACE_OIDC_AUDIENCE: \"https://runtime.internal:8443\"")
    )
    error_message = "The runtime must receive all immutable canonical-demo and identity bindings."
  }

  assert {
    condition = (
      strcontains(local.compose_yaml, "/var/run/colortrace-private:size=64k,uid=65532,gid=65532,mode=0700")
      && strcontains(local.compose_yaml, "http://127.0.0.1:8080/health/startup")
      && strcontains(local.compose_yaml, "COLORTRACE_API_ORIGIN: \"https://runtime.internal:8443\"")
      && strcontains(local.compose_yaml, "COLORTRACE_API_AUDIENCE: \"https://runtime.internal:8443\"")
      && strcontains(local.compose_yaml, "COLORTRACE_GRAFANA_URL: \"https://grafana.internal:8443\"")
      && strcontains(local.compose_yaml, "ipv4_address: 172.30.0.2")
      && strcontains(local.compose_yaml, "ipv4_address: 172.30.0.10")
      && strcontains(local.compose_yaml, "subnet: 172.30.0.0/24")
      && strcontains(local.compose_yaml, "NODE_EXTRA_CA_CERTS: \"/etc/colortrace/caddy-root.crt\"")
      && strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_ENDPOINT: \"http://otel.internal:4318\"")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
      && !strcontains(local.compose_yaml, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
      && strcontains(local.compose_yaml, "GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS: \"prometheus,loki,tempo\"")
      && strcontains(local.compose_yaml, "image: us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/grafana@sha256:6666666666666666666666666666666666666666666666666666666666666666")
      && strcontains(local.compose_yaml, "image: docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0")
      && !strcontains(local.compose_yaml, "otel-lgtm")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "chown -R 65532:65532 \"$ROOT_DIR/caddy-config\" \"$ROOT_DIR/caddy-data\"")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "grafana-datasources.yaml")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "/api/datasources/uid/$datasource_uid/health")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "/api/datasources/proxy/uid/prometheus/api/v1/query")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "/api/datasources/proxy/uid/loki/loki/api/v1/query")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "/api/datasources/proxy/uid/tempo/api/search")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "backends_ready")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "configure_container_metadata_boundary")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "--remove-orphans grafana loki prometheus tempo caddy")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "RUNTIME_CONTAINER_IP='172.30.0.10'")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "METADATA_IP='169.254.169.254'")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "--insert DOCKER-USER 1")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "--jump ACCEPT")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "--jump DROP")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "65532:65532:400")
      && strcontains(google_compute_instance.host[0].metadata_startup_script, "hmac.compare_digest(source.read_bytes(), target.read_bytes())")
      && strcontains(local.caddyfile, "http://otel.internal:4318")
      && strcontains(local.caddyfile, "rewrite * /api/v1/otlp/v1/metrics")
      && strcontains(local.caddyfile, "rewrite * /otlp/v1/logs")
      && strcontains(local.caddyfile, "reverse_proxy tempo:4318")
      && length(regexall("header_up -Authorization", local.caddyfile)) == 2
      && strcontains(local.caddyfile, "https://grafana.internal:8443")
      && strcontains(local.caddyfile, "https://runtime.internal:8443")
      && !strcontains(local.caddyfile, "https://grafana.internal {")
      && !strcontains(local.caddyfile, "https://runtime.internal {")
      && length(regexall("bind 172.30.0.2", local.caddyfile)) == 3
    )
    error_message = "The deployment must preserve non-root state, private token-copy, and runtime/web health contracts."
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

  assert {
    condition = (
      local.private_images_in_owned_registry
      && startswith(var.prometheus_image, "docker.io/prom/prometheus@sha256:")
    )
    error_message = "The exact qualified public Prometheus image must remain outside the private-image registry check."
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
    boot_image                   = "projects/debian-cloud/global/images/debian-12-bookworm-v20260817"
    estimated_seven_day_cost_usd = 101
    runtime_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/runtime@sha256:3333333333333333333333333333333333333333333333333333333333333333"
    web_image                    = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/web@sha256:4444444444444444444444444444444444444444444444444444444444444444"
    caddy_image                  = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/caddy@sha256:5555555555555555555555555555555555555555555555555555555555555555"
    grafana_image                = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/grafana@sha256:6666666666666666666666666666666666666666666666666666666666666666"
    loki_image                   = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/loki@sha256:7777777777777777777777777777777777777777777777777777777777777777"
    prometheus_image             = "docker.io/prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
    tempo_image                  = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images/tempo@sha256:9999999999999999999999999999999999999999999999999999999999999999"
    fixture_bundle_sha256        = "sha256:a9c5234acee64294b149e8e6ee761c7e2799999476943766ae856ec54eac7061"
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
