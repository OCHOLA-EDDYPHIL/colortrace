resource "google_compute_network" "single_host" {
  project                 = var.project_id
  name                    = "${var.resource_prefix}-network"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "single_host" {
  project                  = var.project_id
  name                     = "${var.resource_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.single_host.id
  ip_cidr_range            = local.subnet_cidr
  private_ip_google_access = true
}

resource "google_compute_firewall" "public_https" {
  project   = var.project_id
  name      = "${var.resource_prefix}-https"
  network   = google_compute_network.single_host.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["${var.resource_prefix}-public"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "iap_ssh" {
  project   = var.project_id
  name      = "${var.resource_prefix}-iap-ssh"
  network   = google_compute_network.single_host.name
  direction = "INGRESS"
  priority  = 1000

  source_ranges = [local.iap_tcp_source_range]
  target_tags   = ["${var.resource_prefix}-iap-ssh"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_address" "public" {
  count = var.enable_instance ? 1 : 0

  project      = var.project_id
  name         = "${var.resource_prefix}-public"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}
