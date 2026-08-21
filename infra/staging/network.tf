resource "google_compute_network" "staging" {
  project                 = var.project_id
  name                    = "${var.resource_prefix}-network"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required["compute.googleapis.com"]]
}

resource "google_compute_subnetwork" "staging" {
  project                  = var.project_id
  name                     = "${var.resource_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.staging.id
  ip_cidr_range            = "10.24.0.0/26"
  private_ip_google_access = true
}

resource "google_compute_global_address" "private_services" {
  project       = var.project_id
  name          = "${var.resource_prefix}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.staging.id

  depends_on = [google_project_service.required["servicenetworking.googleapis.com"]]
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.staging.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}
