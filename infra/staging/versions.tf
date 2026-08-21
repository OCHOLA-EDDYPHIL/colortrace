terraform {
  required_version = "= 1.15.9"

  backend "gcs" {}

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.45.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
