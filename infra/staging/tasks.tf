resource "google_cloud_tasks_queue" "worker" {
  project  = var.project_id
  location = var.region
  name     = "${var.resource_prefix}-worker"

  rate_limits {
    max_concurrent_dispatches = 1
    max_dispatches_per_second = 1
  }

  retry_config {
    max_attempts       = 3
    max_retry_duration = "300s"
    min_backoff        = "5s"
    max_backoff        = "60s"
    max_doublings      = 3
  }

  stackdriver_logging_config {
    sampling_ratio = 0
  }

  depends_on = [google_project_service.required["cloudtasks.googleapis.com"]]
}

resource "google_cloud_tasks_queue" "simulator" {
  project  = var.project_id
  location = var.region
  name     = "${var.resource_prefix}-simulator"

  rate_limits {
    max_concurrent_dispatches = 1
    max_dispatches_per_second = 1
  }

  retry_config {
    max_attempts       = 3
    max_retry_duration = "300s"
    min_backoff        = "5s"
    max_backoff        = "60s"
    max_doublings      = 3
  }

  stackdriver_logging_config {
    sampling_ratio = 0
  }

  depends_on = [google_project_service.required["cloudtasks.googleapis.com"]]
}
