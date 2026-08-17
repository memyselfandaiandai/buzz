variable "tenancy_ocid" {
  type        = string
  description = "Root tenancy OCID. Never commit a tfvars file containing tenant identifiers."
  validation {
    condition     = startswith(var.tenancy_ocid, "ocid1.tenancy.")
    error_message = "tenancy_ocid must be an OCI tenancy OCID."
  }
}

variable "oci_config_profile" {
  type        = string
  description = "Existing least-privilege OCI CLI profile used only for an explicitly approved plan/apply."
  default     = "DEFAULT"
}

variable "region" {
  type    = string
  default = "us-phoenix-1"
  validation {
    condition     = var.region == "us-phoenix-1"
    error_message = "The audited pilot is locked to us-phoenix-1."
  }
}

variable "availability_domain_name" {
  type        = string
  description = "Exact Phoenix AD selected after live A1 capacity verification."
}

variable "all_availability_domain_names" {
  type        = set(string)
  description = "Every AD name returned by the tenant; non-selected ADs receive zero A1 quota."
  validation {
    condition     = length(var.all_availability_domain_names) >= 1
    error_message = "Supply the complete availability-domain set from the actual tenant."
  }
}

variable "ubuntu_arm64_image_ocid" {
  type        = string
  description = "Verified current Ubuntu ARM64 image OCID for Phoenix."
  validation {
    condition     = startswith(var.ubuntu_arm64_image_ocid, "ocid1.image.")
    error_message = "ubuntu_arm64_image_ocid must be an OCI image OCID."
  }
}

variable "ssh_authorized_key" {
  type        = string
  description = "Recovery-only public key. The subnet has no ingress rule for SSH."
}

variable "operator_group_name" {
  type        = string
  description = "Existing OCI IAM group receiving compartment-scoped operator policy."
}

variable "budget_amount" {
  type        = number
  description = "Monthly hard attention threshold in the tenancy billing currency."
  default     = 5
  validation {
    condition     = var.budget_amount >= 1
    error_message = "budget_amount must be at least 1."
  }
}

variable "budget_recipients" {
  type        = string
  description = "Comma-separated verified alert recipients."
  validation {
    condition     = can(regex("@", var.budget_recipients))
    error_message = "At least one email recipient is required."
  }
}
