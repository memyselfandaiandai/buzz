locals {
  compartment_name = "BuzzAgentDesktopPilot"
  selected_ad      = lower(var.availability_domain_name)
  other_ads        = setsubtract(var.all_availability_domain_names, toset([var.availability_domain_name]))
  common_tags = {
    "authority" = "final-form"
    "purpose"   = "disposable-agent-desktop"
    "pilot"     = "pre-provision-gated"
  }
  quota_statements = concat(
    [
      "set compute-core quota standard-a1-core-count to 2 in compartment ${local.compartment_name} where request.ad = '${local.selected_ad}'",
      "set compute-memory quota standard-a1-memory-count to 12 in compartment ${local.compartment_name} where request.ad = '${local.selected_ad}'"
    ],
    flatten([
      for ad in local.other_ads : [
        "zero compute-core quota standard-a1-core-count in compartment ${local.compartment_name} where request.ad = '${lower(ad)}'",
        "zero compute-memory quota standard-a1-memory-count in compartment ${local.compartment_name} where request.ad = '${lower(ad)}'"
      ]
    ])
  )
}

resource "oci_identity_compartment" "pilot" {
  compartment_id = var.tenancy_ocid
  name           = local.compartment_name
  description    = "Disposable Buzz graphical execution plane; FINAL-FORM remains authoritative."
  enable_delete  = true
  freeform_tags  = local.common_tags
}

resource "oci_identity_policy" "operators" {
  compartment_id = var.tenancy_ocid
  name           = "BuzzAgentDesktopPilotOperators"
  description    = "Compartment-scoped lifecycle policy for the disposable desktop pilot."
  statements = [
    "Allow group ${var.operator_group_name} to manage instance-family in compartment ${local.compartment_name}",
    "Allow group ${var.operator_group_name} to manage volume-family in compartment ${local.compartment_name}",
    "Allow group ${var.operator_group_name} to manage virtual-network-family in compartment ${local.compartment_name}",
    "Allow group ${var.operator_group_name} to read metrics in compartment ${local.compartment_name}"
  ]
}

resource "oci_limits_quota" "a1_pilot" {
  compartment_id = var.tenancy_ocid
  name           = "BuzzAgentDesktopPilotA1"
  description    = "Limit A1 use to the audited 2 OCPU and 12 GB pilot in one selected AD."
  statements     = local.quota_statements
}

resource "oci_core_vcn" "pilot" {
  compartment_id = oci_identity_compartment.pilot.id
  cidr_blocks    = ["10.77.0.0/24"]
  display_name   = "buzz-agent-desktop"
  dns_label      = "buzzdesktop"
  freeform_tags  = local.common_tags
}

resource "oci_core_internet_gateway" "pilot" {
  compartment_id = oci_identity_compartment.pilot.id
  vcn_id         = oci_core_vcn.pilot.id
  display_name   = "buzz-desktop-egress"
  enabled        = true
  freeform_tags  = local.common_tags
}

resource "oci_core_route_table" "pilot" {
  compartment_id = oci_identity_compartment.pilot.id
  vcn_id         = oci_core_vcn.pilot.id
  display_name   = "buzz-desktop-egress"
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.pilot.id
  }
}

resource "oci_core_security_list" "pilot" {
  compartment_id = oci_identity_compartment.pilot.id
  vcn_id         = oci_core_vcn.pilot.id
  display_name   = "buzz-desktop-no-ingress"

  # Intentionally no ingress rules: SSH, VNC, noVNC, and k3s are not public.
  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
    stateless   = false
  }
}

resource "oci_core_subnet" "pilot" {
  compartment_id             = oci_identity_compartment.pilot.id
  vcn_id                     = oci_core_vcn.pilot.id
  cidr_block                 = "10.77.0.0/28"
  display_name               = "buzz-agent-desktop"
  dns_label                  = "worker"
  route_table_id             = oci_core_route_table.pilot.id
  security_list_ids          = [oci_core_security_list.pilot.id]
  prohibit_public_ip_on_vnic = false
  freeform_tags              = local.common_tags
}

resource "oci_core_instance" "pilot" {
  availability_domain  = var.availability_domain_name
  compartment_id       = oci_identity_compartment.pilot.id
  display_name         = "buzz-agent-desktop-a1"
  shape                = "VM.Standard.A1.Flex"
  preserve_boot_volume = false
  freeform_tags        = local.common_tags

  shape_config {
    ocpus         = 2
    memory_in_gbs = 12
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.pilot.id
    assign_public_ip = true
    display_name     = "buzz-agent-desktop"
    hostname_label   = "a1"
  }

  source_details {
    source_type             = "image"
    source_id               = var.ubuntu_arm64_image_ocid
    boot_volume_size_in_gbs = 100
    boot_volume_vpus_per_gb = 10
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  metadata = {
    ssh_authorized_keys = trimspace(var.ssh_authorized_key)
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      authority = "FINAL-FORM"
    }))
  }

  lifecycle {
    precondition {
      condition     = contains(var.all_availability_domain_names, var.availability_domain_name)
      error_message = "availability_domain_name must be present in all_availability_domain_names."
    }
  }
}

resource "oci_budget_budget" "pilot" {
  compartment_id = var.tenancy_ocid
  amount         = var.budget_amount
  reset_period   = "MONTHLY"
  display_name   = "Buzz agent desktop pilot"
  description    = "Attention budget for the disposable OCI execution plane."
  target_type    = "COMPARTMENT"
  targets        = [oci_identity_compartment.pilot.id]
}

resource "oci_budget_alert_rule" "forecast" {
  budget_id      = oci_budget_budget.pilot.id
  display_name   = "Buzz pilot forecast at 50 percent"
  description    = "Early warning before the pilot budget is consumed."
  type           = "FORECAST"
  threshold      = 50
  threshold_type = "PERCENTAGE"
  recipients     = var.budget_recipients
  message        = "Buzz OCI desktop pilot is forecast to exceed 50 percent of its budget."
}

resource "oci_budget_alert_rule" "actual" {
  budget_id      = oci_budget_budget.pilot.id
  display_name   = "Buzz pilot actual at 80 percent"
  description    = "Escalation when actual spend approaches the attention budget."
  type           = "ACTUAL"
  threshold      = 80
  threshold_type = "PERCENTAGE"
  recipients     = var.budget_recipients
  message        = "Buzz OCI desktop pilot has consumed 80 percent of its budget."
}
