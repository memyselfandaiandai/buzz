output "compartment_id" {
  value       = oci_identity_compartment.pilot.id
  description = "Dedicated pilot compartment."
}

output "instance_id" {
  value       = oci_core_instance.pilot.id
  description = "Disposable execution host identifier."
}

output "private_ip" {
  value       = oci_core_instance.pilot.private_ip
  description = "Host private address; use the Tailscale address for administration after enrollment."
}
