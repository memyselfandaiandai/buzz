# OCI plan only

This directory is deliberately not initialized and has no backend or tfvars.
Do not run `plan` or `apply` until the root package's provisioning gates pass
and the owner explicitly authorizes OCI mutation.

The planned graph creates a dedicated compartment, compartment-scoped operator
policy, AD-specific A1 core/memory quotas, a 2 OCPU/12 GB A1 instance with a
100 GB balanced boot volume, a no-ingress network, and budget alerts. The host
has a public address solely to avoid an always-on NAT Gateway charge; the OCI
security list has no ingress rules, and no public service is created. Viewer
and administrator access remains Tailscale-only after a separate short-lived
enrollment step.

Supplying every Phoenix AD is mandatory because A1 core and memory quotas are
availability-domain scoped. The selected AD receives 2 OCPUs/12 GB and every
other supplied AD receives zero. The implementation uses `compute-core` /
`standard-a1-core-count` and `compute-memory` /
`standard-a1-memory-count`.

After approval, the safe command sequence is `init`, `validate`, then a saved
`plan` reviewed by a human. `apply` is a separate approval. Never pass secrets
on the command line or commit `*.tfvars`, state, plans, or OCI profile files.

The cloud-init deliberately does not install k3s through a mutable internet
script and does not accept a Tailscale key. Before apply, select immutable k3s
and Tailscale package versions, validate their ARM64 digests, and define a
one-time enrollment procedure whose credential never enters Terraform state.
