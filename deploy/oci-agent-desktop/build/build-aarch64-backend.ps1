$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$out = Join-Path $root 'target\oci-aarch64-export'
docker buildx build --platform linux/arm64 --file (Join-Path $PSScriptRoot 'Dockerfile.aarch64-backend') --target export --output "type=local,dest=$out" $root
Write-Host "ARM64 provider exported to $out\buzz-backend-kubernetes"
