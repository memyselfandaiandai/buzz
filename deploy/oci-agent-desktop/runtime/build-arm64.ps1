$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
docker buildx build --platform linux/arm64 --file (Join-Path $PSScriptRoot 'Dockerfile') --tag buzz-desktop:local-arm64 --load $root
docker image inspect buzz-desktop:local-arm64 --format '{{.Architecture}}' | Select-String '^arm64$' | Out-Null
