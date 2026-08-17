$ErrorActionPreference = 'Stop'
$ref = 'ghcr.io/block/buzz-sprig:sha-6530b58@sha256:17facfc7608d8ddb33bc056c9aaba1098f4ef6abe5655702fbfd7584d1f74d76'
node (Join-Path $PSScriptRoot 'verify-image-platform.mjs') $ref
