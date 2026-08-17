param(
  [Parameter(Mandatory = $true)][string]$Namespace,
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')][string]$SessionId,
  [Parameter(Mandatory = $true)][string]$Context,
  [Parameter(Mandatory = $true)][ValidateSet('TerminalResult', 'Expiration')][string]$Mode
)
$ErrorActionPreference = 'Stop'

$expectedNamespace = 'buzz-' + (($SessionId -replace '-', '').Substring(0, 12))
if ($Namespace -cne $expectedNamespace) { throw "Refusing namespace/session mismatch: expected $expectedNamespace" }
if ($Context -notmatch '^(kind-|k3d-)') { throw "Refusing non-disposable context name: $Context" }
$kubeconfigJson = kubectl config view --raw --flatten -o json 2>&1
if ($LASTEXITCODE -ne 0) { throw "Failed to read kubeconfig: $kubeconfigJson" }
$kubeconfig = $kubeconfigJson | ConvertFrom-Json
$selectedContext = $kubeconfig.contexts | Where-Object name -eq $Context
if (-not $selectedContext) { throw "Context not found in kubeconfig: $Context" }
$selectedCluster = ($kubeconfig.clusters | Where-Object name -eq $selectedContext.context.cluster).cluster
$server = [Uri]$selectedCluster.server
if (-not $server.IsLoopback) { throw "Refusing non-loopback disposable-cluster API server: $($server.Host)" }

$rawNamespace = kubectl --context $Context get namespace $Namespace --ignore-not-found -o json 2>&1
if ($LASTEXITCODE -ne 0) { throw "Failed to read namespace ownership: $rawNamespace" }
if (-not $rawNamespace) {
  Write-Host "Cleanup already complete: $Namespace is absent"
  return
}
$info = $rawNamespace | ConvertFrom-Json
if ($info.metadata.name -cne $Namespace) { throw "Namespace readback mismatch" }
if ($info.metadata.labels.'buzz.final-form/managed' -ne 'true') { throw "Refusing unmanaged namespace: $Namespace" }
if ($info.metadata.labels.'buzz.final-form/session-id' -cne $SessionId) { throw "Refusing session ownership mismatch: $Namespace" }
$expires = $info.metadata.annotations.'buzz.final-form/expires-at'
if (-not $expires) { throw "Refusing namespace without expiration: $Namespace" }

if ($Mode -eq 'Expiration') {
  if ([DateTimeOffset]::Parse($expires) -gt [DateTimeOffset]::UtcNow) { throw "Session has not expired: $expires" }
} else {
  if ($info.metadata.annotations.'buzz.final-form/terminal-result' -ne 'true') { throw "Terminal-result cleanup requires verified terminal-result annotation" }
}

$deleteOptions = @{
  apiVersion = 'v1'
  kind = 'DeleteOptions'
  propagationPolicy = 'Foreground'
  preconditions = @{
    uid = $info.metadata.uid
    resourceVersion = $info.metadata.resourceVersion
  }
} | ConvertTo-Json -Depth 5 -Compress
$deleteOutput = $deleteOptions | kubectl --context $Context delete --raw "/api/v1/namespaces/$Namespace" -f - 2>&1
if ($LASTEXITCODE -ne 0) { throw "Ownership-bound namespace deletion failed: $deleteOutput" }
$waitOutput = kubectl --context $Context wait --for=delete "namespace/$Namespace" --timeout=180s 2>&1
if ($LASTEXITCODE -ne 0) { throw "Namespace deletion did not complete: $waitOutput" }
