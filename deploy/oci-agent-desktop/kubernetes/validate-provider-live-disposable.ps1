param([Parameter(Mandatory = $true)][string]$Context)
$ErrorActionPreference = 'Stop'
if ($Context -notmatch '^(kind-|k3d-)') { throw "Refusing non-disposable context: $Context" }
$guardConfig = kubectl config view --raw --flatten -o json | ConvertFrom-Json
$guardContext = $guardConfig.contexts | Where-Object name -eq $Context
if (-not $guardContext) { throw "Context not found in kubeconfig: $Context" }
$guardCluster = ($guardConfig.clusters | Where-Object name -eq $guardContext.context.cluster).cluster
$guardServer = [Uri]$guardCluster.server
if (-not $guardServer.IsLoopback) { throw "Refusing non-loopback cluster API server: $($guardServer.Host)" }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$ns = 'buzz-provider-' + ([Guid]::NewGuid().ToString('N').Substring(0, 10))
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('buzz-kube-' + [Guid]::NewGuid().ToString('N'))
$previousKubeconfig = $env:KUBECONFIG
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
  kubectl --context $Context create namespace $ns
  kubectl --context $Context label namespace $ns pod-security.kubernetes.io/enforce=restricted
  kubectl --context $Context -n $ns create serviceaccount provider-validation

  $role = @{
    apiVersion = 'rbac.authorization.k8s.io/v1'; kind = 'Role'
    metadata = @{ name = 'provider-validation'; namespace = $ns }
    rules = @(
      @{ apiGroups = @(''); resources = @('pods'); verbs = @('create', 'delete', 'get', 'list') },
      @{ apiGroups = @(''); resources = @('pods/status'); verbs = @('get') },
      @{ apiGroups = @(''); resources = @('secrets'); verbs = @('create', 'delete', 'get', 'list') }
    )
  } | ConvertTo-Json -Depth 10
  $role | kubectl --context $Context apply -f -
  kubectl --context $Context -n $ns create rolebinding provider-validation --role=provider-validation --serviceaccount="${ns}:provider-validation"

  $token = kubectl --context $Context -n $ns create token provider-validation --duration=10m
  $raw = kubectl config view --raw --flatten -o json | ConvertFrom-Json
  $ctx = $raw.contexts | Where-Object name -eq $Context
  if (-not $ctx) { throw "Context not found in kubeconfig: $Context" }
  $cluster = ($raw.clusters | Where-Object name -eq $ctx.context.cluster).cluster
  $kubeconfigPath = Join-Path $tempRoot 'config.json'
  @{
    apiVersion = 'v1'; kind = 'Config'; 'current-context' = 'validation'
    clusters = @(@{ name = 'cluster'; cluster = @{ server = $cluster.server; 'certificate-authority-data' = $cluster.'certificate-authority-data' } })
    contexts = @(@{ name = 'validation'; context = @{ cluster = 'cluster'; user = 'provider' } })
    users = @(@{ name = 'provider'; user = @{ token = $token } })
  } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $kubeconfigPath -Encoding utf8NoBOM
  $env:KUBECONFIG = $kubeconfigPath

  cargo build --locked -p buzz-backend-kubernetes --manifest-path (Join-Path $repo 'Cargo.toml')
  $request = Get-Content -Raw -LiteralPath (Join-Path $repo 'crates\buzz-backend-kubernetes\tests\fixtures\provider-wire\deploy-full-launch.request.json') | ConvertFrom-Json
  $request.provider_config.namespace = $ns
  $request.provider_config.image = 'registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c'
  $request.provider_config | Add-Member -NotePropertyName manage_namespace -NotePropertyValue $false -Force
  $binaryRelative = if ($env:OS -eq 'Windows_NT') { 'target\debug\buzz-backend-kubernetes.exe' } else { 'target/debug/buzz-backend-kubernetes' }
  $binary = Join-Path $repo $binaryRelative
  $response = $request | ConvertTo-Json -Depth 20 -Compress | & $binary | ConvertFrom-Json
  if (-not $response.ok) { throw "Provider deploy failed: $($response.error)" }

  if ((kubectl --context $Context auth can-i create namespaces --as="system:serviceaccount:${ns}:provider-validation") -ne 'no') { throw 'provider can create namespaces' }
  if ((kubectl --context $Context -n $ns auth can-i create rolebindings --as="system:serviceaccount:${ns}:provider-validation") -ne 'no') { throw 'provider can change RBAC' }
  kubectl --context $Context -n $ns get pod $response.agent_id -o name | Out-Null
  Write-Host 'provider live least-privilege create/read/result gate PASS'
} finally {
  $env:KUBECONFIG = $previousKubeconfig
  kubectl --context $Context delete namespace $ns --ignore-not-found=true --wait=true --timeout=180s
  if ($tempRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
