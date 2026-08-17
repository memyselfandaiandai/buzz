param(
  [Parameter(Mandatory = $true)][string]$Context,
  [Parameter(Mandatory = $true)][string]$RenderedManifest
)
$ErrorActionPreference = 'Stop'
if ($Context -notmatch '^(kind-|k3d-)') { throw "Refusing non-disposable context: $Context" }
$rawConfig = kubectl config view --raw --flatten -o json | ConvertFrom-Json
$selectedContext = $rawConfig.contexts | Where-Object name -eq $Context
if (-not $selectedContext) { throw "Context not found in kubeconfig: $Context" }
$selectedCluster = ($rawConfig.clusters | Where-Object name -eq $selectedContext.context.cluster).cluster
$apiServer = [Uri]$selectedCluster.server
if (-not $apiServer.IsLoopback) { throw "Refusing non-loopback cluster API server: $($apiServer.Host)" }
$doc = Get-Content -Raw -LiteralPath $RenderedManifest | ConvertFrom-Json
$ns = ($doc.items | Where-Object kind -eq 'Namespace').metadata.name
try {
  kubectl --context $Context apply -f $RenderedManifest
  kubectl --context $Context -n $ns create secret generic buzz-execution-capability --from-literal=capability.json='{"validation":true}' --from-literal=signature='local-validation-only'
  kubectl --context $Context -n $ns auth can-i create pods --as=final-form-buzz-provider | Select-String '^yes$' | Out-Null
  kubectl --context $Context -n $ns auth can-i create secrets --as=final-form-buzz-provider | Select-String '^yes$' | Out-Null
  if ((kubectl --context $Context auth can-i create namespaces --as=final-form-buzz-provider) -ne 'no') { throw 'provider can create namespaces' }
  if ((kubectl --context $Context -n $ns auth can-i create rolebindings --as=final-form-buzz-provider) -ne 'no') { throw 'provider can change RBAC' }
  kubectl --context $Context -n $ns wait --for=condition=ready pod -l app.kubernetes.io/name=buzz-desktop --timeout=300s
  kubectl --context $Context -n $ns exec job/desktop -- sh -lc 'printf BUZZ_K8S_LIFECYCLE_OK > /home/agent/result.txt'
  if ((kubectl --context $Context -n $ns exec job/desktop -- sha256sum /home/agent/result.txt) -notmatch '^[a-f0-9]{64}') { throw 'result hash missing' }
} finally {
  kubectl --context $Context delete namespace $ns --ignore-not-found=true --wait=true --timeout=180s
}
