import { invokeTauri } from "@/shared/api/tauri";

export type SecretBackendKind = "os_keyring" | "bws" | "local_air_gapped";

export interface SecretBackendStatus {
  backend: SecretBackendKind;
  binding_keys: string[];
}

export interface SecretBackendTestResult {
  ok: boolean;
  message: string;
}

export interface BwsSecretBindingInput {
  logicalKey: string;
  secretId: string;
}

export interface SecretPolicy {
  policy_id: string;
  agent_pubkey: string;
  allowed_secrets: string[];
  allowed_tools: string[];
  max_lease_ttl_secs: number;
  expires_at: string;
}

export interface SecretLeaseMetadata {
  lease_id: string;
  secret_key: string;
  agent_pubkey: string;
  tool: string;
  issued_at: string;
  expires_at: string;
}

export interface SecretAccessOverview {
  policies: SecretPolicy[];
  active_leases: SecretLeaseMetadata[];
}

export function getSecretBackendStatus(): Promise<SecretBackendStatus> {
  return invokeTauri<SecretBackendStatus>("get_secret_backend_status");
}

export function setSecretBackend(
  backend: SecretBackendKind,
): Promise<SecretBackendStatus> {
  return invokeTauri<SecretBackendStatus>("set_secret_backend", { backend });
}

export function configureBwsCredentials(input: {
  accessToken?: string;
  projectId?: string;
  bindings?: BwsSecretBindingInput[];
}): Promise<SecretBackendStatus> {
  return invokeTauri<SecretBackendStatus>("configure_bws_credentials", {
    accessToken: input.accessToken,
    projectId: input.projectId,
    bindings: input.bindings?.map(({ logicalKey, secretId }) => ({
      logical_key: logicalKey,
      secret_id: secretId,
    })),
  });
}

export function clearBwsCredentials(): Promise<SecretBackendStatus> {
  return invokeTauri<SecretBackendStatus>("clear_bws_credentials");
}

export function testSecretBackend(
  backend: SecretBackendKind,
): Promise<SecretBackendTestResult> {
  return invokeTauri<SecretBackendTestResult>("test_secret_backend", {
    backend,
  });
}

export function getSecretAccessOverview(): Promise<SecretAccessOverview> {
  return invokeTauri<SecretAccessOverview>("get_secret_access_overview");
}
