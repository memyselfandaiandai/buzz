import {
  HardDrive,
  KeyRound,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  configureBwsThenTest,
  formatLeaseCountdown,
  leaseSecondsRemaining,
} from "../lib/secretsPreferencesView";

import {
  clearBwsCredentials,
  configureBwsCredentials,
  getSecretAccessOverview,
  getSecretBackendStatus,
  setSecretBackend,
  testSecretBackend,
  type SecretAccessOverview,
  type SecretBackendKind,
  type SecretBackendStatus,
  type SecretBackendTestResult,
} from "@/shared/api/secretsPreferences";

const BACKENDS: Array<{
  id: SecretBackendKind;
  label: string;
  description: string;
  icon: typeof KeyRound;
}> = [
  {
    id: "os_keyring",
    label: "OS Keyring",
    description:
      "Windows Credential Manager-backed storage for interactive desktop use.",
    icon: KeyRound,
  },
  {
    id: "bws",
    label: "Bitwarden Secrets Manager",
    description:
      "Machine-token access for shared and cross-machine deployments.",
    icon: Server,
  },
  {
    id: "local_air_gapped",
    label: "Local Air-gapped Store",
    description:
      "Isolated local keyring namespace with no external provider calls.",
    icon: HardDrive,
  },
];

const emptyBindingRow = () => ({
  rowId: crypto.randomUUID(),
  logicalKey: "",
  secretId: "",
});

export function SecretsPreferencesCard() {
  const [status, setStatus] = useState<SecretBackendStatus | null>(null);
  const [overview, setOverview] = useState<SecretAccessOverview>({
    policies: [],
    active_leases: [],
  });
  const accessTokenRef = useRef<HTMLInputElement>(null);
  const [projectId, setProjectId] = useState("");
  const [selectedBackend, setSelectedBackend] =
    useState<SecretBackendKind>("os_keyring");
  const [bindings, setBindings] = useState([emptyBindingRow()]);
  const [testResult, setTestResult] = useState<SecretBackendTestResult | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());

  const load = useCallback(async () => {
    const nextStatus = await getSecretBackendStatus();
    setStatus(nextStatus);
    setSelectedBackend(nextStatus.backend);
    try {
      setOverview(await getSecretAccessOverview());
    } catch {
      // Audit storage is optional to provider selection. Keep the last safe
      // projection (or the initial empty projection) when it is unavailable.
    }
  }, []);

  useEffect(() => {
    load().catch((cause) => setError(String(cause)));
    const overviewTimer = window.setInterval(() => {
      getSecretAccessOverview()
        .then(setOverview)
        .catch(() => undefined);
    }, 5_000);
    const countdownTimer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      window.clearInterval(overviewTimer);
      window.clearInterval(countdownTimer);
    };
  }, [load]);

  const activeLeases = useMemo(
    () =>
      overview.active_leases.filter(
        (lease) => leaseSecondsRemaining(lease.expires_at, now) > 0,
      ),
    [overview.active_leases, now],
  );

  const selectBackend = async (backend: SecretBackendKind) => {
    if (accessTokenRef.current) accessTokenRef.current.value = "";
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      setStatus(await setSecretBackend(backend));
      setSelectedBackend(backend);
    } catch (cause) {
      setError(String(cause));
    } finally {
      if (accessTokenRef.current) accessTokenRef.current.value = "";
      setBusy(false);
    }
  };

  const saveBws = async () => {
    const replacementBindings = bindings.filter(
      ({ logicalKey, secretId }) => logicalKey !== "" || secretId !== "",
    );
    const request = {
      ...(accessTokenRef.current?.value
        ? { accessToken: accessTokenRef.current.value }
        : {}),
      projectId,
      ...(replacementBindings.length > 0
        ? { bindings: replacementBindings }
        : {}),
    };
    if (accessTokenRef.current) accessTokenRef.current.value = "";
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      const result = await configureBwsThenTest(
        request,
        configureBwsCredentials,
        () => testSecretBackend("bws"),
      );
      setStatus(result.status);
      setTestResult(result.testResult);
      setProjectId("");
      setBindings([emptyBindingRow()]);
    } catch (cause) {
      setError(String(cause));
    } finally {
      delete request.accessToken;
      if (accessTokenRef.current) accessTokenRef.current.value = "";
      setBusy(false);
    }
  };

  const clearBws = async () => {
    if (accessTokenRef.current) accessTokenRef.current.value = "";
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      const next = await clearBwsCredentials();
      setStatus(next);
      setProjectId("");
      setBindings([emptyBindingRow()]);
    } catch (cause) {
      setError(String(cause));
    } finally {
      if (accessTokenRef.current) accessTokenRef.current.value = "";
      setBusy(false);
    }
  };

  const runTest = async () => {
    setBusy(true);
    setError(null);
    setTestResult(null);
    try {
      setTestResult(await testSecretBackend(selectedBackend));
      setStatus(await getSecretBackendStatus());
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-5 rounded-xl border border-border bg-card p-5 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <ShieldCheck
              className="size-4 text-emerald-500"
              aria-hidden="true"
            />
            Secrets & Key Storage
          </h3>
          <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
            Select the pluggable vault backend, test it without returning
            credentials, and inspect agent/tool lease scope.
          </p>
        </div>
        <div className="rounded-full bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground">
          {status?.binding_keys.length ? "Bindings configured" : "No bindings"}
        </div>
      </div>

      <div className="grid gap-2 md:grid-cols-3">
        {BACKENDS.map((backend) => {
          const Icon = backend.icon;
          const selected = selectedBackend === backend.id;
          return (
            <button
              key={backend.id}
              type="button"
              disabled={busy}
              onClick={() => selectBackend(backend.id)}
              className={`rounded-lg border p-3 text-left transition-colors disabled:opacity-60 ${
                selected
                  ? "border-primary bg-primary/5"
                  : "border-border bg-background hover:bg-muted/60"
              }`}
            >
              <span className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Icon className="size-4" aria-hidden="true" />
                {backend.label}
              </span>
              <span className="mt-1 block text-xs leading-relaxed text-muted-foreground">
                {backend.description}
              </span>
            </button>
          );
        })}
      </div>

      {selectedBackend === "bws" && (
        <div className="space-y-3 rounded-lg border border-border bg-muted/25 p-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="space-y-1.5 text-xs font-medium text-foreground">
              BWS machine token
              <input
                ref={accessTokenRef}
                type="password"
                autoComplete="off"
                spellCheck={false}
                placeholder="Paste once; the value is never returned"
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground outline-none focus:border-primary"
              />
            </label>
            <label className="space-y-1.5 text-xs font-medium text-foreground">
              Project scope ID
              <input
                type="text"
                value={projectId}
                onChange={(event) => setProjectId(event.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder="Bitwarden project UUID"
                className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground outline-none focus:border-primary"
              />
            </label>
          </div>
          <div className="space-y-2">
            <div className="text-xs font-medium text-foreground">
              Exact logical-key bindings
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">
              Leave every row blank to preserve the current bindings. Enter a
              complete nonempty list to replace them atomically.
            </p>
            {bindings.map((binding, index) => (
              <div
                // The editable rows are ephemeral and never repopulated with UUIDs.
                key={binding.rowId}
                className="grid gap-2 md:grid-cols-[1fr_1fr_auto]"
              >
                <input
                  aria-label={`Logical key ${index + 1}`}
                  type="text"
                  value={binding.logicalKey}
                  onChange={(event) =>
                    setBindings((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? { ...item, logicalKey: event.target.value }
                          : item,
                      ),
                    )
                  }
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Exact logical key"
                  className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground outline-none focus:border-primary"
                />
                <input
                  aria-label={`Secret UUID ${index + 1}`}
                  type="text"
                  value={binding.secretId}
                  onChange={(event) =>
                    setBindings((current) =>
                      current.map((item, itemIndex) =>
                        itemIndex === index
                          ? { ...item, secretId: event.target.value }
                          : item,
                      ),
                    )
                  }
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="BWS secret UUID"
                  className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground outline-none focus:border-primary"
                />
                <button
                  type="button"
                  disabled={busy || bindings.length === 1}
                  onClick={() =>
                    setBindings((current) =>
                      current.filter((_, itemIndex) => itemIndex !== index),
                    )
                  }
                  className="rounded-md border border-border px-3 py-2 text-xs text-muted-foreground disabled:opacity-50"
                >
                  Remove
                </button>
              </div>
            ))}
            <button
              type="button"
              disabled={busy || bindings.length >= 128}
              onClick={() =>
                setBindings((current) => [...current, emptyBindingRow()])
              }
              className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-muted disabled:opacity-50"
            >
              Add binding
            </button>
            {status?.binding_keys.length ? (
              <p className="text-xs text-muted-foreground">
                Configured logical keys: {status.binding_keys.join(", ")}
              </p>
            ) : null}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={saveBws}
              className="rounded-md bg-primary px-3 py-1.5 text-xs font-semibold text-primary-foreground disabled:opacity-50"
            >
              Store securely & test
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={clearBws}
              className="rounded-md border border-border px-3 py-1.5 text-xs font-medium text-muted-foreground hover:bg-muted disabled:opacity-50"
            >
              Clear BWS credentials
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 border-y border-border py-3">
        <button
          type="button"
          disabled={busy || !status}
          onClick={runTest}
          className="inline-flex items-center gap-2 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-semibold text-foreground hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw
            className={`size-3.5 ${busy ? "animate-spin" : ""}`}
            aria-hidden="true"
          />
          Test selected backend
        </button>
        {testResult && (
          <span
            className={
              testResult.ok
                ? "text-xs text-emerald-600"
                : "text-xs text-destructive"
            }
          >
            {testResult.message}
          </span>
        )}
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div>
          <div className="mb-2 flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Agent / tool ACLs
            </h4>
            <span className="text-xs text-muted-foreground">
              {overview.policies.length} policies
            </span>
          </div>
          {overview.policies.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-4 text-xs text-muted-foreground">
              No broker ACL policies are currently reported. Secret lease
              operations remain denied by default.
            </div>
          ) : (
            <div className="space-y-2">
              {overview.policies.map((policy) => (
                <div
                  key={policy.policy_id}
                  className="rounded-lg border border-border bg-muted/25 p-3 text-xs"
                >
                  <div className="break-all font-mono text-foreground">
                    Capability: {policy.policy_id}
                  </div>
                  <div className="break-all font-mono text-muted-foreground">
                    Agent: {policy.agent_pubkey}
                  </div>
                  <div className="mt-2 text-muted-foreground">
                    Keys: {policy.allowed_secrets.join(", ") || "none"}
                  </div>
                  <div className="text-muted-foreground">
                    Tools: {policy.allowed_tools.join(", ") || "none"} · max TTL{" "}
                    {policy.max_lease_ttl_secs}s ·{" "}
                    {formatLeaseCountdown(
                      leaseSecondsRemaining(policy.expires_at, now),
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Active leases
            </h4>
            <span className="text-xs text-muted-foreground">
              {activeLeases.length} active
            </span>
          </div>
          {activeLeases.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-4 text-xs text-muted-foreground">
              No active secret leases are currently reported by capability
              brokers.
            </div>
          ) : (
            <div className="space-y-2">
              {activeLeases.map((lease) => (
                <div
                  key={lease.lease_id}
                  className="rounded-lg border border-border bg-muted/25 p-3 text-xs"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold text-foreground">
                      {lease.secret_key}
                    </span>
                    <span className="font-mono text-amber-600">
                      {formatLeaseCountdown(
                        leaseSecondsRemaining(lease.expires_at, now),
                      )}
                    </span>
                  </div>
                  <div className="mt-1 break-all font-mono text-muted-foreground">
                    {lease.agent_pubkey}
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    Tool: {lease.tool}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
