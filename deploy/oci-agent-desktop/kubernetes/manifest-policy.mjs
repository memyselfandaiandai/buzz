import { isDeepStrictEqual } from "node:util";

const WORKLOAD_KINDS = new Set(["Job", "CronJob", "Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController"]);
const HOST_FIELDS = ["hostNetwork", "hostPID", "hostIPC"];

function fail(message) {
  throw new Error(message);
}

function objectKey(object) {
  const namespace = object.metadata?.namespace ?? "<cluster>";
  return `${object.apiVersion}|${object.kind}|${namespace}|${object.metadata?.name ?? "<missing>"}`;
}

function requireExactKeys(object, keys, where) {
  const actual = Object.keys(object ?? {}).sort();
  const expected = [...keys].sort();
  if (!isDeepStrictEqual(actual, expected)) fail(`${where} keys differ: ${actual.join(",")}`);
}

function validateContainer(container, where, allowedSecretMounts) {
  if (!container || typeof container !== "object") fail(`${where} must be an object`);
  if (!/@sha256:[a-f0-9]{64}$/.test(container.image ?? "")) fail(`${where} image must be digest pinned`);
  const sc = container.securityContext ?? {};
  if (sc.privileged !== false) fail(`${where}: privileged must be false`);
  if (sc.allowPrivilegeEscalation !== false) fail(`${where}: privilege escalation must be false`);
  if (sc.runAsNonRoot === false || sc.runAsUser === 0) fail(`${where}: container must not override non-root execution`);
  if (sc.procMount === "Unmasked") fail(`${where}: unmasked proc is forbidden`);
  if (sc.readOnlyRootFilesystem !== true) fail(`${where}: root filesystem must be read-only`);
  const dropped = new Set(sc.capabilities?.drop ?? []);
  if (!dropped.has("ALL") || !dropped.has("NET_RAW")) fail(`${where}: ALL and NET_RAW must be dropped`);
  const added = sc.capabilities?.add ?? [];
  if (!Array.isArray(added) || added.length !== 0) fail(`${where}: adding Linux capabilities is forbidden`);
  for (const mount of container.volumeMounts ?? []) {
    if (mount.name.toLowerCase().includes("secret") && !allowedSecretMounts.has(mount.name)) fail(`${where} has unexpected Secret mount ${mount.name}`);
  }
}

function validatePodSpec(pod, where, policy, expectedContainers) {
  if (!pod || typeof pod !== "object") fail(`${where} pod spec missing`);
  if (pod.automountServiceAccountToken !== false) fail(`${where} must disable service-account token mounting`);
  if (pod.shareProcessNamespace === true) fail(`${where} must not share process namespace`);
  for (const field of HOST_FIELDS) {
    if (pod[field] !== undefined && pod[field] !== false) fail(`${where} sets ${field}`);
  }
  for (const volume of pod.volumes ?? []) {
    const sourceKeys = Object.keys(volume).filter(key => key !== "name");
    if (sourceKeys.length !== 1 || !policy.allowedVolumeSources.has(sourceKeys[0])) fail(`${where} contains unapproved volume source ${sourceKeys.join(",") || "<missing>"}`);
    if (volume.hostPath) fail(`${where} contains hostPath volume ${volume.name}`);
    if (volume.projected?.sources?.some(source => source.serviceAccountToken)) fail(`${where} contains projected service-account token`);
    if (volume.secret && !policy.allowedSecretVolumes.has(volume.name)) fail(`${where} contains unexpected Secret volume ${volume.name}`);
  }
  const groups = [
    ["containers", pod.containers ?? []],
    ["initContainers", pod.initContainers ?? []],
    ["ephemeralContainers", pod.ephemeralContainers ?? []],
  ];
  if (groups[0][1].length === 0) fail(`${where} has no containers`);
  for (const [group, containers] of groups) {
    const names = containers.map(container => container?.name);
    const expectedNames = expectedContainers?.[group];
    if (!Array.isArray(expectedNames) || !isDeepStrictEqual(names, expectedNames)) fail(`${where}.${group} inventory differs`);
    for (const [index, container] of containers.entries()) validateContainer(container, `${where}.${group}[${index}]`, policy.allowedSecretVolumes);
  }
  const podSc = pod.securityContext ?? {};
  if (podSc.runAsNonRoot !== true) fail(`${where} must run as non-root`);
  if (podSc.seccompProfile?.type !== "RuntimeDefault") fail(`${where} must use RuntimeDefault seccomp`);
}

function jobPodSpec(object) {
  if (object.kind === "Job") return object.spec?.template?.spec;
  return undefined;
}

export function validateClosedWorldManifest(list, policy) {
  requireExactKeys(list, ["apiVersion", "kind", "items"], "manifest");
  if (list.apiVersion !== "v1" || list.kind !== "List" || !Array.isArray(list.items)) fail("manifest must be a v1 List");
  const actualKeys = list.items.map(objectKey);
  const unique = new Set(actualKeys);
  if (unique.size !== actualKeys.length) fail("manifest contains duplicate objects");
  const expectedKeys = new Set(policy.inventory);
  if (actualKeys.length !== expectedKeys.size || actualKeys.some(key => !expectedKeys.has(key))) {
    fail(`manifest inventory differs: ${actualKeys.join(";")}`);
  }

  for (const object of list.items) {
    const namespace = object.metadata?.namespace;
    if (object.kind === "Namespace") {
      if (object.metadata?.name !== policy.namespace) fail("unexpected namespace name");
    } else if (namespace !== policy.namespace) {
      fail(`${object.kind}/${object.metadata?.name} is outside ${policy.namespace}`);
    }
    if (WORKLOAD_KINDS.has(object.kind)) {
      if (object.kind !== "Job") fail(`unexpected workload kind ${object.kind}`);
      validatePodSpec(jobPodSpec(object), `Job/${object.metadata.name}`, policy, policy.workloadContainers.get(objectKey(object)));
    }
    if (object.kind === "NetworkPolicy") {
      const expected = policy.networkPolicies.get(object.metadata.name);
      if (!expected || !isDeepStrictEqual(object.spec, expected)) fail(`NetworkPolicy/${object.metadata.name} widens or changes traffic`);
    }
  }
  return true;
}

export function legacySessionPolicy(list) {
  const namespaceObject = list.items?.find(object => object.kind === "Namespace");
  const namespace = namespaceObject?.metadata?.name;
  if (!/^buzz-[a-z0-9]([-a-z0-9]{0,57}[a-z0-9])?$/.test(namespace ?? "")) fail("namespace must be generated as buzz-<session>");
  const expiresAt = Date.parse(namespaceObject.metadata?.annotations?.["buzz.final-form/expires-at"] ?? "");
  const now = Date.now();
  if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt - now > 7_200_000) fail("namespace expiry exceeds two-hour policy");
  const expectedObjects = [
    ["v1", "Namespace", "<cluster>", namespace],
    ["v1", "ServiceAccount", namespace, "desktop-worker"],
    ["rbac.authorization.k8s.io/v1", "Role", namespace, "buzz-provider"],
    ["rbac.authorization.k8s.io/v1", "RoleBinding", namespace, "buzz-provider"],
    ["v1", "PersistentVolumeClaim", namespace, "workspace"],
    ["networking.k8s.io/v1", "NetworkPolicy", namespace, "default-deny"],
    ["networking.k8s.io/v1", "NetworkPolicy", namespace, "desktop-egress"],
    ["batch/v1", "Job", namespace, "desktop"],
  ];
  const policies = new Map([
    ["default-deny", { podSelector: {}, policyTypes: ["Ingress", "Egress"] }],
    ["desktop-egress", {
      podSelector: { matchLabels: { "app.kubernetes.io/name": "buzz-desktop" } },
      policyTypes: ["Egress"],
      egress: [
        {
          to: [{ namespaceSelector: { matchLabels: { "kubernetes.io/metadata.name": "kube-system" } } }],
          ports: [{ protocol: "UDP", port: 53 }, { protocol: "TCP", port: 53 }],
        },
        {
          to: [{ ipBlock: {
            cidr: "0.0.0.0/0",
            except: ["10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"],
          } }],
          ports: [{ protocol: "TCP", port: 443 }],
        },
      ],
    }],
  ]);
  return {
    namespace,
    inventory: expectedObjects.map(([apiVersion, kind, ns, name]) => `${apiVersion}|${kind}|${ns}|${name}`),
    networkPolicies: policies,
    workloadContainers: new Map([
      [`batch/v1|Job|${namespace}|desktop`, { containers: ["desktop"], initContainers: [], ephemeralContainers: [] }],
    ]),
    allowedVolumeSources: new Set(["persistentVolumeClaim", "emptyDir", "secret", "configMap"]),
    allowedSecretVolumes: new Set(["capability"]),
  };
}
