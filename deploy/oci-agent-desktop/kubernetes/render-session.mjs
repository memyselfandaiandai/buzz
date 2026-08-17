import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const allowedArguments = new Set(["out", "session", "agent", "image", "provider-user", "expires"]);
const args = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const flag = process.argv[index];
  const value = process.argv[index + 1];
  if (!flag?.startsWith("--") || value === undefined || value.startsWith("--")) throw new Error(`invalid renderer argument near: ${flag ?? "<end>"}`);
  const name = flag.slice(2);
  if (!allowedArguments.has(name)) {
    if (name === "namespace") throw new Error("namespace override is forbidden; namespace is generated from session UUID");
    throw new Error(`unknown renderer argument: --${name}`);
  }
  if (Object.hasOwn(args, name)) throw new Error(`duplicate renderer argument: --${name}`);
  args[name] = value;
}

const out = args.out;
if (!out) throw new Error("usage: node render-session.mjs --out FILE [--session UUID --agent ID --image DIGEST_REF]");
const session = args.session ?? randomUUID();
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(session)) throw new Error("session must be a lowercase UUID");
const agent = args.agent ?? "buzz-validation";
if (agent.length < 1 || agent.length > 128 || /[\u0000-\u001f\u007f]/.test(agent)) throw new Error("agent ID is invalid");
const namespace = `buzz-${session.replaceAll("-", "").slice(0, 12)}`;
const image = args.image ?? `ghcr.io/example/buzz-desktop@sha256:${"0".repeat(64)}`;
if (!/@sha256:[a-f0-9]{64}$/.test(image)) throw new Error("desktop image must be digest pinned");
const provider = args["provider-user"] ?? "final-form-buzz-provider";
if (!/^[A-Za-z0-9:@._-]{1,253}$/.test(provider)) throw new Error("provider user is invalid");
const now = Date.now();
const expiresAt = args.expires ? Date.parse(args.expires) : now + 2 * 60 * 60 * 1000;
if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new Error("expires must be a future RFC3339 timestamp");
const ttlSeconds = Math.ceil((expiresAt - now) / 1000);
if (ttlSeconds > 7200) throw new Error("fixture TTL must not exceed 7200 seconds");
const expiry = new Date(expiresAt).toISOString();

const replacements = {
  "__NAMESPACE__": namespace,
  "__SESSION_ID__": session,
  "__AGENT_ID__": agent,
  "__EXPIRES_AT__": expiry,
  "__DESKTOP_IMAGE__": image,
  "__PROVIDER_USER__": provider,
};
function substitute(value) {
  if (Array.isArray(value)) return value.map(substitute);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, substitute(child)]));
  if (typeof value !== "string") return value;
  let result = value;
  for (const [placeholder, replacement] of Object.entries(replacements)) result = result.replaceAll(placeholder, replacement);
  return result;
}

const template = JSON.parse(await readFile(join(here, "session.template.json"), "utf8"));
const rendered = substitute(template);
const workload = rendered.items.find(object => object.kind === "Job" && object.metadata?.name === "desktop");
if (!workload) throw new Error("fixture template is missing desktop Job");
workload.spec.activeDeadlineSeconds = Math.min(workload.spec.activeDeadlineSeconds, ttlSeconds);
await writeFile(out, `${JSON.stringify(rendered, null, 2)}\n`, { flag: "w" });
console.log(`rendered fixture ${namespace} -> ${out}`);
