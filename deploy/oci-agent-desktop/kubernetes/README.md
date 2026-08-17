# Disposable-workspace Kubernetes fixtures

Status: **local rendering and validation only**. Nothing in this directory is
currently connected to a Kubernetes API by the new controller.

The provider-neutral controller lives under [`../controller/`](../controller/README.md).
It is separate from `buzz-backend-kubernetes`: the existing backend continues to
manage ordinary remote-agent Pods and is not the disposable-workspace
controller.

## Closed-world validation

`manifest-policy.mjs` rejects resources outside an exact kind/name/namespace
inventory, duplicates, unexpected workloads, host namespace/path access,
privileged containers, privilege escalation, mutable images, service-account
token mounts, unexpected Secret mounts, and policy additions that widen egress.
It inspects every normal, init, and ephemeral container. The controller also
binds validation to the SHA-256 of its complete expected manifest.

Adversarial fixtures and tests prove that an appended privileged Job, an
additional permissive NetworkPolicy, and duplicate objects fail. These are
local object-validation tests; they do not prove admission behavior in a real
cluster.

## Legacy fixture renderer

`session.template.json` and `render-session.mjs` remain a non-production fixture
for static checks. The renderer now treats substitutions as JSON data, derives
only `buzz-<session>` namespaces, requires a UUID session, and caps expiry at two
hours. The template still represents the earlier single-container design and
must not be described as the output of `buzz-backend-kubernetes` or the new
controller.

The new controller renders a separate agent and browser container with distinct
UIDs and no shared PID namespace. Raw capabilities and signatures are verified
before rendering and do not appear in the manifest. The browser receives no raw
authority material. Its configured command omits `--no-sandbox`, but actual
Chromium sandbox startup remains unvalidated until the split images are built
and tested under their container security contexts.

## Cleanup

Controller cleanup planning is bound to namespace plus session ID, supports
terminal-result and expiration modes, and is idempotent in the fake ledger.
`cleanup-session.ps1` is a deferred cluster helper. It additionally requires:

- a generated namespace matching the supplied session UUID;
- managed/session labels and an expiration annotation;
- verified terminal-result annotation or elapsed expiration;
- a `kind-*`/`k3d-*` context whose API server is loopback;
- UID and resource-version delete preconditions.

No cleanup script was executed in this slice.

## Deferred live tests

`validate-live-disposable.ps1` and
`validate-provider-live-disposable.ps1` are destructive local-cluster tests.
They now require both a disposable context name and loopback API endpoint. They
remain closed gates and were not run. Before use, the first script must be
updated to exercise the new controller-generated graph and split runtime—not
the legacy capability Secret fixture.
