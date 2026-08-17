# syntax=docker/dockerfile:1.7
ARG SPRIG_IMAGE=ghcr.io/block/buzz-sprig:sha-6530b58@sha256:17facfc7608d8ddb33bc056c9aaba1098f4ef6abe5655702fbfd7584d1f74d76
FROM --platform=linux/arm64 ${SPRIG_IMAGE} AS sprig

FROM --platform=linux/arm64 debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG TARGETARCH
RUN test "$TARGETARCH" = arm64 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates chromium curl dbus-x11 fonts-liberation git novnc openbox tini \
      tigervnc-scraping-server websockify xauth xvfb \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 agent \
    && useradd --uid 10001 --gid 10001 --home-dir /home/agent --create-home --shell /bin/bash agent

COPY --from=sprig /usr/local/bin/sprig /usr/local/bin/sprig
RUN for name in buzz-acp buzz-agent buzz-dev-mcp rg tree buzz git-credential-nostr git-sign-nostr; do ln -s sprig "/usr/local/bin/$name"; done \
    && git config --system gpg.format x509 \
    && git config --system gpg.x509.program /usr/local/bin/git-sign-nostr \
    && git config --system commit.gpgSign true \
    && git config --system tag.gpgSign true
COPY --chmod=0755 deploy/oci-agent-desktop/runtime/desktop-entrypoint.sh /usr/local/bin/desktop-entrypoint
COPY --chmod=0755 deploy/oci-agent-desktop/runtime/desktop-healthcheck.sh /usr/local/bin/desktop-healthcheck

ENV HOME=/home/agent DISPLAY=:99 VNC_LISTEN=127.0.0.1 NOVNC_LISTEN=127.0.0.1 \
    CHROMIUM_FLAGS="--no-first-run --no-sandbox --disable-dev-shm-usage --disable-background-networking"
WORKDIR /home/agent
USER 10001:10001
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/desktop-entrypoint"]

# No EXPOSE directive: the viewer is reached only by an authenticated
# Tailscale-side Kubernetes port-forward and both servers bind loopback.
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=4 CMD ["/usr/local/bin/desktop-healthcheck"]
