#!/bin/bash
set -euo pipefail

mkdir -p "$HOME/.config/openbox" "$HOME/.config/chromium" /tmp/.X11-unix
children=()
stop() {
  trap - TERM INT EXIT
  for pid in "${children[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  wait || true
}
trap stop TERM INT EXIT

Xvfb "$DISPLAY" -screen 0 1440x900x24 -nolisten tcp -ac & children+=("$!")
for _ in $(seq 1 50); do [[ -S "/tmp/.X11-unix/X${DISPLAY#:}" ]] && break; sleep 0.1; done
openbox-session & children+=("$!")
x0vncserver -display "$DISPLAY" -rfbport 5900 -localhost -SecurityTypes None & children+=("$!")
websockify --web=/usr/share/novnc/ "${NOVNC_LISTEN}:6080" "${VNC_LISTEN}:5900" & children+=("$!")
chromium $CHROMIUM_FLAGS --user-data-dir="$HOME/.config/chromium" about:blank & children+=("$!")

# Sprig is present as buzz-acp and related multicall links. Autostart remains
# explicit because FINAL-FORM supplies the short-lived task configuration.
if [[ "${BUZZ_ACP_AUTOSTART:-0}" == "1" ]]; then
  buzz-acp ${BUZZ_ACP_ARGS:-} & children+=("$!")
fi

wait -n "${children[@]}"
