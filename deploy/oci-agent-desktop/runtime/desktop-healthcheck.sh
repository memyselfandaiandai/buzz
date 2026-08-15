#!/bin/sh
set -eu
test -S "/tmp/.X11-unix/X${DISPLAY#:}"
chromium --version >/dev/null 2>&1
curl --fail --silent --max-time 1 http://127.0.0.1:6080/vnc.html >/dev/null
