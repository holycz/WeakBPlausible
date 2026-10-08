#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-reference}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/patcheval-cve/patcheval-cve:cve-2020-28360"
REFERENCE="$ROOT/var/agent_work/ssrf_seed/CVE-2020-28360/reference.js"
AGENT="$ROOT/var/agent_work/ssrf_seed/CVE-2020-28360/fixed.js"
OUT="$ROOT/results/experiments/patcheval_cve_2020_28360"
mkdir -p "$OUT"
case "$MODE" in
  baseline|candidate|reference) ;;
  *) echo "usage: $0 baseline|candidate|reference" >&2; exit 2 ;;
esac
MOUNT_ARGS=(-v /dev/null:/tmp/noop:ro)
if [ "$MODE" = candidate ]; then MOUNT_ARGS=(-v "$AGENT:/tmp/fixed.js:ro"); fi
if [ "$MODE" = reference ]; then MOUNT_ARGS=(-v "$REFERENCE:/tmp/reference.js:ro"); fi
docker run --rm --platform linux/amd64 \
  "${MOUNT_ARGS[@]}" \
  --entrypoint sh "$IMAGE" -lc '
    set -eu
    cd /workspace/private-ip
    if [ "'"$MODE"'" = candidate ]; then cp /tmp/fixed.js src/index.js; fi
    if [ "'"$MODE"'" = reference ]; then cp /tmp/reference.js src/index.js; fi
    cp /workspace/poc/files/test.js test.js
    npm test
  ' | tee "$OUT/$MODE.log"
