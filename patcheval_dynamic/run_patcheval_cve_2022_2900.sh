#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/patcheval-cve/patcheval-cve:cve-2022-2900"
AGENT="$ROOT/var/agent_work/ssrf_seed/CVE-2022-2900/fixed.js"
REFERENCE="$ROOT/var/agent_work/ssrf_seed/CVE-2022-2900/reference.js"
OUT="$ROOT/results/experiments/patcheval_cve_2022_2900"
mkdir -p "$OUT"
case "$MODE" in
  baseline) SOURCE="";;
  candidate) SOURCE="$AGENT";;
  reference) SOURCE="$REFERENCE";;
  *) echo "usage: $0 baseline|candidate|reference" >&2; exit 2;;
esac
ARGS=(-v "$ROOT/scripts/patcheval_replace_es_module.py:/tmp/inject.py:ro")
if [ -n "$SOURCE" ]; then ARGS+=(-v "$SOURCE:/tmp/source.js:ro"); fi
docker run --rm --platform linux/amd64 "${ARGS[@]}" --entrypoint sh "$IMAGE" -lc '
  set -eu
  cd /workspace/parse-url
  if [ "'"$MODE"'" != baseline ]; then
    python3 /tmp/inject.py /tmp/source.js lib/index.js
  fi
  cp /workspace/poc/files/test/index.js test/index.js
  node test/index.js
' | tee "$OUT/$MODE.log"
