#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/patcheval-cve/patcheval-cve:cve-2025-23221"
AGENT="$ROOT/var/agent_work/ssrf_seed/CVE-2025-23221/fixed.js"
OUT="$ROOT/results/experiments/patcheval_cve_2025_23221"; mkdir -p "$OUT"
case "$MODE" in candidate) SRC=/tmp/source.js; MOUNT=(-v "$AGENT:/tmp/source.js:ro");; reference) SRC=reference; MOUNT=(-v "$ROOT/scripts/patcheval_replace_from_record.py:/tmp/unused:ro");; baseline) SRC=vulnerable; MOUNT=(-v "$ROOT/scripts/patcheval_replace_from_record.py:/tmp/unused:ro");; *) echo "usage: $0 baseline|candidate|reference"; exit 2;; esac
docker run --rm --platform linux/amd64 \
  -v "$ROOT/scripts/patcheval_replace_from_record.py:/tmp/replace.py:ro" \
  -v "$ROOT/scripts/add_ts_import.py:/tmp/add_import.py:ro" \
  -v "$ROOT/data/raw/patcheval_verified/patcheval_verified.json:/tmp/raw.json:ro" \
  "${MOUNT[@]}" \
  --entrypoint sh "$IMAGE" -lc '
    set -eu
    cd /workspace/fedify
    if [ "'"$MODE"'" != baseline ]; then python3 /tmp/replace.py CVE-2025-23221 /tmp/raw.json '"$SRC"' src/webfinger/lookup.ts; fi
    if [ "'"$MODE"'" = reference ]; then python3 /tmp/add_import.py src/webfinger/lookup.ts; fi
    cp /workspace/poc/files/src/webfinger/lookup.test.ts src/webfinger/lookup.test.ts
    cd src
    deno test --allow-env ./webfinger/lookup.test.ts
  ' | tee "$OUT/$MODE.log"
