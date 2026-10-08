#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/patcheval-cve/patcheval-cve:cve-2022-35949"
CANDIDATE="$ROOT/var/agent_work/ssrf_seed/CVE-2022-35949/fixed.js"
REFERENCE="$ROOT/var/agent_work/ssrf_seed/CVE-2022-35949/vuln.js"
OFFICIAL_REFERENCE="$ROOT/var/agent_work/ssrf_seed/CVE-2022-35949/reference.js"
OUT="$ROOT/results/experiments/patcheval_cve_2022_35949"
mkdir -p "$OUT"

case "$MODE" in
  baseline) MOUNT_ARGS=(-v "$ROOT/scripts/patcheval_cve_2022_35949_test.js:/tmp/unused.js:ro") ;;
  candidate) test -s "$CANDIDATE"; MOUNT_ARGS=(-v "$CANDIDATE:/tmp/candidate.js:ro") ;;
  reference) test -s "$OFFICIAL_REFERENCE"; MOUNT_ARGS=(-v "$OFFICIAL_REFERENCE:/tmp/candidate.js:ro") ;;
  *) echo "usage: $0 baseline|candidate|reference" >&2; exit 2 ;;
esac

docker run --rm --platform linux/amd64 \
  -v "$ROOT/scripts/patcheval_cve_2022_35949_test.js:/tmp/ssrf_test.js:ro" \
  "${MOUNT_ARGS[@]}" --entrypoint sh "$IMAGE" -lc '
    set -eu
    cd /workspace/undici
    TARGET=index.js
    if [ "'"$MODE"'" != baseline ]; then
      node /tmp/ssrf_test.js inject-test /tmp/candidate.js "$TARGET" > /tmp/ssrf-output.txt 2>&1 || ssrf_rc=$?
    else
      node /tmp/ssrf_test.js test > /tmp/ssrf-output.txt 2>&1 || ssrf_rc=$?
    fi
    ssrf_rc=${ssrf_rc:-0}
    npm run test:tap > /tmp/project-output.txt 2>&1 || project_rc=$?
    project_rc=${project_rc:-0}
    cat /tmp/ssrf-output.txt
    printf "\\n=== project_tests_exit=%s ===\\n" "$project_rc"
    tail -60 /tmp/project-output.txt || true
    printf "\\n=== ssrf_test_exit=%s project_test_exit=%s ===\\n" "$ssrf_rc" "$project_rc"
    exit "$ssrf_rc"
  ' | tee "$OUT/$MODE.log"
