#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/patcheval-cve/patcheval-cve:cve-2023-28155}"
MODE="${1:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CANDIDATE="$ROOT/var/agent_work/ssrf_seed/CVE-2023-28155/fixed.js"
REFERENCE="$ROOT/var/agent_work/ssrf_seed/CVE-2023-28155/vuln.js"
OUT="$ROOT/results/experiments/patcheval_cve_2023_28155"
mkdir -p "$OUT"

case "$MODE" in
  baseline) SOURCE_MOUNT="" ;;
  candidate) test -s "$CANDIDATE"; SOURCE_MOUNT="-v $CANDIDATE:/tmp/candidate.js:ro" ;;
  reference) test -s "$REFERENCE"; SOURCE_MOUNT="-v $REFERENCE:/tmp/candidate.js:ro" ;;
  *) echo "usage: $0 baseline|candidate|reference" >&2; exit 2 ;;
esac

docker run --rm --platform linux/amd64 \
  -v "$ROOT/scripts/patcheval_2023_28155_test.js:/tmp/ssrf_test.js:ro" \
  $SOURCE_MOUNT \
  --entrypoint sh "$IMAGE" -lc '
    set -eu
    cd /workspace/request
    cp lib/redirect.js /tmp/redirect.original.js
    INJECT_SOURCE=/tmp/candidate.js
    if [ "'"$MODE"'" = reference ]; then
      cp /tmp/candidate.js /tmp/reference_local.js
      sed -i "s/if (request.uri.protocol !== uriPrev.protocol) {/if (request.uri.protocol !== uriPrev.protocol \&\& self.allowInsecureRedirect) {/" /tmp/reference_local.js
      INJECT_SOURCE=/tmp/reference_local.js
    fi
    if [ "'"$MODE"'" != baseline ]; then
      node /tmp/ssrf_test.js inject "$INJECT_SOURCE" lib/redirect.js
    fi
    node /tmp/ssrf_test.js test /workspace/request > /tmp/ssrf-test-output.txt 2>&1 || rc=$?
    rc=${rc:-0}
    npm run test-ci > /tmp/project-test-output.txt 2>&1 || project_rc=$?
    project_rc=${project_rc:-0}
    cat /tmp/ssrf-test-output.txt
    printf "\\n=== project_tests_exit=%s ===\\n" "$project_rc"
    tail -80 /tmp/project-test-output.txt || true
    printf "\\n=== ssrf_test_exit=%s project_test_exit=%s ===\\n" "$rc" "$project_rc"
    exit "$rc"
  ' | tee "$OUT/$MODE.log"
