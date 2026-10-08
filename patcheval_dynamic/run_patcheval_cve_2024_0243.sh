#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/patcheval-cve/patcheval-cve:cve-2024-0243"
AGENT="$ROOT/var/agent_work/ssrf_seed/CVE-2024-0243/fixed.py"
REFERENCE="$ROOT/results/experiments/patcheval_cases/upstream_files/CVE-2024-0243/html.py"
OUT="$ROOT/results/experiments/patcheval_cve_2024_0243"
mkdir -p "$OUT"
case "$MODE" in
  baseline) MOUNT=(-v "$ROOT/scripts/replace_python_function.py:/tmp/unused.py:ro") ;;
  candidate) MOUNT=(-v "$AGENT:/tmp/fixed.py:ro") ;;
  reference) MOUNT=(-v "$REFERENCE:/tmp/reference.py:ro") ;;
  *) echo "usage: $0 baseline|candidate|reference" >&2; exit 2 ;;
esac
if [ "$MODE" = baseline ]; then MOUNT=(-v "$ROOT/scripts/replace_python_function.py:/tmp/unused.py:ro"); fi
docker run --rm --platform linux/amd64 \
  -v "$ROOT/scripts/replace_python_function.py:/tmp/replace.py:ro" \
  "${MOUNT[@]}" --entrypoint sh "$IMAGE" -lc '
  set -u
  cd /workspace/langchain
  if [ "'"$MODE"'" = candidate ]; then
    /workspace/PoC_env/CVE-2024-0243/bin/python /tmp/replace.py /tmp/fixed.py libs/core/langchain_core/utils/html.py extract_sub_links
  fi
  if [ "'"$MODE"'" = reference ]; then
    cp /tmp/reference.py libs/core/langchain_core/utils/html.py
  fi
  cp /workspace/poc/files/poc_recursive_url_loader_scope.py ./poc_recursive_url_loader_scope.py
  PYTHONPATH=/workspace/langchain/libs/community:/workspace/langchain/libs/core /workspace/PoC_env/CVE-2024-0243/bin/python poc_recursive_url_loader_scope.py
' | tee "$OUT/$MODE.log"
