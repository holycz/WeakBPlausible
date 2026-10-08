#!/usr/bin/env bash
set -euo pipefail
CVE="${1:?CVE}"
MODE="${2:-candidate}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RAW="$ROOT/data/raw/patcheval_verified/patcheval_verified.json"
case "$CVE" in
  CVE-2023-24623) IMAGE=ghcr.io/patcheval-cve/patcheval-cve:cve-2023-24623; DIR=paranoidhttp; TARGET=client.go; TEST='cp /workspace/poc/files/client_test.go client_test.go; go test -timeout 30s -run ^TestRequest$ github.com/hakobe/paranoidhttp';;
  CVE-2022-24825) IMAGE=ghcr.io/patcheval-cve/patcheval-cve:cve-2022-24825; DIR=smokescreen; TARGET=pkg/smokescreen/acl/v1/acl.go; TEST='cp /workspace/poc/files/pkg/smokescreen/acl/v1/acl_test.go pkg/smokescreen/acl/v1/acl_test.go; mkdir -p pkg/smokescreen/acl/v1/testdata; cp /workspace/poc/files/pkg/smokescreen/acl/v1/testdata/poc_config_global_deny_canonical_entries.yaml pkg/smokescreen/acl/v1/testdata/; cd pkg/smokescreen/acl/v1; go test -timeout 30s -v';;
  CVE-2022-29188) IMAGE=ghcr.io/patcheval-cve/patcheval-cve:cve-2022-29188; DIR=smokescreen; TARGET=pkg/smokescreen/smokescreen.go; TEST='cp /workspace/poc/files/pkg/smokescreen/smokescreen_test.go pkg/smokescreen/smokescreen_test.go; go test -timeout 30s -run ^TestHostSquareBrackets$ github.com/stripe/smokescreen/pkg/smokescreen';;
  CVE-2023-5122) IMAGE=ghcr.io/patcheval-cve/patcheval-cve:cve-2023-5122; DIR=grafana-csv-datasource; TARGET=pkg/http_storage.go; TEST='cp /workspace/poc/files/pkg/http_storage_test.go pkg/http_storage_test.go; go test -timeout 30s -run ^TestHTTPStorage_UrlHandling$ github.com/grafana/grafana-csv-datasource/pkg';;
  *) echo unknown Go case >&2; exit 2;;
esac
case "$CVE" in
  CVE-2023-24623) UPSTREAM="$ROOT/results/experiments/patcheval_cases/upstream_files/CVE-2023-24623_client.go" ;;
  *) UPSTREAM="$ROOT/results/experiments/patcheval_cases/upstream_files/${CVE}_$(basename "$TARGET")" ;;
esac
AGENT="$ROOT/var/agent_work/ssrf_seed/$CVE/fixed.go"
OUT="$ROOT/results/experiments/patcheval_$CVE"; mkdir -p "$OUT"
ARGS=(-v "$ROOT/scripts/patcheval_replace_from_record.py:/tmp/replace.py:ro" -v "$RAW:/tmp/raw.json:ro")
if [ "$MODE" = candidate ]; then ARGS+=(-v "$AGENT:/tmp/fixed.go:ro"); fi
if [ "$MODE" = reference ]; then ARGS+=(-v "$UPSTREAM:/tmp/upstream.go:ro"); fi
set +e
docker run --rm --platform linux/amd64 "${ARGS[@]}" --entrypoint sh "$IMAGE" -lc '
  set -eu
  cd /workspace/'"$DIR"'
  if [ "'"$MODE"'" = candidate ]; then python3 /tmp/replace.py '"$CVE"' /tmp/raw.json /tmp/fixed.go '"$TARGET"'; fi
  if [ "'"$MODE"'" = reference ]; then cp /tmp/upstream.go '"$TARGET"'; fi
  '"$TEST"'
' | tee "$OUT/$MODE.log"
rc=${PIPESTATUS[0]}
printf '\n=== security_test_exit=%s ===\n' "$rc" | tee -a "$OUT/$MODE.log"
exit "$rc"
