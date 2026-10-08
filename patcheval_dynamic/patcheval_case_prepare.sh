#!/usr/bin/env bash
set -euo pipefail

CASE="${1:?usage: $0 CVE-ID IMAGE [ROOT]}"
IMAGE="${2:?usage: $0 CVE-ID IMAGE [ROOT]}"
ROOT="${3:-$(pwd)/results/experiments/patcheval_cases/$CASE}"
PLATFORM="${PATCHEVAL_PLATFORM:-linux/amd64}"
mkdir -p "$ROOT/logs"

docker image inspect "$IMAGE" --format 'image={{.RepoTags}} size={{.Size}} workdir={{.Config.WorkingDir}}' | tee "$ROOT/logs/image.txt" >/dev/null || {
  echo "Image not found; pulling $IMAGE"
  docker pull --platform "$PLATFORM" "$IMAGE" | tee "$ROOT/logs/pull.log"
}

PROBE_EXIT=0
docker run --rm --platform "$PLATFORM" --entrypoint sh "$IMAGE" -lc '
  set -eu
  PROJECT_DIR=""
  for candidate in /workspace/request /workspace/undici /workspace /app /repo /src; do
    if [ -d "$candidate/.git" ]; then PROJECT_DIR="$candidate"; break; fi
  done
  if [ -z "$PROJECT_DIR" ]; then
    GIT_DIR=$(find /workspace /app /repo /src -maxdepth 4 -type d -name .git -print -quit 2>/dev/null || true)
    if [ -n "$GIT_DIR" ]; then PROJECT_DIR=${GIT_DIR%/.git}; fi
  fi
  if [ -z "$PROJECT_DIR" ]; then
    echo "ERROR: could not locate a Git project directory" >&2
    find /workspace /app /repo /src -maxdepth 3 -type d 2>/dev/null | sort | sed -n "1,120p"
    exit 2
  fi
  cd "$PROJECT_DIR"
  echo "case='"$CASE"'"
  echo "project_dir=$PROJECT_DIR"
  echo "commit=$(git rev-parse HEAD)"
  echo "node=$(node --version 2>/dev/null || true)"
  echo "python=$(python3 --version 2>/dev/null || true)"
  echo "go=$(go version 2>/dev/null || true)"
  if [ -f package.json ] && command -v node >/dev/null 2>&1; then
    node -e "const p=require('./package.json'); console.log('scripts='+JSON.stringify(p.scripts||{}))" 2>/dev/null || echo "scripts=<unavailable>"
  else
    echo "scripts=<unavailable>"
  fi
  find . -maxdepth 2 -type f -not -path './node_modules/*' -not -path './.git/*' 2>/dev/null | sort | sed -n "1,160p" || true
' | tee "$ROOT/logs/probe.txt" || PROBE_EXIT=$?

cat > "$ROOT/status.json" <<EOF
{"case":"$CASE","image":"$IMAGE","platform":"$PLATFORM","status":"PREPARED","probe_exit":$PROBE_EXIT,"dynamic_test":"NOT_IMPLEMENTED","note":"Project directory and probe details are recorded in logs/probe.txt; a run-specific adapter is required before interpreting security results."}
EOF
echo "prepared: $ROOT (probe_exit=$PROBE_EXIT)"
