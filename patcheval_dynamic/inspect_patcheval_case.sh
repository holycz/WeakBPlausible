#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?usage: $0 IMAGE CVE [SOURCE_FILE_HINT]}"
CVE="${2:?usage: $0 IMAGE CVE [SOURCE_FILE_HINT]}"
HINT="${3:-}"

docker run --rm --platform linux/amd64 --entrypoint sh "$IMAGE" -lc '
  set -eu
  cd /workspace/request
  echo "=== image="'"$IMAGE"'";
  echo "=== cve="'"$CVE"'";
  echo "=== git="; git status --short; git log -1 --oneline;
  echo "=== matching source files=";
  if [ -n "'"$HINT"'" ]; then find . -type f -not -path "./node_modules/*" -not -path "./.git/*" -name "'"$HINT"'" -print; fi
  grep -RIl --exclude-dir=node_modules --exclude-dir=.git "processRedirect" . | sort || true
  echo "=== test files=";
  find tests -type f -maxdepth 3 | sort | sed -n "1,220p";
  echo "=== test-ci=";
  node -e "const p=require(\"./package.json\"); console.log(p.scripts && p.scripts[\"test-ci\"])"
'
