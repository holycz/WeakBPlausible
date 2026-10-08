#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:?usage: $0 IMAGE}"
docker run --rm --platform linux/amd64 --entrypoint sh "$IMAGE" -lc '
  set -eu
  cd /workspace/request
  printf "node="; node --version || true
  printf "npm="; npm --version || true
  printf "\npackage.json:\n"; sed -n "1,220p" package.json
  printf "\nfiles:\n"; find . -maxdepth 3 -type f | sort | sed -n "1,180p"
  printf "\npackage scripts:\n"; node -e "const p=require(\"./package.json\"); console.log(JSON.stringify(p.scripts||{}, null, 2))"
  printf "\ninstalled dependencies:\n"; test -d node_modules && du -sh node_modules || echo unavailable
'
