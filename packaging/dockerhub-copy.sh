#!/bin/bash
# Copies a published ghcr.io/qorechain/qorel image, with its CI signature, to
# Docker Hub using the local Docker login (no rebuild: same digest, so the
# GitHub Actions signature stays valid). Used while CI has no Docker Hub token.
#   packaging/dockerhub-copy.sh 0.1.0 [namespace]
set -euo pipefail
V="$1"
NS="${2:-liviuepure}"
SRC="ghcr.io/qorechain/qorel:${V}"
DST="docker.io/${NS}/qorel"

docker buildx imagetools create -t "${DST}:${V}" -t "${DST}:latest" "${SRC}"
digest="$(docker buildx imagetools inspect "${SRC}" --format '{{json .Manifest}}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')"
cosign copy --only=sig --force "ghcr.io/qorechain/qorel@${digest}" "${DST}"
cosign verify "${DST}:${V}" \
  --certificate-identity-regexp 'https://github.com/qorechain/QORel/.github/workflows/qorel-release.yml@refs/tags/qorel-v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null
echo "${DST}:${V} copied (${digest}) and its signature verifies"
