#!/bin/sh
# Builds one image per block. Each carries its own digest, and therefore its
# own attestation measurement — see docker/Dockerfile.block.
set -eu
TAG="${TAG:-dev}"
REGISTRY="${REGISTRY:-ghcr.io/datakaveri}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for block in preprocess crypto kanon; do
    image="${REGISTRY}/skald-${block}:${TAG}"
    echo "── building ${image}"
    docker build \
        -f "${ROOT}/docker/Dockerfile.block" \
        --build-arg "BLOCK_BIN=skald_${block}" \
        -t "${image}" \
        "${ROOT}"
done

echo "── building ${REGISTRY}/skald-ao:${TAG} (orchestrator toolkit)"
docker build \
    -f "${ROOT}/docker/Dockerfile.ao" \
    -t "${REGISTRY}/skald-ao:${TAG}" \
    "${ROOT}"

echo "done:"
for b in preprocess crypto kanon ao; do
    printf '  %s\n' "${REGISTRY}/skald-${b}:${TAG}"
done
