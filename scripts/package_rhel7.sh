#!/usr/bin/env bash
set -euo pipefail

# Build and extract the statically linked x86_64 binary for RHEL 7 hosts.
# The recipient still supplies their input file under data/.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-${repo_root}/dist/skald-rhel7}"
config_source="${2:-${repo_root}/config/config.json}"
image_name="skald-rhel7-builder"

if [[ ! -f "${config_source}" ]]; then
  printf 'Config file not found: %s\n' "${config_source}" >&2
  exit 1
fi

mkdir -p "${output_dir}/config" "${output_dir}/data" "${output_dir}/output"
output_dir="$(realpath "${output_dir}")"

docker build \
  --target builder \
  --tag "${image_name}" \
  "${repo_root}"

docker run --rm \
  --entrypoint /bin/sh \
  --volume "${output_dir}:/bundle" \
  "${image_name}" \
  -c 'cp /build/target/x86_64-unknown-linux-musl/release/skald_pipeline /bundle/skald_pipeline'
if [[ ! -s "${output_dir}/skald_pipeline" ]]; then
  printf 'Extracted binary is missing or empty: %s\n' "${output_dir}/skald_pipeline" >&2
  exit 1
fi
chmod 0755 "${output_dir}/skald_pipeline"

cp "${config_source}" "${output_dir}/config/config.json"

# If sudo was used, return the bundle to the invoking user.
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
  chown -R "${SUDO_UID}:${SUDO_GID}" "${output_dir}"
fi

printf 'RHEL 7 bundle created at %s\n' "${output_dir}"
printf 'Config bundled from %s\n' "${config_source}"
printf 'Place exactly one input file in %s/data/ before running.\n' "${output_dir}"
