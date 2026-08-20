#!/usr/bin/env bash
set -euo pipefail

# Build and extract the statically linked x86_64 binary for RHEL 7 hosts.
#
#   package_rhel7.sh [output_dir] [config ...]
#
# Every argument after the output directory is a config to ship in the bundle —
# a .json file, or a directory whose .json files are all copied. Shipping more
# than one is the point: the binary picks its config at run time (--config), so
# one bundle covers every dataset the recipient anonymizes.
#
# With no config argument the repo's config/config.json is shipped as the
# default, which is what a bundle built before --config existed contained.
#
# The recipient still supplies their input under data/, or points --data at a
# file, or configures a postgres input in the config.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-${repo_root}/dist/skald-rhel7}"
shift || true
config_sources=("$@")
image_name="skald-rhel7-builder"

if [[ ${#config_sources[@]} -eq 0 ]]; then
  config_sources=("${repo_root}/config/config.json")
fi

for source in "${config_sources[@]}"; do
  if [[ ! -e "${source}" ]]; then
    printf 'Config not found: %s\n' "${source}" >&2
    exit 1
  fi
done

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

bundled_configs=()
for source in "${config_sources[@]}"; do
  if [[ -d "${source}" ]]; then
    while IFS= read -r -d '' file; do
      cp "${file}" "${output_dir}/config/"
      bundled_configs+=("$(basename "${file}")")
    done < <(find "${source}" -maxdepth 1 -name '*.json' -type f -print0)
  else
    cp "${source}" "${output_dir}/config/"
    bundled_configs+=("$(basename "${source}")")
  fi
done

# A wrapper so the bundle runs from anywhere: the pipeline resolves config/,
# data/ and output/ relative to its working directory, which is rarely where
# the operator happens to be standing.
cat > "${output_dir}/run.sh" <<'WRAPPER'
#!/bin/sh
# Runs the bundled pipeline with the bundle directory as the working directory,
# so the default config/, data/ and output/ resolve. All flags pass through:
#
#   ./run.sh                                    # first config in config/, one file in data/
#   ./run.sh --config config/telangana.json     # choose among the bundled configs
#   ./run.sh --config /etc/skald/live.json      # a config from outside the bundle
#   ./run.sh --data /mnt/export/patients.csv    # an input from outside the bundle
#   ./run.sh --output /var/skald/2026-08-20     # results somewhere else
#   ./run.sh --help                             # every flag
set -e
cd "$(dirname "$0")"
exec ./skald_pipeline "$@"
WRAPPER
chmod 0755 "${output_dir}/run.sh"

cat > "${output_dir}/README.txt" <<'BUNDLE_README'
SKALD — standalone anonymization pipeline
=========================================

One statically linked binary. No Python, no glibc version to match, nothing to
install: it runs on RHEL 7 as shipped.

  ./run.sh --help          every flag
  ./run.sh                 run with the bundled config and the file in data/

LAYOUT

  skald_pipeline   the binary
  run.sh           wrapper that runs it from this directory
  config/          the configs shipped with this bundle
  data/            put exactly one .csv, .json or .xlsx here
  output/          results, logs and key material land here

CHOOSING A CONFIG AND AN INPUT

The config is not fixed. With no flags the first *.json in config/ is used;
otherwise name one:

  ./run.sh --config config/telangana_ration.json
  ./run.sh --config /etc/skald/live.json --data /mnt/export/patients.csv
  ./run.sh --output /var/skald/runs/2026-08-20

The same paths can come from the environment instead, which suits cron and
systemd units:

  SKALD_CONFIG=/etc/skald/live.json SKALD_DATA=/mnt/export/patients.csv ./run.sh

A flag always wins over the environment variable of the same name.

READING FROM AND WRITING TO POSTGRESQL

Instead of a file in data/, a config can read its rows straight from a database
and load the anonymized result back into another table. Both are configured in
the config JSON — see the "input" and "output_sink" sections in the project
README. Credentials belong in the environment, not in the config file:

  "input":  { "type": "postgres", "dsn": "postgresql://skald@db.internal/health",
              "password_env": "SKALD_PG_PASSWORD", "sslmode": "verify-full",
              "table": "public.patients" },
  "output_sink": { "type": "postgres", "table": "anon.patients", "mode": "replace" }

  SKALD_PG_PASSWORD=… ./run.sh --config config/live.json

RESULTS

  output/status.json    machine-readable result; "status": "success" or "error",
                        with an error code, a suggested fix, and where the
                        output landed
  output/pipeline.log   full trace of the run
  output/*keys*.json    key material for reversing hashing/encryption/tokenization
                        — treat as secret, and back it up: without it the
                        anonymized output cannot be reversed by anyone

Exit code 0 means the run succeeded, 1 means it failed — read status.json.
BUNDLE_README

# If sudo was used, return the bundle to the invoking user.
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
  chown -R "${SUDO_UID}:${SUDO_GID}" "${output_dir}"
fi

printf 'RHEL 7 bundle created at %s\n' "${output_dir}"
printf 'Configs bundled: %s\n' "${bundled_configs[*]}"
printf 'Run it with:  cd %s && ./run.sh --help\n' "${output_dir}"
printf 'The config is chosen at run time (--config / SKALD_CONFIG), so one bundle covers every dataset.\n'
