#!/usr/bin/env bash
#
# Install the `dist` binary (cargo-dist) after verifying it against a pinned
# SHA-256 digest.
#
# The upstream instruction is `curl ... cargo-dist-installer.sh | sh`, which
# executes a remotely fetched script with no integrity check. Every release job
# runs with a GitHub token in the environment, so a swapped release asset would
# execute with that token. Instead this script downloads the platform archive
# for one pinned version, verifies its digest, and unpacks only the binary.
#
# To move to a new cargo-dist version:
#   1. Set CARGO_DIST_VERSION below to match `cargo-dist-version` in
#      dist-workspace.toml.
#   2. Refresh the digests from the release's own `sha256.sum` asset:
#        curl -sSL https://github.com/axodotdev/cargo-dist/releases/download/v<VERSION>/sha256.sum
#   3. Run `dist generate && scripts/harden-release-workflow.py`.
#
# The platform is detected from `uname`, because this installs a tool that runs
# on the host, not a build artefact for a target. Only Linux aarch64 and x86_64
# are handled, which is what this project releases for; anything else is a hard
# error rather than a silent fallback.
#
# Usage: scripts/install-dist.sh [install-dir]
#   install-dir defaults to $CARGO_HOME/bin, else ~/.cargo/bin.

set -euo pipefail

# Keep in sync with `cargo-dist-version` in dist-workspace.toml.
CARGO_DIST_VERSION="0.32.0"

# From https://github.com/axodotdev/cargo-dist/releases/download/v0.32.0/sha256.sum
SHA256_aarch64_unknown_linux_gnu="d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a"
SHA256_x86_64_unknown_linux_gnu="eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946"

main() {
  local install_dir target expected archive workdir
  install_dir="${1:-${CARGO_HOME:-$HOME/.cargo}/bin}"

  case "$(uname -s)/$(uname -m)" in
    Linux/aarch64 | Linux/arm64)
      target="aarch64-unknown-linux-gnu"
      expected="$SHA256_aarch64_unknown_linux_gnu"
      ;;
    Linux/x86_64 | Linux/amd64)
      target="x86_64-unknown-linux-gnu"
      expected="$SHA256_x86_64_unknown_linux_gnu"
      ;;
    *)
      echo "install-dist: unsupported platform $(uname -s)/$(uname -m);" \
        "this project only releases Linux aarch64 and x86_64" >&2
      exit 1
      ;;
  esac

  archive="cargo-dist-${target}.tar.xz"
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand workdir now, while it is still set
  trap "rm -rf '$workdir'" EXIT

  echo "install-dist: fetching cargo-dist ${CARGO_DIST_VERSION} for ${target}"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-connrefused \
    "https://github.com/axodotdev/cargo-dist/releases/download/v${CARGO_DIST_VERSION}/${archive}" \
    -o "${workdir}/${archive}"

  echo "${expected}  ${workdir}/${archive}" >"${workdir}/expected.sha256"
  if ! sha256sum --check --status "${workdir}/expected.sha256"; then
    echo "install-dist: digest mismatch for ${archive}" >&2
    echo "install-dist:   expected ${expected}" >&2
    echo "install-dist:   actual   $(sha256sum "${workdir}/${archive}" | cut -d' ' -f1)" >&2
    echo "install-dist: refusing to run an unverified binary" >&2
    exit 1
  fi
  echo "install-dist: digest verified (${expected})"

  tar --extract --xz --file "${workdir}/${archive}" --directory "${workdir}" \
    "cargo-dist-${target}/dist"
  mkdir -p "${install_dir}"
  install -m 0755 "${workdir}/cargo-dist-${target}/dist" "${install_dir}/dist"

  # Release jobs invoke a bare `dist`, so make sure the directory is on PATH.
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${install_dir}" >>"${GITHUB_PATH}"
  fi
  export PATH="${install_dir}:${PATH}"
  echo "install-dist: installed $("${install_dir}/dist" --version)"
}

main "$@"
