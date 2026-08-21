#!/usr/bin/env bash
#
# Install the `actionlint` binary after verifying it against a pinned SHA-256
# digest, using the same fail-closed pattern as scripts/install-dist.sh.
#
# To move to a new version: bump ACTIONLINT_VERSION and refresh the digests
# from the release's own checksum file:
#   curl -sSL https://github.com/rhysd/actionlint/releases/download/v<VERSION>/actionlint_<VERSION>_checksums.txt
#
# Usage: scripts/install-actionlint.sh [install-dir]
#   install-dir defaults to ./.tools

set -euo pipefail

ACTIONLINT_VERSION="1.7.7"

# From actionlint_1.7.7_checksums.txt
SHA256_arm64="401942f9c24ed71e4fe71b76c7d638f66d8633575c4016efd2977ce7c28317d0"
SHA256_amd64="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"

main() {
  local install_dir arch expected archive workdir
  install_dir="${1:-.tools}"

  case "$(uname -s)/$(uname -m)" in
    Linux/aarch64 | Linux/arm64)
      arch="arm64"
      expected="$SHA256_arm64"
      ;;
    Linux/x86_64 | Linux/amd64)
      arch="amd64"
      expected="$SHA256_amd64"
      ;;
    *)
      echo "install-actionlint: unsupported platform $(uname -s)/$(uname -m)" >&2
      exit 1
      ;;
  esac

  archive="actionlint_${ACTIONLINT_VERSION}_linux_${arch}.tar.gz"
  workdir="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand workdir now, while it is still set
  trap "rm -rf '$workdir'" EXIT

  echo "install-actionlint: fetching actionlint ${ACTIONLINT_VERSION} for linux/${arch}"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-connrefused \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${archive}" \
    -o "${workdir}/${archive}"

  echo "${expected}  ${workdir}/${archive}" >"${workdir}/expected.sha256"
  if ! sha256sum --check --status "${workdir}/expected.sha256"; then
    echo "install-actionlint: digest mismatch for ${archive}" >&2
    echo "install-actionlint:   expected ${expected}" >&2
    echo "install-actionlint:   actual   $(sha256sum "${workdir}/${archive}" | cut -d' ' -f1)" >&2
    exit 1
  fi
  echo "install-actionlint: digest verified (${expected})"

  tar --extract --gzip --file "${workdir}/${archive}" --directory "${workdir}" actionlint
  mkdir -p "${install_dir}"
  install -m 0755 "${workdir}/actionlint" "${install_dir}/actionlint"
  echo "install-actionlint: installed ${install_dir}/actionlint"
}

main "$@"
