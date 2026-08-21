#!/usr/bin/env bash
#
# Run the Secret Service integration test against an isolated keyring.
#
# The ordinary test suite pins the encrypted file backend so it needs no desktop
# session, which leaves the D-Bus code in `SecretServiceStore` unexecuted. This
# script fills that gap without going anywhere near the developer's real login
# keyring:
#
#   * a private D-Bus session bus, from `dbus-run-session`;
#   * a throwaway XDG_DATA_HOME, so gnome-keyring creates a fresh keyring rather
#     than opening an existing one;
#   * `gnome-keyring-daemon --unlock`, which registers the Secret Service on
#     that private bus only.
#
# Nothing survives the run: the temporary directory holds the whole keyring.
#
# Requires `dbus-run-session` (dbus-daemon) and `gnome-keyring-daemon`. On
# Debian and Ubuntu: apt-get install dbus gnome-keyring.
#
# Usage: scripts/integration/secret-service.sh [extra cargo test args...]

set -euo pipefail

# Not readonly: it is passed into the private session as an environment variable.
keyring_password="integration-keyring-password"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

missing=""
for tool in dbus-run-session gnome-keyring-daemon; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing="${missing} ${tool}"
  fi
done
if [ -n "$missing" ]; then
  echo "secret-service: missing required tools:${missing}" >&2
  echo "secret-service: on Debian/Ubuntu, apt-get install dbus gnome-keyring" >&2
  exit 1
fi

workdir="$(mktemp -d)"
cleanup() {
  local status=$?
  # The keyring, its data, and the bus socket all live in here.
  rm -rf "$workdir"
  return "$status"
}
trap cleanup EXIT

mkdir -p "${workdir}/data" "${workdir}/config" "${workdir}/run"
chmod 700 "${workdir}/run"

# Build first, outside the private session, so compiler output is not tangled up
# with the daemon's and a build failure is reported plainly.
echo "secret-service: building the test binary"
(cd "$repo_root" && cargo test --no-run --test secret_service >/dev/null)

echo "secret-service: starting an isolated session bus and keyring"
cd "$repo_root"
# The single-quoted body below is deliberately not expanded here: it runs inside
# the private session, where the environment set on the command is in scope.
# shellcheck disable=SC2016
XDG_DATA_HOME="${workdir}/data" \
  XDG_CONFIG_HOME="${workdir}/config" \
  XDG_RUNTIME_DIR="${workdir}/run" \
  KEYRING_PASSWORD="$keyring_password" \
  dbus-run-session -- bash -euo pipefail -c \
  '
    # --unlock reads the password from stdin and creates the keyring when there
    # is none, which is exactly the case in a fresh XDG_DATA_HOME.
    printf "%s" "$KEYRING_PASSWORD" |
      gnome-keyring-daemon --unlock --components=secrets >/dev/null

    # Fail loudly if the Secret Service did not actually appear, rather than
    # letting the tests skip and look green.
    if command -v gdbus >/dev/null 2>&1; then
      gdbus call --session --dest org.freedesktop.secrets \
        --object-path /org/freedesktop/secrets \
        --method org.freedesktop.DBus.Peer.Ping >/dev/null
    fi

    REMINDERS_TEST_SECRET_SERVICE=1 exec cargo test --test secret_service -- --nocapture "$@"
  ' bash "$@"
