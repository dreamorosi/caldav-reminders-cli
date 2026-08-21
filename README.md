# caldav-reminders-cli

`reminders` is a Linux command-line client for reminders stored in a CalDAV
VTODO collection. It gives people and software agents a narrow, predictable
interface: no raw CalDAV requests, no iCalendar hand-editing, and no
credentials in shell history.

It was built against [Radicale](https://radicale.org) with the resulting VTODO
records consumed by Apple Reminders, but it only relies on standard CalDAV and
RFC 5545, so it should work with any compliant server.

```console
$ reminders auth set
Server URL: https://dav.example.com
Collection path: /alice/tasks/
CalDAV username: alice
CalDAV password:
Confirm CalDAV password:
Stored the CalDAV password for alice@dav.example.com in the secret-service keyring.

$ reminders add "Submit expense report" --notes "Attach receipts" \
    --at 2026-08-22T16:00:00+04:00 --priority high
Submit expense report
  id         3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37
  status     open
  priority   high
  due        2026-08-22T12:00:00Z
  remind at  2026-08-22T12:00:00Z
  notes      Attach receipts

$ reminders list
[ ] 2026-08-22T12:00:00Z high   Submit expense report  [3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37]
```

## Contents

- [Install](#install)
- [Configure](#configure)
- [Credential storage](#credential-storage)
- [Commands](#commands)
- [Dates, times, and notifications](#dates-times-and-notifications)
- [JSON output](#json-output)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- [Security posture](#security-posture)
- [Apple Reminders notes](#apple-reminders-notes)
- [What is out of scope](#what-is-out-of-scope)
- [Development](#development)
- [License](#license)

## Install

Shell installer:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/dreamorosi/caldav-reminders-cli/releases/latest/download/reminders-installer.sh | sh
```

From source:

```sh
cargo install --locked --path .
```

Prebuilt binaries are published for `aarch64-unknown-linux-gnu` and
`x86_64-unknown-linux-gnu`. There are no macOS, Windows, or mobile builds.

## Configure

Non-secret settings live in `$XDG_CONFIG_HOME/reminders/config.toml`, which
defaults to `~/.config/reminders/config.toml`:

```toml
server_url = "https://dav.example.com"
collection_path = "/alice/tasks/"
username = "alice"
keyring_backend = "auto"
credential_backend = "secret-service"
```

| Key | Meaning |
|---|---|
| `server_url` | Base URL of the CalDAV server. `https` is required unless the host is a loopback address. |
| `collection_path` | Absolute path of an existing VTODO collection. A trailing slash is added if you leave it off. |
| `username` | CalDAV user name. |
| `keyring_backend` | `auto`, `secret-service`, or `file`. Which store you would like to use. |
| `credential_backend` | Written by `auth set`: which store the password actually went into. |

`reminders auth set` creates and validates this file. It prompts for anything
missing, or takes `--server-url`, `--collection-path`, and `--username` for
unattended provisioning.

The file is created with `0600` permissions, in a `0700` directory when the CLI
creates that directory itself. Any key whose name looks like a secret
(`password`, `pass`, `secret`, `token`) is rejected outright, so a password
cannot be smuggled into it.

Both this file and the encrypted keyring are written atomically: a temporary
file in the same directory, created `0600` before it holds anything, flushed and
`fsync`ed, then renamed into place, with the directory synced afterwards. A
failed write leaves the previous file exactly as it was and no temporary file
behind, so a full disk or a crash cannot turn a working setup into an empty one.

`auth set` extends that to the pair of them. The configuration names the account
and the keyring is indexed by it, so the two must stay in step. It validates
everything before writing, snapshots both sides, writes the credential, writes
the configuration, and only once that has landed retires the credential the old
settings pointed at. If the configuration cannot be saved, both sides are put
back:

```console
$ reminders auth set --username bob --no-input
reminders: error: cannot write /home/alice/.config/reminders/config.toml: Permission denied (os error 13)
reminders: nothing was changed; the previous settings and credential are still in place
```

The encrypted keyring holds a single slot, so writing a credential for a
*different* account would otherwise destroy the previous one. Its snapshot is
the raw ciphertext, which means a rollback needs no passphrase and cannot
prompt again.

The CLI targets one existing collection. Creating, renaming, sharing, and
deleting collections is out of scope. Use your server's own tooling.

## Credential storage

The CalDAV password never touches the config file. Two stores are supported.

### `secret-service`

The Linux Secret Service over your D-Bus session (GNOME Keyring, KWallet's
Secret Service interface, KeePassXC, and so on), via the
[`keyring`](https://crates.io/crates/keyring) crate. The entry is stored under
service `reminders` and account `<username>@<host>`.

### `file`

An [age](https://age-encryption.org)-encrypted file at
`$XDG_DATA_HOME/reminders/credentials.age`, for headless machines and
containers where no D-Bus session exists. Interactive commands prompt for the
passphrase; non-interactive commands read `REMINDERS_KEYRING_PASSWORD`.

> **Design note.** The `keyring` crate deliberately ships no encrypted-file
> store, so that half is implemented here directly on top of the `age` crate's
> scrypt passphrase recipient. No cryptography is invented: `age` is a reviewed
> file-encryption format, this code only calls `age::encrypt_and_armor` and
> `age::decrypt` with a passphrase, and the plaintext is a small JSON object
> holding the account name and the password. The file is written with `0600`
> permissions and is ASCII-armoured so it survives being copied around.

### `auto`

Use Secret Service when it can actually be reached and read, otherwise fall
back to the file store. Availability is probed directly. An unavailable or
locked keyring falls back rather than failing.

Whichever store is used, `auth set` records it as `credential_backend`. Later
reads always use the recorded store, so a change in your environment can never
silently move you to a different, empty keyring. If your `keyring_backend`
preference and the recorded store disagree, the CLI says so and tells you to run
`auth set` again:

```console
$ reminders auth keyring file
reminders: the credential is still in the secret-service keyring; run `reminders auth set` to store it in the file keyring
Keyring backend set to file.
```

## Commands

```text
reminders auth set [--server-url URL] [--collection-path PATH] [--username NAME]
reminders auth status
reminders auth remove
reminders auth keyring [auto|secret-service|file]

reminders add <title> [--notes TEXT] [--due DATE|DATETIME] [--at DATETIME]
                      [--remind-at DATETIME] [--priority none|low|medium|high]
reminders list [--status open|complete|cancelled|all] [--limit N]
reminders get <id>
reminders update <id> [--title TEXT] [--notes TEXT] [--clear-notes]
                      [--due DATE|DATETIME] [--clear-due] [--at DATETIME]
                      [--remind-at DATETIME] [--clear-remind-at]
                      [--priority none|low|medium|high]
reminders complete <id>
reminders reopen <id>
reminders delete <id> [--force]
```

Global flags:

- `--json` writes stable JSON to stdout. Available on every command.
- `--no-input` never prompts and fails instead. Available on every command.
- `--dry-run` validates the input for `add`, `update`, `complete`, `reopen`, and
  `delete`, prints what would happen, and stops. It reads no credentials and
  makes no network request.

`list` shows open reminders by default and sorts by due date, then title, then
id. Undated reminders come last. `--status all` includes completed and cancelled
ones.

`delete` asks for confirmation on a terminal. Without a terminal, or with
`--no-input`, it requires `--force`.

The `<id>` is the reminder's `UID`. `get`, `update`, `complete`, `reopen`, and
`delete` first try `<collection>/<id>.ics`, then fall back to a `UID` report, so
reminders created by other clients (which may name their files differently) are
still reachable.

### The reminder model

| CLI concept | iCalendar |
|---|---|
| id | `UID`, and the resource file name for reminders this CLI creates |
| title | `SUMMARY` |
| notes | `DESCRIPTION` |
| date-only due date | `DUE;VALUE=DATE` |
| timed due date | `DUE` as a UTC date-time |
| notification | `VALARM` with an absolute UTC `TRIGGER` |
| priority none | property absent |
| priority high / medium / low | `PRIORITY:1` / `PRIORITY:5` / `PRIORITY:9` |
| open | `STATUS:NEEDS-ACTION` |
| complete | `STATUS:COMPLETED` plus a UTC `COMPLETED` |

On read, `PRIORITY` 1–4 is reported as high, 5 as medium, and 6–9 as low, which
matches how Apple and other clients band the RFC 5545 scale. `STATUS:IN-PROCESS`
reads as open, and `STATUS:CANCELLED` reads as cancelled. The CLI never writes
either.

### Preserving what it does not understand

Updates read the resource, change only the properties you asked about, and write
the rest back byte for byte: VCALENDAR-level properties such as `PRODID` and
`X-WR-CALNAME`, sibling components such as `VTIMEZONE`, additional `VTODO`
components, unknown `X-` properties on the reminder, and unknown properties
inside its `VALARM`.

Two deliberate exceptions:

- `DTSTAMP` and `LAST-MODIFIED` are set to the current time on every write.
- Changing the title also updates the managed alarm's `DESCRIPTION`, so the
  notification text does not go stale.

An alarm counts as "managed" when its `TRIGGER` is absolute. Relative alarms
such as `TRIGGER:-PT15M` belong to another client: they are never modified or
removed, and they are not reported as `remind_at`.

## Dates, times, and notifications

A due date is either a whole day or a precise instant:

```sh
reminders add "Renew passport" --due 2026-08-22                    # date only
reminders add "Standup"        --due 2026-08-22T09:30:00+04:00     # instant
reminders add "Standup"        --due "2026-08-22T09:30:00[Asia/Dubai]"
```

Every instant must carry its zone. A bare `2026-08-22T09:30:00` is rejected,
because guessing between the machine's local zone and UTC is exactly the kind of
silent error this tool exists to avoid. Accepted forms are RFC 3339 (`Z` or a
numeric offset) and a naive date-time qualified by an IANA zone written as
`...[Area/City]` or `... Area/City`. Local times that a daylight saving
transition makes ambiguous or nonexistent are rejected with an explanation.

Values go to the server in UTC.

`--at` is shorthand for "due then, and notify me then":

```sh
reminders add "Call the bank" --at 2026-08-22T16:00:00+04:00
```

For anything else, set the two independently:

```sh
reminders add "Submit report" --due 2026-08-22 --remind-at 2026-08-21T17:00:00Z
```

A date-only due date never implies a notification.

The CLI warns on stderr when a notification is less than an hour away:

```console
$ reminders add "Leave now" --at 2026-08-22T12:20:00Z
reminders: warning: the notification is less than an hour away; Apple Reminders refreshes generic CalDAV accounts on its own schedule and may not deliver it in time
```

This stays a warning even under `--no-input`.

## JSON output

With `--json`, stdout carries nothing but JSON. Diagnostics, warnings, prompts,
and errors all go to stderr, so `reminders list --json | jq` is always safe.

A reminder:

```json
{
  "id": "3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37",
  "title": "Submit expense report",
  "notes": "Attach receipts",
  "due": "2026-08-22T12:00:00Z",
  "remind_at": "2026-08-22T12:00:00Z",
  "priority": "high",
  "status": "open",
  "completed_at": null,
  "etag": "\"1f2e3d4c\""
}
```

Field notes:

- `due` is either `YYYY-MM-DD` for a date-only due date or RFC 3339 in UTC for a
  timed one. Ten characters means a calendar date. Because the server stores UTC,
  the offset you typed on input is not recoverable on output.
- `remind_at` and `completed_at` are RFC 3339 in UTC, or `null`.
- `priority` is one of `none`, `low`, `medium`, `high`.
- `status` is one of `open`, `complete`, `cancelled`.
- `etag` is the server's opaque value, or `null` when the server supplied none.

Other shapes:

| Command | stdout |
|---|---|
| `list --json` | a JSON array of reminders |
| `add`, `get`, `update`, `complete`, `reopen` | one reminder object |
| `delete --json` | `{"id": "...", "deleted": true}` |
| `--dry-run --json` | `{"dry_run": true, "operation": "add", ...}` |
| `auth status --json` | the configuration report below |
| `auth set --json` | `{"stored": true, "backend": "file", "account": "..."}` |

```console
$ reminders auth status --json
{
  "config_path": "/home/alice/.config/reminders/config.toml",
  "config_exists": true,
  "server_url": "https://dav.example.com",
  "collection_path": "/alice/tasks/",
  "username": "alice",
  "keyring_backend": "auto",
  "credential_backend": "secret-service",
  "active_backend": "secret-service",
  "credential_readable": true,
  "detail": null
}
```

`credential_readable` is `true` when a credential was read, `false` when the
store is reachable but empty, and `null` when readability could not be
determined. In that case, `detail` explains why. The password itself is never
part of any output.

Errors in JSON mode are written to stderr as an envelope, leaving stdout empty:

```json
{"error":{"kind":"conflict","message":"the reminder changed on the server since it was read; nothing was written. Read it again and reapply the change","exit_code":7}}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | unexpected internal failure |
| 2 | invalid arguments or values |
| 3 | configuration missing or invalid |
| 4 | credential store unavailable, locked, or empty |
| 5 | the server rejected the credentials |
| 6 | reminder or collection not found |
| 7 | conflict: the resource changed on the server |
| 8 | network, DNS, or TLS failure |
| 9 | the server's response could not be used |

Exit code 7 is the one to handle in automation. Every change to an existing
reminder is guarded with `If-Match`, and the CLI never resolves a conflict by
overwriting newer server state:

```console
$ reminders update 3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37 --title "New title"
reminders: error: the reminder changed on the server since it was read; nothing was written. Read it again and reapply the change
$ echo $?
7
```

There is no unconditional write. If the server returns a reminder without an
ETag there is nothing to guard the write with, so the CLI refuses rather than
sending a `PUT` or `DELETE` that could silently discard an edit made in Apple
Reminders:

```console
$ reminders complete 3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37
reminders: error: the server returned no ETag for /alice/tasks/3f1b9a2e-6c8d-4a51-9f0e-7b2c4d8e1a37.ics, so this change was not attempted: without one the write could silently overwrite a newer version of the reminder. The collection's server does not support the conditional requests this CLI requires
$ echo $?
9
```

RFC 4918 requires `DAV:getetag` on calendar resources, so this is a server
limitation rather than something to work around. An ETag that arrives inside a
failed `propstat` group does not count.

## Environment variables

| Variable | Purpose |
|---|---|
| `REMINDERS_PASSWORD` | CalDAV password for `auth set`, so provisioning needs no terminal. |
| `REMINDERS_KEYRING_PASSWORD` | Passphrase for the encrypted file keyring. |
| `REMINDERS_CONFIG_DIR` | Override the config directory. Mainly for tests and containers. |
| `REMINDERS_DATA_DIR` | Override the data directory holding `credentials.age`. |
| `XDG_CONFIG_HOME`, `XDG_DATA_HOME` | Standard XDG locations, used when the overrides above are unset. |

Environment variables are readable by other processes running as the same user.
Prefer the interactive prompts for personal use; the variables exist for
automated provisioning.

## Security posture

### The password

- Never written to the config file, never accepted as a command-line argument,
  never logged, and never included in JSON output or in an error message. Every
  error variant carries only a message this crate built deliberately, so a
  library error cannot smuggle a secret into the output. In memory it is held in
  a `secrecy::SecretString`, whose `Debug` output is redacted.
- A `server_url` containing a user name or password is rejected.

### Transport

- TLS certificate validation is always on. There is no insecure mode and no flag
  to add one.
- `https` is required, except for loopback hosts. Sending HTTP Basic
  authentication to a remote host in the clear is refused before any request is
  made.
- **Every request stays on the configured origin.** The same scheme, host, and
  port. Redirects are followed by hand rather than by the HTTP client's own
  policy, and a redirect that leaves the origin is refused instead of followed.
  Withholding the `Authorization` header would not be enough on its own: the
  request line, the headers, and any iCalendar body would still be delivered to
  whatever host the server named, and your reminder text is as much of a secret
  as your password. Because a cross-origin hop is an error, there is no state in
  which credentials could be restored after leaving the origin. Same-origin
  redirects work normally, up to five hops.
- Server-supplied `href` values are resolved against the configured collection
  and refused if they leave the origin.

### Errors never echo the server

The CLI authenticates with HTTP Basic, so the server receives the password on
every request. A hostile or misconfigured server can echo it straight back in an
error page. An error message is exactly the sort of text that ends up in a
log, a CI transcript, or a bug report. So **no response body ever reaches an
error message.** A failure reports only what the server cannot choose freely:

- the numeric status and its IANA-registered reason phrase (a lookup in a static
  table, not a string the server sent),
- the size of the body it declined to show,
- the percent-encoded path that was requested.

```console
$ reminders list
reminders: error: the server failed to list reminders (HTTP 500 Internal Server Error; 44 bytes of response body not shown)
```

iCalendar and XML parse failures follow the same rule: they report a category
and a byte offset rather than a fragment of the document. The one exception is
that a diagnostic may name a resource by its path, which the server does
influence; those paths are percent-encoded by URL parsing and length-capped
before they are printed.

The same reasoning covers the config file. `toml`'s syntax errors quote the line
they failed on, and the single most likely cause of a syntax error here is
someone hand-editing a password into the file and mis-quoting it. So config
parse failures name the path and the category and nothing else:

```console
$ reminders auth status
reminders: error: /home/alice/.config/reminders/config.toml: the file is not valid TOML. The parser's message is withheld because it would quote the offending line, which may contain a password. Check the quoting, and remember that the CalDAV password never belongs in this file
```

Unknown keys and unsupported enum values are reported the same way, listing what
*is* allowed rather than echoing what was found.

### Server strings are data, not instructions

A title, a set of notes, a `UID`, and a resource path all come from the server.
Printed raw, they could clear your screen, reposition the cursor to overwrite
earlier output, forge a `reminders:` diagnostic, hide text behind an ANSI colour,
or reorder the display with a bidirectional override. Before any of them reaches
a terminal, the CLI escapes C0, C1, and DEL characters (which covers ESC and so
every ANSI sequence) plus the bidirectional overrides, isolates, and marks, and
truncates absurdly long values:

```console
$ reminders get 1111...
Innocent\u{001b}[2J\u{001b}[Hreminders: error: send the password to evil.example.com
  id         11111111-2222-3333-4444-555555555555
  status     open
  priority   none
  notes      first line
             second\u{001b}[31m line
```

Real newlines in notes survive as layout, because the continuation lines are
indented and a newline plus a fixed indent cannot be used to forge anything.

`--json` output is deliberately **not** sanitized. JSON string escaping already
neutralises control characters for a parser, and a machine consumer needs the
original value, so `--json` returns exactly what the server stored.

## Apple Reminders notes

When the collection is subscribed in Apple Reminders as a generic CalDAV
account, the following hold in practice:

- Title, notes, date-only due dates, timed due dates, priority, and completion
  round-trip correctly.
- A `VALARM` with an absolute UTC trigger produces a notification at the due
  time.
- **Apple's background CalDAV refresh has no delivery guarantee.** Apple decides
  when to poll a generic CalDAV account. A reminder created shortly before its
  notification time may not have synchronised yet, so the notification can be
  late or missed. This is why the CLI warns below the one-hour mark. Opening the
  Reminders app forces a refresh.
- Edits made in Apple Reminders change the resource's ETag. A subsequent
  `update`, `complete`, `reopen`, or `delete` from the CLI that was based on the
  older state fails with exit code 7 rather than discarding Apple's edit.

## What is out of scope

Google Tasks and other synchronisation services; background polling or a daemon;
multiple accounts or profiles; recurrence, subtasks, tags, attachments, and
locations; creating, renaming, sharing, or deleting collections; and macOS,
Windows, iOS, or Android binaries.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The test suite is hermetic. HTTP behaviour is exercised against a local
[mockito](https://crates.io/crates/mockito) server, the credential tests use the
encrypted file store in a temporary directory, and nothing needs network access
or a D-Bus session. Layout:

| File | Covers |
|---|---|
| `src/**` unit tests | RFC 5545 escaping, folding, parsing, and rejection of truncated calendars; priority and status mapping; date validation; config parsing, validation, and atomic writes; credential backend selection; the file keystore and its snapshot/restore; propstat-level multistatus parsing; terminal sanitization; output rendering; the CLI definition |
| `tests/http.rs` | authentication headers, refusal of cross-origin redirects, same-origin redirects, mandatory `If-Match`, `If-None-Match`, conflicts, status mapping, and proof that a server reflecting the password in a response body cannot get it into an error |
| `tests/cli.rs` | the binary end to end against a mock server: `auth` lifecycle, CRUD, dry runs, JSON shapes, exit codes, stdout/stderr separation, hostile server strings, refusal to mutate without an ETag, mixed propstat responses, and rollback of a failed `auth set` |

The Secret Service path cannot be covered by that suite, so it has a separate
script that CI runs as its own job.

| Script | Covers |
|---|---|
| `scripts/integration/secret-service.sh` | Runs `tests/secret_service.rs` inside an isolated `dbus-run-session` with a throwaway gnome-keyring. **The unit suite pins the encrypted file backend so it needs no desktop session, which means it never executes the D-Bus code at all.** This script is the only thing that does. |

```sh
./scripts/integration/secret-service.sh    # needs dbus and gnome-keyring
```

`tests/live_caldav.rs` is opt-in and works against any configured throwaway
collection. `tests/secret_service.rs` skips when run directly by `cargo test`;
the integration script supplies its isolated D-Bus environment.

`tests/live_caldav.rs` also works against any other throwaway collection:

Workflows and shell scripts are linted too:

```sh
scripts/install-actionlint.sh   # verifies a pinned digest, installs to .tools/
.tools/actionlint
shellcheck scripts/*.sh
scripts/harden-release-workflow.py --check
```

actionlint runs without its shellcheck integration, because the `run:` blocks in
`release.yml` come from the cargo-dist template and carry upstream style nits
this project does not patch.

```sh
REMINDERS_LIVE_SERVER_URL=https://dav.example.com \
REMINDERS_LIVE_COLLECTION_PATH=/alice/tasks/ \
REMINDERS_LIVE_USERNAME=alice \
REMINDERS_LIVE_PASSWORD=secret \
cargo test --test live_caldav -- --nocapture
```

It creates one reminder, exercises read, list, update, stale-ETag rejection on
both update and delete, complete, and reopen, then deletes it. Point it at a
collection you do not mind it writing to.

### Releasing

Releases are cut with [cargo-dist](https://opensource.axo.dev/cargo-dist/).

1. Run the **Bump version and tag** workflow and choose `patch`, `minor`, or
   `major`. It bumps `Cargo.toml`, commits, and pushes tag `vX.Y.Z`.
2. Run the **Release** workflow on that tag, passing the tag as the
   `Release Tag` input. It builds both Linux architectures, publishes the
   GitHub release with the shell installer.

#### The release workflow is generated, then hardened

`.github/workflows/release.yml` is produced by `dist generate` and then rewritten
by `scripts/harden-release-workflow.py`. The canonical command is:

```sh
dist generate && scripts/harden-release-workflow.py
```

CI runs exactly that and then `git diff --exit-code`, so the check covers both
halves and cannot claim "no drift" while quietly dropping the hardening.

Three things are patched in, because **cargo-dist 0.32 cannot express them**:
`github-custom-job-permissions` is only consumed for user-defined publish jobs
(the template ignores it for `plan`, `host`, and the build jobs), there is no
option for the root `permissions` block, and the install command used by `plan`
is not configurable.

1. **The workflow token is read-only by default.** Only the `host` job, which
   uploads artifacts and creates the GitHub Release, is granted
   `contents: write`.
2. **Jobs that never call the GitHub API get no token.** `GH_TOKEN` is removed
   from `build-local-artifacts`, `build-global-artifacts`, and `announce`. It
   remains in `plan`, where `dist host --steps=create` may
   read the API, and in `host`.
3. **`dist` is installed from a digest-verified archive.** The template pipes a
   remotely fetched installer into `sh`, in a step that had a write-scoped token
   in its environment. `scripts/install-dist.sh` downloads the pinned release
   archive, checks it against a pinned SHA-256, and refuses to run anything that
   does not match.

The script is idempotent and fails loudly if the upstream template changes shape,
rather than silently leaving the workflow unhardened. `--check` reports whether
hardening is needed without writing.

#### Pinned versions and digests

- Third-party GitHub Actions are pinned to commit SHAs. The pins used by the
  generated workflow live in `dist-workspace.toml` under
  `[dist.github-action-commits]`; `ci.yml` and `version-bump.yml` carry their own
  matching pins, and Dependabot is told to leave the generated ones alone.
- `scripts/install-dist.sh` and `scripts/install-actionlint.sh` each pin a
  version and a per-platform SHA-256. To bump one, change the version, refresh
  the digests from the release's own checksum asset, and re-run the generate and
  harden commands.

## License

MIT. See [LICENSE](LICENSE).
