# CalDAV Reminders CLI v1 specification

## Purpose

`reminders` is a Linux-only command-line client for managing reminders in a CalDAV VTODO collection. It gives people and software agents a narrow interface without exposing CalDAV requests, iCalendar serialization, or credentials.

The first supported deployment is Radicale at `dav.apps.andrebuilds.dev`, with the resulting VTODO records consumed by Apple Reminders. The protocol implementation must remain server-independent where CalDAV standards permit.

## Commands

```text
reminders auth set
reminders auth status
reminders auth remove
reminders auth keyring [auto|secret-service|file]

reminders add <title> [options]
reminders list [options]
reminders get <id>
reminders update <id> [options]
reminders complete <id>
reminders reopen <id>
reminders delete <id> [--force]
```

All data commands support `--json`. Mutating commands support `--dry-run`. Commands that might otherwise prompt support `--no-input`.

## Configuration and credentials

Non-secret configuration follows the XDG base directory specification and defaults to `~/.config/reminders/config.toml`.

```toml
server_url = "https://dav.example.com"
collection_path = "/username/tasks/"
username = "username"
keyring_backend = "auto"
```

The CalDAV password must never appear in the configuration file, process arguments, logs, JSON output, or errors. Configuration parse failures must not include the parser's own message or any excerpt of the file, because the most likely reason for a malformed line is a password typed into it by hand; they report the path and a generic category only.

Configuration and credential files are written atomically and durably: a temporary file in the same directory, created `0600` before it holds anything, flushed and synced, then renamed over the destination. A failed write leaves the previous file untouched and no temporary file behind.

`auth set` keeps the configuration and the credential store in step. It validates everything before it writes, snapshots both sides, writes the credential, writes the configuration, and only then retires the credential the previous settings pointed at. If any step fails, both sides are restored, so a failure can neither destroy a working pair nor leave a credential indexed under settings that were never saved.

Supported credential backends:

- `secret-service`: Linux Secret Service over the user D-Bus session.
- `file`: an encrypted file keyring for headless systems. Interactive commands may prompt for its passphrase. Non-interactive commands read `REMINDERS_KEYRING_PASSWORD`.
- `auto`: use Secret Service when available and unlocked, otherwise use the file backend. The selected backend is recorded when credentials are stored so later reads do not silently switch stores.

`auth set` prompts for missing connection settings and the CalDAV password. `auth status` reports configuration, selected backend, and whether a credential is readable without printing it. Switching backend requires storing the credential again.

## Reminder model

| CLI concept | iCalendar representation |
|---|---|
| ID | `UID` and resource filename |
| Title | `SUMMARY` |
| Notes | `DESCRIPTION` |
| Date-only due date | `DUE;VALUE=DATE` |
| Timed due date | UTC `DUE` date-time |
| Notification | `VALARM` with an absolute UTC trigger |
| Priority none | absent or `PRIORITY:0` |
| Priority high | `PRIORITY:1` |
| Priority medium | `PRIORITY:5` |
| Priority low | `PRIORITY:9` |
| Open | `STATUS:NEEDS-ACTION` |
| Complete | `STATUS:COMPLETED` and UTC `COMPLETED` |

Text values follow RFC 5545 escaping and line folding rules. Date-time input must include an offset or IANA time zone. The server receives UTC values.

`--at <RFC3339>` is shorthand for a timed due date and notification at the same instant. Advanced callers can set `--due <DATE|RFC3339>` and `--remind-at <RFC3339>` independently. A date-only due date does not imply a notification time.

The CLI warns when a notification is less than one hour away because Apple Reminders may not refresh generic CalDAV accounts in time. `--no-input` does not turn this warning into an error.

## CalDAV behavior

- The CLI targets one configured, existing VTODO collection. Collection management is out of scope.
- New resources use UUID v4 values for both UID and filename.
- Reads use CalDAV `REPORT` or WebDAV `PROPFIND` as appropriate.
- A `multistatus` response is read at `propstat` granularity. One `response` element may carry several `propstat` groups, each with its own status; a `404` group naming properties the server could not return must not discard calendar data or an ETag returned in a `200` group.
- Calendar data that does not end with `END:VCALENDAR` is rejected as truncated rather than parsed as far as it goes, because a partial parse would drop properties on the next write.
- Every change to an existing resource is conditional. Updates, completion changes, and deletes send the ETag read moments earlier with `If-Match`, and there is no way to ask for an unconditional write.
- A resource the server returns without an ETag therefore cannot be changed at all. The CLI reports this as a server limitation and makes no request, rather than falling back to an unconditional write that could silently discard an edit made elsewhere. An ETag returned inside a failed `propstat` does not count.
- Deletes require `--force` in non-interactive mode, and like every other change they require an ETag.
- HTTP `412 Precondition Failed` is reported as a conflict. The CLI never retries by overwriting newer server state.
- Every request stays on the configured origin, meaning the same scheme, host, and port. A redirect that leaves it is refused rather than followed with credentials withheld, because the request line, the headers, and any iCalendar body would otherwise still reach a host the server chose. There is no state in which credentials can be restored after leaving the origin. Same-origin redirects are followed normally, up to five hops.
- Server-supplied `href` values are resolved against the configured collection and refused if they leave the origin.
- TLS certificate validation is mandatory. There is no insecure mode.

## Output and agent safety

Human-readable output is concise. JSON output uses stable field names and writes only JSON to stdout. Diagnostics go to stderr.

Errors never quote a response body. The CLI authenticates with HTTP Basic, so a hostile or misconfigured server can echo the credentials it was just sent back in an error page, and anything copied from that body could carry the password. Failures report only values the server cannot choose freely: the numeric status, its IANA-registered reason phrase, the size of the body, and the percent-encoded path that was requested. iCalendar and XML parse failures follow the same rule and report a category and an offset rather than a fragment of the document.

Values that arrive from the server are data, not instructions. Before any string the server controls, such as a title, notes, an id, or a resource path, is written to a terminal, C0, C1, DEL, ANSI escape, and bidirectional override characters are escaped so they are visible rather than active, and over-long values are truncated. Newlines in notes survive as layout because the continuation lines are indented; every other control character is escaped. JSON output is not sanitized: JSON string escaping already neutralises control characters for a parser, and machine consumers receive the original value unchanged.

Reminder JSON includes:

```json
{
  "id": "uuid",
  "title": "Submit report",
  "notes": "Attach receipts",
  "due": "2026-08-22T16:00:00+04:00",
  "remind_at": "2026-08-22T16:00:00+04:00",
  "priority": "high",
  "status": "open",
  "etag": "opaque-server-value"
}
```

`--dry-run` validates input and prints the intended operation without reading credentials or contacting the server. It must not print authorization material.

## Out of scope

- Google Tasks or any synchronization service
- Background polling or a daemon
- Multiple accounts or profiles
- Recurrence, subtasks, tags, attachments, and locations
- Creating, renaming, sharing, or deleting collections
- macOS, Windows, iOS, or Android binaries

## Distribution

- Language: Rust, stable toolchain
- License: MIT
- Binary: `reminders`
- Repository: `caldav-reminders-cli`
- Release targets: `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu`
- Distribution: GitHub Releases, cargo-dist shell installer, and Homebrew formula
- GitHub Actions must pin third-party actions to commit SHAs.
- Release tooling downloaded during CI must be verified against a pinned checksum before it is executed. Piping a remotely fetched script into a shell is not acceptable.
- The release workflow's token is read-only by default. Only the job that uploads artifacts and creates the GitHub Release may hold `contents: write`, and jobs that never call the GitHub API receive no token at all.
- cargo-dist generates the release workflow and cannot express the two rules above, so a documented, idempotent post-generation patch applies them and CI fails if either the generated half or the patched half has drifted.

## Verification

Automated tests cover:

- Argument and date-time validation
- RFC 5545 escaping, folding, parsing, and priority mapping
- XML parsing
- HTTP authentication, refusal of cross-origin redirects, ETags, conflicts, and error redaction, including that a server reflecting the password in a response body cannot get it into an error
- Escaping of server-controlled strings in terminal output, and preservation of the original values in JSON
- Credential backend selection and locked/unavailable stores
- Rejection of a mutation when the fetched resource carries no usable ETag
- Mixed `200`/`404` propstat responses
- Rejection of calendar data with no `END:VCALENDAR`
- Atomic write behaviour, including that an injected write failure preserves the previous configuration and credential

Additional integration verification:

- Optional full CRUD and stale-ETag verification against a configured Radicale instance through `tests/live_caldav.rs`
- The Secret Service backend against an isolated `dbus-run-session` and gnome-keyring, driven by `scripts/integration/secret-service.sh`, because the hermetic suite deliberately pins the file backend and so never executes the D-Bus path

Manual Apple acceptance covers:

- Title, notes, date-only due date, timed due date, and priority display
- Notification at the exact due time
- Completion round trip
- The documented limitation that Apple background CalDAV refresh has no delivery guarantee

## Acceptance criteria

1. A fresh Linux installation can configure credentials and create a reminder without raw CalDAV knowledge.
2. The created reminder appears in Apple Reminders with title, notes, date/time, priority, and notification semantics intact.
3. List, get, update, complete, reopen, and delete preserve unknown iCalendar properties where practical.
4. Concurrent Apple edits produce a conflict instead of silent data loss, and a server that cannot supply ETags is refused rather than written to unconditionally.
5. No command exposes the CalDAV password, including when the server reflects it in a response body.
6. No server-controlled string can emit an active terminal control sequence in human-readable output.
7. Both Linux release architectures pass tests and produce installable artifacts.
