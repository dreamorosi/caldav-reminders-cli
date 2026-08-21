//! Output rendering. JSON goes to stdout and nothing else does; every
//! diagnostic goes to stderr.

use std::fmt::Write as FmtWrite;
use std::io::Write as _;

use serde::Serialize;
use serde_json::json;

use crate::error::{Error, Result};
use crate::model::Reminder;

/// Renders command results in either human or JSON form.
#[derive(Debug, Clone, Copy)]
pub struct Printer {
    json: bool,
}

/// What `auth status` reports. Never contains the password.
#[derive(Debug, Clone, Serialize)]
pub struct AuthStatus {
    /// Where the config file lives, whether or not it exists.
    pub config_path: String,
    /// Whether that file exists.
    pub config_exists: bool,
    /// Configured server.
    pub server_url: Option<String>,
    /// Configured collection.
    pub collection_path: Option<String>,
    /// Configured user name.
    pub username: Option<String>,
    /// Preferred backend from the config file.
    pub keyring_backend: String,
    /// Backend recorded when the credential was last stored.
    pub credential_backend: Option<String>,
    /// Backend that reads will actually use.
    pub active_backend: Option<String>,
    /// Whether a credential could be read. `null` when it could not be checked.
    pub credential_readable: Option<bool>,
    /// Why the check failed, or extra context. Never contains secret material.
    pub detail: Option<String>,
}

impl Printer {
    /// Build a printer.
    pub fn new(json: bool) -> Printer {
        Printer { json }
    }

    /// Whether JSON mode is on.
    pub fn is_json(&self) -> bool {
        self.json
    }

    /// A diagnostic that is not an error.
    ///
    /// Sanitized as a backstop: diagnostics are built from this crate's own
    /// prose, but some of them quote a resource path that the server chose.
    pub fn note(&self, message: &str) {
        eprintln!("reminders: {}", sanitize_line(message));
    }

    /// A warning the user should see but that does not stop the command.
    pub fn warn(&self, message: &str) {
        eprintln!("reminders: warning: {}", sanitize_line(message));
    }

    /// Print one reminder.
    pub fn reminder(&self, reminder: &Reminder) -> Result<()> {
        if self.json {
            return self.emit(reminder);
        }
        self.write(&render_reminder(reminder))
    }

    /// Print a list of reminders.
    pub fn list(&self, reminders: &[Reminder]) -> Result<()> {
        if self.json {
            return self.emit(&reminders);
        }
        if reminders.is_empty() {
            return self.line("No matching reminders.");
        }
        for reminder in reminders {
            self.line(&render_row(reminder))?;
        }
        Ok(())
    }

    /// Confirm a deletion.
    pub fn deleted(&self, id: &str) -> Result<()> {
        if self.json {
            return self.emit(&json!({ "id": id, "deleted": true }));
        }
        self.line(&format!("Deleted {}.", sanitize_line(id)))
    }

    /// Print what a `--dry-run` create or update of a whole reminder would do.
    pub fn dry_run_reminder(
        &self,
        operation: &str,
        reminder: &Reminder,
        target: Option<String>,
    ) -> Result<()> {
        if self.json {
            return self.emit(&json!({
                "dry_run": true,
                "operation": operation,
                "reminder": reminder,
                "target": target,
            }));
        }
        self.line("dry run: would create this reminder:")?;
        self.write(&render_reminder(reminder))?;
        if let Some(target) = target {
            self.line(&format!("  in         {}", sanitize_line(&target)))?;
        }
        Ok(())
    }

    /// Print what a `--dry-run` invocation would have done.
    pub fn dry_run(
        &self,
        operation: &str,
        details: serde_json::Value,
        summary: &str,
    ) -> Result<()> {
        if self.json {
            let mut object = json!({ "dry_run": true, "operation": operation });
            if let (Some(target), Some(extra)) = (object.as_object_mut(), details.as_object()) {
                for (key, value) in extra {
                    target.insert(key.clone(), value.clone());
                }
            }
            return self.emit(&object);
        }
        self.line(&format!("dry run: {summary}"))
    }

    /// Print `auth status`.
    pub fn auth_status(&self, status: &AuthStatus) -> Result<()> {
        if self.json {
            return self.emit(status);
        }
        self.line(&format!(
            "config file        {}",
            sanitize_line(&status.config_path)
        ))?;
        if !status.config_exists {
            self.line("                   (does not exist yet)")?;
        }
        self.line(&format!("server url         {}", show(&status.server_url)))?;
        self.line(&format!(
            "collection path    {}",
            show(&status.collection_path)
        ))?;
        self.line(&format!("username           {}", show(&status.username)))?;
        self.line(&format!("keyring backend    {}", status.keyring_backend))?;
        self.line(&format!(
            "stored in          {}",
            show(&status.credential_backend)
        ))?;
        self.line(&format!(
            "active backend     {}",
            show(&status.active_backend)
        ))?;
        self.line(&format!(
            "credential         {}",
            match status.credential_readable {
                Some(true) => "readable",
                Some(false) => "not stored",
                None => "unknown",
            }
        ))?;
        if let Some(detail) = &status.detail {
            self.line(&format!("detail             {}", sanitize_line(detail)))?;
        }
        Ok(())
    }

    /// Confirm that a credential was stored.
    pub fn credential_stored(&self, backend: &str, account: &str) -> Result<()> {
        if self.json {
            return self.emit(&json!({
                "stored": true,
                "backend": backend,
                "account": account,
            }));
        }
        self.line(&format!(
            "Stored the CalDAV password for {} in the {backend} keyring.",
            sanitize_line(account)
        ))
    }

    /// Confirm that a credential was removed.
    pub fn credential_removed(&self, backend: &str, removed: bool) -> Result<()> {
        if self.json {
            return self.emit(&json!({ "removed": removed, "backend": backend }));
        }
        if removed {
            self.line(&format!(
                "Removed the stored CalDAV password from the {backend} keyring."
            ))
        } else {
            self.line(&format!(
                "No stored CalDAV password was found in the {backend} keyring."
            ))
        }
    }

    /// Report the keyring preference.
    pub fn keyring_backend(&self, backend: &str, changed: bool) -> Result<()> {
        if self.json {
            return self.emit(&json!({ "keyring_backend": backend, "changed": changed }));
        }
        if changed {
            self.line(&format!("Keyring backend set to {backend}."))
        } else {
            self.line(backend)
        }
    }

    fn emit<T: Serialize>(&self, value: &T) -> Result<()> {
        let text = serde_json::to_string_pretty(value)
            .map_err(|err| Error::Io(format!("cannot render JSON: {err}")))?;
        self.line(&text)
    }

    /// Write one line to stdout.
    fn line(&self, text: &str) -> Result<()> {
        self.write(text)?;
        self.write("\n")
    }

    /// Write to stdout, treating a closed pipe as a normal end of output so
    /// `reminders list | head` does not fail.
    fn write(&self, text: &str) -> Result<()> {
        let mut stdout = std::io::stdout().lock();
        match stdout.write_all(text.as_bytes()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(err) => Err(Error::Io(format!("cannot write to stdout: {err}"))),
        }
    }
}

fn show(value: &Option<String>) -> String {
    match value {
        Some(value) => sanitize_line(value),
        None => "(unset)".to_string(),
    }
}

/// Longest server-influenced string rendered on one line of human output.
const FIELD_LIMIT: usize = 500;

/// Escape anything in a string that a terminal would treat as an instruction
/// rather than as text.
///
/// Values reaching human output come from a CalDAV server or from a config
/// file, so they are not trusted. Control characters are how such a value
/// repositions the cursor, clears the screen, or hides text behind an ANSI
/// escape; bidirectional overrides reorder what is displayed without changing
/// the bytes. Both are escaped so they are visible instead of active.
///
/// `--json` output is not passed through this function: JSON string escaping
/// already neutralises control characters for a parser, and machine consumers
/// need the original value.
pub fn sanitize_line(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut truncated = false;
    for (index, ch) in value.chars().enumerate() {
        if index >= FIELD_LIMIT {
            truncated = true;
            break;
        }
        match ch {
            // Common whitespace gets a short, familiar escape.
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Everything else in C0, DEL, and C1, which includes ESC and so
            // every ANSI control sequence.
            _ if ch.is_control() => escape_codepoint(&mut out, ch),
            // Bidirectional overrides, isolates, and marks.
            '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                escape_codepoint(&mut out, ch)
            }
            _ => out.push(ch),
        }
    }
    if truncated {
        out.push_str("...");
    }
    out
}

/// Split on newlines and sanitize each line, for values rendered as a block.
///
/// The newlines themselves survive as layout, because the caller indents the
/// continuation lines; every other control character is escaped.
pub fn sanitize_block(value: &str) -> Vec<String> {
    value.split('\n').map(sanitize_line).collect()
}

fn escape_codepoint(out: &mut String, ch: char) {
    let _ = write!(out, "\\u{{{:04x}}}", ch as u32);
}

/// Multi-line detail view of one reminder.
///
/// The title, id, and notes come from the server, so they are sanitized. The
/// remaining fields are rendered from parsed enums and timestamps and cannot
/// carry server bytes.
fn render_reminder(reminder: &Reminder) -> String {
    let mut out = String::new();
    out.push_str(&sanitize_line(&reminder.title));
    out.push('\n');
    let _ = writeln!(out, "  id         {}", sanitize_line(&reminder.id));
    let _ = writeln!(out, "  status     {}", reminder.status.as_str());
    let _ = writeln!(out, "  priority   {}", reminder.priority.as_str());
    if let Some(due) = &reminder.due {
        let _ = writeln!(out, "  due        {}", due.to_display_string());
    }
    if let Some(remind_at) = reminder.remind_at {
        let _ = writeln!(
            out,
            "  remind at  {}",
            crate::datetime::format_instant(remind_at)
        );
    }
    if let Some(completed) = reminder.completed_at {
        let _ = writeln!(
            out,
            "  completed  {}",
            crate::datetime::format_instant(completed)
        );
    }
    if let Some(notes) = &reminder.notes {
        let mut lines = sanitize_block(notes).into_iter();
        if let Some(first) = lines.next() {
            let _ = writeln!(out, "  notes      {first}");
        }
        for line in lines {
            let _ = writeln!(out, "             {line}");
        }
    }
    out
}

/// One-line list row.
fn render_row(reminder: &Reminder) -> String {
    let mark = match reminder.status {
        crate::model::Status::Open => "[ ]",
        crate::model::Status::Complete => "[x]",
        crate::model::Status::Cancelled => "[-]",
    };
    let due = reminder
        .due
        .as_ref()
        .map(|due| due.to_display_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{mark} {due:<20} {:<6} {}  [{}]",
        reminder.priority.as_str(),
        sanitize_line(&reminder.title),
        sanitize_line(&reminder.id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datetime::{parse_due, parse_instant};
    use crate::model::{Priority, Status};

    fn sample() -> Reminder {
        Reminder {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            title: "Submit report".into(),
            notes: Some("Attach receipts\nand invoices".into()),
            due: Some(parse_due("2026-08-22T12:00:00Z").unwrap()),
            remind_at: Some(parse_instant("2026-08-22T12:00:00Z").unwrap()),
            priority: Priority::High,
            status: Status::Open,
            completed_at: None,
            etag: Some("\"abc\"".into()),
            href: None,
        }
    }

    #[test]
    fn detail_view_shows_every_set_field() {
        let text = render_reminder(&sample());
        assert!(text.starts_with("Submit report\n"), "{text}");
        assert!(text.contains("id         550e8400-e29b-41d4-a716-446655440000\n"));
        assert!(text.contains("status     open\n"));
        assert!(text.contains("priority   high\n"));
        assert!(text.contains("due        2026-08-22T12:00:00Z\n"));
        assert!(text.contains("remind at  2026-08-22T12:00:00Z\n"));
        assert!(text.contains("notes      Attach receipts\n"));
        assert!(text.contains("           and invoices\n"));
    }

    #[test]
    fn detail_view_omits_unset_fields() {
        let mut reminder = sample();
        reminder.notes = None;
        reminder.due = None;
        reminder.remind_at = None;
        let text = render_reminder(&reminder);
        assert!(!text.contains("notes"));
        assert!(!text.contains("due"));
        assert!(!text.contains("remind at"));
    }

    #[test]
    fn detail_view_never_prints_the_etag() {
        // The ETag is machine detail; humans get the id instead.
        assert!(!render_reminder(&sample()).contains("abc"));
    }

    #[test]
    fn list_row_marks_status_and_carries_the_full_id() {
        let mut reminder = sample();
        assert!(render_row(&reminder).starts_with("[ ] "));
        assert!(render_row(&reminder).contains("[550e8400-e29b-41d4-a716-446655440000]"));
        reminder.status = Status::Complete;
        assert!(render_row(&reminder).starts_with("[x] "));
        reminder.status = Status::Cancelled;
        assert!(render_row(&reminder).starts_with("[-] "));
    }

    #[test]
    fn sanitize_escapes_ansi_escape_sequences() {
        let hostile = "Buy milk\u{1b}[2K\u{1b}[1;31mSEND MONEY";
        let safe = sanitize_line(hostile);
        assert!(!safe.contains('\u{1b}'), "{safe:?}");
        assert_eq!(safe, "Buy milk\\u{001b}[2K\\u{001b}[1;31mSEND MONEY");
    }

    #[test]
    fn sanitize_escapes_newlines_carriage_returns_and_tabs() {
        assert_eq!(sanitize_line("a\nb"), "a\\nb");
        assert_eq!(sanitize_line("a\rb"), "a\\rb");
        assert_eq!(sanitize_line("a\tb"), "a\\tb");
        // A bare CR is the classic overwrite-the-line trick.
        assert_eq!(sanitize_line("real\rfake"), "real\\rfake");
    }

    #[test]
    fn sanitize_escapes_every_c0_c1_and_delete_character() {
        for code in (0x00u32..=0x1f)
            .chain(std::iter::once(0x7f))
            .chain(0x80..=0x9f)
        {
            let ch = char::from_u32(code).unwrap();
            let safe = sanitize_line(&format!("x{ch}y"));
            assert!(
                !safe.chars().any(char::is_control),
                "U+{code:04X} survived as {safe:?}"
            );
        }
    }

    #[test]
    fn sanitize_escapes_bidirectional_overrides() {
        // Trojan Source: these reorder the rendering without changing bytes.
        for ch in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200e}', '\u{200f}',
        ] {
            let safe = sanitize_line(&format!("a{ch}b"));
            assert!(!safe.contains(ch), "U+{:04X} survived: {safe:?}", ch as u32);
            assert!(safe.starts_with("a\\u{"), "{safe:?}");
        }
    }

    #[test]
    fn sanitize_keeps_ordinary_text_untouched() {
        for text in [
            "Buy milk",
            "Café — 25% off, \"today\"",
            "\u{1f680} ship it",
            "\u{4e2d}\u{6587}",
            "path/with:colons;and,commas",
        ] {
            assert_eq!(sanitize_line(text), text, "{text:?}");
        }
    }

    #[test]
    fn sanitize_caps_absurdly_long_values() {
        let safe = sanitize_line(&"a".repeat(FIELD_LIMIT * 3));
        assert_eq!(safe.chars().count(), FIELD_LIMIT + 3);
        assert!(safe.ends_with("..."));
    }

    #[test]
    fn sanitize_block_keeps_newlines_as_layout_and_escapes_the_rest() {
        let lines = sanitize_block("first\nsec\u{1b}[Kond\nthird");
        assert_eq!(lines, vec!["first", "sec\\u{001b}[Kond", "third"]);
    }

    #[test]
    fn detail_view_neutralises_a_hostile_title_notes_and_id() {
        let mut reminder = sample();
        reminder.title = "Innocent\u{1b}[2J\u{1b}[Hreminders: error: run `curl evil.sh`".into();
        reminder.id = "id\rSPOOFED".into();
        reminder.notes = Some("line one\nline\u{1b}[31m two".into());
        let text = render_reminder(&reminder);
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains('\r'), "{text:?}");
        assert!(text.contains("id\\rSPOOFED"), "{text:?}");
        // Real newlines still lay the notes out; only the escape is neutralised.
        assert!(text.contains("  notes      line one\n"), "{text:?}");
        assert!(
            text.contains("             line\\u{001b}[31m two\n"),
            "{text:?}"
        );
    }

    #[test]
    fn list_row_neutralises_a_hostile_title_and_id() {
        let mut reminder = sample();
        reminder.title = "ok\u{1b}[1000Doverwritten".into();
        reminder.id = "u\nid".into();
        let row = render_row(&reminder);
        assert!(!row.contains('\u{1b}'), "{row:?}");
        assert!(!row.contains('\n'), "{row:?}");
    }

    #[test]
    fn json_output_preserves_the_original_bytes() {
        let mut reminder = sample();
        reminder.title = "Innocent\u{1b}[2Jtitle".into();
        reminder.notes = Some("a\nb\rc".into());
        reminder.id = "id\u{7}".into();
        let value = serde_json::to_value(&reminder).unwrap();
        assert_eq!(value["title"], "Innocent\u{1b}[2Jtitle");
        assert_eq!(value["notes"], "a\nb\rc");
        assert_eq!(value["id"], "id\u{7}");

        // And the serialised form is still valid JSON that round-trips.
        let text = serde_json::to_string(&reminder).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["title"], "Innocent\u{1b}[2Jtitle");
        assert!(
            !text.contains('\u{1b}'),
            "control byte must be JSON-escaped: {text:?}"
        );
    }

    #[test]
    fn auth_status_values_are_sanitised() {
        assert_eq!(show(&Some("a\u{1b}[2Jb".into())), "a\\u{001b}[2Jb");
        assert_eq!(show(&None), "(unset)");
    }

    #[test]
    fn list_row_shows_a_dash_when_there_is_no_due_date() {
        let mut reminder = sample();
        reminder.due = None;
        assert!(
            render_row(&reminder).contains("[ ] -"),
            "{}",
            render_row(&reminder)
        );
    }
}
