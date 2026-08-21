//! The reminder domain model: the small surface the CLI exposes instead of
//! iCalendar.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::datetime::{format_instant, Due};

/// Reminder priority, mapped to the RFC 5545 1-9 scale on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// No priority: the PRIORITY property is absent.
    #[default]
    None,
    /// Low priority: PRIORITY:9.
    Low,
    /// Medium priority: PRIORITY:5.
    Medium,
    /// High priority: PRIORITY:1.
    High,
}

impl Priority {
    /// The value we write. `None` means the property is removed.
    pub fn to_ical(self) -> Option<u8> {
        match self {
            Priority::None => None,
            Priority::High => Some(1),
            Priority::Medium => Some(5),
            Priority::Low => Some(9),
        }
    }

    /// Read the full 0-9 range, folding the bands the way Apple and RFC 5545 do.
    pub fn from_ical(value: u8) -> Priority {
        match value {
            1..=4 => Priority::High,
            5 => Priority::Medium,
            6..=9 => Priority::Low,
            _ => Priority::None,
        }
    }

    /// Lowercase name used in human output.
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::None => "none",
            Priority::Low => "low",
            Priority::Medium => "medium",
            Priority::High => "high",
        }
    }
}

/// Completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// `STATUS:NEEDS-ACTION`, `STATUS:IN-PROCESS`, or absent.
    Open,
    /// `STATUS:COMPLETED`.
    Complete,
    /// `STATUS:CANCELLED`. Read-only: the CLI never writes it.
    Cancelled,
}

impl Status {
    /// Lowercase name used in human output.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Complete => "complete",
            Status::Cancelled => "cancelled",
        }
    }
}

/// A reminder as the CLI presents it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reminder {
    /// `UID`, and the resource file name for reminders this CLI created.
    pub id: String,
    /// `SUMMARY`.
    pub title: String,
    /// `DESCRIPTION`.
    pub notes: Option<String>,
    /// `DUE`, either a calendar date or a UTC instant.
    pub due: Option<Due>,
    /// Absolute `VALARM` trigger, in UTC.
    #[serde(serialize_with = "serialize_optional_instant")]
    pub remind_at: Option<DateTime<Utc>>,
    /// `PRIORITY`.
    pub priority: Priority,
    /// `STATUS`.
    pub status: Status,
    /// `COMPLETED`, present when the reminder is complete.
    #[serde(serialize_with = "serialize_optional_instant")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Opaque server ETag for the resource this reminder came from.
    pub etag: Option<String>,
    /// Resource path on the server. Internal; never serialised.
    #[serde(skip)]
    pub href: Option<String>,
}

fn serialize_optional_instant<S: serde::Serializer>(
    value: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(dt) => serializer.serialize_str(&format_instant(*dt)),
        None => serializer.serialize_none(),
    }
}

/// The set of field changes an `update` invocation asks for. `None` means
/// "leave alone"; `Some(None)` means "clear".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReminderChanges {
    /// New `SUMMARY`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// New or cleared `DESCRIPTION`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Option<String>>,
    /// New or cleared `DUE`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due: Option<Option<Due>>,
    /// New or cleared alarm trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_nested_instant")]
    pub remind_at: Option<Option<DateTime<Utc>>>,
    /// New `PRIORITY`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// New `STATUS`, used by `complete` and `reopen`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

fn serialize_nested_instant<S: serde::Serializer>(
    value: &Option<Option<DateTime<Utc>>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(Some(dt)) => serializer.serialize_str(&format_instant(*dt)),
        Some(None) | None => serializer.serialize_none(),
    }
}

impl ReminderChanges {
    /// True when nothing would change.
    pub fn is_empty(&self) -> bool {
        *self == ReminderChanges::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datetime::parse_due;

    #[test]
    fn priority_write_mapping() {
        assert_eq!(Priority::None.to_ical(), None);
        assert_eq!(Priority::High.to_ical(), Some(1));
        assert_eq!(Priority::Medium.to_ical(), Some(5));
        assert_eq!(Priority::Low.to_ical(), Some(9));
    }

    #[test]
    fn priority_read_mapping_covers_full_range() {
        assert_eq!(Priority::from_ical(0), Priority::None);
        for v in 1..=4 {
            assert_eq!(Priority::from_ical(v), Priority::High, "{v}");
        }
        assert_eq!(Priority::from_ical(5), Priority::Medium);
        for v in 6..=9 {
            assert_eq!(Priority::from_ical(v), Priority::Low, "{v}");
        }
        assert_eq!(Priority::from_ical(10), Priority::None);
    }

    #[test]
    fn priority_round_trips_through_bands() {
        for p in [Priority::High, Priority::Medium, Priority::Low] {
            let written = p.to_ical().unwrap();
            assert_eq!(Priority::from_ical(written), p);
        }
    }

    #[test]
    fn reminder_json_uses_stable_field_names() {
        let reminder = Reminder {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            title: "Submit report".into(),
            notes: Some("Attach receipts".into()),
            due: Some(parse_due("2026-08-22T16:00:00+04:00").unwrap()),
            remind_at: Some(crate::datetime::parse_instant("2026-08-22T16:00:00+04:00").unwrap()),
            priority: Priority::High,
            status: Status::Open,
            completed_at: None,
            etag: Some("\"abc\"".into()),
            href: Some("/u/tasks/x.ics".into()),
        };
        let json = serde_json::to_value(&reminder).unwrap();
        assert_eq!(json["id"], "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(json["title"], "Submit report");
        assert_eq!(json["notes"], "Attach receipts");
        assert_eq!(json["due"], "2026-08-22T12:00:00Z");
        assert_eq!(json["remind_at"], "2026-08-22T12:00:00Z");
        assert_eq!(json["priority"], "high");
        assert_eq!(json["status"], "open");
        assert_eq!(json["etag"], "\"abc\"");
        assert!(json["completed_at"].is_null());
        assert!(json.get("href").is_none(), "href must never be serialised");
    }

    #[test]
    fn date_only_due_serialises_as_date() {
        let json = serde_json::to_value(parse_due("2026-08-22").unwrap()).unwrap();
        assert_eq!(json, "2026-08-22");
    }

    #[test]
    fn empty_changes_detected() {
        assert!(ReminderChanges::default().is_empty());
        assert!(!ReminderChanges {
            title: Some("x".into()),
            ..Default::default()
        }
        .is_empty());
        // Clearing a field is a real change.
        assert!(!ReminderChanges {
            notes: Some(None),
            ..Default::default()
        }
        .is_empty());
    }
}
