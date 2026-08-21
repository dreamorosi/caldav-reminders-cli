//! VTODO documents: parse, mutate, and serialise while preserving everything
//! the CLI does not understand.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

use crate::datetime::Due;
use crate::error::{Error, Result};
use crate::ical::lines::{fold, unfold, ContentLine};
use crate::model::{Priority, Reminder, ReminderChanges, Status};

/// `PRODID` written on resources this CLI creates.
pub const PRODID: &str = concat!(
    "-//caldav-reminders-cli//reminders ",
    env!("CARGO_PKG_VERSION"),
    "//EN"
);

/// A parsed `text/calendar` resource holding exactly one primary VTODO.
///
/// Everything that is not a property this CLI manages is retained verbatim:
/// VCALENDAR-level properties, sibling components such as VTIMEZONE, extra
/// VTODO components, unknown VTODO properties, and unknown VALARM properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    calendar_props: Vec<ContentLine>,
    /// Logical lines of preserved sibling components, `BEGIN`/`END` included.
    other_components: Vec<Vec<String>>,
    props: Vec<ContentLine>,
    alarms: Vec<Vec<ContentLine>>,
}

impl Document {
    /// Parse a `text/calendar` body.
    pub fn parse(text: &str) -> Result<Document> {
        let logical = unfold(text);
        let mut iter = logical.iter().peekable();

        // Skip anything before BEGIN:VCALENDAR; some servers prepend blanks.
        let mut found_calendar = false;
        for line in iter.by_ref() {
            if line.eq_ignore_ascii_case("BEGIN:VCALENDAR") {
                found_calendar = true;
                break;
            }
        }
        if !found_calendar {
            return Err(Error::server("calendar data has no BEGIN:VCALENDAR"));
        }

        let mut doc = Document {
            calendar_props: Vec::new(),
            other_components: Vec::new(),
            props: Vec::new(),
            alarms: Vec::new(),
        };
        let mut primary_todo: Option<(Vec<ContentLine>, Vec<Vec<ContentLine>>)> = None;
        let mut closed_calendar = false;

        while let Some(line) = iter.next() {
            if line.eq_ignore_ascii_case("END:VCALENDAR") {
                closed_calendar = true;
                break;
            }
            if let Some(name) = component_name(line) {
                let block = collect_component(&name, &mut iter)?;
                if name.eq_ignore_ascii_case("VTODO") && primary_todo.is_none() {
                    primary_todo = Some(split_todo(&block)?);
                } else {
                    let mut raw = Vec::with_capacity(block.len() + 2);
                    raw.push(format!("BEGIN:{name}"));
                    raw.extend(block);
                    raw.push(format!("END:{name}"));
                    doc.other_components.push(raw);
                }
                continue;
            }
            doc.calendar_props.push(ContentLine::parse(line)?);
        }

        // A response that stops before END:VCALENDAR was truncated in transit,
        // so whatever we did parse may be missing properties we would then drop
        // on the next write.
        if !closed_calendar {
            return Err(Error::server(
                "the calendar data ends without END:VCALENDAR, so it is incomplete or was \
                 truncated",
            ));
        }

        let (props, alarms) = primary_todo
            .ok_or_else(|| Error::server("calendar data contains no VTODO component"))?;
        doc.props = props;
        doc.alarms = alarms;

        if doc.uid().is_none() {
            return Err(Error::server("VTODO has no UID"));
        }
        Ok(doc)
    }

    /// Build a fresh document for a new reminder.
    pub fn new_reminder(
        uid: &str,
        title: &str,
        notes: Option<&str>,
        due: Option<Due>,
        remind_at: Option<DateTime<Utc>>,
        priority: Priority,
        now: DateTime<Utc>,
    ) -> Document {
        let mut doc = Document {
            calendar_props: vec![
                ContentLine::raw("VERSION", "2.0"),
                ContentLine::raw("PRODID", PRODID),
                ContentLine::raw("CALSCALE", "GREGORIAN"),
            ],
            other_components: Vec::new(),
            props: vec![
                ContentLine::raw("UID", uid),
                ContentLine::raw("DTSTAMP", format_utc(now)),
                ContentLine::raw("CREATED", format_utc(now)),
                ContentLine::raw("LAST-MODIFIED", format_utc(now)),
                ContentLine::text("SUMMARY", title),
                ContentLine::raw("STATUS", "NEEDS-ACTION"),
            ],
            alarms: Vec::new(),
        };
        if let Some(notes) = notes {
            doc.set_prop(ContentLine::text("DESCRIPTION", notes));
        }
        doc.set_due(due);
        doc.set_priority(priority);
        doc.set_remind_at(remind_at);
        doc
    }

    /// `UID` of the primary VTODO.
    pub fn uid(&self) -> Option<String> {
        self.get_prop("UID").map(|line| line.text_value())
    }

    /// Serialise to a CRLF-folded `text/calendar` body.
    pub fn to_ics(&self) -> String {
        let mut out = String::new();
        out.push_str(&fold("BEGIN:VCALENDAR"));
        for line in &self.calendar_props {
            out.push_str(&fold(&line.to_logical_line()));
        }
        for component in &self.other_components {
            for line in component {
                out.push_str(&fold(line));
            }
        }
        out.push_str(&fold("BEGIN:VTODO"));
        for line in &self.props {
            out.push_str(&fold(&line.to_logical_line()));
        }
        for alarm in &self.alarms {
            out.push_str(&fold("BEGIN:VALARM"));
            for line in alarm {
                out.push_str(&fold(&line.to_logical_line()));
            }
            out.push_str(&fold("END:VALARM"));
        }
        out.push_str(&fold("END:VTODO"));
        out.push_str(&fold("END:VCALENDAR"));
        out
    }

    /// Project the document onto the CLI's reminder model.
    pub fn to_reminder(&self, etag: Option<String>, href: Option<String>) -> Result<Reminder> {
        let id = self
            .uid()
            .ok_or_else(|| Error::server("VTODO has no UID"))?;
        let title = self
            .get_prop("SUMMARY")
            .map(|line| line.text_value())
            .unwrap_or_default();
        let notes = self
            .get_prop("DESCRIPTION")
            .map(|line| line.text_value())
            .filter(|text| !text.is_empty());
        let due = match self.get_prop("DUE") {
            Some(line) => Some(parse_due_property(line)?),
            None => None,
        };
        let priority = self
            .get_prop("PRIORITY")
            .and_then(|line| line.value.trim().parse::<u8>().ok())
            .map(Priority::from_ical)
            .unwrap_or_default();
        let status = match self
            .get_prop("STATUS")
            .map(|line| line.value.to_ascii_uppercase())
        {
            Some(value) if value == "COMPLETED" => Status::Complete,
            Some(value) if value == "CANCELLED" => Status::Cancelled,
            _ => Status::Open,
        };
        let completed_at = match self.get_prop("COMPLETED") {
            Some(line) => parse_datetime_property(line).ok(),
            None => None,
        };
        let remind_at = self.managed_alarm_index().and_then(|index| {
            self.alarms[index]
                .iter()
                .find(|line| line.name == "TRIGGER")
                .and_then(|line| parse_datetime_property(line).ok())
        });

        Ok(Reminder {
            id,
            title,
            notes,
            due,
            remind_at,
            priority,
            status,
            completed_at,
            etag,
            href,
        })
    }

    /// Apply a change set, refreshing `DTSTAMP` and `LAST-MODIFIED`.
    pub fn apply(&mut self, changes: &ReminderChanges, now: DateTime<Utc>) {
        if let Some(title) = &changes.title {
            self.set_prop(ContentLine::text("SUMMARY", title));
            // Keep the notification text in step with the reminder title.
            if let Some(index) = self.managed_alarm_index() {
                if self.alarms[index]
                    .iter()
                    .any(|line| line.name == "DESCRIPTION")
                {
                    set_in(
                        &mut self.alarms[index],
                        ContentLine::text("DESCRIPTION", title),
                    );
                }
            }
        }
        if let Some(notes) = &changes.notes {
            match notes {
                Some(text) => self.set_prop(ContentLine::text("DESCRIPTION", text)),
                None => self.remove_prop("DESCRIPTION"),
            }
        }
        if let Some(due) = &changes.due {
            self.set_due(*due);
        }
        if let Some(priority) = changes.priority {
            self.set_priority(priority);
        }
        if let Some(remind_at) = &changes.remind_at {
            self.set_remind_at(*remind_at);
        }
        if let Some(status) = changes.status {
            self.set_status(status, now);
        }
        self.set_prop(ContentLine::raw("DTSTAMP", format_utc(now)));
        self.set_prop(ContentLine::raw("LAST-MODIFIED", format_utc(now)));
    }

    fn set_status(&mut self, status: Status, now: DateTime<Utc>) {
        match status {
            Status::Complete => {
                self.set_prop(ContentLine::raw("STATUS", "COMPLETED"));
                self.set_prop(ContentLine::raw("PERCENT-COMPLETE", "100"));
                if self.get_prop("COMPLETED").is_none() {
                    self.set_prop(ContentLine::raw("COMPLETED", format_utc(now)));
                }
            }
            Status::Open => {
                self.set_prop(ContentLine::raw("STATUS", "NEEDS-ACTION"));
                self.remove_prop("COMPLETED");
                self.remove_prop("PERCENT-COMPLETE");
            }
            // The CLI never writes CANCELLED; treat it as a no-op guard.
            Status::Cancelled => {}
        }
    }

    fn set_due(&mut self, due: Option<Due>) {
        match due {
            Some(Due::Date(date)) => {
                self.set_prop(
                    ContentLine::raw("DUE", format_date(date)).with_param("VALUE", "DATE"),
                );
            }
            Some(Due::At(dt)) => {
                self.set_prop(ContentLine::raw("DUE", format_utc(dt)));
            }
            None => self.remove_prop("DUE"),
        }
    }

    fn set_priority(&mut self, priority: Priority) {
        match priority.to_ical() {
            Some(value) => self.set_prop(ContentLine::raw("PRIORITY", value.to_string())),
            None => self.remove_prop("PRIORITY"),
        }
    }

    fn set_remind_at(&mut self, remind_at: Option<DateTime<Utc>>) {
        match remind_at {
            Some(dt) => {
                let trigger =
                    ContentLine::raw("TRIGGER", format_utc(dt)).with_param("VALUE", "DATE-TIME");
                match self.managed_alarm_index() {
                    Some(index) => set_in(&mut self.alarms[index], trigger),
                    None => {
                        let summary = self
                            .get_prop("SUMMARY")
                            .map(|line| line.text_value())
                            .unwrap_or_else(|| "Reminder".to_string());
                        self.alarms.push(vec![
                            ContentLine::raw("ACTION", "DISPLAY"),
                            ContentLine::text("DESCRIPTION", &summary),
                            trigger,
                            ContentLine::raw("UID", uuid::Uuid::new_v4().to_string()),
                        ]);
                    }
                }
            }
            None => self.alarms.retain(|alarm| !has_absolute_trigger(alarm)),
        }
    }

    /// Index of the first alarm with an absolute trigger. Relative alarms
    /// belong to another client and are left untouched.
    fn managed_alarm_index(&self) -> Option<usize> {
        self.alarms
            .iter()
            .position(|alarm| has_absolute_trigger(alarm))
    }

    fn get_prop(&self, name: &str) -> Option<&ContentLine> {
        self.props.iter().find(|line| line.name == name)
    }

    fn set_prop(&mut self, line: ContentLine) {
        set_in(&mut self.props, line);
    }

    fn remove_prop(&mut self, name: &str) {
        self.props.retain(|line| line.name != name);
    }
}

/// Replace the first property with a matching name in place, or append.
fn set_in(lines: &mut Vec<ContentLine>, new: ContentLine) {
    match lines.iter().position(|line| line.name == new.name) {
        Some(index) => {
            lines[index] = new;
            // Drop any duplicates that follow, keeping the document single-valued.
            let name = lines[index].name.clone();
            let mut seen = false;
            lines.retain(|line| {
                if line.name != name {
                    return true;
                }
                if seen {
                    return false;
                }
                seen = true;
                true
            });
        }
        None => lines.push(new),
    }
}

fn has_absolute_trigger(alarm: &[ContentLine]) -> bool {
    alarm.iter().any(|line| {
        line.name == "TRIGGER"
            && (line
                .param("VALUE")
                .is_some_and(|v| v.eq_ignore_ascii_case("DATE-TIME"))
                || line.value.ends_with('Z')
                || line.value.ends_with('z'))
    })
}

/// `BEGIN:NAME` -> `NAME`.
fn component_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("BEGIN:").or_else(|| {
        if line.len() > 6 && line[..6].eq_ignore_ascii_case("BEGIN:") {
            Some(&line[6..])
        } else {
            None
        }
    })?;
    Some(rest.trim().to_ascii_uppercase())
}

/// Consume lines up to the matching `END:NAME`, handling nesting.
fn collect_component<'a, I>(name: &str, iter: &mut std::iter::Peekable<I>) -> Result<Vec<String>>
where
    I: Iterator<Item = &'a String>,
{
    let end = format!("END:{name}");
    let mut depth = 1usize;
    let mut block = Vec::new();
    for line in iter.by_ref() {
        if line.eq_ignore_ascii_case(&end) {
            depth -= 1;
            if depth == 0 {
                return Ok(block);
            }
        } else if let Some(inner) = component_name(line) {
            if inner.eq_ignore_ascii_case(name) {
                depth += 1;
            }
        }
        block.push(line.clone());
    }
    let _ = name;
    Err(Error::server(
        "the calendar data contains a component that is never closed with an END line",
    ))
}

/// Split a VTODO body into its own properties and its VALARM children.
fn split_todo(block: &[String]) -> Result<(Vec<ContentLine>, Vec<Vec<ContentLine>>)> {
    let mut props = Vec::new();
    let mut alarms = Vec::new();
    let mut current: Option<Vec<ContentLine>> = None;

    for line in block {
        if let Some(name) = component_name(line) {
            if name == "VALARM" {
                current = Some(Vec::new());
                continue;
            }
            let _ = name;
            return Err(Error::server(
                "the VTODO contains a nested component this client does not support (only \
                 VALARM is allowed)",
            ));
        }
        if line.eq_ignore_ascii_case("END:VALARM") {
            match current.take() {
                Some(alarm) => alarms.push(alarm),
                None => return Err(Error::server("END:VALARM without BEGIN:VALARM")),
            }
            continue;
        }
        let parsed = ContentLine::parse(line)?;
        match current.as_mut() {
            Some(alarm) => alarm.push(parsed),
            None => props.push(parsed),
        }
    }
    if current.is_some() {
        return Err(Error::server("unterminated VALARM component"));
    }
    Ok((props, alarms))
}

/// `20260822`
fn format_date(date: NaiveDate) -> String {
    date.format("%Y%m%d").to_string()
}

/// `20260822T120000Z`
fn format_utc(dt: DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Read a `DUE` property, honouring `VALUE=DATE` and `TZID`.
fn parse_due_property(line: &ContentLine) -> Result<Due> {
    let is_date = line
        .param("VALUE")
        .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
        || (line.value.trim().len() == 8 && line.param("VALUE").is_none());
    if is_date {
        let date = NaiveDate::parse_from_str(line.value.trim(), "%Y%m%d").map_err(|_| {
            Error::server(format!(
                "DUE holds a {}-character value that is not a YYYYMMDD date",
                line.value.trim().chars().count()
            ))
        })?;
        return Ok(Due::Date(date));
    }
    parse_datetime_property(line).map(Due::At)
}

/// Read a date-time property. UTC (`Z`) values are exact; `TZID` values are
/// converted; floating values are read as UTC because there is nothing better
/// to assume from a server that omitted the zone.
///
/// Errors may name the property, because every caller looks the line up by one
/// of this crate's own constants (`DUE`, `COMPLETED`, `TRIGGER`), so the name
/// is never a string the server chose. Values and time zone names are not
/// quoted: those the server does choose.
fn parse_datetime_property(line: &ContentLine) -> Result<DateTime<Utc>> {
    let value = line.value.trim();
    let (naive_text, is_utc) = match value.strip_suffix('Z').or_else(|| value.strip_suffix('z')) {
        Some(rest) => (rest, true),
        None => (value, false),
    };
    let naive = NaiveDateTime::parse_from_str(naive_text, "%Y%m%dT%H%M%S").map_err(|_| {
        Error::server(format!(
            "{} holds a {}-character value that is not an iCalendar date-time",
            line.name,
            value.chars().count()
        ))
    })?;
    if is_utc {
        return Ok(naive.and_utc());
    }
    if let Some(tzid) = line.param("TZID") {
        if let Ok(tz) = tzid.parse::<Tz>() {
            return match tz.from_local_datetime(&naive) {
                chrono::LocalResult::Single(dt) => Ok(dt.with_timezone(&Utc)),
                // Be lenient when reading: pick the earlier of two candidates.
                chrono::LocalResult::Ambiguous(dt, _) => Ok(dt.with_timezone(&Utc)),
                chrono::LocalResult::None => Err(Error::server(format!(
                    "the {} value does not exist in the time zone the server named, because \
                     of a daylight saving transition",
                    line.name
                ))),
            };
        }
        let _ = tzid;
        return Err(Error::server(format!(
            "{} names a time zone this client does not recognise",
            line.name
        )));
    }
    Ok(naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datetime::{parse_due, parse_instant};

    fn now() -> DateTime<Utc> {
        parse_instant("2026-08-20T09:00:00Z").unwrap()
    }

    fn sample_new() -> Document {
        Document::new_reminder(
            "550e8400-e29b-41d4-a716-446655440000",
            "Submit report; final",
            Some("Attach receipts\nand invoices"),
            Some(parse_due("2026-08-22T16:00:00+04:00").unwrap()),
            Some(parse_instant("2026-08-22T16:00:00+04:00").unwrap()),
            Priority::High,
            now(),
        )
    }

    #[test]
    fn new_reminder_serialises_expected_properties() {
        let ics = sample_new().to_ics();
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"), "{ics}");
        assert!(ics.ends_with("END:VCALENDAR\r\n"), "{ics}");
        assert!(ics.contains("\r\nVERSION:2.0\r\n"));
        assert!(ics.contains("UID:550e8400-e29b-41d4-a716-446655440000\r\n"));
        assert!(ics.contains("SUMMARY:Submit report\\; final\r\n"));
        assert!(ics.contains("DESCRIPTION:Attach receipts\\nand invoices\r\n"));
        assert!(ics.contains("DUE:20260822T120000Z\r\n"));
        assert!(ics.contains("PRIORITY:1\r\n"));
        assert!(ics.contains("STATUS:NEEDS-ACTION\r\n"));
        assert!(ics.contains("BEGIN:VALARM\r\n"));
        assert!(ics.contains("TRIGGER;VALUE=DATE-TIME:20260822T120000Z\r\n"));
        assert!(ics.contains("ACTION:DISPLAY\r\n"));
    }

    #[test]
    fn every_physical_line_ends_with_crlf() {
        let ics = sample_new().to_ics();
        assert!(!ics.contains('\n') || ics.split("\r\n").count() > 1);
        for chunk in ics.split("\r\n") {
            assert!(!chunk.contains('\n'), "stray LF in {chunk:?}");
        }
    }

    #[test]
    fn round_trips_through_parse() {
        let doc = sample_new();
        let reparsed = Document::parse(&doc.to_ics()).unwrap();
        assert_eq!(reparsed.to_ics(), doc.to_ics());
    }

    #[test]
    fn reminder_projection_matches_input() {
        let reminder = sample_new()
            .to_reminder(Some("\"etag1\"".into()), Some("/u/t/x.ics".into()))
            .unwrap();
        assert_eq!(reminder.id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(reminder.title, "Submit report; final");
        assert_eq!(
            reminder.notes.as_deref(),
            Some("Attach receipts\nand invoices")
        );
        assert_eq!(
            reminder.due,
            Some(parse_due("2026-08-22T12:00:00Z").unwrap())
        );
        assert_eq!(
            reminder.remind_at,
            Some(parse_instant("2026-08-22T12:00:00Z").unwrap())
        );
        assert_eq!(reminder.priority, Priority::High);
        assert_eq!(reminder.status, Status::Open);
        assert_eq!(reminder.etag.as_deref(), Some("\"etag1\""));
        assert_eq!(reminder.href.as_deref(), Some("/u/t/x.ics"));
    }

    #[test]
    fn date_only_due_uses_value_date_parameter() {
        let doc = Document::new_reminder(
            "u1",
            "Groceries",
            None,
            Some(parse_due("2026-08-22").unwrap()),
            None,
            Priority::None,
            now(),
        );
        let ics = doc.to_ics();
        assert!(ics.contains("DUE;VALUE=DATE:20260822\r\n"), "{ics}");
        assert!(!ics.contains("PRIORITY"), "priority none must be absent");
        assert!(!ics.contains("VALARM"), "date-only due implies no alarm");
        let reminder = doc.to_reminder(None, None).unwrap();
        assert_eq!(reminder.due, Some(parse_due("2026-08-22").unwrap()));
        assert_eq!(reminder.remind_at, None);
    }

    const FOREIGN: &str = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Apple Inc.//iOS 18.0//EN\r\n\
X-WR-CALNAME:Tasks\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/London\r\n\
BEGIN:STANDARD\r\n\
DTSTART:19710101T020000\r\n\
TZOFFSETFROM:+0100\r\n\
TZOFFSETTO:+0000\r\n\
END:STANDARD\r\n\
END:VTIMEZONE\r\n\
BEGIN:VTODO\r\n\
UID:apple-uid-1\r\n\
DTSTAMP:20260801T100000Z\r\n\
SUMMARY:Foreign task\r\n\
DUE;TZID=Europe/London:20260822T170000\r\n\
PRIORITY:5\r\n\
STATUS:NEEDS-ACTION\r\n\
X-APPLE-SORT-ORDER:12345\r\n\
X-VENDOR-BLOB;X-P=\"a;b\":opaque-value\r\n\
BEGIN:VALARM\r\n\
ACTION:DISPLAY\r\n\
DESCRIPTION:Foreign task\r\n\
TRIGGER;VALUE=DATE-TIME:20260822T160000Z\r\n\
X-WR-ALARMUID:alarm-1\r\n\
END:VALARM\r\n\
END:VTODO\r\n\
END:VCALENDAR\r\n";

    #[test]
    fn parses_tzid_due_into_utc() {
        let reminder = Document::parse(FOREIGN)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        // Europe/London is UTC+1 in August.
        assert_eq!(
            reminder.due,
            Some(parse_due("2026-08-22T16:00:00Z").unwrap())
        );
        assert_eq!(reminder.priority, Priority::Medium);
    }

    #[test]
    fn preserves_unknown_properties_and_components_on_update() {
        let mut doc = Document::parse(FOREIGN).unwrap();
        doc.apply(
            &ReminderChanges {
                title: Some("Renamed".into()),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert!(ics.contains("X-APPLE-SORT-ORDER:12345\r\n"), "{ics}");
        assert!(
            ics.contains("X-VENDOR-BLOB;X-P=\"a;b\":opaque-value\r\n"),
            "{ics}"
        );
        assert!(ics.contains("X-WR-CALNAME:Tasks\r\n"));
        assert!(ics.contains("BEGIN:VTIMEZONE\r\n"));
        assert!(ics.contains("TZOFFSETFROM:+0100\r\n"));
        assert!(ics.contains("X-WR-ALARMUID:alarm-1\r\n"));
        assert!(ics.contains("PRODID:-//Apple Inc.//iOS 18.0//EN\r\n"));
        assert!(ics.contains("SUMMARY:Renamed\r\n"));
        // The alarm text follows the title.
        assert!(ics.contains("DESCRIPTION:Renamed\r\n"));
        assert!(ics.contains("LAST-MODIFIED:20260820T090000Z\r\n"));
    }

    #[test]
    fn update_replaces_properties_in_place() {
        let mut doc = Document::parse(FOREIGN).unwrap();
        doc.apply(
            &ReminderChanges {
                priority: Some(Priority::Low),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert_eq!(ics.matches("PRIORITY:").count(), 1, "{ics}");
        assert!(ics.contains("PRIORITY:9\r\n"));
    }

    #[test]
    fn clearing_notes_removes_description() {
        let mut doc = sample_new();
        doc.apply(
            &ReminderChanges {
                notes: Some(None),
                ..Default::default()
            },
            now(),
        );
        assert!(!doc.to_ics().contains("DESCRIPTION:Attach"));
        assert_eq!(doc.to_reminder(None, None).unwrap().notes, None);
    }

    #[test]
    fn clearing_due_removes_property_but_keeps_alarm_untouched() {
        let mut doc = sample_new();
        doc.apply(
            &ReminderChanges {
                due: Some(None),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert!(!ics.contains("\r\nDUE"), "{ics}");
        assert!(
            ics.contains("TRIGGER;VALUE=DATE-TIME:"),
            "alarm is independent"
        );
    }

    #[test]
    fn clearing_reminder_removes_absolute_alarm_only() {
        let with_relative =
            FOREIGN.replace("TRIGGER;VALUE=DATE-TIME:20260822T160000Z", "TRIGGER:-PT15M");
        let mut doc = Document::parse(&with_relative).unwrap();
        doc.apply(
            &ReminderChanges {
                remind_at: Some(None),
                ..Default::default()
            },
            now(),
        );
        assert!(
            doc.to_ics().contains("TRIGGER:-PT15M"),
            "relative alarm survives"
        );
    }

    #[test]
    fn relative_trigger_is_not_reported_as_remind_at() {
        let with_relative =
            FOREIGN.replace("TRIGGER;VALUE=DATE-TIME:20260822T160000Z", "TRIGGER:-PT15M");
        let reminder = Document::parse(&with_relative)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        assert_eq!(reminder.remind_at, None);
    }

    #[test]
    fn setting_reminder_reuses_existing_alarm_and_keeps_its_extras() {
        let mut doc = Document::parse(FOREIGN).unwrap();
        doc.apply(
            &ReminderChanges {
                remind_at: Some(Some(parse_instant("2026-08-23T09:30:00Z").unwrap())),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert_eq!(ics.matches("BEGIN:VALARM").count(), 1, "{ics}");
        assert!(ics.contains("TRIGGER;VALUE=DATE-TIME:20260823T093000Z\r\n"));
        assert!(ics.contains("X-WR-ALARMUID:alarm-1\r\n"));
    }

    #[test]
    fn complete_sets_status_and_timestamp() {
        let mut doc = sample_new();
        doc.apply(
            &ReminderChanges {
                status: Some(Status::Complete),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert!(ics.contains("STATUS:COMPLETED\r\n"), "{ics}");
        assert!(ics.contains("COMPLETED:20260820T090000Z\r\n"));
        assert!(ics.contains("PERCENT-COMPLETE:100\r\n"));
        let reminder = doc.to_reminder(None, None).unwrap();
        assert_eq!(reminder.status, Status::Complete);
        assert_eq!(reminder.completed_at, Some(now()));
    }

    #[test]
    fn reopen_clears_completion_state() {
        let mut doc = sample_new();
        doc.apply(
            &ReminderChanges {
                status: Some(Status::Complete),
                ..Default::default()
            },
            now(),
        );
        doc.apply(
            &ReminderChanges {
                status: Some(Status::Open),
                ..Default::default()
            },
            now(),
        );
        let ics = doc.to_ics();
        assert!(ics.contains("STATUS:NEEDS-ACTION\r\n"), "{ics}");
        assert!(!ics.contains("COMPLETED:"));
        assert!(!ics.contains("PERCENT-COMPLETE"));
        assert_eq!(doc.to_reminder(None, None).unwrap().completed_at, None);
    }

    #[test]
    fn cancelled_status_is_reported_but_never_written() {
        let cancelled = FOREIGN.replace("STATUS:NEEDS-ACTION", "STATUS:CANCELLED");
        let mut doc = Document::parse(&cancelled).unwrap();
        assert_eq!(
            doc.to_reminder(None, None).unwrap().status,
            Status::Cancelled
        );
        doc.apply(
            &ReminderChanges {
                status: Some(Status::Cancelled),
                ..Default::default()
            },
            now(),
        );
        assert!(doc.to_ics().contains("STATUS:CANCELLED"));
    }

    #[test]
    fn long_values_survive_folding_round_trip() {
        let notes = "\u{4e2d}\u{6587}".repeat(200);
        let doc = Document::new_reminder(
            "u2",
            &"long title ".repeat(20),
            Some(&notes),
            None,
            None,
            Priority::None,
            now(),
        );
        let reparsed = Document::parse(&doc.to_ics()).unwrap();
        let reminder = reparsed.to_reminder(None, None).unwrap();
        assert_eq!(reminder.notes.as_deref(), Some(notes.as_str()));
        assert_eq!(reminder.title, "long title ".repeat(20));
    }

    #[test]
    fn rejects_data_without_vtodo() {
        let err =
            Document::parse("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n").unwrap_err();
        assert!(err.to_string().contains("no VTODO"), "{err}");
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);
    }

    #[test]
    fn rejects_data_without_calendar() {
        assert!(Document::parse("nonsense").is_err());
    }

    #[test]
    fn rejects_vtodo_without_uid() {
        let err = Document::parse(
            "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nSUMMARY:x\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("no UID"), "{err}");
    }

    #[test]
    fn rejects_calendar_data_without_end_vcalendar() {
        // Truncated after a complete VTODO: everything else parsed fine, so the
        // terminator is the only thing that catches it.
        let truncated = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:x\r\n\
SUMMARY:y\r\nEND:VTODO\r\n";
        let err = Document::parse(truncated).unwrap_err();
        assert!(err.to_string().contains("END:VCALENDAR"), "{err}");
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);

        // And the same data with the terminator is accepted.
        let whole = format!("{truncated}END:VCALENDAR\r\n");
        assert_eq!(
            Document::parse(&whole)
                .unwrap()
                .to_reminder(None, None)
                .unwrap()
                .id,
            "x"
        );
    }

    #[test]
    fn rejects_calendar_data_truncated_mid_property() {
        let err =
            Document::parse("BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:x\r\nEND:VTODO\r\nX-TRAILING:")
                .unwrap_err();
        assert!(err.to_string().contains("END:VCALENDAR"), "{err}");
    }

    #[test]
    fn rejects_unterminated_component() {
        assert!(Document::parse("BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:x\r\n").is_err());
    }

    #[test]
    fn extra_vtodo_components_are_preserved_verbatim() {
        let two = "BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
BEGIN:VTODO\r\n\
UID:primary\r\n\
SUMMARY:First\r\n\
END:VTODO\r\n\
BEGIN:VTODO\r\n\
UID:primary\r\n\
RECURRENCE-ID:20260901T000000Z\r\n\
SUMMARY:Override\r\n\
END:VTODO\r\n\
END:VCALENDAR\r\n";
        let doc = Document::parse(two).unwrap();
        assert_eq!(doc.to_reminder(None, None).unwrap().title, "First");
        let ics = doc.to_ics();
        assert!(ics.contains("RECURRENCE-ID:20260901T000000Z\r\n"), "{ics}");
        assert_eq!(ics.matches("BEGIN:VTODO").count(), 2);
    }

    #[test]
    fn parses_lowercase_and_lf_only_input() {
        let lax = "begin:VCALENDAR\nbegin:VTODO\nuid:x\nsummary:y\nend:VTODO\nend:VCALENDAR\n";
        let reminder = Document::parse(lax)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        assert_eq!(reminder.id, "x");
        assert_eq!(reminder.title, "y");
    }

    #[test]
    fn floating_datetime_is_read_as_utc() {
        let floating = FOREIGN.replace(
            "DUE;TZID=Europe/London:20260822T170000",
            "DUE:20260822T170000",
        );
        let reminder = Document::parse(&floating)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        assert_eq!(
            reminder.due,
            Some(parse_due("2026-08-22T17:00:00Z").unwrap())
        );
    }

    #[test]
    fn invalid_due_value_is_a_server_error() {
        let bad = FOREIGN.replace("DUE;TZID=Europe/London:20260822T170000", "DUE:not-a-date");
        let err = Document::parse(&bad)
            .unwrap()
            .to_reminder(None, None)
            .unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);
    }

    #[test]
    fn eight_digit_due_without_value_param_is_a_date() {
        let bare = FOREIGN.replace("DUE;TZID=Europe/London:20260822T170000", "DUE:20260822");
        let reminder = Document::parse(&bare)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        assert_eq!(reminder.due, Some(parse_due("2026-08-22").unwrap()));
    }

    #[test]
    fn set_in_collapses_duplicates() {
        let mut lines = vec![
            ContentLine::raw("A", "1"),
            ContentLine::raw("B", "2"),
            ContentLine::raw("A", "3"),
        ];
        set_in(&mut lines, ContentLine::raw("A", "9"));
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].value, "9");
        assert_eq!(lines[1].name, "B");
    }
}
