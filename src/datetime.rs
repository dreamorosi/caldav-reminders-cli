//! Date and date-time parsing.
//!
//! The CLI refuses naive local date-times: an instant must carry either a UTC
//! offset (RFC 3339) or an IANA time zone name. Everything is normalised to UTC
//! because that is what goes on the wire.

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

use crate::error::{Error, Result};

/// A due date is either a floating calendar date or a precise instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// `DUE;VALUE=DATE` — a whole day, with no time zone.
    Date(NaiveDate),
    /// `DUE` as a UTC date-time.
    At(DateTime<Utc>),
}

impl Due {
    /// Sort key: date-only values sort at the start of their day.
    pub fn sort_key(&self) -> DateTime<Utc> {
        match self {
            Due::Date(d) => d
                .and_hms_opt(0, 0, 0)
                .expect("midnight is always valid")
                .and_utc(),
            Due::At(dt) => *dt,
        }
    }

    /// Canonical string form: `YYYY-MM-DD` or RFC 3339 in UTC.
    pub fn to_display_string(&self) -> String {
        match self {
            Due::Date(d) => d.format("%Y-%m-%d").to_string(),
            Due::At(dt) => format_instant(*dt),
        }
    }
}

impl serde::Serialize for Due {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_display_string())
    }
}

/// RFC 3339 in UTC with second precision, e.g. `2026-08-22T12:00:00Z`.
pub fn format_instant(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

const OFFSET_HINT: &str = "date-times need a UTC offset (2026-08-22T16:00:00+04:00), \
     a trailing Z, or an IANA time zone (2026-08-22T16:00:00[Asia/Dubai])";

/// Parse an instant. Accepts RFC 3339, or a naive date-time qualified by an
/// IANA zone written as `...[Area/City]` or `... Area/City`.
pub fn parse_instant(input: &str) -> Result<DateTime<Utc>> {
    let text = input.trim();
    if text.is_empty() {
        return Err(Error::usage("empty date-time value"));
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
        return Ok(dt.with_timezone(&Utc));
    }

    if let Some((naive_part, zone_part)) = split_zone(text) {
        let naive = parse_naive_datetime(naive_part)?;
        let tz: Tz = zone_part
            .parse()
            .map_err(|_| Error::usage(format!("unknown IANA time zone {zone_part:?}")))?;
        return match tz.from_local_datetime(&naive) {
            chrono::LocalResult::Single(dt) => Ok(dt.with_timezone(&Utc)),
            chrono::LocalResult::Ambiguous(_, _) => Err(Error::usage(format!(
                "{text:?} is ambiguous in {zone_part} because of a daylight saving \
                 transition; use an explicit UTC offset instead"
            ))),
            chrono::LocalResult::None => Err(Error::usage(format!(
                "{text:?} does not exist in {zone_part} because of a daylight saving \
                 transition"
            ))),
        };
    }

    // Give a targeted message when the value merely lacks zone information.
    if parse_naive_datetime(text).is_ok() {
        return Err(Error::usage(format!(
            "{text:?} has no time zone: {OFFSET_HINT}"
        )));
    }

    Err(Error::usage(format!(
        "{text:?} is not a valid date-time: {OFFSET_HINT}"
    )))
}

/// Parse a due value: a bare calendar date or an instant.
pub fn parse_due(input: &str) -> Result<Due> {
    let text = input.trim();
    if is_calendar_date(text) {
        let date = NaiveDate::parse_from_str(text, "%Y-%m-%d")
            .map_err(|_| Error::usage(format!("{text:?} is not a valid calendar date")))?;
        return Ok(Due::Date(date));
    }
    parse_instant(text).map(Due::At)
}

/// True for exactly `YYYY-MM-DD`.
fn is_calendar_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}

/// Split `2026-08-22T16:00:00[Asia/Dubai]` or `2026-08-22T16:00 Asia/Dubai`
/// into the naive part and the zone name.
fn split_zone(text: &str) -> Option<(&str, &str)> {
    if let Some(open) = text.find('[') {
        let rest = &text[open + 1..];
        let close = rest.find(']')?;
        if !rest[close + 1..].trim().is_empty() {
            return None;
        }
        return Some((text[..open].trim(), rest[..close].trim()));
    }
    let (left, right) = text.rsplit_once(char::is_whitespace)?;
    if right.contains('/') || right.eq_ignore_ascii_case("utc") {
        return Some((left.trim(), right.trim()));
    }
    None
}

/// Accept `T` or a space separator, with or without seconds.
fn parse_naive_datetime(text: &str) -> Result<NaiveDateTime> {
    for format in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(text, format) {
            return Ok(dt);
        }
    }
    Err(Error::usage(format!("{text:?} is not a valid date-time")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_rfc3339_with_offset() {
        let dt = parse_instant("2026-08-22T16:00:00+04:00").unwrap();
        assert_eq!(format_instant(dt), "2026-08-22T12:00:00Z");
    }

    #[test]
    fn accepts_rfc3339_zulu() {
        let dt = parse_instant("2026-08-22T12:00:00Z").unwrap();
        assert_eq!(format_instant(dt), "2026-08-22T12:00:00Z");
    }

    #[test]
    fn accepts_bracketed_iana_zone() {
        let dt = parse_instant("2026-08-22T16:00:00[Asia/Dubai]").unwrap();
        assert_eq!(format_instant(dt), "2026-08-22T12:00:00Z");
    }

    #[test]
    fn accepts_space_separated_iana_zone_without_seconds() {
        let dt = parse_instant("2026-08-22T16:00 Asia/Dubai").unwrap();
        assert_eq!(format_instant(dt), "2026-08-22T12:00:00Z");
    }

    #[test]
    fn rejects_naive_datetime() {
        let err = parse_instant("2026-08-22T16:00:00").unwrap_err();
        assert!(err.to_string().contains("no time zone"), "{err}");
        assert_eq!(err.exit_code(), crate::error::exit::USAGE);
    }

    #[test]
    fn rejects_unknown_zone() {
        let err = parse_instant("2026-08-22T16:00:00[Mars/Olympus]").unwrap_err();
        assert!(err.to_string().contains("unknown IANA time zone"), "{err}");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_instant("tomorrow").is_err());
        assert!(parse_instant("").is_err());
    }

    #[test]
    fn rejects_nonexistent_local_time_in_dst_gap() {
        // 2026-03-29 01:30 does not exist in Europe/London (clocks jump 01:00 -> 02:00).
        let err = parse_instant("2026-03-29T01:30:00[Europe/London]").unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn rejects_ambiguous_local_time_in_dst_overlap() {
        // 2026-10-25 01:30 happens twice in Europe/London.
        let err = parse_instant("2026-10-25T01:30:00[Europe/London]").unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }

    #[test]
    fn parses_calendar_date() {
        assert_eq!(
            parse_due("2026-08-22").unwrap(),
            Due::Date(NaiveDate::from_ymd_opt(2026, 8, 22).unwrap())
        );
    }

    #[test]
    fn rejects_impossible_calendar_date() {
        let err = parse_due("2026-02-30").unwrap_err();
        assert!(
            err.to_string().contains("not a valid calendar date"),
            "{err}"
        );
    }

    #[test]
    fn due_display_round_trips() {
        assert_eq!(
            parse_due("2026-08-22").unwrap().to_display_string(),
            "2026-08-22"
        );
        assert_eq!(
            parse_due("2026-08-22T16:00:00+04:00")
                .unwrap()
                .to_display_string(),
            "2026-08-22T12:00:00Z"
        );
    }

    #[test]
    fn date_only_sorts_before_same_day_times() {
        let date = parse_due("2026-08-22").unwrap();
        let timed = parse_due("2026-08-22T00:00:01Z").unwrap();
        assert!(date.sort_key() < timed.sort_key());
    }

    #[test]
    fn zone_split_rejects_trailing_junk() {
        assert!(split_zone("2026-08-22T16:00:00[Asia/Dubai]x").is_none());
        assert!(split_zone("2026-08-22T16:00:00 not-a-zone").is_none());
    }
}
