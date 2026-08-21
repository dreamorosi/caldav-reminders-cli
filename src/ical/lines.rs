//! RFC 5545 content lines: folding, unfolding, escaping, and parameters.

use std::fmt::Write as _;

use crate::error::{Error, Result};

/// Maximum octets per physical line, excluding CRLF (RFC 5545 section 3.1).
const MAX_OCTETS: usize = 75;

/// One logical property line: `NAME;PARAM=value:VALUE`.
///
/// `value` is stored in its escaped, on-the-wire form so unknown properties
/// survive a read/write cycle byte for byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLine {
    /// Upper-case property name, e.g. `SUMMARY`.
    pub name: String,
    /// Parameters in source order, names upper-cased.
    pub params: Vec<(String, String)>,
    /// Raw, still-escaped value.
    pub value: String,
}

impl ContentLine {
    /// Build a line whose value is a TEXT type; the value is escaped for you.
    pub fn text(name: &str, value: &str) -> Self {
        ContentLine {
            name: name.to_ascii_uppercase(),
            params: Vec::new(),
            value: escape_text(value),
        }
    }

    /// Build a line whose value needs no escaping (dates, integers, enums).
    pub fn raw(name: &str, value: impl Into<String>) -> Self {
        ContentLine {
            name: name.to_ascii_uppercase(),
            params: Vec::new(),
            value: value.into(),
        }
    }

    /// Add a parameter, returning self for chaining.
    pub fn with_param(mut self, name: &str, value: &str) -> Self {
        self.params
            .push((name.to_ascii_uppercase(), value.to_string()));
        self
    }

    /// Look up a parameter value, case-insensitively by name.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The value with TEXT escaping removed.
    pub fn text_value(&self) -> String {
        unescape_text(&self.value)
    }

    /// Parse one already-unfolded logical line.
    ///
    /// Failures describe *where* the line is malformed and never quote it. The
    /// line comes from an authenticated server, which could have put the
    /// credentials it was sent into a property value.
    pub fn parse(line: &str) -> Result<Self> {
        let bytes = line.as_bytes();
        let mut index = 0;

        // Property name runs to the first ';' or ':'.
        while index < bytes.len() && bytes[index] != b';' && bytes[index] != b':' {
            index += 1;
        }
        if index == 0 || index == bytes.len() {
            return Err(Error::server(format!(
                "malformed iCalendar content line at byte 0 of {} (no property name, or no \
                 ':' separator)",
                bytes.len()
            )));
        }
        let name = line[..index].to_ascii_uppercase();

        // Parameters, up to the first colon that is not inside a quoted string.
        let mut params = Vec::new();
        while bytes[index] == b';' {
            index += 1;
            let start = index;
            let mut quoted = false;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => quoted = !quoted,
                    b';' | b':' if !quoted => break,
                    _ => {}
                }
                index += 1;
            }
            if index == bytes.len() {
                return Err(Error::server(format!(
                    "iCalendar content line of {} bytes ends inside its parameters, with no \
                     ':' separator",
                    bytes.len()
                )));
            }
            let chunk = &line[start..index];
            let (key, raw_value) = chunk.split_once('=').ok_or_else(|| {
                Error::server(format!(
                    "iCalendar parameter at byte {start} is missing '='"
                ))
            })?;
            params.push((
                key.to_ascii_uppercase(),
                strip_quotes(raw_value).to_string(),
            ));
        }

        debug_assert_eq!(bytes[index], b':');
        Ok(ContentLine {
            name,
            params,
            value: line[index + 1..].to_string(),
        })
    }

    /// Render back to a single logical line, unfolded.
    pub fn to_logical_line(&self) -> String {
        let mut out = String::with_capacity(self.name.len() + self.value.len() + 8);
        out.push_str(&self.name);
        for (key, value) in &self.params {
            let _ = write!(out, ";{key}={}", quote_param_if_needed(value));
        }
        out.push(':');
        out.push_str(&self.value);
        out
    }
}

fn strip_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    }
}

/// Parameter values containing `:`, `;`, or `,` must be quoted.
fn quote_param_if_needed(value: &str) -> String {
    if value.contains([':', ';', ',', '"']) {
        format!("\"{}\"", value.replace('"', ""))
    } else {
        value.to_string()
    }
}

/// Escape a TEXT value: backslash, semicolon, comma, and newlines.
///
/// Colons are deliberately left alone; RFC 5545 does not escape them in TEXT.
pub fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            // A bare CR is not representable; fold it into the newline escape.
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

/// Reverse [`escape_text`]. Unknown escapes keep their literal character,
/// which is what every real-world parser does.
pub fn unescape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(';') => out.push(';'),
            Some(',') => out.push(','),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Fold one logical line into CRLF-terminated physical lines of at most 75
/// octets, never splitting a UTF-8 character.
pub fn fold(line: &str) -> String {
    let mut out = String::with_capacity(line.len() + line.len() / MAX_OCTETS + 2);
    let mut budget = MAX_OCTETS;
    let mut used = 0usize;

    for ch in line.chars() {
        let width = ch.len_utf8();
        if used + width > budget {
            out.push_str("\r\n ");
            // The leading space counts toward the 75 octets.
            budget = MAX_OCTETS - 1;
            used = 0;
        }
        out.push(ch);
        used += width;
    }
    out.push_str("\r\n");
    out
}

/// Unfold an iCalendar document into logical lines.
///
/// Accepts CRLF, LF, and CR line endings, and both space and tab continuations.
pub fn unfold(text: &str) -> Vec<String> {
    let mut logical: Vec<String> = Vec::new();
    for physical in text.split('\n') {
        let physical = physical.strip_suffix('\r').unwrap_or(physical);
        if let Some(rest) = physical
            .strip_prefix(' ')
            .or_else(|| physical.strip_prefix('\t'))
        {
            if let Some(last) = logical.last_mut() {
                last.push_str(rest);
                continue;
            }
        }
        if physical.is_empty() {
            continue;
        }
        logical.push(physical.to_string());
    }
    logical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_reserved_text_characters() {
        assert_eq!(escape_text("a,b;c\\d\ne"), "a\\,b\\;c\\\\d\\ne");
    }

    #[test]
    fn does_not_escape_colon_in_text() {
        assert_eq!(escape_text("http://example.com"), "http://example.com");
    }

    #[test]
    fn unescape_reverses_escape() {
        for original in [
            "plain",
            "a,b;c\\d\ne",
            "trailing backslash \\",
            "http://x/y?z=1",
            "emoji \u{1f680} and accents \u{e9}",
        ] {
            assert_eq!(
                unescape_text(&escape_text(original)),
                original,
                "{original}"
            );
        }
    }

    #[test]
    fn unescape_keeps_unknown_escapes_literal() {
        assert_eq!(unescape_text("\\q"), "q");
        assert_eq!(unescape_text("ends with \\"), "ends with \\");
    }

    #[test]
    fn carriage_returns_are_dropped_not_emitted_raw() {
        assert_eq!(escape_text("a\r\nb"), "a\\nb");
    }

    #[test]
    fn folds_at_seventy_five_octets() {
        let line = format!("DESCRIPTION:{}", "x".repeat(200));
        let folded = fold(&line);
        assert!(folded.ends_with("\r\n"));
        for (index, physical) in folded.trim_end_matches("\r\n").split("\r\n").enumerate() {
            assert!(
                physical.len() <= MAX_OCTETS,
                "line {index} is {} octets: {physical}",
                physical.len()
            );
            if index > 0 {
                assert!(
                    physical.starts_with(' '),
                    "continuation must start with space"
                );
            }
        }
    }

    #[test]
    fn folding_never_splits_multibyte_characters() {
        // Four-byte characters force the folder to stop short of the limit.
        let line = format!("DESCRIPTION:{}", "\u{1f680}".repeat(80));
        let folded = fold(&line);
        for physical in folded.trim_end_matches("\r\n").split("\r\n") {
            assert!(physical.len() <= MAX_OCTETS);
            // If a character had been split, this string would not be valid UTF-8
            // and we could not have got here; assert the round trip instead.
        }
        let unfolded = unfold(&folded);
        assert_eq!(unfolded, vec![line]);
    }

    #[test]
    fn fold_unfold_round_trip_for_short_line() {
        let line = "SUMMARY:hello";
        assert_eq!(unfold(&fold(line)), vec![line.to_string()]);
    }

    #[test]
    fn unfold_accepts_tab_continuations_and_bare_lf() {
        let text = "SUMMARY:hel\n\tlo\nDESCRIPTION:x\n y\n";
        assert_eq!(
            unfold(text),
            vec!["SUMMARY:hello".to_string(), "DESCRIPTION:xy".to_string()]
        );
    }

    #[test]
    fn unfold_preserves_significant_leading_space_after_join() {
        // A folded value whose next chunk legitimately starts with a space is
        // encoded with two spaces; the first is the fold marker.
        assert_eq!(unfold("SUMMARY:a\n  b\n"), vec!["SUMMARY:a b".to_string()]);
    }

    #[test]
    fn parses_name_params_and_value() {
        let line = ContentLine::parse("DUE;VALUE=DATE:20260822").unwrap();
        assert_eq!(line.name, "DUE");
        assert_eq!(line.param("value"), Some("DATE"));
        assert_eq!(line.value, "20260822");
    }

    #[test]
    fn parses_quoted_parameter_containing_colon_and_semicolon() {
        let line =
            ContentLine::parse("ATTACH;FMTTYPE=\"text/plain;x=:y\":http://example.com/a").unwrap();
        assert_eq!(line.name, "ATTACH");
        assert_eq!(line.param("FMTTYPE"), Some("text/plain;x=:y"));
        assert_eq!(line.value, "http://example.com/a");
    }

    #[test]
    fn parses_value_containing_colons() {
        let line = ContentLine::parse("SUMMARY:12:34:56").unwrap();
        assert_eq!(line.value, "12:34:56");
    }

    #[test]
    fn parses_empty_value() {
        let line = ContentLine::parse("DESCRIPTION:").unwrap();
        assert_eq!(line.value, "");
    }

    #[test]
    fn parse_uppercases_names_but_not_values() {
        let line = ContentLine::parse("summary;language=en-GB:Keep Case").unwrap();
        assert_eq!(line.name, "SUMMARY");
        assert_eq!(line.params[0].0, "LANGUAGE");
        assert_eq!(line.params[0].1, "en-GB");
        assert_eq!(line.value, "Keep Case");
    }

    #[test]
    fn rejects_line_without_colon() {
        let err = ContentLine::parse("SUMMARY").unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);
    }

    #[test]
    fn rejects_empty_property_name() {
        assert!(ContentLine::parse(":value").is_err());
    }

    #[test]
    fn rejects_parameter_without_equals() {
        assert!(ContentLine::parse("DUE;VALUE:20260822").is_err());
    }

    #[test]
    fn round_trips_logical_line() {
        for source in [
            "SUMMARY:hello",
            "DUE;VALUE=DATE:20260822",
            "X-VENDOR-THING;X-P=1:opaque",
            "DESCRIPTION:a\\,b\\;c",
        ] {
            let parsed = ContentLine::parse(source).unwrap();
            assert_eq!(parsed.to_logical_line(), source, "{source}");
        }
    }

    #[test]
    fn requotes_parameters_that_need_it() {
        let parsed = ContentLine::parse("ATTACH;FMTTYPE=\"a;b\":x").unwrap();
        assert_eq!(parsed.to_logical_line(), "ATTACH;FMTTYPE=\"a;b\":x");
    }

    #[test]
    fn text_helper_escapes_and_text_value_unescapes() {
        let line = ContentLine::text("SUMMARY", "a;b");
        assert_eq!(line.value, "a\\;b");
        assert_eq!(line.text_value(), "a;b");
    }
}
