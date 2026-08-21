//! WebDAV `multistatus` parsing, limited to the properties reminders need.

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{Error, Result};

/// One `<propstat>` element: a group of properties and the status that applies
/// to *that group only*.
///
/// RFC 4918 section 13 lets one `<response>` carry several `<propstat>`
/// elements, and servers routinely use two: a `200 OK` group holding the
/// properties they could return, and a `404 Not Found` group naming the ones
/// they could not. Flattening the statuses together makes a perfectly good
/// `calendar-data` look like a missing resource, so each group keeps its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PropStat {
    /// The `<status>` line for this group, e.g. `HTTP/1.1 200 OK`.
    pub status: Option<String>,
    /// `<getetag>` from this group.
    pub etag: Option<String>,
    /// `<calendar-data>` from this group, with surrounding whitespace removed.
    pub calendar_data: Option<String>,
}

impl PropStat {
    /// The numeric code from the status line, when there is one.
    pub fn status_code(&self) -> Option<u16> {
        self.status.as_deref().and_then(parse_status_code)
    }

    /// Whether the properties in this group were actually returned.
    ///
    /// A group with no status line at all is treated as successful: it is not
    /// legal WebDAV, but the properties are there and refusing them would be
    /// less useful than using them.
    pub fn is_success(&self) -> bool {
        match self.status_code() {
            Some(code) => (200..300).contains(&code),
            None => true,
        }
    }
}

/// One `<response>` element from a `multistatus` document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The `<href>` value, as sent by the server.
    pub href: String,
    /// A `<status>` that is a direct child of `<response>`, which RFC 4918
    /// allows instead of `<propstat>` when one status covers the whole href.
    pub status: Option<String>,
    /// The `<propstat>` groups, in document order.
    pub propstats: Vec<PropStat>,
}

impl Entry {
    /// The numeric code of the response-level status, when there is one.
    pub fn status_code(&self) -> Option<u16> {
        self.status.as_deref().and_then(parse_status_code)
    }

    /// `getetag` from a group that actually succeeded.
    pub fn etag(&self) -> Option<&str> {
        self.propstats
            .iter()
            .filter(|propstat| propstat.is_success())
            .filter_map(|propstat| propstat.etag.as_deref())
            .find(|etag| !etag.is_empty())
    }

    /// `calendar-data` from a group that actually succeeded.
    pub fn calendar_data(&self) -> Option<&str> {
        self.propstats
            .iter()
            .filter(|propstat| propstat.is_success())
            .filter_map(|propstat| propstat.calendar_data.as_deref())
            .find(|data| !data.is_empty())
    }

    /// True when this response carries nothing usable and says so.
    ///
    /// A 404 on *some* property group is not enough: what matters is whether
    /// any group succeeded with something in it.
    pub fn is_not_found(&self) -> bool {
        if self.etag().is_some() || self.calendar_data().is_some() {
            return false;
        }
        if self.status_code() == Some(404) {
            return true;
        }
        self.propstats
            .iter()
            .any(|propstat| propstat.status_code() == Some(404))
    }
}

/// Pull the numeric code out of `HTTP/1.1 200 OK`.
fn parse_status_code(status: &str) -> Option<u16> {
    status
        .split_whitespace()
        .filter_map(|token| token.parse::<u16>().ok())
        .find(|code| (100..600).contains(code))
}

/// Which leaf element's text we are currently collecting.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    None,
    Href,
    Etag,
    CalendarData,
    PropStatStatus,
    ResponseStatus,
}

/// Describe a parse failure without quoting the document.
///
/// quick-xml's own messages embed fragments of the input, and the input is an
/// authenticated server's response, so it could contain reflected credentials.
/// This maps the failure to a fixed label instead.
fn classify_xml_error(err: &quick_xml::Error) -> &'static str {
    match err {
        quick_xml::Error::Io(_) => "read error",
        quick_xml::Error::Syntax(_) => "syntax error",
        quick_xml::Error::Encoding(_) => "encoding error",
        quick_xml::Error::IllFormed(_) => "ill-formed markup",
        quick_xml::Error::InvalidAttr(_) => "invalid attribute",
        quick_xml::Error::Escape(_) => "invalid escape",
        _ => "parse error",
    }
}

/// Parse a `multistatus` body.
///
/// Namespace prefixes are ignored and only local element names are matched,
/// because servers disagree about which prefix maps to `DAV:`.
///
/// Failures report a category and a byte offset, never a fragment of the
/// document.
pub fn parse_multistatus(xml: &str) -> Result<Vec<Entry>> {
    let mut reader = Reader::from_str(xml);
    // Never trim: folded iCalendar continuation lines begin with a space.
    reader.config_mut().trim_text(false);

    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    let mut target = Target::None;
    let mut buffer = String::new();
    let mut saw_multistatus = false;
    // Element names of the open elements, so `<status>` can be attributed to
    // the right parent and an `<href>` nested inside `<owner>` ignored.
    let mut stack: Vec<String> = Vec::new();

    loop {
        let event = reader.read_event().map_err(|err| {
            Error::server(format!(
                "cannot parse the server's XML response: {} at byte {}",
                classify_xml_error(&err),
                reader.buffer_position()
            ))
        })?;
        match event {
            Event::Eof => break,
            Event::Start(start) => {
                let name = local_name(start.local_name().as_ref());
                let parent = stack.last().map(String::as_str).unwrap_or("");
                match (parent, name.as_str()) {
                    (_, "multistatus") => saw_multistatus = true,
                    ("multistatus", "response") => current = Some(Entry::default()),
                    ("response", "propstat") => {
                        if let Some(entry) = current.as_mut() {
                            entry.propstats.push(PropStat::default());
                        }
                    }
                    // Only the href that names the resource, never one buried
                    // in a property value such as `<owner><href>`.
                    ("response", "href") => target = Target::Href,
                    ("response", "status") => target = Target::ResponseStatus,
                    ("propstat", "status") => target = Target::PropStatStatus,
                    (_, "getetag") => target = Target::Etag,
                    (_, "calendar-data") => target = Target::CalendarData,
                    _ => {}
                }
                stack.push(name);
                buffer.clear();
            }
            Event::Empty(start) => {
                // Self-closing elements carry no text, so they open no target
                // and never enter the stack. `<getetag/>` inside a 404 group is
                // the server saying the property is absent, which is already
                // what a missing value means here.
                let name = local_name(start.local_name().as_ref());
                if name == "multistatus" {
                    saw_multistatus = true;
                }
                if name == "propstat" {
                    if let Some(entry) = current.as_mut() {
                        entry.propstats.push(PropStat::default());
                    }
                }
                target = Target::None;
                buffer.clear();
            }
            Event::Text(text) => {
                if target != Target::None {
                    let decoded = text.xml10_content().map_err(|_| {
                        Error::server(format!(
                            "the server's XML response is not valid UTF-8 at byte {}",
                            reader.buffer_position()
                        ))
                    })?;
                    buffer.push_str(&decoded);
                }
            }
            // quick-xml reports `&amp;` and `&#13;` as separate events so that
            // callers can decide how to resolve them.
            Event::GeneralRef(reference) => {
                if target != Target::None {
                    let resolved = reference.resolve_char_ref().map_err(|_| {
                        Error::server(format!(
                            "the server's XML response has an invalid character reference at \
                             byte {}",
                            reader.buffer_position()
                        ))
                    })?;
                    match resolved {
                        Some(ch) => buffer.push(ch),
                        None => {
                            let name = reference.decode().map_err(|_| {
                                Error::server(format!(
                                    "the server's XML response has an undecodable entity at \
                                     byte {}",
                                    reader.buffer_position()
                                ))
                            })?;
                            match quick_xml::escape::resolve_predefined_entity(&name) {
                                Some(text) => buffer.push_str(text),
                                None => {
                                    return Err(Error::server(format!(
                                        "the server's XML response uses an entity that is not \
                                         predefined in XML, at byte {}",
                                        reader.buffer_position()
                                    )))
                                }
                            }
                        }
                    }
                }
            }
            Event::CData(data) => {
                if target != Target::None {
                    let decoded = String::from_utf8_lossy(data.as_ref()).to_string();
                    buffer.push_str(&decoded);
                }
            }
            Event::End(end) => {
                let name = local_name(end.local_name().as_ref());
                stack.pop();
                if let Some(entry) = current.as_mut() {
                    match (name.as_str(), target) {
                        ("href", Target::Href) => {
                            if entry.href.is_empty() {
                                entry.href = buffer.trim().to_string();
                            }
                        }
                        ("status", Target::ResponseStatus) => {
                            entry.status = Some(buffer.trim().to_string());
                        }
                        ("status", Target::PropStatStatus) => {
                            if let Some(propstat) = entry.propstats.last_mut() {
                                propstat.status = Some(buffer.trim().to_string());
                            }
                        }
                        ("getetag", Target::Etag) => {
                            if let Some(propstat) = entry.propstats.last_mut() {
                                propstat.etag = Some(buffer.trim().to_string());
                            }
                        }
                        ("calendar-data", Target::CalendarData) => {
                            if let Some(propstat) = entry.propstats.last_mut() {
                                propstat.calendar_data = Some(buffer.trim().to_string());
                            }
                        }
                        _ => {}
                    }
                }
                if name == "response" {
                    if let Some(entry) = current.take() {
                        entries.push(entry);
                    }
                }
                target = Target::None;
                buffer.clear();
            }
            _ => {}
        }
    }

    if !saw_multistatus {
        return Err(Error::server(
            "the server did not return a WebDAV multistatus document",
        ));
    }
    Ok(entries)
}

fn local_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_lowercase()
}

/// Escape text for inclusion in an XML element.
pub fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RADICALE: &str = r#"<?xml version="1.0"?>
<multistatus xmlns="DAV:" xmlns:CAL="urn:ietf:params:xml:ns:caldav">
  <response>
    <href>/agent/tasks/abc.ics</href>
    <propstat>
      <prop>
        <getetag>"1f2e3d"</getetag>
        <CAL:calendar-data>BEGIN:VCALENDAR&#13;
VERSION:2.0&#13;
BEGIN:VTODO&#13;
UID:abc&#13;
SUMMARY:Buy milk&#13;
END:VTODO&#13;
END:VCALENDAR&#13;
</CAL:calendar-data>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>
</multistatus>"#;

    #[test]
    fn parses_radicale_style_response() {
        let entries = parse_multistatus(RADICALE).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.href, "/agent/tasks/abc.ics");
        assert_eq!(entry.etag(), Some("\"1f2e3d\""));
        assert_eq!(entry.propstats.len(), 1);
        assert_eq!(entry.propstats[0].status_code(), Some(200));
        let data = entry.calendar_data().unwrap();
        assert!(data.starts_with("BEGIN:VCALENDAR"), "{data}");
        assert!(data.contains("SUMMARY:Buy milk"), "{data}");
        assert!(!entry.is_not_found());
    }

    #[test]
    fn parsed_calendar_data_is_usable_by_the_ical_parser() {
        let entries = parse_multistatus(RADICALE).unwrap();
        let data = entries[0].calendar_data().unwrap().to_string();
        let doc = crate::ical::Document::parse(&data).unwrap();
        assert_eq!(doc.to_reminder(None, None).unwrap().title, "Buy milk");
    }

    #[test]
    fn ignores_namespace_prefixes() {
        let xml = r#"<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<D:response><D:href>/a.ics</D:href><D:propstat><D:prop>
<D:getetag>"e"</D:getetag><C:calendar-data>BEGIN:VCALENDAR
END:VCALENDAR</C:calendar-data>
</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>
</D:multistatus>"#;
        let entries = parse_multistatus(xml).unwrap();
        assert_eq!(entries[0].href, "/a.ics");
        assert_eq!(entries[0].etag(), Some("\"e\""));
        assert!(entries[0].calendar_data().is_some());
    }

    #[test]
    fn resolves_character_references_so_crlf_survives() {
        let entries = parse_multistatus(RADICALE).unwrap();
        let data = entries[0].calendar_data().unwrap();
        assert!(data.contains("VERSION:2.0\r\n"), "CR lost: {data:?}");
    }

    #[test]
    fn resolves_predefined_entities() {
        let xml = "<multistatus xmlns=\"DAV:\"><response><href>/a.ics</href><propstat><prop>\
<calendar-data>BEGIN:VCALENDAR\nSUMMARY:a &amp; b &lt;c&gt;\nEND:VCALENDAR</calendar-data>\
</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>";
        let entries = parse_multistatus(xml).unwrap();
        assert!(entries[0]
            .calendar_data()
            .unwrap()
            .contains("SUMMARY:a & b <c>"));
    }

    #[test]
    fn preserves_folded_continuation_lines() {
        let xml = "<multistatus xmlns=\"DAV:\"><response><href>/a.ics</href><propstat><prop>\
<calendar-data>BEGIN:VCALENDAR\nDESCRIPTION:aaa\n bbb\nEND:VCALENDAR</calendar-data>\
</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>";
        let entries = parse_multistatus(xml).unwrap();
        let data = entries[0].calendar_data().unwrap();
        assert!(data.contains("\n bbb"), "fold marker lost: {data:?}");
        let doc = crate::ical::Document::parse(&format!(
            "BEGIN:VCALENDAR\nBEGIN:VTODO\nUID:x\n{}\nEND:VTODO\nEND:VCALENDAR",
            "DESCRIPTION:aaa\n bbb"
        ))
        .unwrap();
        assert_eq!(
            doc.to_reminder(None, None).unwrap().notes.as_deref(),
            Some("aaabbb")
        );
    }

    #[test]
    fn parses_multiple_responses() {
        let xml = r#"<multistatus xmlns="DAV:">
<response><href>/a.ics</href><propstat><prop><getetag>"1"</getetag></prop><status>HTTP/1.1 200 OK</status></propstat></response>
<response><href>/b.ics</href><propstat><prop><getetag>"2"</getetag></prop><status>HTTP/1.1 200 OK</status></propstat></response>
</multistatus>"#;
        let entries = parse_multistatus(xml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].href, "/b.ics");
        assert_eq!(entries[1].etag(), Some("\"2\""));
    }

    #[test]
    fn detects_not_found_propstat() {
        let xml = r#"<multistatus xmlns="DAV:">
<response><href>/missing.ics</href><propstat><prop><getetag/></prop>
<status>HTTP/1.1 404 Not Found</status></propstat></response>
</multistatus>"#;
        let entries = parse_multistatus(xml).unwrap();
        assert!(entries[0].is_not_found());
        assert_eq!(entries[0].calendar_data(), None);
        assert_eq!(entries[0].etag(), None);
    }

    /// The regression: two propstat groups, one succeeding with the calendar
    /// data and one reporting 404 for a property the server could not produce.
    /// Flattening the statuses made the whole resource look missing.
    #[test]
    fn a_404_propstat_does_not_hide_calendar_data_in_a_200_propstat() {
        let xml = r#"<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<response>
  <href>/u/tasks/mixed.ics</href>
  <propstat>
    <prop>
      <getetag>"good"</getetag>
      <C:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:mixed
SUMMARY:Still here
END:VTODO
END:VCALENDAR</C:calendar-data>
    </prop>
    <status>HTTP/1.1 200 OK</status>
  </propstat>
  <propstat>
    <prop><displayname/><resourcetype/></prop>
    <status>HTTP/1.1 404 Not Found</status>
  </propstat>
</response>
</multistatus>"#;
        let entries = parse_multistatus(xml).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.propstats.len(), 2);
        assert!(
            !entry.is_not_found(),
            "a usable resource was reported missing"
        );
        assert_eq!(entry.etag(), Some("\"good\""));
        let data = entry.calendar_data().expect("calendar data must survive");
        assert!(data.contains("SUMMARY:Still here"), "{data}");
    }

    /// The mirror image: the ETag is in the 404 group and the data in the 200
    /// group. The data must still be used, and the ETag must be treated as
    /// absent rather than picked up from a failed group.
    #[test]
    fn an_etag_in_a_404_propstat_is_not_used() {
        let xml = r#"<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<response>
  <href>/u/tasks/noetag.ics</href>
  <propstat>
    <prop><C:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:noetag
END:VTODO
END:VCALENDAR</C:calendar-data></prop>
    <status>HTTP/1.1 200 OK</status>
  </propstat>
  <propstat>
    <prop><getetag>"from-a-failed-group"</getetag></prop>
    <status>HTTP/1.1 404 Not Found</status>
  </propstat>
</response>
</multistatus>"#;
        let entry = &parse_multistatus(xml).unwrap()[0];
        assert!(!entry.is_not_found());
        assert!(entry.calendar_data().is_some());
        assert_eq!(entry.etag(), None, "must not trust a failed propstat");
    }

    #[test]
    fn a_response_level_status_is_kept_apart_from_propstat_statuses() {
        let xml = r#"<multistatus xmlns="DAV:">
<response><href>/gone.ics</href><status>HTTP/1.1 404 Not Found</status></response>
</multistatus>"#;
        let entry = &parse_multistatus(xml).unwrap()[0];
        assert_eq!(entry.status_code(), Some(404));
        assert!(entry.propstats.is_empty());
        assert!(entry.is_not_found());
    }

    #[test]
    fn a_propstat_without_a_status_is_taken_at_face_value() {
        let xml = r#"<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<response><href>/a.ics</href><propstat><prop>
<getetag>"e"</getetag><C:calendar-data>BEGIN:VCALENDAR
END:VCALENDAR</C:calendar-data>
</prop></propstat></response></multistatus>"#;
        let entry = &parse_multistatus(xml).unwrap()[0];
        assert!(entry.propstats[0].is_success());
        assert_eq!(entry.etag(), Some("\"e\""));
        assert!(!entry.is_not_found());
    }

    #[test]
    fn other_success_codes_count_as_success() {
        for line in [
            "HTTP/1.1 200 OK",
            "HTTP/1.1 207 Multi-Status",
            "HTTP/1.0 226 IM Used",
        ] {
            let propstat = PropStat {
                status: Some(line.to_string()),
                etag: Some("\"e\"".into()),
                calendar_data: None,
            };
            assert!(propstat.is_success(), "{line}");
        }
        for line in [
            "HTTP/1.1 404 Not Found",
            "HTTP/1.1 403 Forbidden",
            "HTTP/1.1 500 Oops",
        ] {
            let propstat = PropStat {
                status: Some(line.to_string()),
                etag: Some("\"e\"".into()),
                calendar_data: None,
            };
            assert!(!propstat.is_success(), "{line}");
        }
    }

    #[test]
    fn status_codes_are_extracted_from_the_status_line() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found"), Some(404));
        // The version number must not be mistaken for the code.
        assert_eq!(
            parse_status_code("HTTP/1.0 500 Internal Server Error"),
            Some(500)
        );
        assert_eq!(parse_status_code("nonsense"), None);
        assert_eq!(parse_status_code(""), None);
        // Out-of-range numbers are not status codes.
        assert_eq!(parse_status_code("HTTP/1.1 99 Nope"), None);
        assert_eq!(parse_status_code("HTTP/1.1 6000 Nope"), None);
    }

    #[test]
    fn empty_property_values_are_not_mistaken_for_data() {
        let xml = r#"<multistatus xmlns="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
<response><href>/a.ics</href><propstat><prop>
<getetag></getetag><C:calendar-data></C:calendar-data>
</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"#;
        let entry = &parse_multistatus(xml).unwrap()[0];
        assert_eq!(entry.etag(), None);
        assert_eq!(entry.calendar_data(), None);
    }

    #[test]
    fn ignores_an_href_nested_inside_a_property_value() {
        let xml = r#"<multistatus xmlns="DAV:"><response>
<href>/first.ics</href>
<propstat><prop><owner><href>/principals/me/</href></owner></prop><status>HTTP/1.1 200 OK</status></propstat>
</response></multistatus>"#;
        let entries = parse_multistatus(xml).unwrap();
        assert_eq!(entries[0].href, "/first.ics");
    }

    #[test]
    fn handles_cdata_sections() {
        let xml = "<multistatus xmlns=\"DAV:\"><response><href>/a.ics</href><propstat><prop>\
<calendar-data><![CDATA[BEGIN:VCALENDAR\nEND:VCALENDAR]]></calendar-data>\
</prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>";
        let entries = parse_multistatus(xml).unwrap();
        assert_eq!(
            entries[0].calendar_data(),
            Some("BEGIN:VCALENDAR\nEND:VCALENDAR")
        );
    }

    #[test]
    fn rejects_documents_that_are_not_multistatus() {
        let err = parse_multistatus("<html><body>Nope</body></html>").unwrap_err();
        assert!(err.to_string().contains("multistatus"), "{err}");
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);
    }

    #[test]
    fn rejects_malformed_xml() {
        let err = parse_multistatus("<multistatus xmlns=\"DAV:\"><response").unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::SERVER);
    }

    #[test]
    fn empty_multistatus_yields_no_entries() {
        let entries = parse_multistatus("<multistatus xmlns=\"DAV:\"/>").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn escapes_xml_special_characters() {
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }
}
