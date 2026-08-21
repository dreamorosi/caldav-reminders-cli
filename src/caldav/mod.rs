//! CalDAV over HTTP.
//!
//! Redirects are followed by hand so that HTTP Basic credentials are only ever
//! offered to the configured origin. TLS verification is always on and there is
//! no option to turn it off.

pub mod xml;

use std::time::Duration;

use reqwest::blocking::{Client as HttpClient, Response as HttpResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::config::Settings;
use crate::error::{Error, Result};

/// Maximum redirect hops we will follow.
const MAX_REDIRECTS: usize = 5;
/// Whole-request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest resource path echoed back in an error message.
const PATH_LIMIT: usize = 120;

/// `User-Agent` sent with every request.
pub const USER_AGENT: &str = concat!("reminders/", env!("CARGO_PKG_VERSION"));

/// One calendar resource on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Path of the resource, relative to the server root.
    pub href: String,
    /// Opaque ETag, when the server supplied one.
    pub etag: Option<String>,
    /// The `text/calendar` body.
    pub data: String,
}

/// A CalDAV client bound to one collection.
pub struct Client {
    http: HttpClient,
    collection: Url,
    username: String,
    password: SecretString,
}

impl Client {
    /// Build a client for the configured collection.
    pub fn new(settings: &Settings, password: &SecretString) -> Result<Client> {
        let http = HttpClient::builder()
            .user_agent(USER_AGENT)
            // Redirects are handled in `execute` so credentials never cross origins.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|err| Error::Network(format!("cannot build the HTTP client: {err}")))?;
        Ok(Client {
            http,
            collection: settings.collection_url()?,
            username: settings.username.clone(),
            password: password.clone(),
        })
    }

    /// The collection URL this client targets.
    pub fn collection_url(&self) -> &Url {
        &self.collection
    }

    /// Every VTODO in the collection, with ETags.
    pub fn list_todos(&self) -> Result<Vec<Resource>> {
        self.report(&calendar_query(None))
    }

    /// Find one VTODO by `UID`.
    ///
    /// Tries `<collection>/<uid>.ics` first, which is where this CLI puts its
    /// own resources, then falls back to a `UID` report for resources another
    /// client named differently.
    pub fn find_by_uid(&self, uid: &str) -> Result<Option<Resource>> {
        let direct = self.resource_url(&format!("{uid}.ics"))?;
        if let Some(resource) = self.get(&direct)? {
            if resource_uid_matches(&resource.data, uid) {
                return Ok(Some(resource));
            }
        }
        let mut found = self.report(&calendar_query(Some(uid)))?;
        // Guard against a server that ignores the filter.
        found.retain(|resource| resource_uid_matches(&resource.data, uid));
        Ok(found.into_iter().next())
    }

    /// `GET` a resource. `None` when the server says it is not there.
    pub fn get(&self, url: &Url) -> Result<Option<Resource>> {
        let response = self.execute(Method::GET, url.clone(), &[], None)?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        self.check(&response, "read the reminder")?;
        Ok(Some(Resource {
            href: url.path().to_string(),
            etag: etag_header(&response.headers),
            data: response.text()?,
        }))
    }

    /// Create a new resource, refusing to clobber an existing one.
    pub fn create(&self, uid: &str, ics: &str) -> Result<Resource> {
        let url = self.resource_url(&format!("{uid}.ics"))?;
        let response = self.execute(
            Method::PUT,
            url.clone(),
            &[
                ("content-type", "text/calendar; charset=utf-8"),
                ("if-none-match", "*"),
            ],
            Some(ics.as_bytes().to_vec()),
        )?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Err(Error::Conflict(format!(
                "a reminder with id {uid} already exists on the server"
            )));
        }
        self.check(&response, "create the reminder")?;
        let etag = match etag_header(&response.headers) {
            Some(etag) => Some(etag),
            // Not every server returns an ETag on PUT; ask for it once.
            None => self.get(&url)?.and_then(|resource| resource.etag),
        };
        Ok(Resource {
            href: url.path().to_string(),
            etag,
            data: ics.to_string(),
        })
    }

    /// Replace a resource, guarded by its ETag.
    ///
    /// The ETag is mandatory. An unconditional `PUT` would overwrite whatever
    /// the server currently holds, silently discarding an edit made elsewhere,
    /// so there is deliberately no way to ask for one.
    pub fn update(&self, href: &str, ics: &str, etag: &str) -> Result<Resource> {
        let url = self.resolve_href(href)?;
        let headers: Vec<(&str, &str)> = vec![
            ("content-type", "text/calendar; charset=utf-8"),
            ("if-match", etag),
        ];
        let response = self.execute(
            Method::PUT,
            url.clone(),
            &headers,
            Some(ics.as_bytes().to_vec()),
        )?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Err(conflict_error());
        }
        self.check(&response, "save the reminder")?;
        let new_etag = match etag_header(&response.headers) {
            Some(etag) => Some(etag),
            None => self.get(&url)?.and_then(|resource| resource.etag),
        };
        Ok(Resource {
            href: url.path().to_string(),
            etag: new_etag,
            data: ics.to_string(),
        })
    }

    /// Delete a resource, guarded by its ETag.
    ///
    /// Mandatory for the same reason as [`Client::update`]: an unconditional
    /// `DELETE` would discard an edit made elsewhere without noticing.
    pub fn delete(&self, href: &str, etag: &str) -> Result<()> {
        let url = self.resolve_href(href)?;
        let headers: Vec<(&str, &str)> = vec![("if-match", etag)];
        let response = self.execute(Method::DELETE, url, &headers, None)?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Err(conflict_error());
        }
        self.check(&response, "delete the reminder")?;
        Ok(())
    }

    /// Issue a `REPORT` and turn the multistatus into resources.
    fn report(&self, body: &str) -> Result<Vec<Resource>> {
        let method = Method::from_bytes(b"REPORT")
            .map_err(|err| Error::Network(format!("invalid HTTP method: {err}")))?;
        let response = self.execute(
            method,
            self.collection.clone(),
            &[
                ("content-type", "application/xml; charset=utf-8"),
                ("depth", "1"),
            ],
            Some(body.as_bytes().to_vec()),
        )?;
        if response.status == StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!(
                "the collection {} does not exist on the server",
                self.collection.path()
            )));
        }
        self.check(&response, "list reminders")?;
        let entries = xml::parse_multistatus(&response.text()?)?;
        let mut resources = Vec::with_capacity(entries.len());
        for entry in entries {
            // Only skip a response that carries nothing usable. A 404 on some
            // other property must not discard calendar data the server did
            // return in a successful propstat.
            if entry.is_not_found() {
                continue;
            }
            let Some(data) = entry.calendar_data() else {
                continue;
            };
            resources.push(Resource {
                href: entry.href.clone(),
                etag: entry.etag().map(str::to_string),
                data: data.to_string(),
            });
        }
        Ok(resources)
    }

    /// Build the URL of a child resource of the collection.
    fn resource_url(&self, name: &str) -> Result<Url> {
        let mut url = self.collection.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| Error::config("the server URL cannot have path segments"))?;
            segments.pop_if_empty().push(name);
        }
        Ok(url)
    }

    /// Turn a server-supplied href into an absolute URL, refusing anything that
    /// would move us to another origin.
    fn resolve_href(&self, href: &str) -> Result<Url> {
        let url = self
            .collection
            .join(href)
            .map_err(|_| Error::server("the server returned an unusable href"))?;
        self.require_same_origin(&url)?;
        Ok(url)
    }

    /// Send a request, following redirects without leaking credentials.
    fn execute(
        &self,
        method: Method,
        url: Url,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let mut method = method;
        let mut url = url;
        let mut body = body;
        let requested = url.clone();

        // Nothing this client sends may leave the configured origin, so the
        // very first URL is checked too, whoever built it.
        self.require_same_origin(&url)?;

        for _ in 0..=MAX_REDIRECTS {
            let mut request = self.http.request(method.clone(), url.clone());
            for (name, value) in headers {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|err| Error::Network(format!("invalid header name: {err}")))?;
                let value = HeaderValue::from_str(value)
                    .map_err(|err| Error::Network(format!("invalid header value: {err}")))?;
                request = request.header(name, value);
            }
            // Safe unconditionally: the loop cannot reach a foreign origin.
            request = request.basic_auth(&self.username, Some(self.password.expose_secret()));
            if let Some(bytes) = body.clone() {
                request = request.body(bytes);
            }

            let response = request.send().map_err(network_error)?;
            let status = response.status();
            if !is_redirect(status) {
                return Response::collect(response, requested);
            }

            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .ok_or_else(|| {
                    Error::server(format!(
                        "the server answered {} without a Location header",
                        status.as_u16()
                    ))
                })?;
            let next = url
                .join(&location)
                .map_err(|_| Error::server("the server sent an unusable Location header"))?;
            // Refused before the next request is built, so neither the method,
            // the body, nor any header is ever offered to another origin.
            self.require_same_origin(&next)?;
            if status == StatusCode::SEE_OTHER {
                method = Method::GET;
                body = None;
            }
            url = next;
        }

        Err(Error::Network(format!(
            "more than {MAX_REDIRECTS} redirects while talking to the server"
        )))
    }

    /// Refuse any URL outside the configured origin.
    ///
    /// Withholding credentials from a foreign origin is not enough on its own:
    /// the request line, the headers, and an iCalendar body would still be
    /// delivered to whatever host the server named. So a cross-origin hop is
    /// an error, and there is no state in which credentials could be restored
    /// after one.
    fn require_same_origin(&self, url: &Url) -> Result<()> {
        if same_origin(&self.collection, url) {
            return Ok(());
        }
        Err(Error::server(format!(
            "refusing to follow {} to {}: requests never leave the configured origin",
            origin_of(&self.collection),
            origin_of(url)
        )))
    }

    /// Map an HTTP status onto a CLI error.
    ///
    /// The response body is never quoted. The CLI authenticates with HTTP
    /// Basic, so a hostile or misconfigured server can echo the credentials it
    /// was just sent straight back in an error page; anything copied from the
    /// body could therefore contain the password. Only values the server cannot
    /// choose freely are reported: the numeric status, its registered reason
    /// phrase, the size of the body, and the percent-encoded path we asked for.
    fn check(&self, response: &Response, action: &str) -> Result<()> {
        let status = response.status;
        if status.is_success() {
            return Ok(());
        }
        let detail = response.describe();
        Err(match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::Auth(format!(
                "the server rejected the credentials ({detail}); check the user name and run \
                 `reminders auth set` to store the password again"
            )),
            StatusCode::NOT_FOUND => Error::NotFound(format!(
                "the server could not find {}",
                response.requested_path()
            )),
            StatusCode::PRECONDITION_FAILED => conflict_error(),
            StatusCode::CONFLICT => Error::Conflict(format!(
                "the server refused to {action} because of a conflict ({detail})"
            )),
            _ if status.is_server_error() => {
                Error::Server(format!("the server failed to {action} ({detail})"))
            }
            _ => Error::Server(format!("could not {action} ({detail})")),
        })
    }
}

/// The parts of a response we care about, already read into memory.
struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    /// The URL originally asked for, before any redirect.
    requested: Url,
}

impl Response {
    fn collect(response: HttpResponse, requested: Url) -> Result<Response> {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().map_err(network_error)?.to_vec();
        Ok(Response {
            status,
            headers,
            body,
            requested,
        })
    }

    /// The body as UTF-8. CalDAV mandates UTF-8 for both XML and iCalendar.
    ///
    /// Only used on success, to hand calendar data to the parsers. It never
    /// feeds an error message.
    fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|_| Error::server("the server sent a response that is not valid UTF-8"))
    }

    /// Context for an error message, with nothing the server can fill in.
    ///
    /// `canonical_reason` is a lookup in the `http` crate's static table of
    /// IANA status phrases, not a string the server sent.
    fn describe(&self) -> String {
        let reason = self.status.canonical_reason().unwrap_or("unknown status");
        format!(
            "HTTP {} {reason}; {} bytes of response body not shown",
            self.status.as_u16(),
            self.body.len()
        )
    }

    /// The percent-encoded path we requested, capped for display.
    ///
    /// `Url` percent-encodes the path, so this cannot carry a control
    /// character even when a redirect influenced it.
    fn requested_path(&self) -> String {
        let path = self.requested.path();
        if path.len() <= PATH_LIMIT {
            return path.to_string();
        }
        format!("{}...", &path[..PATH_LIMIT])
    }
}

/// `scheme://host[:port]`, for messages about origins.
fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// The error raised when a resource the CLI must modify carries no ETag.
///
/// Reported as a server problem rather than a client one: RFC 4918 requires a
/// `DAV:getetag` on calendar resources, so a server that omits it cannot
/// support the conditional requests this CLI relies on.
pub fn missing_etag_error(path: &str) -> Error {
    Error::Server(format!(
        "the server returned no ETag for {path}, so this change was not attempted: without \
         one the write could silently overwrite a newer version of the reminder. The \
         collection's server does not support the conditional requests this CLI requires"
    ))
}

fn conflict_error() -> Error {
    Error::Conflict(
        "the reminder changed on the server since it was read; nothing was written. Read it \
         again and reapply the change"
            .to_string(),
    )
}

/// reqwest errors can name the URL but never the credentials, because the
/// password is only ever passed through `basic_auth`.
fn network_error(err: reqwest::Error) -> Error {
    // The useful detail (a TLS or DNS reason) lives in the source chain, not in
    // the top-level message.
    let detail = error_chain(&err);
    if err.is_timeout() {
        return Error::Network(format!("the request timed out: {detail}"));
    }
    if err.is_connect() {
        if detail.to_lowercase().contains("certificate") {
            return Error::Network(format!(
                "the server's TLS certificate was rejected: {detail}. Certificate \
                 verification cannot be disabled"
            ));
        }
        return Error::Network(format!("cannot reach the server: {detail}"));
    }
    Error::Network(format!("HTTP request failed: {detail}"))
}

/// Flatten an error and its causes, skipping causes already quoted by a parent.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(inner) = source {
        let text = inner.to_string();
        if !parts.iter().any(|part| part.contains(&text)) {
            parts.push(text);
        }
        source = inner.source();
    }
    parts.join(": ")
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn etag_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Scheme, host, and effective port must all match.
pub fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

/// Cheap `UID` check that avoids a full parse when matching report results.
fn resource_uid_matches(data: &str, uid: &str) -> bool {
    crate::ical::unfold(data).iter().any(|line| {
        crate::ical::ContentLine::parse(line)
            .map(|parsed| parsed.name == "UID" && parsed.text_value() == uid)
            .unwrap_or(false)
    })
}

/// Build a `calendar-query` REPORT body, optionally filtered by `UID`.
pub fn calendar_query(uid: Option<&str>) -> String {
    let filter = match uid {
        Some(uid) => format!(
            "<C:comp-filter name=\"VTODO\">\
<C:prop-filter name=\"UID\">\
<C:text-match collation=\"i;octet\">{}</C:text-match>\
</C:prop-filter>\
</C:comp-filter>",
            xml::escape_xml(uid)
        ),
        None => "<C:comp-filter name=\"VTODO\"/>".to_string(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">\
<D:prop><D:getetag/><C:calendar-data/></D:prop>\
<C:filter><C:comp-filter name=\"VCALENDAR\">{filter}</C:comp-filter></C:filter>\
</C:calendar-query>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let base = Url::parse("https://dav.example.com/u/tasks/").unwrap();
        assert!(same_origin(
            &base,
            &Url::parse("https://dav.example.com/other").unwrap()
        ));
        assert!(same_origin(
            &base,
            &Url::parse("https://DAV.EXAMPLE.COM/x").unwrap()
        ));
        assert!(same_origin(
            &base,
            &Url::parse("https://dav.example.com:443/x").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://evil.example.com/x").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("http://dav.example.com/x").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://dav.example.com:8443/x").unwrap()
        ));
    }

    #[test]
    fn calendar_query_without_uid_filters_only_vtodo() {
        let body = calendar_query(None);
        assert!(body.contains("<C:comp-filter name=\"VTODO\"/>"), "{body}");
        assert!(body.contains("<D:getetag/>"));
        assert!(body.contains("<C:calendar-data/>"));
        assert!(!body.contains("prop-filter"));
    }

    #[test]
    fn calendar_query_escapes_the_uid() {
        let body = calendar_query(Some("a&b<c>"));
        assert!(body.contains("a&amp;b&lt;c&gt;"), "{body}");
        assert!(!body.contains("a&b<c>"));
    }

    #[test]
    fn uid_matching_reads_the_uid_property() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:abc\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert!(resource_uid_matches(ics, "abc"));
        assert!(!resource_uid_matches(ics, "abd"));
        assert!(!resource_uid_matches("garbage", "abc"));
    }

    #[test]
    fn redirect_statuses_are_recognised() {
        for code in [301u16, 302, 303, 307, 308] {
            assert!(is_redirect(StatusCode::from_u16(code).unwrap()), "{code}");
        }
        for code in [200u16, 204, 304, 400, 412, 500] {
            assert!(!is_redirect(StatusCode::from_u16(code).unwrap()), "{code}");
        }
    }

    #[test]
    fn etag_header_is_trimmed_and_emptiness_is_none() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::ETAG, HeaderValue::from_static(" \"abc\" "));
        assert_eq!(etag_header(&headers), Some("\"abc\"".to_string()));
        headers.insert(reqwest::header::ETAG, HeaderValue::from_static(""));
        assert_eq!(etag_header(&headers), None);
        assert_eq!(etag_header(&HeaderMap::new()), None);
    }

    #[test]
    fn error_chain_joins_causes_without_repeating_them() {
        #[derive(Debug)]
        struct Layer {
            message: String,
            source: Option<Box<Layer>>,
        }
        impl std::fmt::Display for Layer {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(&self.message)
            }
        }
        impl std::error::Error for Layer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.source.as_ref().map(|inner| inner.as_ref() as _)
            }
        }

        let inner = Layer {
            message: "invalid peer certificate: UnknownIssuer".to_string(),
            source: None,
        };
        let outer = Layer {
            message: "error sending request".to_string(),
            source: Some(Box::new(inner)),
        };
        assert_eq!(
            error_chain(&outer),
            "error sending request: invalid peer certificate: UnknownIssuer"
        );

        // A parent that already quotes its cause is not made repetitive.
        let inner = Layer {
            message: "boom".to_string(),
            source: None,
        };
        let outer = Layer {
            message: "failed: boom".to_string(),
            source: Some(Box::new(inner)),
        };
        assert_eq!(error_chain(&outer), "failed: boom");
    }

    fn response_with(status: u16, body: &[u8], url: &str) -> Response {
        Response {
            status: StatusCode::from_u16(status).unwrap(),
            headers: HeaderMap::new(),
            body: body.to_vec(),
            requested: Url::parse(url).unwrap(),
        }
    }

    #[test]
    fn describe_reports_status_and_size_but_never_the_body() {
        let response = response_with(
            500,
            b"Authorization: Basic YWxpY2U6aHVudGVyMg== hunter2",
            "https://dav.example.com/u/tasks/",
        );
        let described = response.describe();
        assert_eq!(
            described,
            "HTTP 500 Internal Server Error; 49 bytes of response body not shown"
        );
        assert!(!described.contains("hunter2"));
        assert!(!described.contains("YWxpY2U"));
    }

    #[test]
    fn describe_uses_the_registered_reason_not_server_text() {
        // 599 has no IANA phrase, so the fallback must still be a fixed string.
        assert_eq!(
            response_with(599, b"", "https://dav.example.com/").describe(),
            "HTTP 599 unknown status; 0 bytes of response body not shown"
        );
    }

    #[test]
    fn requested_path_is_percent_encoded_and_capped() {
        // A control character in the path cannot survive `Url` parsing.
        let response = response_with(404, b"", "https://dav.example.com/u/tasks/a%0Db.ics");
        let path = response.requested_path();
        assert_eq!(path, "/u/tasks/a%0Db.ics");
        assert!(!path.contains('\r'));

        let long = format!("https://dav.example.com/{}", "a".repeat(400));
        let path = response_with(404, b"", &long).requested_path();
        assert!(path.ends_with("..."));
        assert_eq!(path.len(), PATH_LIMIT + 3);
    }

    #[test]
    fn origin_serialisation_omits_default_ports() {
        assert_eq!(
            origin_of(&Url::parse("https://dav.example.com/u/tasks/").unwrap()),
            "https://dav.example.com"
        );
        assert_eq!(
            origin_of(&Url::parse("http://127.0.0.1:8080/u/").unwrap()),
            "http://127.0.0.1:8080"
        );
    }
}
