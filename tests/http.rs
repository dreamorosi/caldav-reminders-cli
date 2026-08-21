//! HTTP-level behaviour of the CalDAV client: authentication, redirects,
//! ETags, conflicts, and error redaction.
//!
//! These tests run against a local mock server, so they never touch a real
//! CalDAV deployment and never need a D-Bus session.

use mockito::{Matcher, Server, ServerGuard};
use reminders::caldav::Client;
use reminders::config::{Config, Settings};
use reminders::error::{exit, Error};
use secrecy::SecretString;

const USER: &str = "alice";
const PASSWORD: &str = "hunter2";
/// base64("alice:hunter2")
const BASIC: &str = "Basic YWxpY2U6aHVudGVyMg==";
const COLLECTION: &str = "/u/tasks/";

fn ics(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:{uid}\r\nSUMMARY:{summary}\r\n\
         STATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
    )
}

fn multistatus(entries: &[(&str, &str, String)]) -> String {
    let mut body = String::from(
        "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
         xmlns:C=\"urn:ietf:params:xml:ns:caldav\">",
    );
    for (href, etag, data) in entries {
        body.push_str(&format!(
            "<D:response><D:href>{href}</D:href><D:propstat><D:prop>\
             <D:getetag>{etag}</D:getetag><C:calendar-data>{}</C:calendar-data>\
             </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
            data.replace('\r', "&#13;")
        ));
    }
    body.push_str("</D:multistatus>");
    body
}

fn settings_for(base: &str) -> Settings {
    Config {
        server_url: Some(base.to_string()),
        collection_path: Some(COLLECTION.to_string()),
        username: Some(USER.to_string()),
        ..Default::default()
    }
    .settings()
    .expect("settings")
}

fn client_for(server: &ServerGuard) -> Client {
    Client::new(
        &settings_for(&server.url()),
        &SecretString::from(PASSWORD.to_string()),
    )
    .expect("client")
}

/// No error message may ever quote the password.
fn assert_redacted(err: &Error) {
    let rendered = err.to_string();
    assert!(
        !rendered.contains(PASSWORD),
        "leaked the password: {rendered}"
    );
    assert!(
        !rendered.contains(BASIC),
        "leaked the auth header: {rendered}"
    );
    assert!(
        !rendered.to_lowercase().contains("authorization"),
        "leaked the auth header name: {rendered}"
    );
}

#[test]
fn sends_basic_authentication_on_reads() {
    let mut server = Server::new();
    let mock = server
        .mock("REPORT", COLLECTION)
        .match_header("authorization", BASIC)
        .match_header("depth", "1")
        .with_status(207)
        .with_header("content-type", "application/xml; charset=utf-8")
        .with_body(multistatus(&[(
            "/u/tasks/a.ics",
            "\"e1\"",
            ics("a", "Buy milk"),
        )]))
        .create();

    let resources = client_for(&server).list_todos().unwrap();
    mock.assert();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].href, "/u/tasks/a.ics");
    assert_eq!(resources[0].etag.as_deref(), Some("\"e1\""));
    assert!(resources[0].data.contains("SUMMARY:Buy milk"));
}

#[test]
fn report_body_asks_only_for_vtodo_with_etags() {
    let mut server = Server::new();
    let mock = server
        .mock("REPORT", COLLECTION)
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("calendar-query".into()),
            Matcher::Regex("comp-filter name=\"VTODO\"".into()),
            Matcher::Regex("getetag".into()),
        ]))
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();

    assert!(client_for(&server).list_todos().unwrap().is_empty());
    mock.assert();
}

#[test]
fn skips_responses_that_report_not_found() {
    let mut server = Server::new();
    let body = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">\
<D:response><D:href>/u/tasks/gone.ics</D:href><D:propstat><D:prop><D:getetag/></D:prop>\
<D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response></D:multistatus>";
    server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(body)
        .create();
    assert!(client_for(&server).list_todos().unwrap().is_empty());
}

#[test]
fn finds_a_reminder_by_direct_get() {
    let mut server = Server::new();
    let mock = server
        .mock("GET", "/u/tasks/abc.ics")
        .match_header("authorization", BASIC)
        .with_status(200)
        .with_header("content-type", "text/calendar; charset=utf-8")
        .with_header("etag", "\"v1\"")
        .with_body(ics("abc", "Direct"))
        .create();

    let resource = client_for(&server).find_by_uid("abc").unwrap().unwrap();
    mock.assert();
    assert_eq!(resource.etag.as_deref(), Some("\"v1\""));
    assert!(resource.data.contains("SUMMARY:Direct"));
}

#[test]
fn falls_back_to_a_uid_report_when_the_file_name_differs() {
    let mut server = Server::new();
    let get = server
        .mock("GET", "/u/tasks/foreign-uid.ics")
        .with_status(404)
        .create();
    let report = server
        .mock("REPORT", COLLECTION)
        .match_body(Matcher::Regex("foreign-uid".into()))
        .with_status(207)
        .with_body(multistatus(&[(
            "/u/tasks/1234-apple.ics",
            "\"e9\"",
            ics("foreign-uid", "From Apple"),
        )]))
        .create();

    let resource = client_for(&server)
        .find_by_uid("foreign-uid")
        .unwrap()
        .unwrap();
    get.assert();
    report.assert();
    assert_eq!(resource.href, "/u/tasks/1234-apple.ics");
    assert_eq!(resource.etag.as_deref(), Some("\"e9\""));
}

#[test]
fn ignores_report_results_whose_uid_does_not_match() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/wanted.ics")
        .with_status(404)
        .create();
    server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[(
            "/u/tasks/other.ics",
            "\"e\"",
            ics("something-else", "Wrong"),
        )]))
        .create();

    assert!(client_for(&server).find_by_uid("wanted").unwrap().is_none());
}

#[test]
fn missing_reminder_is_reported_as_absent_not_as_an_error() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/nope.ics")
        .with_status(404)
        .create();
    server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();
    assert!(client_for(&server).find_by_uid("nope").unwrap().is_none());
}

#[test]
fn create_guards_against_overwriting_with_if_none_match() {
    let mut server = Server::new();
    let mock = server
        .mock("PUT", "/u/tasks/new-uid.ics")
        .match_header("if-none-match", "*")
        .match_header("content-type", "text/calendar; charset=utf-8")
        .match_body(Matcher::Regex("UID:new-uid".into()))
        .with_status(201)
        .with_header("etag", "\"created\"")
        .create();

    let resource = client_for(&server)
        .create("new-uid", &ics("new-uid", "Fresh"))
        .unwrap();
    mock.assert();
    assert_eq!(resource.href, "/u/tasks/new-uid.ics");
    assert_eq!(resource.etag.as_deref(), Some("\"created\""));
}

#[test]
fn create_reads_the_etag_back_when_the_put_response_omits_it() {
    let mut server = Server::new();
    server
        .mock("PUT", "/u/tasks/u1.ics")
        .with_status(204)
        .create();
    let get = server
        .mock("GET", "/u/tasks/u1.ics")
        .with_status(200)
        .with_header("etag", "\"looked-up\"")
        .with_body(ics("u1", "Fresh"))
        .create();

    let resource = client_for(&server)
        .create("u1", &ics("u1", "Fresh"))
        .unwrap();
    get.assert();
    assert_eq!(resource.etag.as_deref(), Some("\"looked-up\""));
}

#[test]
fn create_reports_an_existing_resource_as_a_conflict() {
    let mut server = Server::new();
    server
        .mock("PUT", "/u/tasks/dup.ics")
        .with_status(412)
        .create();

    let err = client_for(&server)
        .create("dup", &ics("dup", "Dup"))
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFLICT);
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_redacted(&err);
}

#[test]
fn update_sends_if_match_with_the_current_etag() {
    let mut server = Server::new();
    let mock = server
        .mock("PUT", "/u/tasks/a.ics")
        .match_header("if-match", "\"e1\"")
        .with_status(204)
        .with_header("etag", "\"e2\"")
        .create();

    let resource = client_for(&server)
        .update("/u/tasks/a.ics", &ics("a", "Changed"), "\"e1\"")
        .unwrap();
    mock.assert();
    assert_eq!(resource.etag.as_deref(), Some("\"e2\""));
}

/// There is no API for an unconditional write, so `If-Match` is always sent.
#[test]
fn update_always_sends_if_match() {
    let mut server = Server::new();
    let mock = server
        .mock("PUT", "/u/tasks/a.ics")
        .match_header("if-match", Matcher::Regex(r"^\S+$".into()))
        .with_status(204)
        .with_header("etag", "\"e2\"")
        .create();

    client_for(&server)
        .update("/u/tasks/a.ics", &ics("a", "Changed"), "\"e1\"")
        .unwrap();
    mock.assert();
}

/// A server that answers a mutation with no `If-Match` at all would be a bug in
/// this client, so the mock refuses such a request outright.
#[test]
fn a_mutation_without_if_match_is_never_issued() {
    let mut server = Server::new();
    let unconditional = server
        .mock("PUT", Matcher::Any)
        .match_header("if-match", Matcher::Missing)
        .with_status(204)
        .expect(0)
        .create();
    let conditional = server
        .mock("PUT", "/u/tasks/a.ics")
        .match_header("if-match", "\"e1\"")
        .with_status(204)
        .with_header("etag", "\"e2\"")
        .create();

    client_for(&server)
        .update("/u/tasks/a.ics", &ics("a", "x"), "\"e1\"")
        .unwrap();
    conditional.assert();
    unconditional.assert();

    let mut server = Server::new();
    let unconditional = server
        .mock("DELETE", Matcher::Any)
        .match_header("if-match", Matcher::Missing)
        .with_status(204)
        .expect(0)
        .create();
    let conditional = server
        .mock("DELETE", "/u/tasks/a.ics")
        .match_header("if-match", "\"e1\"")
        .with_status(204)
        .create();

    client_for(&server)
        .delete("/u/tasks/a.ics", "\"e1\"")
        .unwrap();
    conditional.assert();
    unconditional.assert();
}

/// A resource the server returned without an ETag cannot be modified.
#[test]
fn a_resource_without_an_etag_reports_a_server_limitation() {
    let err = reminders::caldav::missing_etag_error("/u/tasks/a.ics");
    assert_eq!(err.exit_code(), exit::SERVER);
    let message = err.to_string();
    assert!(message.contains("no ETag"), "{message}");
    assert!(message.contains("/u/tasks/a.ics"), "{message}");
    assert!(message.contains("silently overwrite"), "{message}");
}

/// A GET that returns no ETag header yields a resource with none, so the
/// command layer can refuse the mutation rather than the client guessing.
#[test]
fn a_get_without_an_etag_header_reports_no_etag() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/abc.ics")
        .with_status(200)
        .with_body(ics("abc", "No etag"))
        .create();
    let resource = client_for(&server).find_by_uid("abc").unwrap().unwrap();
    assert_eq!(resource.etag, None);
}

#[test]
fn update_maps_precondition_failed_to_a_conflict_and_never_retries() {
    let mut server = Server::new();
    let mock = server
        .mock("PUT", "/u/tasks/a.ics")
        .match_header("if-match", "\"stale\"")
        .with_status(412)
        .with_body("stale etag")
        .expect(1)
        .create();

    let err = client_for(&server)
        .update("/u/tasks/a.ics", &ics("a", "Changed"), "\"stale\"")
        .unwrap_err();
    // Exactly one attempt: the CLI must not overwrite newer server state.
    mock.assert();
    assert_eq!(err.exit_code(), exit::CONFLICT);
    assert!(err.to_string().contains("changed on the server"), "{err}");
    assert_redacted(&err);
}

#[test]
fn delete_sends_if_match_and_maps_precondition_failed_to_a_conflict() {
    let mut server = Server::new();
    let ok = server
        .mock("DELETE", "/u/tasks/a.ics")
        .match_header("if-match", "\"e1\"")
        .with_status(204)
        .create();
    client_for(&server)
        .delete("/u/tasks/a.ics", "\"e1\"")
        .unwrap();
    ok.assert();

    let mut server = Server::new();
    server
        .mock("DELETE", "/u/tasks/a.ics")
        .with_status(412)
        .create();
    let err = client_for(&server)
        .delete("/u/tasks/a.ics", "\"e1\"")
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFLICT);
}

#[test]
fn delete_of_a_missing_resource_is_not_found() {
    let mut server = Server::new();
    server
        .mock("DELETE", "/u/tasks/a.ics")
        .with_status(404)
        .create();
    let err = client_for(&server)
        .delete("/u/tasks/a.ics", "\"e1\"")
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::NOT_FOUND);
}

#[test]
fn unauthorized_is_an_auth_error_without_credential_material() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(401)
        .with_header("www-authenticate", "Basic realm=\"dav\"")
        .with_body("Bad credentials for alice with password hunter2")
        .create();

    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::AUTH);
    assert!(
        err.to_string().contains("rejected the credentials"),
        "{err}"
    );
    // Even a careless server echoing the password must not reach the user.
    assert!(
        !err.to_string().contains(PASSWORD),
        "server text leaked the password: {err}"
    );
}

#[test]
fn forbidden_is_also_an_auth_error() {
    let mut server = Server::new();
    server.mock("REPORT", COLLECTION).with_status(403).create();
    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::AUTH);
}

#[test]
fn missing_collection_is_not_found() {
    let mut server = Server::new();
    server.mock("REPORT", COLLECTION).with_status(404).create();
    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::NOT_FOUND);
    assert!(err.to_string().contains(COLLECTION), "{err}");
}

#[test]
fn server_errors_report_status_and_size_but_never_the_body() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(500)
        .with_body("Traceback: auth failed for alice / hunter2")
        .create();

    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
    let rendered = err.to_string();
    assert!(
        rendered.contains("HTTP 500 Internal Server Error"),
        "{rendered}"
    );
    assert!(
        rendered.contains("42 bytes of response body not shown"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("Traceback"),
        "quoted the body: {rendered}"
    );
    assert_redacted(&err);
}

/// The point of the reflection fix: a server we authenticated to can echo the
/// credentials it was sent, so no error may carry its response body.
#[test]
fn a_server_reflecting_the_password_cannot_get_it_into_an_error() {
    let reflections = [
        PASSWORD.to_string(),
        BASIC.to_string(),
        format!("<error>{USER}:{PASSWORD}</error>"),
        format!("Authorization: {BASIC}"),
    ];
    for status in [400u16, 401, 403, 409, 500, 502, 507] {
        for body in &reflections {
            let mut server = Server::new();
            server
                .mock("REPORT", COLLECTION)
                .with_status(status.into())
                .with_header("content-type", "text/plain")
                .with_body(body.clone())
                .create();

            let err = client_for(&server).list_todos().unwrap_err();
            let rendered = err.to_string();
            assert!(
                !rendered.contains(PASSWORD),
                "status {status} with body {body:?} leaked the password: {rendered}"
            );
            assert!(
                !rendered.contains("YWxpY2U"),
                "status {status} with body {body:?} leaked the auth header: {rendered}"
            );
        }
    }
}

#[test]
fn a_reflecting_body_cannot_reach_a_not_found_or_conflict_error() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/abc.ics")
        .with_status(404)
        .with_body(PASSWORD)
        .create();
    server
        .mock("REPORT", COLLECTION)
        .with_status(404)
        .with_body(PASSWORD)
        .create();
    server
        .mock("PUT", "/u/tasks/abc.ics")
        .with_status(409)
        .with_body(PASSWORD)
        .create();

    let client = client_for(&server);
    let err = client.find_by_uid("abc").unwrap_err();
    assert_eq!(err.exit_code(), exit::NOT_FOUND);
    assert_redacted(&err);

    let err = client
        .update("/u/tasks/abc.ics", &ics("abc", "x"), "\"e1\"")
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFLICT);
    assert_redacted(&err);
}

#[test]
fn a_control_character_laden_body_cannot_reach_an_error() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(502)
        .with_body("\u{1b}[2J\u{1b}[1;31mfake prompt\u{7}")
        .create();
    let err = client_for(&server).list_todos().unwrap_err();
    let rendered = err.to_string();
    assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
    assert!(!rendered.contains("fake prompt"), "{rendered:?}");
}

#[test]
fn not_found_names_only_the_path_we_asked_for() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(404)
        .with_body("gone")
        .create();
    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::NOT_FOUND);
    assert!(err.to_string().contains(COLLECTION), "{err}");
    assert!(!err.to_string().contains("gone"), "{err}");
}

#[test]
fn non_multistatus_report_response_is_a_server_error() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body("<html><body>hello</body></html>")
        .create();
    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
}

#[test]
fn same_host_redirects_keep_the_credentials() {
    let mut server = Server::new();
    let first = server
        .mock("GET", "/u/tasks/a.ics")
        .with_status(301)
        .with_header("location", "/u/tasks/moved.ics")
        .create();
    let second = server
        .mock("GET", "/u/tasks/moved.ics")
        .match_header("authorization", BASIC)
        .with_status(200)
        .with_header("etag", "\"e1\"")
        .with_body(ics("a", "Moved"))
        .create();

    let resource = client_for(&server).find_by_uid("a").unwrap().unwrap();
    first.assert();
    second.assert();
    assert!(resource.data.contains("SUMMARY:Moved"));
}

/// A cross-origin redirect is refused outright. Withholding credentials is not
/// enough on its own: the method, the headers, and any iCalendar body would
/// still be delivered to a host the server picked.
#[test]
fn a_redirect_to_another_host_is_refused_and_never_sent() {
    let mut elsewhere = Server::new();
    // Any request reaching this server at all is a failure.
    let never = elsewhere
        .mock("GET", Matcher::Any)
        .with_status(200)
        .with_body(ics("a", "Elsewhere"))
        .expect(0)
        .create();

    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/a.ics")
        .with_status(302)
        .with_header("location", &format!("{}/u/tasks/a.ics", elsewhere.url()))
        .create();

    let url = format!("{}/u/tasks/a.ics", server.url()).parse().unwrap();
    let err = client_for(&server).get(&url).unwrap_err();
    never.assert();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("refusing to follow"), "{err}");
    assert!(
        err.to_string()
            .contains("never leave the configured origin"),
        "{err}"
    );
    assert_redacted(&err);
}

#[test]
fn a_cross_origin_redirect_is_refused_for_every_redirect_status() {
    for status in [301u16, 302, 303, 307, 308] {
        let mut elsewhere = Server::new();
        let never = elsewhere
            .mock("PUT", Matcher::Any)
            .with_status(200)
            .expect(0)
            .create();
        let never_get = elsewhere
            .mock("GET", Matcher::Any)
            .with_status(200)
            .expect(0)
            .create();

        let mut server = Server::new();
        server
            .mock("PUT", "/u/tasks/a.ics")
            .with_status(status.into())
            .with_header("location", &format!("{}/u/tasks/a.ics", elsewhere.url()))
            .create();

        // The body carries the user's reminder text, which must not travel
        // either, so this also covers 307/308 body forwarding.
        let err = client_for(&server)
            .update("/u/tasks/a.ics", &ics("a", "private notes"), "\"e1\"")
            .unwrap_err();
        never.assert();
        never_get.assert();
        assert_eq!(err.exit_code(), exit::SERVER, "status {status}: {err}");
        assert!(
            err.to_string().contains("refusing to follow"),
            "status {status}: {err}"
        );
    }
}

/// A same-origin hop followed by a cross-origin one is still refused, so no
/// sequence of redirects can re-attach credentials after leaving the origin.
#[test]
fn a_redirect_chain_cannot_escape_the_origin_on_a_later_hop() {
    let mut elsewhere = Server::new();
    let never = elsewhere
        .mock("GET", Matcher::Any)
        .with_status(200)
        .expect(0)
        .create();

    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/a.ics")
        .with_status(302)
        .with_header("location", "/u/tasks/hop.ics")
        .create();
    let hop = server
        .mock("GET", "/u/tasks/hop.ics")
        .match_header("authorization", BASIC)
        .with_status(302)
        .with_header("location", &format!("{}/u/tasks/a.ics", elsewhere.url()))
        .create();

    let url = format!("{}/u/tasks/a.ics", server.url()).parse().unwrap();
    let err = client_for(&server).get(&url).unwrap_err();
    hop.assert();
    never.assert();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("refusing to follow"), "{err}");
}

#[test]
fn a_redirect_to_a_different_scheme_or_port_is_refused() {
    for location in [
        "http://127.0.0.1:1/u/tasks/a.ics",
        "https://127.0.0.1/u/tasks/a.ics",
        "http://localhost:1/u/tasks/a.ics",
    ] {
        let mut server = Server::new();
        server
            .mock("GET", "/u/tasks/a.ics")
            .with_status(307)
            .with_header("location", location)
            .create();
        let url = format!("{}/u/tasks/a.ics", server.url()).parse().unwrap();
        let err = client_for(&server).get(&url).unwrap_err();
        assert_eq!(err.exit_code(), exit::SERVER, "{location}: {err}");
        assert!(
            err.to_string().contains("refusing to follow"),
            "{location}: {err}"
        );
    }
}

#[test]
fn a_url_outside_the_configured_origin_is_refused_before_any_request() {
    let server = Server::new();
    let err = client_for(&server)
        .get(&"https://evil.example.com/u/tasks/a.ics".parse().unwrap())
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("refusing to follow"), "{err}");
}

#[test]
fn a_redirect_loop_is_stopped() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/a.ics")
        .with_status(302)
        .with_header("location", "/u/tasks/a.ics")
        .create();

    let url = format!("{}/u/tasks/a.ics", server.url()).parse().unwrap();
    let err = client_for(&server).get(&url).unwrap_err();
    assert_eq!(err.exit_code(), exit::NETWORK);
    assert!(err.to_string().contains("redirects"), "{err}");
}

#[test]
fn a_redirect_without_a_location_header_is_a_server_error() {
    let mut server = Server::new();
    server
        .mock("GET", "/u/tasks/a.ics")
        .with_status(302)
        .create();
    let url = format!("{}/u/tasks/a.ics", server.url()).parse().unwrap();
    let err = client_for(&server).get(&url).unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("Location"), "{err}");
}

#[test]
fn a_see_other_redirect_becomes_a_get() {
    let mut server = Server::new();
    server
        .mock("PUT", "/u/tasks/a.ics")
        .with_status(303)
        .with_header("location", "/u/tasks/after.ics")
        .create();
    let after = server
        .mock("GET", "/u/tasks/after.ics")
        .match_body(Matcher::Missing)
        .with_status(200)
        .with_header("etag", "\"e\"")
        .with_body(ics("a", "After"))
        .create();

    client_for(&server)
        .update("/u/tasks/a.ics", &ics("a", "x"), "\"e1\"")
        .unwrap();
    after.assert();
}

#[test]
fn an_href_pointing_at_another_host_is_refused() {
    let server = Server::new();
    let err = client_for(&server)
        .update("https://evil.example.com/x.ics", &ics("a", "x"), "\"e1\"")
        .unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("refusing to follow"), "{err}");
    assert!(err.to_string().contains("evil.example.com"), "{err}");
}

#[test]
fn an_unreachable_server_is_a_network_error() {
    // Port 1 is reserved and nothing listens there.
    let client = Client::new(
        &settings_for("http://127.0.0.1:1"),
        &SecretString::from(PASSWORD.to_string()),
    )
    .unwrap();
    let err = client.list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::NETWORK);
    assert_redacted(&err);
}

#[test]
fn a_non_utf8_response_body_is_a_server_error() {
    let mut server = Server::new();
    server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(vec![0xff, 0xfe, 0xfd])
        .create();
    let err = client_for(&server).list_todos().unwrap_err();
    assert_eq!(err.exit_code(), exit::SERVER);
    assert!(err.to_string().contains("UTF-8"), "{err}");
}

#[test]
fn plain_http_to_a_remote_host_is_refused_before_any_request() {
    let err = Config {
        server_url: Some("http://dav.example.com".into()),
        collection_path: Some(COLLECTION.into()),
        username: Some(USER.into()),
        ..Default::default()
    }
    .settings()
    .unwrap_err();
    assert_eq!(err.exit_code(), exit::CONFIG);
    assert!(err.to_string().contains("https"), "{err}");
}
