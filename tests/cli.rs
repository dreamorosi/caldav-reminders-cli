//! End-to-end tests of the `reminders` binary against a local mock CalDAV
//! server and an encrypted file keyring.
//!
//! The file keyring is pinned explicitly so nothing here needs a D-Bus session.

use std::path::Path;

use assert_cmd::Command;
use mockito::{Matcher, Server, ServerGuard};
use reminders::config::{Config, KeyringBackend, ResolvedBackend};
use reminders::credentials::{FileStore, Keystore, PassphraseSource, KEYRING_FILE_NAME};
use secrecy::SecretString;
use tempfile::TempDir;

const USER: &str = "alice";
const PASSWORD: &str = "hunter2";
const PASSPHRASE: &str = "file-keyring-passphrase";
const COLLECTION: &str = "/u/tasks/";
const UID: &str = "11111111-2222-3333-4444-555555555555";

fn ics(uid: &str, summary: &str, extra: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Apple Inc.//iOS 18//EN\r\nBEGIN:VTODO\r\n\
         UID:{uid}\r\nDTSTAMP:20260801T100000Z\r\nSUMMARY:{summary}\r\nSTATUS:NEEDS-ACTION\r\n\
         X-APPLE-SORT-ORDER:42\r\n{extra}END:VTODO\r\nEND:VCALENDAR\r\n"
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

/// A temporary XDG-style home plus a mock server.
struct Fixture {
    config_dir: TempDir,
    data_dir: TempDir,
    server: ServerGuard,
}

impl Fixture {
    fn new() -> Fixture {
        Fixture {
            config_dir: TempDir::new().unwrap(),
            data_dir: TempDir::new().unwrap(),
            server: Server::new(),
        }
    }

    fn config(&self) -> Config {
        Config {
            server_url: Some(self.server.url()),
            collection_path: Some(COLLECTION.to_string()),
            username: Some(USER.to_string()),
            keyring_backend: KeyringBackend::File,
            credential_backend: Some(ResolvedBackend::File),
        }
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.config_dir.path().join("config.toml")
    }

    /// Write a complete configuration and store the password in the file keyring.
    fn provision(&self) {
        let config = self.config();
        config.save_to(&self.config_path()).unwrap();
        let account = config.settings().unwrap().account();
        FileStore::new(
            self.data_dir.path().join(KEYRING_FILE_NAME),
            PassphraseSource::Fixed(SecretString::from(PASSPHRASE.to_string())),
        )
        .store(&account, &SecretString::from(PASSWORD.to_string()))
        .unwrap();
    }

    /// Write configuration but store no credential.
    fn provision_without_credential(&self) {
        self.config().save_to(&self.config_path()).unwrap();
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("reminders").unwrap();
        cmd.env("REMINDERS_CONFIG_DIR", self.config_dir.path())
            .env("REMINDERS_DATA_DIR", self.data_dir.path())
            .env("REMINDERS_KEYRING_PASSWORD", PASSPHRASE)
            .env_remove("REMINDERS_PASSWORD");
        cmd
    }
}

/// Parse stdout as JSON, which also proves nothing else was written there.
fn json_stdout(output: &std::process::Output) -> serde_json::Value {
    let text = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("stdout is not JSON ({err}): {text}"))
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn assert_no_secrets(output: &std::process::Output) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(output)
    );
    for secret in [PASSWORD, PASSPHRASE, "YWxpY2U6aHVudGVyMg=="] {
        assert!(
            !combined.contains(secret),
            "output leaked {secret:?}: {combined}"
        );
    }
}

#[test]
fn help_and_version_work() {
    let mut cmd = Command::cargo_bin("reminders").unwrap();
    let output = cmd.arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "auth", "add", "list", "get", "update", "complete", "reopen", "delete",
    ] {
        assert!(
            text.contains(expected),
            "help is missing {expected}: {text}"
        );
    }

    let mut cmd = Command::cargo_bin("reminders").unwrap();
    let output = cmd.arg("--version").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("reminders"));
}

#[test]
fn dry_run_needs_neither_configuration_nor_a_server() {
    let fixture = Fixture::new();
    let output = fixture
        .cmd()
        .args([
            "add",
            "Submit report",
            "--notes",
            "Attach receipts",
            "--at",
            "2030-08-22T16:00:00+04:00",
            "--priority",
            "high",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let json = json_stdout(&output);
    assert_eq!(json["dry_run"], true);
    assert_eq!(json["operation"], "add");
    let reminder = &json["reminder"];
    assert_eq!(reminder["title"], "Submit report");
    assert_eq!(reminder["notes"], "Attach receipts");
    assert_eq!(reminder["due"], "2030-08-22T12:00:00Z");
    assert_eq!(reminder["remind_at"], "2030-08-22T12:00:00Z");
    assert_eq!(reminder["priority"], "high");
    assert_eq!(reminder["status"], "open");
    assert!(reminder["etag"].is_null());
    assert!(!reminder["id"].as_str().unwrap().is_empty());
    // No credential store was touched, so nothing was created.
    assert!(!fixture.data_dir.path().join(KEYRING_FILE_NAME).exists());
}

#[test]
fn dry_run_reports_the_intended_update_without_a_server() {
    let fixture = Fixture::new();
    let output = fixture
        .cmd()
        .args([
            "update",
            UID,
            "--title",
            "New title",
            "--clear-due",
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    assert_eq!(json["operation"], "update");
    assert_eq!(json["id"], UID);
    assert_eq!(json["changes"]["title"], "New title");
    assert!(json["changes"]["due"].is_null());
}

#[test]
fn invalid_dates_are_usage_errors() {
    let fixture = Fixture::new();
    for args in [
        vec!["add", "x", "--due", "not-a-date", "--dry-run"],
        vec!["add", "x", "--at", "2026-08-22", "--dry-run"],
        vec![
            "add",
            "x",
            "--remind-at",
            "2026-08-22T10:00:00",
            "--dry-run",
        ],
        vec!["add", "x", "--due", "2026-02-30", "--dry-run"],
    ] {
        let output = fixture.cmd().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
        assert!(!stderr(&output).is_empty(), "{args:?} said nothing");
    }
}

#[test]
fn an_empty_update_is_a_usage_error() {
    let fixture = Fixture::new();
    let output = fixture
        .cmd()
        .args(["update", UID, "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("nothing to change"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn missing_configuration_is_a_configuration_error() {
    let fixture = Fixture::new();
    let output = fixture.cmd().args(["list", "--no-input"]).output().unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("server_url"), "{text}");
    assert!(text.contains("auth set"), "{text}");
}

#[test]
fn a_password_in_the_config_file_is_rejected() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.config_dir.path()).unwrap();
    std::fs::write(
        fixture.config_path(),
        "server_url = \"https://dav.example.com\"\npassword = \"hunter2\"\n",
    )
    .unwrap();
    let output = fixture.cmd().args(["auth", "status"]).output().unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not allowed"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_missing_credential_is_a_credential_error() {
    let fixture = Fixture::new();
    fixture.provision_without_credential();
    let output = fixture.cmd().args(["list", "--no-input"]).output().unwrap();
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(stderr(&output).contains("auth set"), "{}", stderr(&output));
}

#[test]
fn auth_set_stores_the_password_outside_the_config_file() {
    let fixture = Fixture::new();
    fixture
        .cmd()
        .args(["auth", "keyring", "file"])
        .assert()
        .success();

    let output = fixture
        .cmd()
        .env("REMINDERS_PASSWORD", PASSWORD)
        .args([
            "auth",
            "set",
            "--server-url",
            &fixture.server.url(),
            "--collection-path",
            "/u/tasks",
            "--username",
            USER,
            "--no-input",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_no_secrets(&output);
    let json = json_stdout(&output);
    assert_eq!(json["stored"], true);
    assert_eq!(json["backend"], "file");

    let config_text = std::fs::read_to_string(fixture.config_path()).unwrap();
    assert!(!config_text.contains(PASSWORD), "{config_text}");
    assert!(
        config_text.contains("credential_backend = \"file\""),
        "{config_text}"
    );
    // The trailing slash is normalised on the way in.
    assert!(
        config_text.contains("collection_path = \"/u/tasks/\""),
        "{config_text}"
    );

    let keyring = fixture.data_dir.path().join(KEYRING_FILE_NAME);
    assert!(keyring.exists());
    let encrypted = std::fs::read_to_string(&keyring).unwrap();
    assert!(
        encrypted.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "{encrypted}"
    );
    assert!(!encrypted.contains(PASSWORD));
    assert_owner_only(&keyring);

    // And the credential can be read straight back.
    let output = fixture
        .cmd()
        .args(["auth", "status", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_no_secrets(&output);
    let json = json_stdout(&output);
    assert_eq!(json["credential_readable"], true);
    assert_eq!(json["active_backend"], "file");
    assert_eq!(json["keyring_backend"], "file");
    assert_eq!(json["username"], USER);
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{} is {mode:o}", path.display());
}

#[cfg(not(unix))]
fn assert_owner_only(_path: &Path) {}

#[test]
fn auth_set_refuses_to_run_without_a_password_source() {
    let fixture = Fixture::new();
    let output = fixture
        .cmd()
        .args([
            "auth",
            "set",
            "--server-url",
            "https://dav.example.com",
            "--collection-path",
            "/u/tasks/",
            "--username",
            USER,
            "--no-input",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("REMINDERS_PASSWORD"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn auth_keyring_reports_and_changes_the_preference() {
    let fixture = Fixture::new();
    let output = fixture.cmd().args(["auth", "keyring"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "auto");

    fixture
        .cmd()
        .args(["auth", "keyring", "file"])
        .assert()
        .success();
    let output = fixture
        .cmd()
        .args(["auth", "keyring", "--json"])
        .output()
        .unwrap();
    assert_eq!(json_stdout(&output)["keyring_backend"], "file");
}

#[test]
fn auth_remove_forgets_the_credential_and_its_backend() {
    let fixture = Fixture::new();
    fixture.provision();
    let output = fixture
        .cmd()
        .args(["auth", "remove", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(json_stdout(&output)["removed"], true);
    assert!(!fixture.data_dir.path().join(KEYRING_FILE_NAME).exists());

    let config_text = std::fs::read_to_string(fixture.config_path()).unwrap();
    assert!(!config_text.contains("credential_backend"), "{config_text}");

    // Removing again is not an error, it just reports nothing was there.
    let output = fixture
        .cmd()
        .args(["auth", "remove", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(json_stdout(&output)["removed"], false);
}

#[test]
fn add_creates_a_reminder_on_the_server() {
    let mut fixture = Fixture::new();
    fixture.provision();
    let put = fixture
        .server
        .mock(
            "PUT",
            Matcher::Regex(r"^/u/tasks/[0-9a-fA-F-]+\.ics$".into()),
        )
        .match_header("if-none-match", "*")
        .match_header("content-type", "text/calendar; charset=utf-8")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex(r"BEGIN:VTODO".into()),
            Matcher::Regex(r"SUMMARY:Submit report".into()),
            Matcher::Regex(r"DESCRIPTION:Attach receipts".into()),
            Matcher::Regex(r"DUE:20300822T120000Z".into()),
            Matcher::Regex(r"PRIORITY:1".into()),
            Matcher::Regex(r"TRIGGER;VALUE=DATE-TIME:20300822T120000Z".into()),
        ]))
        .with_status(201)
        .with_header("etag", "\"created\"")
        .create();

    let output = fixture
        .cmd()
        .args([
            "add",
            "Submit report",
            "--notes",
            "Attach receipts",
            "--at",
            "2030-08-22T16:00:00+04:00",
            "--priority",
            "high",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    put.assert();
    assert_no_secrets(&output);

    let json = json_stdout(&output);
    assert_eq!(json["title"], "Submit report");
    assert_eq!(json["etag"], "\"created\"");
    assert_eq!(json["due"], "2030-08-22T12:00:00Z");
    assert_eq!(json["status"], "open");
}

#[test]
fn add_warns_about_a_notification_less_than_an_hour_away() {
    let fixture = Fixture::new();
    let soon = (chrono::Utc::now() + chrono::Duration::minutes(10))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let output = fixture
        .cmd()
        .args([
            "add",
            "Soon",
            "--at",
            &soon,
            "--dry-run",
            "--json",
            "--no-input",
        ])
        .output()
        .unwrap();
    // The warning must not turn into a failure, even with --no-input.
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("less than an hour"),
        "{}",
        stderr(&output)
    );
    // And it must not pollute the JSON channel.
    json_stdout(&output);
}

#[test]
fn list_sorts_by_due_date_and_hides_completed_reminders_by_default() {
    let mut fixture = Fixture::new();
    fixture.provision();
    let done = ics("done", "Finished", "").replace("STATUS:NEEDS-ACTION", "STATUS:COMPLETED");
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[
            (
                "/u/tasks/late.ics",
                "\"e1\"",
                ics("late", "Later", "DUE;VALUE=DATE:20300201\r\n"),
            ),
            (
                "/u/tasks/soon.ics",
                "\"e2\"",
                ics("soon", "Sooner", "DUE;VALUE=DATE:20300101\r\n"),
            ),
            ("/u/tasks/none.ics", "\"e3\"", ics("none", "Undated", "")),
            ("/u/tasks/done.ics", "\"e4\"", done),
        ]))
        .create();

    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    let titles: Vec<&str> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, vec!["Sooner", "Later", "Undated"]);

    let output = fixture
        .cmd()
        .args(["list", "--status", "all", "--json"])
        .output()
        .unwrap();
    assert_eq!(json_stdout(&output).as_array().unwrap().len(), 4);

    let output = fixture
        .cmd()
        .args(["list", "--status", "complete", "--json"])
        .output()
        .unwrap();
    let json = json_stdout(&output);
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert_eq!(json[0]["title"], "Finished");

    let output = fixture
        .cmd()
        .args(["list", "--limit", "1", "--json"])
        .output()
        .unwrap();
    assert_eq!(json_stdout(&output).as_array().unwrap().len(), 1);
}

#[test]
fn list_skips_an_unparseable_resource_and_warns() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[
            ("/u/tasks/ok.ics", "\"e1\"", ics("ok", "Fine", "")),
            (
                "/u/tasks/bad.ics",
                "\"e2\"",
                "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_string(),
            ),
        ]))
        .create();

    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    assert_eq!(json.as_array().unwrap().len(), 1);
    assert!(
        stderr(&output).contains("/u/tasks/bad.ics"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn list_of_an_empty_collection_is_an_empty_array() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();
    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(json_stdout(&output), serde_json::json!([]));
}

#[test]
fn get_reads_one_reminder() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v7\"")
        .with_body(ics(
            UID,
            "Read me",
            "DUE;VALUE=DATE:20300101\r\nPRIORITY:5\r\n",
        ))
        .create();

    let output = fixture.cmd().args(["get", UID, "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    assert_eq!(json["id"], UID);
    assert_eq!(json["title"], "Read me");
    assert_eq!(json["due"], "2030-01-01");
    assert_eq!(json["priority"], "medium");
    assert_eq!(json["etag"], "\"v7\"");
}

#[test]
fn get_of_an_unknown_id_is_not_found() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(404)
        .create();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();

    let output = fixture.cmd().args(["get", UID, "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(6), "{}", stderr(&output));
    assert!(
        output.stdout.is_empty(),
        "stdout must stay clean on failure"
    );
    let envelope: serde_json::Value = serde_json::from_str(stderr(&output).trim()).unwrap();
    assert_eq!(envelope["error"]["kind"], "not_found");
    assert_eq!(envelope["error"]["exit_code"], 6);
}

#[test]
fn update_preserves_unknown_properties_and_uses_if_match() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics(UID, "Before", ""))
        .create();
    let put = fixture
        .server
        .mock("PUT", format!("/u/tasks/{UID}.ics").as_str())
        .match_header("if-match", "\"v1\"")
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("SUMMARY:After".into()),
            Matcher::Regex("X-APPLE-SORT-ORDER:42".into()),
            Matcher::Regex("PRODID:-//Apple Inc.//iOS 18//EN".into()),
            Matcher::Regex("PRIORITY:9".into()),
        ]))
        .with_status(204)
        .with_header("etag", "\"v2\"")
        .create();

    let output = fixture
        .cmd()
        .args([
            "update",
            UID,
            "--title",
            "After",
            "--priority",
            "low",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    put.assert();
    let json = json_stdout(&output);
    assert_eq!(json["title"], "After");
    assert_eq!(json["priority"], "low");
    assert_eq!(json["etag"], "\"v2\"");
}

#[test]
fn a_concurrent_edit_produces_a_conflict_rather_than_data_loss() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics(UID, "Before", ""))
        .create();
    let put = fixture
        .server
        .mock("PUT", format!("/u/tasks/{UID}.ics").as_str())
        .match_header("if-match", "\"v1\"")
        .with_status(412)
        .expect(1)
        .create();

    let output = fixture
        .cmd()
        .args(["update", UID, "--title", "After"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));
    put.assert();
    assert!(
        stderr(&output).contains("changed on the server"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn complete_and_reopen_round_trip() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics(UID, "Task", ""))
        .create();
    let put = fixture
        .server
        .mock("PUT", format!("/u/tasks/{UID}.ics").as_str())
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("STATUS:COMPLETED".into()),
            Matcher::Regex("PERCENT-COMPLETE:100".into()),
            Matcher::Regex("COMPLETED:".into()),
        ]))
        .with_status(204)
        .with_header("etag", "\"v2\"")
        .create();

    let output = fixture
        .cmd()
        .args(["complete", UID, "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    put.assert();
    let json = json_stdout(&output);
    assert_eq!(json["status"], "complete");
    assert!(json["completed_at"].is_string());

    // Reopening a completed resource clears the completion state.
    let mut fixture = Fixture::new();
    fixture.provision();
    let completed = ics(
        UID,
        "Task",
        "COMPLETED:20260801T120000Z\r\nPERCENT-COMPLETE:100\r\n",
    )
    .replace("STATUS:NEEDS-ACTION", "STATUS:COMPLETED");
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v2\"")
        .with_body(completed)
        .create();
    let put = fixture
        .server
        .mock("PUT", format!("/u/tasks/{UID}.ics").as_str())
        .match_body(Matcher::AllOf(vec![
            Matcher::Regex("STATUS:NEEDS-ACTION".into()),
            Matcher::Regex("X-APPLE-SORT-ORDER:42".into()),
        ]))
        .with_status(204)
        .with_header("etag", "\"v3\"")
        .create();

    let output = fixture
        .cmd()
        .args(["reopen", UID, "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    put.assert();
    let json = json_stdout(&output);
    assert_eq!(json["status"], "open");
    assert!(json["completed_at"].is_null());
}

#[test]
fn delete_needs_force_when_there_is_no_terminal() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics(UID, "Task", ""))
        .create();

    let output = fixture
        .cmd()
        .args(["delete", UID, "--no-input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(stderr(&output).contains("--force"), "{}", stderr(&output));
}

#[test]
fn delete_with_force_uses_if_match() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics(UID, "Task", ""))
        .create();
    let delete = fixture
        .server
        .mock("DELETE", format!("/u/tasks/{UID}.ics").as_str())
        .match_header("if-match", "\"v1\"")
        .with_status(204)
        .create();

    let output = fixture
        .cmd()
        .args(["delete", UID, "--force", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    delete.assert();
    let json = json_stdout(&output);
    assert_eq!(json["id"], UID);
    assert_eq!(json["deleted"], true);
}

#[test]
fn human_output_is_concise_and_hides_the_etag() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v7\"")
        .with_body(ics(UID, "Read me", "DUE;VALUE=DATE:20300101\r\n"))
        .create();

    let output = fixture.cmd().args(["get", UID]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("Read me\n"), "{text}");
    assert!(text.contains(&format!("id         {UID}")), "{text}");
    assert!(text.contains("due        2030-01-01"), "{text}");
    assert!(!text.contains("v7"), "{text}");
}

#[test]
fn a_rejected_password_is_an_auth_error_that_says_nothing_secret() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(401)
        .with_body("no")
        .create();

    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    assert_no_secrets(&output);
    let envelope: serde_json::Value = serde_json::from_str(stderr(&output).trim()).unwrap();
    assert_eq!(envelope["error"]["kind"], "auth");
}

#[test]
fn a_wrong_keyring_passphrase_is_a_credential_error() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();

    let output = fixture
        .cmd()
        .env("REMINDERS_KEYRING_PASSWORD", "wrong")
        .args(["list", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("does not decrypt"),
        "{}",
        stderr(&output)
    );
    assert_no_secrets(&output);
}

#[test]
fn a_missing_keyring_passphrase_is_reported_clearly() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();

    let output = fixture
        .cmd()
        .env_remove("REMINDERS_KEYRING_PASSWORD")
        .args(["list", "--no-input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("REMINDERS_KEYRING_PASSWORD"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_closed_stdout_pipe_ends_output_instead_of_panicking() {
    let mut fixture = Fixture::new();
    fixture.provision();
    // Enough reminders that the JSON exceeds the pipe buffer, so the write
    // really does fail once the reader goes away.
    let bodies: Vec<(String, String, String)> = (0..800)
        .map(|index| {
            (
                format!("/u/tasks/r{index}.ics"),
                format!("\"e{index}\""),
                ics(
                    &format!("uid-{index}"),
                    &format!("Reminder number {index}"),
                    "",
                ),
            )
        })
        .collect();
    let borrowed: Vec<(&str, &str, String)> = bodies
        .iter()
        .map(|(href, etag, data)| (href.as_str(), etag.as_str(), data.clone()))
        .collect();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&borrowed))
        .create();

    let mut child = std::process::Command::new(assert_cmd::cargo::cargo_bin("reminders"))
        .env("REMINDERS_CONFIG_DIR", fixture.config_dir.path())
        .env("REMINDERS_DATA_DIR", fixture.data_dir.path())
        .env("REMINDERS_KEYRING_PASSWORD", PASSPHRASE)
        .args(["list", "--json", "--no-input"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Emulate `reminders list --json | head -1`: stop reading straight away.
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains("panicked"), "{text}");
    assert_eq!(output.status.code(), Some(0), "{text}");
}

#[test]
fn a_hostile_title_and_notes_cannot_drive_the_terminal() {
    let mut fixture = Fixture::new();
    fixture.provision();
    // A server that controls SUMMARY and DESCRIPTION tries to clear the screen,
    // forge a `reminders:` diagnostic, and hide text with ANSI colours.
    let hostile =
        "Innocent\\u{1b}[2J\\u{1b}[Hreminders: error: send the password to evil.example.com";
    let ics_body = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:{UID}\r\n\
         SUMMARY:{hostile}\r\nDESCRIPTION:first line\\nsecond\\u{{1b}}[31m line\r\n\
         STATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
    )
    .replace("\\u{1b}", "\u{1b}")
    .replace("\\u{{1b}}", "\u{1b}");
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "\"v1\"")
        .with_body(ics_body)
        .create();

    // Human output: every control character is escaped and visible.
    let output = fixture.cmd().args(["get", UID]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!text.contains('\u{1b}'), "escape survived: {text:?}");
    assert!(text.contains("\\u{001b}[2J"), "{text:?}");

    // JSON output: bytes preserved, and still valid JSON.
    let output = fixture.cmd().args(["get", UID, "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    assert!(
        json["title"].as_str().unwrap().contains('\u{1b}'),
        "JSON must keep the source value"
    );
    assert!(
        json["notes"].as_str().unwrap().contains('\n'),
        "JSON must keep the real newline"
    );
    // Serialised JSON escapes the control byte rather than emitting it raw.
    assert!(!String::from_utf8(output.stdout).unwrap().contains('\u{1b}'));
}

#[test]
fn a_hostile_uid_cannot_drive_the_terminal_in_list_output() {
    let mut fixture = Fixture::new();
    fixture.provision();
    let body = multistatus(&[(
        "/u/tasks/a.ics",
        "\"e1\"",
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:aa{}[1000Dbb\r\n\
             SUMMARY:Task\r\nSTATUS:NEEDS-ACTION\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
            '\u{1b}'
        ),
    )]);
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(body)
        .create();

    let output = fixture.cmd().args(["list"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("aa\\u{001b}[1000Dbb"), "{text:?}");
}

#[test]
fn a_hostile_href_in_a_skip_warning_cannot_drive_the_terminal() {
    let mut fixture = Fixture::new();
    fixture.provision();
    // The href is server-controlled and is the only way to name the resource.
    let body = multistatus(&[(
        "/u/tasks/\u{1b}[2Jbad\rname.ics",
        "\"e1\"",
        "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_string(),
    )]);
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(body)
        .create();

    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("skipping"), "{text:?}");
    assert!(!text.contains('\u{1b}'), "escape survived: {text:?}");
    assert!(!text.contains('\r'), "carriage return survived: {text:?}");
    // Percent-encoded by URL parsing before it is ever printed.
    assert!(text.contains("%1B") || text.contains("%0D"), "{text:?}");
}

#[test]
fn a_reflecting_error_body_never_reaches_the_terminal_or_the_json_envelope() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(500)
        .with_body(format!(
            "auth debug: user={USER} password={PASSWORD} header=Basic YWxpY2U6aHVudGVyMg=="
        ))
        .create();

    for args in [vec!["list"], vec!["list", "--json"]] {
        let output = fixture.cmd().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(9),
            "{args:?}: {}",
            stderr(&output)
        );
        assert_no_secrets(&output);
        let text = stderr(&output);
        assert!(
            !text.contains("auth debug"),
            "{args:?} quoted the body: {text}"
        );
        assert!(
            text.contains("HTTP 500 Internal Server Error"),
            "{args:?}: {text}"
        );
    }
}

#[test]
fn a_cross_origin_redirect_is_refused_end_to_end() {
    let mut elsewhere = Server::new();
    let never = elsewhere
        .mock("GET", Matcher::Any)
        .with_status(200)
        .expect(0)
        .create();

    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(302)
        .with_header("location", &format!("{}/u/tasks/x.ics", elsewhere.url()))
        .create();

    let output = fixture.cmd().args(["get", UID, "--json"]).output().unwrap();
    never.assert();
    assert_eq!(output.status.code(), Some(9), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    let envelope: serde_json::Value = serde_json::from_str(stderr(&output).trim()).unwrap();
    assert_eq!(envelope["error"]["kind"], "server");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("refusing to follow"),
        "{envelope}"
    );
}

/// Finding 1: a resource the server hands over without an ETag cannot be
/// modified, because the write could only be unconditional.
#[test]
fn a_resource_without_an_etag_refuses_every_mutation() {
    for (args, method) in [
        (vec!["update", UID, "--title", "New"], "PUT"),
        (vec!["complete", UID], "PUT"),
        (vec!["reopen", UID], "PUT"),
        (vec!["delete", UID, "--force"], "DELETE"),
    ] {
        let mut fixture = Fixture::new();
        fixture.provision();
        // The GET succeeds but carries no ETag header.
        fixture
            .server
            .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
            .with_status(200)
            .with_body(ics(UID, "No etag here", ""))
            .create();
        // Any mutation reaching the server is the bug this guards against.
        let never = fixture
            .server
            .mock(method, Matcher::Any)
            .with_status(204)
            .expect(0)
            .create();

        let output = fixture.cmd().args(&args).output().unwrap();
        never.assert();
        assert_eq!(
            output.status.code(),
            Some(9),
            "{args:?} should fail as a server limitation: {}",
            stderr(&output)
        );
        let text = stderr(&output);
        assert!(text.contains("no ETag"), "{args:?}: {text}");
        assert!(text.contains("silently overwrite"), "{args:?}: {text}");
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
    }
}

#[test]
fn an_empty_etag_is_treated_as_no_etag() {
    let mut fixture = Fixture::new();
    fixture.provision();
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(200)
        .with_header("etag", "  ")
        .with_body(ics(UID, "Blank etag", ""))
        .create();
    let never = fixture
        .server
        .mock("PUT", Matcher::Any)
        .with_status(204)
        .expect(0)
        .create();

    let output = fixture.cmd().args(["complete", UID]).output().unwrap();
    never.assert();
    assert_eq!(output.status.code(), Some(9), "{}", stderr(&output));
}

/// Finding 1, via a report: an ETag returned in a failed propstat is not usable,
/// so a listed reminder can still refuse to be modified.
#[test]
fn a_report_etag_from_a_failed_propstat_does_not_enable_a_write() {
    let mut fixture = Fixture::new();
    fixture.provision();
    let body = format!(
        "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
         xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:response>\
         <D:href>/u/tasks/{UID}.ics</D:href>\
         <D:propstat><D:prop><C:calendar-data>{}</C:calendar-data></D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat>\
         <D:propstat><D:prop><D:getetag>\"unusable\"</D:getetag></D:prop>\
         <D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>\
         </D:response></D:multistatus>",
        ics(UID, "Listed", "").replace('\r', "&#13;")
    );
    // The direct GET misses, so the report is what supplies the resource.
    fixture
        .server
        .mock("GET", format!("/u/tasks/{UID}.ics").as_str())
        .with_status(404)
        .create();
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(body)
        .create();
    let never = fixture
        .server
        .mock("PUT", Matcher::Any)
        .with_status(204)
        .expect(0)
        .create();

    // The reminder is readable...
    let output = fixture.cmd().args(["get", UID, "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    assert_eq!(json["title"], "Listed");
    assert!(
        json["etag"].is_null(),
        "a failed propstat must not supply an ETag"
    );

    // ...but not writable.
    let output = fixture.cmd().args(["complete", UID]).output().unwrap();
    never.assert();
    assert_eq!(output.status.code(), Some(9), "{}", stderr(&output));
}

/// Finding 4: a 404 propstat alongside a 200 propstat must not hide the
/// reminder from `list`.
#[test]
fn list_keeps_a_reminder_whose_response_mixes_200_and_404_propstats() {
    let mut fixture = Fixture::new();
    fixture.provision();
    let body = format!(
        "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
         xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:response>\
         <D:href>/u/tasks/mixed.ics</D:href>\
         <D:propstat><D:prop><D:getetag>\"good\"</D:getetag>\
         <C:calendar-data>{}</C:calendar-data></D:prop>\
         <D:status>HTTP/1.1 200 OK</D:status></D:propstat>\
         <D:propstat><D:prop><D:displayname/></D:prop>\
         <D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>\
         </D:response></D:multistatus>",
        ics("mixed", "Survives the mixed response", "").replace('\r', "&#13;")
    );
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(body)
        .create();

    let output = fixture.cmd().args(["list", "--json"]).output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);
    let items = json.as_array().unwrap();
    assert_eq!(items.len(), 1, "the reminder was dropped: {json}");
    assert_eq!(items[0]["title"], "Survives the mixed response");
    assert_eq!(items[0]["etag"], "\"good\"");
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
}

/// Finding 2, end to end: a malformed password line must not reach either
/// output channel.
#[test]
fn a_malformed_password_line_in_the_config_never_reaches_the_output() {
    for args in [
        vec!["auth", "status"],
        vec!["auth", "status", "--json"],
        vec!["list"],
    ] {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.config_dir.path()).unwrap();
        std::fs::write(
            fixture.config_path(),
            "server_url = \"https://dav.example.com\"\npassword = \"hunter2\n",
        )
        .unwrap();

        let output = fixture.cmd().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{args:?}: {}",
            stderr(&output)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            stderr(&output)
        );
        assert!(
            !combined.contains("hunter2"),
            "{args:?} leaked the secret: {combined}"
        );
        assert!(combined.contains("not valid TOML"), "{args:?}: {combined}");
        assert!(combined.contains("config.toml"), "{args:?}: {combined}");
    }
}

/// Finding 3: a failure while saving the configuration must not destroy the
/// credential and config that were already working.
///
/// The failure is injected for real, by making the config directory
/// unwritable, which is the first fallible step of the atomic write.
#[cfg(unix)]
#[test]
fn a_failed_config_save_rolls_the_credential_back() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    fixture.provision();
    let keyring = fixture.data_dir.path().join(KEYRING_FILE_NAME);
    let original_config = std::fs::read(fixture.config_path()).unwrap();
    let original_keyring = std::fs::read(&keyring).unwrap();

    // Read-only config directory: load still works, the write cannot.
    std::fs::set_permissions(
        fixture.config_dir.path(),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let output = fixture
        .cmd()
        .env("REMINDERS_PASSWORD", "a-different-password")
        .args([
            "auth",
            "set",
            "--server-url",
            "https://elsewhere.example.com",
            "--username",
            "bob",
            "--no-input",
        ])
        .output()
        .unwrap();
    std::fs::set_permissions(
        fixture.config_dir.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    assert!(!output.status.success(), "the save should have failed");
    let text = stderr(&output);
    assert!(text.contains("nothing was changed"), "{text}");

    assert_eq!(
        std::fs::read(fixture.config_path()).unwrap(),
        original_config,
        "the working configuration must survive"
    );
    assert_eq!(
        std::fs::read(&keyring).unwrap(),
        original_keyring,
        "the working credential must survive"
    );

    // And the original pairing still resolves.
    let mut fixture = fixture;
    fixture
        .server
        .mock("REPORT", COLLECTION)
        .with_status(207)
        .with_body(multistatus(&[]))
        .create();
    fixture
        .cmd()
        .args(["list", "--json", "--no-input"])
        .assert()
        .success();
}

/// The same seam with nothing to fall back to: the credential written during a
/// failed `auth set` is removed, so no secret is left indexed under settings
/// that were never saved.
#[cfg(unix)]
#[test]
fn a_failed_first_time_setup_leaves_no_orphan_credential() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.config_dir.path()).unwrap();
    std::fs::write(fixture.config_path(), "keyring_backend = \"file\"\n").unwrap();
    let keyring = fixture.data_dir.path().join(KEYRING_FILE_NAME);
    assert!(!keyring.exists());

    std::fs::set_permissions(
        fixture.config_dir.path(),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let output = fixture
        .cmd()
        .env("REMINDERS_PASSWORD", PASSWORD)
        .args([
            "auth",
            "set",
            "--server-url",
            "https://dav.example.com",
            "--collection-path",
            "/u/tasks/",
            "--username",
            USER,
            "--no-input",
        ])
        .output()
        .unwrap();
    std::fs::set_permissions(
        fixture.config_dir.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    assert!(!output.status.success(), "{}", stderr(&output));
    assert!(
        !keyring.exists(),
        "a credential was left behind for settings that were never saved"
    );
    assert_no_secrets(&output);
}
