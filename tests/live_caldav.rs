//! CRUD against a real CalDAV server.
//!
//! Normally driven by `scripts/integration/radicale.sh`, which starts a pinned
//! Radicale container, creates a VTODO collection, and points this test at it.
//! That script sets `REMINDERS_LIVE_REQUIRED=1`, so a missing server is a
//! failure rather than a skip: a silently skipped integration test is worse
//! than none, because it reads as passing.
//!
//! Run by hand against any throwaway collection:
//!
//! ```sh
//! REMINDERS_LIVE_SERVER_URL=https://dav.example.com \
//! REMINDERS_LIVE_COLLECTION_PATH=/user/tasks/ \
//! REMINDERS_LIVE_USERNAME=user \
//! REMINDERS_LIVE_PASSWORD=secret \
//! cargo test --test live_caldav -- --nocapture
//! ```

use reminders::caldav::Client;
use reminders::config::Config;
use reminders::datetime::parse_instant;
use reminders::ical::Document;
use reminders::model::{Priority, ReminderChanges, Status};
use secrecy::SecretString;

struct Live {
    client: Client,
}

/// Build a client from the environment, or `None` when no server was supplied.
fn live() -> Option<Live> {
    let read = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let server_url = read("REMINDERS_LIVE_SERVER_URL")?;
    let collection_path = read("REMINDERS_LIVE_COLLECTION_PATH")?;
    let username = read("REMINDERS_LIVE_USERNAME")?;
    let password = read("REMINDERS_LIVE_PASSWORD")?;

    let settings = Config {
        server_url: Some(server_url),
        collection_path: Some(collection_path),
        username: Some(username),
        ..Default::default()
    }
    .settings()
    .expect("live settings");
    let client = Client::new(&settings, &SecretString::from(password)).expect("live client");
    Some(Live { client })
}

/// Whether a missing server should fail rather than skip.
fn required() -> bool {
    std::env::var("REMINDERS_LIVE_REQUIRED").is_ok_and(|value| !value.is_empty())
}

/// The ETag of a resource, which every mutation needs.
fn etag_of(resource: &reminders::caldav::Resource) -> String {
    resource
        .etag
        .clone()
        .expect("the server must return an ETag; without one no write is safe")
}

#[test]
fn full_crud_against_a_live_collection() {
    let Some(live) = live() else {
        assert!(
            !required(),
            "REMINDERS_LIVE_REQUIRED is set but the server details are missing; run this \
             through scripts/integration/radicale.sh"
        );
        eprintln!(
            "skipping: set REMINDERS_LIVE_SERVER_URL, REMINDERS_LIVE_COLLECTION_PATH, \
             REMINDERS_LIVE_USERNAME, and REMINDERS_LIVE_PASSWORD, or run \
             scripts/integration/radicale.sh"
        );
        return;
    };

    let uid = uuid::Uuid::new_v4().to_string();
    let due = parse_instant("2030-08-22T16:00:00+04:00").unwrap();
    let document = Document::new_reminder(
        &uid,
        "reminders live test",
        Some("created by the automated live test\nsecond line"),
        Some(reminders::datetime::Due::At(due)),
        Some(due),
        Priority::High,
        chrono::Utc::now(),
    );

    // Create.
    let created = live
        .client
        .create(&uid, &document.to_ics())
        .expect("create should succeed");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Read back.
        let fetched = live
            .client
            .find_by_uid(&uid)
            .expect("find should succeed")
            .expect("the reminder should exist");
        let reminder = Document::parse(&fetched.data)
            .unwrap()
            .to_reminder(fetched.etag.clone(), Some(fetched.href.clone()))
            .unwrap();
        assert_eq!(reminder.id, uid);
        assert_eq!(reminder.title, "reminders live test");
        assert_eq!(
            reminder.notes.as_deref(),
            Some("created by the automated live test\nsecond line")
        );
        assert_eq!(reminder.priority, Priority::High);
        assert_eq!(reminder.status, Status::Open);
        assert_eq!(reminder.remind_at, Some(due));
        assert_eq!(reminder.due, Some(reminders::datetime::Due::At(due)));
        let first_etag = etag_of(&fetched);

        // The collection listing includes it, with a usable ETag. This is the
        // path that a mixed 200/404 propstat response used to break.
        let listed = live.client.list_todos().expect("list should succeed");
        let ours = listed
            .iter()
            .find(|resource| resource.data.contains(&uid))
            .expect("the new reminder should appear in the listing");
        assert!(
            ours.etag.is_some(),
            "the listing must carry an ETag, or nothing found this way can be modified"
        );

        // Update under If-Match.
        let mut document = Document::parse(&fetched.data).unwrap();
        document.apply(
            &ReminderChanges {
                title: Some("reminders live test (updated)".into()),
                priority: Some(Priority::Low),
                ..Default::default()
            },
            chrono::Utc::now(),
        );
        let updated = live
            .client
            .update(&fetched.href, &document.to_ics(), &first_etag)
            .expect("update should succeed");
        assert_ne!(
            updated.etag,
            Some(first_etag.clone()),
            "the ETag should change after a write"
        );

        let after = live.client.find_by_uid(&uid).unwrap().unwrap();
        let reminder = Document::parse(&after.data)
            .unwrap()
            .to_reminder(None, None)
            .unwrap();
        assert_eq!(reminder.title, "reminders live test (updated)");
        assert_eq!(reminder.priority, Priority::Low);
        // Unknown properties written at creation are still there.
        assert!(after.data.contains(&uid));

        // A stale ETag must be refused instead of overwriting.
        let err = live
            .client
            .update(&fetched.href, &document.to_ics(), &first_etag)
            .expect_err("a stale ETag must be refused");
        assert_eq!(
            err.exit_code(),
            reminders::error::exit::CONFLICT,
            "stale write should be a conflict: {err}"
        );

        // And the refused write changed nothing.
        let unchanged = live.client.find_by_uid(&uid).unwrap().unwrap();
        assert_eq!(
            unchanged.etag, after.etag,
            "a refused write must not alter the resource"
        );

        // Complete, then reopen.
        for status in [Status::Complete, Status::Open] {
            let current = live.client.find_by_uid(&uid).unwrap().unwrap();
            let mut document = Document::parse(&current.data).unwrap();
            document.apply(
                &ReminderChanges {
                    status: Some(status),
                    ..Default::default()
                },
                chrono::Utc::now(),
            );
            live.client
                .update(&current.href, &document.to_ics(), &etag_of(&current))
                .expect("status change should succeed");
            let after = live.client.find_by_uid(&uid).unwrap().unwrap();
            let reminder = Document::parse(&after.data)
                .unwrap()
                .to_reminder(None, None)
                .unwrap();
            assert_eq!(reminder.status, status);
            if status == Status::Complete {
                assert!(reminder.completed_at.is_some());
            } else {
                assert!(reminder.completed_at.is_none());
            }
        }

        // A stale ETag must also stop a delete.
        let err = live
            .client
            .delete(&fetched.href, &first_etag)
            .expect_err("a stale ETag must refuse a delete");
        assert_eq!(
            err.exit_code(),
            reminders::error::exit::CONFLICT,
            "stale delete should be a conflict: {err}"
        );
        assert!(
            live.client.find_by_uid(&uid).unwrap().is_some(),
            "a refused delete must not remove the reminder"
        );
    }));

    // Always clean up, then surface any assertion failure.
    let current = live.client.find_by_uid(&uid).ok().flatten();
    let (href, etag) = match &current {
        Some(resource) => (resource.href.clone(), resource.etag.clone()),
        None => (created.href.clone(), created.etag.clone()),
    };
    let cleanup = match etag {
        Some(etag) => live.client.delete(&href, &etag),
        None => Ok(()),
    };

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    cleanup.expect("delete should succeed");
    assert!(
        live.client.find_by_uid(&uid).unwrap().is_none(),
        "the reminder should be gone after delete"
    );
}

/// The CLI binary itself, end to end, against the same server.
#[test]
fn the_binary_works_against_a_live_collection() {
    let Some(_live) = live() else {
        assert!(
            !required(),
            "REMINDERS_LIVE_REQUIRED is set but no server was supplied"
        );
        eprintln!("skipping: no live server configured");
        return;
    };

    let config_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();
    let passphrase = "integration-file-keyring";
    let title = format!("cli integration {}", uuid::Uuid::new_v4());

    let cmd = || {
        let mut cmd = assert_cmd::Command::cargo_bin("reminders").unwrap();
        cmd.env("REMINDERS_CONFIG_DIR", config_dir.path())
            .env("REMINDERS_DATA_DIR", data_dir.path())
            .env("REMINDERS_KEYRING_PASSWORD", passphrase)
            .env_remove("REMINDERS_PASSWORD");
        cmd
    };

    // Pin the file keyring so nothing needs a D-Bus session here.
    cmd().args(["auth", "keyring", "file"]).assert().success();
    cmd()
        .env(
            "REMINDERS_PASSWORD",
            std::env::var("REMINDERS_LIVE_PASSWORD").unwrap(),
        )
        .args([
            "auth",
            "set",
            "--server-url",
            &std::env::var("REMINDERS_LIVE_SERVER_URL").unwrap(),
            "--collection-path",
            &std::env::var("REMINDERS_LIVE_COLLECTION_PATH").unwrap(),
            "--username",
            &std::env::var("REMINDERS_LIVE_USERNAME").unwrap(),
            "--no-input",
        ])
        .assert()
        .success();

    cmd().args(["auth", "status", "--json"]).assert().success();

    // Create.
    let output = cmd()
        .args([
            "add",
            &title,
            "--notes",
            "line one\nline two",
            "--at",
            "2030-09-01T12:00:00Z",
            "--priority",
            "medium",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let created: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["title"], title.as_str());
    assert!(
        created["etag"].is_string(),
        "the server must return an ETag on create: {created}"
    );

    // Read, change, complete, reopen, delete. Any of these failing leaves the
    // reminder behind, which the final assertion catches.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let output = cmd().args(["get", &id, "--json"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(got["notes"], "line one\nline two");
        assert_eq!(got["priority"], "medium");
        assert_eq!(got["due"], "2030-09-01T12:00:00Z");
        assert_eq!(got["remind_at"], "2030-09-01T12:00:00Z");

        let output = cmd().args(["list", "--json"]).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["id"] == id.as_str()),
            "the new reminder should be listed"
        );

        for args in [
            vec![
                "update",
                &id,
                "--title",
                "renamed by the integration test",
                "--json",
            ],
            vec!["complete", &id, "--json"],
            vec!["reopen", &id, "--json"],
        ] {
            let output = cmd().args(&args).output().unwrap();
            assert!(
                output.status.success(),
                "{args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }));

    let deleted = cmd()
        .args(["delete", &id, "--force", "--json"])
        .output()
        .unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert!(
        deleted.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&deleted.stderr)
    );
    cmd().args(["get", &id]).assert().failure();
}
