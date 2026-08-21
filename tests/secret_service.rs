//! The Secret Service credential backend, over a real D-Bus session.
//!
//! Unit tests cannot cover this path: they deliberately pin the encrypted file
//! backend so the suite needs no desktop session, which means the D-Bus code in
//! `SecretServiceStore` is never executed by `cargo test` alone.
//!
//! Driven by `scripts/integration/secret-service.sh`, which starts an isolated
//! `dbus-run-session`, unlocks a throwaway gnome-keyring inside it, and sets
//! `REMINDERS_TEST_SECRET_SERVICE=1`. Without that variable every test here
//! skips, because it would otherwise touch the developer's real login keyring.

use reminders::config::{KeyringBackend, ResolvedBackend};
use reminders::credentials::{
    resolve_backend, secret_service_usable, CredentialSnapshot, Keystore, SecretServiceStore,
};
use secrecy::{ExposeSecret, SecretString};

/// Whether the harness set this run up.
fn enabled() -> bool {
    std::env::var("REMINDERS_TEST_SECRET_SERVICE").is_ok_and(|value| !value.is_empty())
}

/// Skip cleanly, but loudly, when there is no session to talk to.
macro_rules! require_session {
    () => {
        if !enabled() {
            eprintln!(
                "skipping: run scripts/integration/secret-service.sh to exercise the real \
                 Secret Service"
            );
            return;
        }
    };
}

/// A distinct account per test, so repeats and parallel runs cannot collide.
fn unique_account(label: &str) -> String {
    format!("{label}-{}@secret-service.test", uuid::Uuid::new_v4())
}

struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = SecretServiceStore.delete(&self.0);
    }
}

#[test]
fn the_store_is_reachable_and_reports_itself_usable() {
    require_session!();
    let account = unique_account("probe");
    assert!(
        secret_service_usable(&account),
        "the harness should have provided an unlocked Secret Service"
    );
    // And `auto` therefore picks it, which is the branch the unit tests can only
    // simulate with an injected probe.
    let (backend, note) = resolve_backend(KeyringBackend::Auto, None, || {
        secret_service_usable(&account)
    });
    assert_eq!(backend, ResolvedBackend::SecretService);
    assert!(note.is_none(), "{note:?}");
}

#[test]
fn a_password_round_trips_through_the_secret_service() {
    require_session!();
    let account = unique_account("round-trip");
    let _cleanup = Cleanup(account.clone());
    let store = SecretServiceStore;
    assert_eq!(store.backend(), ResolvedBackend::SecretService);

    assert!(
        store.retrieve(&account).unwrap().is_none(),
        "a fresh account should hold nothing"
    );

    store
        .store(&account, &SecretString::from("hunter2".to_string()))
        .unwrap();
    assert_eq!(
        store.retrieve(&account).unwrap().unwrap().expose_secret(),
        "hunter2"
    );

    // Overwriting replaces rather than duplicating.
    store
        .store(&account, &SecretString::from("second".to_string()))
        .unwrap();
    assert_eq!(
        store.retrieve(&account).unwrap().unwrap().expose_secret(),
        "second"
    );

    assert!(store.delete(&account).unwrap());
    assert!(store.retrieve(&account).unwrap().is_none());
    assert!(
        !store.delete(&account).unwrap(),
        "deleting twice should report that nothing was removed"
    );
}

#[test]
fn values_that_stress_the_encoding_survive() {
    require_session!();
    let account = unique_account("encoding");
    let _cleanup = Cleanup(account.clone());
    let store = SecretServiceStore;

    for secret in [
        "plain",
        "with spaces and \"quotes\"",
        "unicode \u{1f680} \u{4e2d}\u{6587} caf\u{e9}",
        "newline\nand\ttab",
        &"long".repeat(500),
    ] {
        store
            .store(&account, &SecretString::from(secret.to_string()))
            .unwrap();
        assert_eq!(
            store.retrieve(&account).unwrap().unwrap().expose_secret(),
            secret,
            "value did not survive: {secret:?}"
        );
    }
}

#[test]
fn snapshot_and_restore_undo_a_change() {
    require_session!();
    let account = unique_account("snapshot");
    let _cleanup = Cleanup(account.clone());
    let store = SecretServiceStore;

    // Snapshotting an empty slot, then restoring it, removes what was written.
    let absent = store.snapshot(&account).unwrap();
    assert!(matches!(absent, CredentialSnapshot::Absent));
    store
        .store(&account, &SecretString::from("written".to_string()))
        .unwrap();
    store.restore(&account, &absent).unwrap();
    assert!(store.retrieve(&account).unwrap().is_none());

    // Snapshotting a real value, then restoring it, undoes an overwrite.
    store
        .store(&account, &SecretString::from("original".to_string()))
        .unwrap();
    let snapshot = store.snapshot(&account).unwrap();
    assert!(matches!(snapshot, CredentialSnapshot::Secret(_)));
    store
        .store(&account, &SecretString::from("replacement".to_string()))
        .unwrap();
    store.restore(&account, &snapshot).unwrap();
    assert_eq!(
        store.retrieve(&account).unwrap().unwrap().expose_secret(),
        "original"
    );
}

/// The whole CLI, using the Secret Service rather than the file keyring.
#[test]
fn the_binary_uses_the_secret_service_end_to_end() {
    require_session!();

    let username = format!("ss-{}", uuid::Uuid::new_v4());
    let config_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();

    let mut server = mockito::Server::new();
    let account = format!("{username}@{}", server.url().trim_start_matches("http://"));
    let _cleanup = Cleanup(account.clone());

    let cmd = || {
        let mut cmd = assert_cmd::Command::cargo_bin("reminders").unwrap();
        cmd.env("REMINDERS_CONFIG_DIR", config_dir.path())
            .env("REMINDERS_DATA_DIR", data_dir.path())
            // No file-keyring passphrase anywhere: if anything falls back to the
            // file backend, it fails instead of silently working.
            .env_remove("REMINDERS_KEYRING_PASSWORD")
            .env_remove("REMINDERS_PASSWORD");
        cmd
    };

    cmd()
        .args(["auth", "keyring", "secret-service"])
        .assert()
        .success();
    cmd()
        .env("REMINDERS_PASSWORD", "hunter2")
        .args([
            "auth",
            "set",
            "--server-url",
            &server.url(),
            "--collection-path",
            "/u/tasks/",
            "--username",
            &username,
            "--no-input",
        ])
        .assert()
        .success();

    // The credential is in the Secret Service, not on disk.
    assert!(
        !data_dir.path().join("credentials.age").exists(),
        "nothing should have been written to the file keyring"
    );
    assert_eq!(
        SecretServiceStore
            .retrieve(&account)
            .unwrap()
            .unwrap()
            .expose_secret(),
        "hunter2"
    );

    let output = cmd().args(["auth", "status", "--json"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["active_backend"], "secret-service");
    assert_eq!(status["credential_backend"], "secret-service");
    assert_eq!(status["credential_readable"], true);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("hunter2"),
        "auth status must not print the password"
    );

    // A real request, proving the credential is read back and used.
    let listed = server
        .mock("REPORT", "/u/tasks/")
        .match_header(
            "authorization",
            mockito::Matcher::Regex("^Basic .+$".into()),
        )
        .with_status(207)
        .with_body("<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"></D:multistatus>")
        .create();
    let output = cmd()
        .args(["list", "--json", "--no-input"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    listed.assert();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );

    // And `auth remove` clears the entry from the real store.
    cmd().args(["auth", "remove", "--json"]).assert().success();
    assert!(SecretServiceStore.retrieve(&account).unwrap().is_none());
}

/// With the Secret Service available and unlocked, an explicit `file`
/// preference must still not reach D-Bus. Proven by the failure being about the
/// *file* keyring: had it fallen back, the read would have succeeded or failed
/// naming the Secret Service instead.
#[test]
fn an_explicit_file_preference_does_not_fall_back_to_the_secret_service() {
    require_session!();

    let config_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::tempdir().unwrap();
    let mut cmd = assert_cmd::Command::cargo_bin("reminders").unwrap();
    cmd.env("REMINDERS_CONFIG_DIR", config_dir.path())
        .env("REMINDERS_DATA_DIR", data_dir.path())
        .env_remove("REMINDERS_KEYRING_PASSWORD")
        .env_remove("REMINDERS_PASSWORD");
    std::fs::create_dir_all(config_dir.path()).unwrap();
    std::fs::write(
        config_dir.path().join("config.toml"),
        "server_url = \"https://dav.example.com\"\ncollection_path = \"/u/tasks/\"\n\
         username = \"someone\"\nkeyring_backend = \"file\"\n",
    )
    .unwrap();

    let output = cmd.args(["list", "--no-input"]).output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("file keyring"), "{text}");
    assert!(
        !text.contains("Secret Service"),
        "an explicit file preference must not consult the Secret Service: {text}"
    );

    // And the Secret Service genuinely was reachable during that run, so the
    // absence of a fallback is a real result rather than an unavailable store.
    assert!(secret_service_usable("someone@dav.example.com"));
}
