//! Credential storage.
//!
//! Two stores are supported: the Linux Secret Service (through the `keyring`
//! crate) and an [age](https://age-encryption.org)-encrypted file for headless
//! systems. The plaintext password is never written to disk and never appears
//! in an error message.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::config::{
    create_private_dir, data_dir, write_private_file, KeyringBackend, ResolvedBackend,
};
use crate::error::{Error, Result};

/// Service name used for Secret Service entries.
pub const KEYRING_SERVICE: &str = "reminders";
/// Environment variable holding the encrypted-file passphrase.
pub const KEYRING_PASSPHRASE_ENV: &str = "REMINDERS_KEYRING_PASSWORD";
/// Environment variable holding the CalDAV password, for provisioning without a TTY.
pub const CALDAV_PASSWORD_ENV: &str = "REMINDERS_PASSWORD";
/// File name of the encrypted keyring.
pub const KEYRING_FILE_NAME: &str = "credentials.age";
/// Payload format version, so a future change can be detected rather than guessed.
const PAYLOAD_VERSION: u32 = 1;

/// Enough of a store's previous state to put it back exactly as it was.
///
/// Deliberately opaque: the file store snapshots raw ciphertext, which needs no
/// passphrase to restore, while the Secret Service snapshots the secret itself.
pub enum CredentialSnapshot {
    /// Nothing was stored.
    Absent,
    /// A plaintext secret to write back.
    Secret(SecretString),
    /// The encrypted file's bytes, restored without needing the passphrase.
    RawFile(Vec<u8>),
}

/// A place to keep exactly one CalDAV password.
pub trait Keystore {
    /// Which store this is.
    fn backend(&self) -> ResolvedBackend;
    /// Write (or overwrite) the password for `account`.
    fn store(&self, account: &str, secret: &SecretString) -> Result<()>;
    /// Read the password for `account`, or `None` when nothing is stored.
    fn retrieve(&self, account: &str) -> Result<Option<SecretString>>;
    /// Remove the password. Returns whether anything was removed.
    fn delete(&self, account: &str) -> Result<bool>;
    /// Capture what is stored now, so a failed change can be undone.
    ///
    /// Must not need a passphrase or any interaction: it runs before a change
    /// that might fail, and the undo has to work without asking again.
    fn snapshot(&self, account: &str) -> Result<CredentialSnapshot>;
    /// Put a [`Keystore::snapshot`] back, including "there was nothing here".
    fn restore(&self, account: &str, snapshot: &CredentialSnapshot) -> Result<()>;
}

/// Decide which store to use, and optionally explain the decision.
///
/// A recorded backend always wins so that reads never silently move to another
/// store; the returned note tells the user how to change it.
pub fn resolve_backend(
    preference: KeyringBackend,
    recorded: Option<ResolvedBackend>,
    secret_service_usable: impl FnOnce() -> bool,
) -> (ResolvedBackend, Option<String>) {
    if let Some(recorded) = recorded {
        let wanted = match preference {
            KeyringBackend::Auto => None,
            KeyringBackend::SecretService => Some(ResolvedBackend::SecretService),
            KeyringBackend::File => Some(ResolvedBackend::File),
        };
        let note = match wanted {
            Some(wanted) if wanted != recorded => Some(format!(
                "the credential is stored in the {} keyring but the configured backend is \
                 {}; run `reminders auth set` to move it",
                recorded.as_str(),
                wanted.as_str()
            )),
            _ => None,
        };
        return (recorded, note);
    }

    match preference {
        KeyringBackend::SecretService => (ResolvedBackend::SecretService, None),
        KeyringBackend::File => (ResolvedBackend::File, None),
        KeyringBackend::Auto => {
            if secret_service_usable() {
                (ResolvedBackend::SecretService, None)
            } else {
                (
                    ResolvedBackend::File,
                    Some(
                        "Secret Service is unavailable or locked; using the encrypted file \
                         keyring"
                            .to_string(),
                    ),
                )
            }
        }
    }
}

/// True when the Secret Service can be reached and read right now.
pub fn secret_service_usable(account: &str) -> bool {
    if keyring::Entry::store_status().is_err() {
        return false;
    }
    match keyring::Entry::new(KEYRING_SERVICE, account) {
        Ok(entry) => matches!(entry.get_password(), Ok(_) | Err(keyring::Error::NoEntry)),
        Err(_) => false,
    }
}

/// Open a store by name.
pub fn open_store(
    backend: ResolvedBackend,
    passphrase: PassphraseSource,
) -> Result<Box<dyn Keystore>> {
    match backend {
        ResolvedBackend::SecretService => Ok(Box::new(SecretServiceStore)),
        ResolvedBackend::File => Ok(Box::new(FileStore::new(keyring_file_path()?, passphrase))),
    }
}

/// Default path of the encrypted keyring file.
pub fn keyring_file_path() -> Result<PathBuf> {
    Ok(data_dir()?.join(KEYRING_FILE_NAME))
}

/// The Linux Secret Service, reached over the user's D-Bus session.
pub struct SecretServiceStore;

impl SecretServiceStore {
    fn entry(account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(KEYRING_SERVICE, account).map_err(map_keyring_error)
    }
}

impl Keystore for SecretServiceStore {
    fn backend(&self) -> ResolvedBackend {
        ResolvedBackend::SecretService
    }

    fn store(&self, account: &str, secret: &SecretString) -> Result<()> {
        Self::entry(account)?
            .set_password(secret.expose_secret())
            .map_err(map_keyring_error)
    }

    fn retrieve(&self, account: &str) -> Result<Option<SecretString>> {
        match Self::entry(account)?.get_password() {
            Ok(password) => Ok(Some(SecretString::from(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match Self::entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn snapshot(&self, account: &str) -> Result<CredentialSnapshot> {
        Ok(match self.retrieve(account)? {
            Some(secret) => CredentialSnapshot::Secret(secret),
            None => CredentialSnapshot::Absent,
        })
    }

    fn restore(&self, account: &str, snapshot: &CredentialSnapshot) -> Result<()> {
        match snapshot {
            CredentialSnapshot::Secret(secret) => self.store(account, secret),
            CredentialSnapshot::Absent => self.delete(account).map(|_| ()),
            CredentialSnapshot::RawFile(_) => Err(Error::credential(
                "internal error: a file keyring snapshot cannot be restored into the \
                 Secret Service",
            )),
        }
    }
}

/// Translate keyring failures into actionable advice. The keyring crate never
/// puts secret material in its errors, but it can carry the password bytes in
/// `BadEncoding`, so that variant is reported without its payload.
fn map_keyring_error(err: keyring::Error) -> Error {
    match err {
        keyring::Error::NoDefaultStore => Error::credential(
            "the Secret Service is unavailable: no D-Bus session was found. On a headless \
             system run `reminders auth keyring file` and `reminders auth set`",
        ),
        keyring::Error::NoStorageAccess(_) => Error::credential(
            "the Secret Service keyring is locked or refused access; unlock it, or run \
             `reminders auth keyring file` and `reminders auth set`",
        ),
        keyring::Error::PlatformFailure(inner) => {
            Error::credential(format!("the Secret Service reported a failure: {inner}"))
        }
        keyring::Error::BadEncoding(_) => {
            Error::credential("the stored credential is not valid UTF-8; run `reminders auth set`")
        }
        keyring::Error::Ambiguous(_) => Error::credential(
            "more than one matching credential is stored; remove the duplicates with your \
             keyring manager, then run `reminders auth set`",
        ),
        keyring::Error::NoEntry => {
            Error::credential("no credential is stored for this account; run `reminders auth set`")
        }
        other => Error::credential(format!("credential store error: {other}")),
    }
}

/// How to obtain the encrypted keyring's passphrase.
pub enum PassphraseSource {
    /// Use this exact passphrase. Used by tests and by callers that already have it.
    Fixed(SecretString),
    /// Read `$REMINDERS_KEYRING_PASSWORD`, else prompt when a terminal is attached.
    Ambient {
        /// Whether prompting is allowed at all (`--no-input` clears this).
        interactive: bool,
    },
}

impl PassphraseSource {
    /// Resolve the passphrase, prompting twice when `confirm` is set.
    pub fn resolve(&self, confirm: bool) -> Result<SecretString> {
        match self {
            PassphraseSource::Fixed(secret) => Ok(secret.clone()),
            PassphraseSource::Ambient { interactive } => {
                if let Some(value) = non_empty_env(KEYRING_PASSPHRASE_ENV) {
                    return Ok(SecretString::from(value));
                }
                if !*interactive || !std::io::stdin().is_terminal() {
                    return Err(Error::credential(format!(
                        "the encrypted file keyring needs a passphrase: set \
                         ${KEYRING_PASSPHRASE_ENV} or run the command with a terminal \
                         attached"
                    )));
                }
                let first = prompt_secret("File keyring passphrase: ")?;
                if first.expose_secret().is_empty() {
                    return Err(Error::credential("the passphrase must not be empty"));
                }
                if confirm {
                    let second = prompt_secret("Confirm file keyring passphrase: ")?;
                    if first.expose_secret() != second.expose_secret() {
                        return Err(Error::credential("the passphrases did not match"));
                    }
                }
                Ok(first)
            }
        }
    }
}

/// Read an environment variable, treating empty as unset.
pub fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Prompt for a secret on the terminal, echoing nothing.
pub fn prompt_secret(prompt: &str) -> Result<SecretString> {
    let value = rpassword::prompt_password(prompt)
        .map_err(|err| Error::credential(format!("cannot read the passphrase: {err}")))?;
    Ok(SecretString::from(value))
}

#[derive(Serialize, Deserialize)]
struct Payload {
    version: u32,
    account: String,
    password: String,
}

/// An age-encrypted file holding one credential.
pub struct FileStore {
    path: PathBuf,
    passphrase: PassphraseSource,
}

impl FileStore {
    /// Build a store over `path`, taking the passphrase from `passphrase`.
    pub fn new(path: PathBuf, passphrase: PassphraseSource) -> Self {
        FileStore { path, passphrase }
    }

    /// Path of the backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the backing file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

impl Keystore for FileStore {
    fn backend(&self) -> ResolvedBackend {
        ResolvedBackend::File
    }

    fn store(&self, account: &str, secret: &SecretString) -> Result<()> {
        // Writing always re-creates the file, so the passphrase can be changed
        // freely and we never need to read the previous contents.
        let passphrase = self.passphrase.resolve(true)?;
        let payload = Payload {
            version: PAYLOAD_VERSION,
            account: account.to_string(),
            password: secret.expose_secret().to_string(),
        };
        let plaintext = serde_json::to_vec(&payload)
            .map_err(|err| Error::credential(format!("cannot encode the credential: {err}")))?;
        let recipient = age::scrypt::Recipient::new(to_age_secret(&passphrase));
        let armored = age::encrypt_and_armor(&recipient, &plaintext)
            .map_err(|err| Error::credential(format!("cannot encrypt the credential: {err}")))?;
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        // Reported as a credential problem for the same reason as elsewhere: the
        // exit code should say which half of the setup failed.
        write_private_file(&self.path, armored.as_bytes())
            .map_err(|err| Error::credential(err.to_string()))
    }

    fn retrieve(&self, account: &str) -> Result<Option<SecretString>> {
        let ciphertext = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(Error::credential(format!(
                    "cannot read {}: {err}",
                    self.path.display()
                )))
            }
        };
        let passphrase = self.passphrase.resolve(false)?;
        let identity = age::scrypt::Identity::new(to_age_secret(&passphrase));
        let plaintext = age::decrypt(&identity, &ciphertext).map_err(|err| match err {
            age::DecryptError::NoMatchingKeys | age::DecryptError::DecryptionFailed => {
                Error::credential(format!(
                    "the passphrase does not decrypt {}",
                    self.path.display()
                ))
            }
            other => Error::credential(format!("cannot decrypt {}: {other}", self.path.display())),
        })?;
        let payload: Payload = serde_json::from_slice(&plaintext).map_err(|_| {
            Error::credential(format!(
                "{} does not contain a credential this version understands",
                self.path.display()
            ))
        })?;
        if payload.version != PAYLOAD_VERSION {
            return Err(Error::credential(format!(
                "{} was written by an incompatible version; run `reminders auth set`",
                self.path.display()
            )));
        }
        if payload.account != account {
            return Err(Error::credential(format!(
                "{} holds a credential for {:?}, not {account:?}; run `reminders auth set`",
                self.path.display(),
                payload.account
            )));
        }
        Ok(Some(SecretString::from(payload.password)))
    }

    fn delete(&self, _account: &str) -> Result<bool> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(Error::credential(format!(
                "cannot remove {}: {err}",
                self.path.display()
            ))),
        }
    }

    /// Snapshots the ciphertext, so restoring needs no passphrase.
    ///
    /// This matters because the passphrase may have come from a one-shot
    /// prompt: re-encrypting on rollback could not be done silently, and this
    /// store holds a single slot, so a write for a *different* account still
    /// destroys the previous one.
    fn snapshot(&self, _account: &str) -> Result<CredentialSnapshot> {
        Ok(match crate::config::read_optional(&self.path)? {
            Some(bytes) => CredentialSnapshot::RawFile(bytes),
            None => CredentialSnapshot::Absent,
        })
    }

    fn restore(&self, _account: &str, snapshot: &CredentialSnapshot) -> Result<()> {
        match snapshot {
            CredentialSnapshot::RawFile(bytes) => {
                crate::config::restore_optional(&self.path, Some(bytes))
            }
            CredentialSnapshot::Absent => crate::config::restore_optional(&self.path, None),
            CredentialSnapshot::Secret(secret) => self.store(_account, secret),
        }
    }
}

/// Bridge our secret type to the one `age` expects.
fn to_age_secret(secret: &SecretString) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(secret.expose_secret().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(value: &str) -> PassphraseSource {
        PassphraseSource::Fixed(SecretString::from(value.to_string()))
    }

    fn store_in(dir: &Path, passphrase: &str) -> FileStore {
        FileStore::new(dir.join(KEYRING_FILE_NAME), fixed(passphrase))
    }

    #[test]
    fn explicit_preference_wins_when_nothing_is_recorded() {
        let (backend, note) =
            resolve_backend(KeyringBackend::File, None, || panic!("must not probe"));
        assert_eq!(backend, ResolvedBackend::File);
        assert!(note.is_none());

        let (backend, note) = resolve_backend(KeyringBackend::SecretService, None, || {
            panic!("must not probe")
        });
        assert_eq!(backend, ResolvedBackend::SecretService);
        assert!(note.is_none());
    }

    #[test]
    fn auto_uses_secret_service_when_it_works() {
        let (backend, note) = resolve_backend(KeyringBackend::Auto, None, || true);
        assert_eq!(backend, ResolvedBackend::SecretService);
        assert!(note.is_none());
    }

    #[test]
    fn auto_falls_back_to_file_when_secret_service_is_unusable() {
        let (backend, note) = resolve_backend(KeyringBackend::Auto, None, || false);
        assert_eq!(backend, ResolvedBackend::File);
        assert!(note.unwrap().contains("encrypted file keyring"));
    }

    #[test]
    fn recorded_backend_is_never_silently_changed() {
        for preference in [
            KeyringBackend::Auto,
            KeyringBackend::SecretService,
            KeyringBackend::File,
        ] {
            let (backend, _) = resolve_backend(preference, Some(ResolvedBackend::File), || true);
            assert_eq!(backend, ResolvedBackend::File, "{preference:?}");
        }
    }

    #[test]
    fn recorded_backend_conflict_is_explained() {
        let (backend, note) = resolve_backend(
            KeyringBackend::SecretService,
            Some(ResolvedBackend::File),
            || true,
        );
        assert_eq!(backend, ResolvedBackend::File);
        let note = note.unwrap();
        assert!(note.contains("stored in the file keyring"), "{note}");
        assert!(note.contains("auth set"), "{note}");
    }

    #[test]
    fn matching_recorded_backend_produces_no_note() {
        let (_, note) = resolve_backend(KeyringBackend::File, Some(ResolvedBackend::File), || true);
        assert!(note.is_none());
        let (_, note) = resolve_backend(
            KeyringBackend::Auto,
            Some(ResolvedBackend::SecretService),
            || true,
        );
        assert!(note.is_none());
    }

    #[test]
    fn file_store_round_trips_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "correct horse");
        assert_eq!(store.backend(), ResolvedBackend::File);
        assert!(store.retrieve("alice@example.com").unwrap().is_none());

        store
            .store(
                "alice@example.com",
                &SecretString::from("hunter2".to_string()),
            )
            .unwrap();
        let secret = store.retrieve("alice@example.com").unwrap().unwrap();
        assert_eq!(secret.expose_secret(), "hunter2");
    }

    #[test]
    fn file_store_ciphertext_is_armored_and_hides_the_password() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), "pp")
            .store(
                "alice@example.com",
                &SecretString::from("hunter2".to_string()),
            )
            .unwrap();
        let bytes = fs::read(dir.path().join(KEYRING_FILE_NAME)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
            "{text}"
        );
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("alice@example.com"));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("data");
        store_in(&nested, "pp")
            .store("a@b", &SecretString::from("x".to_string()))
            .unwrap();
        let mode = fs::metadata(nested.join(KEYRING_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }

    #[test]
    fn wrong_passphrase_is_reported_without_leaking() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), "right")
            .store("a@b", &SecretString::from("hunter2".to_string()))
            .unwrap();
        let err = store_in(dir.path(), "wrong").retrieve("a@b").unwrap_err();
        assert!(err.to_string().contains("does not decrypt"), "{err}");
        assert!(!err.to_string().contains("hunter2"));
        assert!(!err.to_string().contains("right"));
        assert_eq!(err.exit_code(), crate::error::exit::CREDENTIAL);
    }

    #[test]
    fn account_mismatch_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), "pp")
            .store("alice@example.com", &SecretString::from("x".to_string()))
            .unwrap();
        let err = store_in(dir.path(), "pp")
            .retrieve("bob@example.com")
            .unwrap_err();
        assert!(err.to_string().contains("alice@example.com"), "{err}");
        assert!(err.to_string().contains("auth set"), "{err}");
    }

    #[test]
    fn corrupt_file_is_reported_as_a_credential_error() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(KEYRING_FILE_NAME), b"not age at all").unwrap();
        let err = store_in(dir.path(), "pp").retrieve("a@b").unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::CREDENTIAL);
    }

    #[test]
    fn delete_reports_whether_anything_was_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "pp");
        assert!(!store.delete("a@b").unwrap());
        store
            .store("a@b", &SecretString::from("x".to_string()))
            .unwrap();
        assert!(store.exists());
        assert!(store.delete("a@b").unwrap());
        assert!(!store.exists());
    }

    #[test]
    fn overwriting_may_change_the_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), "first")
            .store("a@b", &SecretString::from("one".to_string()))
            .unwrap();
        store_in(dir.path(), "second")
            .store("a@b", &SecretString::from("two".to_string()))
            .unwrap();
        assert!(store_in(dir.path(), "first").retrieve("a@b").is_err());
        assert_eq!(
            store_in(dir.path(), "second")
                .retrieve("a@b")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "two"
        );
    }

    #[test]
    fn file_snapshot_and_restore_need_no_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        store_in(dir.path(), "pp")
            .store("a@b", &SecretString::from("original".to_string()))
            .unwrap();

        // A store built with a passphrase source that would fail if consulted.
        let no_passphrase = FileStore::new(
            dir.path().join(KEYRING_FILE_NAME),
            PassphraseSource::Ambient { interactive: false },
        );
        let snapshot = no_passphrase.snapshot("a@b").unwrap();
        assert!(matches!(snapshot, CredentialSnapshot::RawFile(_)));

        // Clobber it, then roll back without ever supplying a passphrase.
        store_in(dir.path(), "other")
            .store("a@b", &SecretString::from("replacement".to_string()))
            .unwrap();
        no_passphrase.restore("a@b", &snapshot).unwrap();

        assert_eq!(
            store_in(dir.path(), "pp")
                .retrieve("a@b")
                .unwrap()
                .unwrap()
                .expose_secret(),
            "original"
        );
    }

    #[test]
    fn restoring_an_absent_snapshot_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "pp");
        let snapshot = store.snapshot("a@b").unwrap();
        assert!(matches!(snapshot, CredentialSnapshot::Absent));

        store
            .store("a@b", &SecretString::from("x".to_string()))
            .unwrap();
        assert!(store.exists());
        store.restore("a@b", &snapshot).unwrap();
        assert!(!store.exists(), "rollback must undo the creation");
    }

    #[cfg(unix)]
    #[test]
    fn a_restored_file_is_still_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path(), "pp");
        store
            .store("a@b", &SecretString::from("x".to_string()))
            .unwrap();
        let snapshot = store.snapshot("a@b").unwrap();
        store.delete("a@b").unwrap();
        store.restore("a@b", &snapshot).unwrap();
        let mode = fs::metadata(dir.path().join(KEYRING_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }

    #[test]
    fn ambient_passphrase_without_a_terminal_is_an_error() {
        // The test harness has no TTY on stdin, so this exercises the
        // non-interactive path deterministically.
        let source = PassphraseSource::Ambient { interactive: false };
        let err = source.resolve(false).unwrap_err();
        assert!(err.to_string().contains(KEYRING_PASSPHRASE_ENV), "{err}");
        assert_eq!(err.exit_code(), crate::error::exit::CREDENTIAL);
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        let secret = SecretString::from("hunter2".to_string());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}
