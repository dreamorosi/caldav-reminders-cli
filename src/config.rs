//! Non-secret configuration, stored under the XDG config directory.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

/// Environment variable that overrides the config directory. Intended for
/// tests and for pinning state in containers.
pub const CONFIG_DIR_ENV: &str = "REMINDERS_CONFIG_DIR";
/// Environment variable that overrides the data directory (encrypted keyring).
pub const DATA_DIR_ENV: &str = "REMINDERS_DATA_DIR";

/// Keys that must never appear in the config file.
const FORBIDDEN_KEYS: [&str; 4] = ["password", "pass", "secret", "token"];

/// Every key this version understands.
const ALLOWED_KEYS: [&str; 5] = [
    "server_url",
    "collection_path",
    "username",
    "keyring_backend",
    "credential_backend",
];

/// Reported for any TOML syntax error.
///
/// The parser's own message quotes the line it failed on, and the mistake that
/// most often produces a syntax error here is someone hand-editing a password
/// into the file and mis-quoting it. So the message is withheld entirely.
const MALFORMED_TOML: &str = "the file is not valid TOML. The parser's message is withheld \
     because it would quote the offending line, which may contain a password. Check the \
     quoting, and remember that the CalDAV password never belongs in this file";

/// Which credential store to prefer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum KeyringBackend {
    /// Secret Service when it is available and unlocked, otherwise the file store.
    #[default]
    Auto,
    /// Linux Secret Service over the user D-Bus session.
    SecretService,
    /// Encrypted file for headless systems.
    File,
}

impl KeyringBackend {
    /// Name as written in the config file and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyringBackend::Auto => "auto",
            KeyringBackend::SecretService => "secret-service",
            KeyringBackend::File => "file",
        }
    }
}

/// A concrete store, with `auto` already resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolvedBackend {
    /// Linux Secret Service.
    SecretService,
    /// Encrypted file.
    File,
}

impl ResolvedBackend {
    /// Name as written in the config file and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            ResolvedBackend::SecretService => "secret-service",
            ResolvedBackend::File => "file",
        }
    }
}

impl From<ResolvedBackend> for KeyringBackend {
    fn from(value: ResolvedBackend) -> Self {
        match value {
            ResolvedBackend::SecretService => KeyringBackend::SecretService,
            ResolvedBackend::File => KeyringBackend::File,
        }
    }
}

/// On-disk configuration. Every connection field is optional so `auth set` can
/// fill in the gaps interactively.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base URL of the CalDAV server, e.g. `https://dav.example.com`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// Absolute path of the VTODO collection, e.g. `/user/tasks/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_path: Option<String>,
    /// CalDAV user name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Preferred credential store.
    #[serde(default)]
    pub keyring_backend: KeyringBackend,
    /// Store the credential was actually written to. Recorded so reads never
    /// silently move to a different store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_backend: Option<ResolvedBackend>,
}

/// Configuration with every required field present and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Validated base URL.
    pub server_url: Url,
    /// Normalised collection path with leading and trailing slashes.
    pub collection_path: String,
    /// CalDAV user name.
    pub username: String,
}

impl Settings {
    /// The absolute collection URL.
    pub fn collection_url(&self) -> Result<Url> {
        self.server_url
            .join(&self.collection_path)
            .map_err(|err| Error::config(format!("cannot build collection URL: {err}")))
    }

    /// Keyring account name: unique per user and server.
    pub fn account(&self) -> String {
        let host = self.server_url.host_str().unwrap_or("");
        match self.server_url.port() {
            Some(port) => format!("{}@{host}:{port}", self.username),
            None => format!("{}@{host}", self.username),
        }
    }
}

impl Config {
    /// Path of the config file.
    pub fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("config.toml"))
    }

    /// Load the config file, or return defaults when it does not exist.
    pub fn load() -> Result<Config> {
        let path = Config::path()?;
        Config::load_from(&path)
    }

    /// Load from an explicit path.
    pub fn load_from(path: &Path) -> Result<Config> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(err) => {
                return Err(Error::config(format!(
                    "cannot read {}: {err}",
                    path.display()
                )))
            }
        };
        Config::parse(&text).map_err(|err| match err {
            Error::Config(message) => Error::Config(format!("{}: {message}", path.display())),
            other => other,
        })
    }

    /// Parse TOML, rejecting any attempt to keep a secret in the file.
    ///
    /// No error from this function carries text from the file. Both `toml`'s
    /// syntax errors and serde's deserialisation errors quote the source they
    /// choked on, including the value, so their messages are replaced with
    /// fixed ones that name only the category and what is allowed.
    pub fn parse(text: &str) -> Result<Config> {
        let table: toml::Table = text.parse().map_err(|_| Error::config(MALFORMED_TOML))?;
        for key in table.keys() {
            let lowered = key.to_ascii_lowercase();
            // The matched word comes from our own list, not from the file.
            if let Some(word) = FORBIDDEN_KEYS.iter().find(|bad| lowered.contains(**bad)) {
                return Err(Error::config(format!(
                    "a key whose name contains {word:?} is not allowed in the config file; \
                     the CalDAV password is only ever kept in the credential store (run \
                     `reminders auth set`)"
                )));
            }
            if !ALLOWED_KEYS.contains(&lowered.as_str()) {
                return Err(Error::config(format!(
                    "the config file sets something this version does not understand. The \
                     allowed keys are {}",
                    ALLOWED_KEYS.join(", ")
                )));
            }
        }
        table.try_into().map_err(|_| {
            Error::config(
                "a setting in the config file has the wrong type or an unsupported value. \
                 keyring_backend must be auto, secret-service, or file; credential_backend \
                 must be secret-service or file; every other setting is a string",
            )
        })
    }

    /// Write the config file with `0600` permissions inside a `0700` directory.
    pub fn save(&self) -> Result<PathBuf> {
        let dir = config_dir()?;
        let path = dir.join("config.toml");
        self.save_to(&path)?;
        Ok(path)
    }

    /// Write to an explicit path.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|err| Error::config(format!("cannot serialise configuration: {err}")))?;
        // Reported as a configuration problem so the exit code matches what the
        // user is actually being told to fix.
        write_private_file(path, text.as_bytes()).map_err(|err| Error::config(err.to_string()))
    }

    /// Validate and complete the connection settings.
    pub fn settings(&self) -> Result<Settings> {
        let mut missing = Vec::new();
        if self.server_url.is_none() {
            missing.push("server_url");
        }
        if self.collection_path.is_none() {
            missing.push("collection_path");
        }
        if self.username.is_none() {
            missing.push("username");
        }
        if !missing.is_empty() {
            return Err(Error::config(format!(
                "configuration is incomplete (missing {}); run `reminders auth set`",
                missing.join(", ")
            )));
        }
        Ok(Settings {
            server_url: parse_server_url(self.server_url.as_deref().unwrap())?,
            collection_path: normalize_collection_path(self.collection_path.as_deref().unwrap())?,
            username: validate_username(self.username.as_deref().unwrap())?,
        })
    }
}

/// Validate a server URL: http(s) only, no credentials, no path noise, and
/// plain HTTP only for loopback addresses.
pub fn parse_server_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    let url = Url::parse(trimmed)
        .map_err(|err| Error::config(format!("server_url {trimmed:?} is not a URL: {err}")))?;
    match url.scheme() {
        "https" => {}
        "http" => {
            if !is_loopback(&url) {
                return Err(Error::config(
                    "server_url must use https; plain http is only allowed for loopback \
                     addresses because Basic authentication would otherwise be sent in \
                     the clear",
                ));
            }
        }
        other => {
            return Err(Error::config(format!(
                "server_url scheme {other:?} is not supported; use https"
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::config(
            "server_url must not contain a user name or password; run `reminders auth set`",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::config(
            "server_url must not contain a query string or fragment",
        ));
    }
    if url.host_str().is_none() {
        return Err(Error::config("server_url must contain a host"));
    }
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        Some(url::Host::Domain(name)) => {
            name.eq_ignore_ascii_case("localhost") || name.eq_ignore_ascii_case("localhost.")
        }
        None => false,
    }
}

/// Normalise a collection path to `/.../` form.
pub fn normalize_collection_path(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::config("collection_path must not be empty"));
    }
    if !trimmed.starts_with('/') {
        return Err(Error::config(format!(
            "collection_path {trimmed:?} must start with '/'"
        )));
    }
    if trimmed.contains(['?', '#']) {
        return Err(Error::config(
            "collection_path must not contain a query string or fragment",
        ));
    }
    if trimmed.contains("..") {
        return Err(Error::config("collection_path must not contain '..'"));
    }
    Ok(if trimmed.ends_with('/') {
        trimmed.to_string()
    } else {
        format!("{trimmed}/")
    })
}

/// Reject user names that cannot go into an HTTP Basic header.
pub fn validate_username(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::config("username must not be empty"));
    }
    if trimmed.contains(':') {
        return Err(Error::config(
            "username must not contain ':' because HTTP Basic authentication uses it as \
             a separator",
        ));
    }
    if trimmed.chars().any(|ch| ch.is_control()) {
        return Err(Error::config(
            "username must not contain control characters",
        ));
    }
    Ok(trimmed.to_string())
}

/// Config directory: `$REMINDERS_CONFIG_DIR`, else `$XDG_CONFIG_HOME/reminders`.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    dirs::config_dir()
        .map(|dir| dir.join("reminders"))
        .ok_or_else(|| {
            Error::config(format!(
                "cannot determine the config directory; set $XDG_CONFIG_HOME, $HOME, or \
                 ${CONFIG_DIR_ENV}"
            ))
        })
}

/// Data directory: `$REMINDERS_DATA_DIR`, else `$XDG_DATA_HOME/reminders`.
pub fn data_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(DATA_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    dirs::data_dir()
        .map(|dir| dir.join("reminders"))
        .ok_or_else(|| {
            Error::config(format!(
                "cannot determine the data directory; set $XDG_DATA_HOME, $HOME, or \
                 ${DATA_DIR_ENV}"
            ))
        })
}

/// Create a directory tree, creating the final component as `0700`.
///
/// An existing directory keeps whatever mode it already has. The files written
/// inside are `0600` regardless, and silently re-permissioning a directory the
/// user or their dotfile manager set up deliberately causes more surprises than
/// it prevents.
pub fn create_private_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(path)
        .map_err(|err| Error::Io(format!("cannot create {}: {err}", path.display())))?;
    set_mode(path, 0o700)
}

/// Write a file that only the owner can read, atomically and durably.
///
/// The sequence matters for both safety and correctness:
///
/// 1. Create a temporary file *in the same directory*, so the later rename is a
///    same-filesystem operation and therefore atomic.
/// 2. Create it with mode `0600` from the outset, so the contents are never
///    readable by anyone else, not even for the instant between creation and a
///    later `chmod`.
/// 3. Write, flush, and `fsync` the file, so a crash cannot leave a renamed but
///    empty file where a working credential used to be.
/// 4. Rename over the destination. A reader either sees the whole old file or
///    the whole new one, never a truncated mixture.
/// 5. `fsync` the directory, so the rename itself survives a crash.
///
/// The temporary file is removed if any step fails, so a failure leaves the
/// original file exactly as it was.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let directory = match parent {
        Some(dir) => dir.to_path_buf(),
        None => PathBuf::from("."),
    };
    let temporary = temporary_sibling(path);

    let write = || -> std::io::Result<()> {
        use std::io::Write as _;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        // Losing the rename would leave the old file in place, which is safe,
        // but a durable write is cheap here and the caller has just been told
        // the credential was stored.
        if let Ok(dir) = fs::File::open(&directory) {
            let _ = dir.sync_all();
        }
        Ok(())
    };

    match write() {
        Ok(()) => {}
        Err(err) => {
            let _ = fs::remove_file(&temporary);
            return Err(Error::Io(format!("cannot write {}: {err}", path.display())));
        }
    }

    // Tighten a destination that predates this change, and confirm the mode we
    // asked for actually took effect.
    set_mode(path, 0o600)
}

/// A unique sibling path for the temporary file.
///
/// Same directory so the rename is atomic, and unique per process and call so
/// two concurrent invocations cannot collide. `create_new` then makes the
/// creation itself the collision check.
fn temporary_sibling(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let unique = format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => dir.join(unique),
        None => PathBuf::from(unique),
    }
}

/// Read a file's bytes, or `None` when it does not exist.
///
/// Used to snapshot a file before it is replaced, so a later failure can put it
/// back.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Io(format!("cannot read {}: {err}", path.display()))),
    }
}

/// Put a snapshot from [`read_optional`] back, including "it was not there".
pub fn restore_optional(path: &Path, snapshot: Option<&Vec<u8>>) -> Result<()> {
    match snapshot {
        Some(bytes) => write_private_file(path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::Io(format!(
                "cannot remove {}: {err}",
                path.display()
            ))),
        },
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
            Error::Io(format!(
                "cannot set permissions on {}: {err}",
                path.display()
            ))
        })?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
server_url = "https://dav.example.com"
collection_path = "/username/tasks/"
username = "username"
keyring_backend = "auto"
"#;

    #[test]
    fn parses_the_documented_example() {
        let config = Config::parse(SAMPLE).unwrap();
        assert_eq!(
            config.server_url.as_deref(),
            Some("https://dav.example.com")
        );
        assert_eq!(config.collection_path.as_deref(), Some("/username/tasks/"));
        assert_eq!(config.username.as_deref(), Some("username"));
        assert_eq!(config.keyring_backend, KeyringBackend::Auto);
        assert_eq!(config.credential_backend, None);
    }

    #[test]
    fn keyring_backend_defaults_to_auto_when_absent() {
        let config = Config::parse("username = \"u\"").unwrap();
        assert_eq!(config.keyring_backend, KeyringBackend::Auto);
    }

    #[test]
    fn rejects_password_bearing_keys() {
        for key in [
            "password",
            "Password",
            "caldav_password",
            "secret",
            "api_token",
        ] {
            let text = format!("{key} = \"hunter2\"");
            let err = Config::parse(&text).unwrap_err();
            assert!(err.to_string().contains("not allowed"), "{key}: {err}");
            assert_eq!(err.exit_code(), crate::error::exit::CONFIG);
        }
    }

    #[test]
    fn rejects_unknown_keys_without_echoing_them() {
        let err = Config::parse("colour = \"blue\"").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("does not understand"), "{message}");
        assert!(
            message.contains("server_url"),
            "should list what is allowed: {message}"
        );
        assert!(!message.contains("colour"), "echoed the key: {message}");
        assert!(!message.contains("blue"), "echoed the value: {message}");
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(Config::parse("this is not toml").is_err());
    }

    /// The regression this guards: `toml`'s syntax errors quote the line they
    /// failed on, and an unterminated password string is a syntax error.
    #[test]
    fn a_malformed_password_line_never_reaches_the_error() {
        for text in [
            "password = \"hunter2",
            "server_url = \"https://dav.example.com\"\npassword = \"hunter2",
            "[section\npassword = \"hunter2\"",
            "password = hunter2",
            "caldav_password = \"hunter2\"\nbroken = ",
        ] {
            let err = Config::parse(text).unwrap_err();
            let message = err.to_string();
            assert!(
                !message.contains("hunter2"),
                "leaked the secret for {text:?}: {message}"
            );
            assert_eq!(err.exit_code(), crate::error::exit::CONFIG);
        }
    }

    /// serde's "unknown variant" error quotes the offending value, so a
    /// password mistakenly typed into an enum field would have leaked too.
    #[test]
    fn an_unsupported_enum_value_is_not_echoed() {
        for text in [
            "keyring_backend = \"hunter2\"",
            "credential_backend = \"hunter2\"",
            "keyring_backend = 42",
            "server_url = 42",
        ] {
            let err = Config::parse(text).unwrap_err();
            let message = err.to_string();
            assert!(!message.contains("hunter2"), "{text:?}: {message}");
            assert!(!message.contains("42"), "{text:?}: {message}");
        }
    }

    #[test]
    fn forbidden_key_errors_name_only_the_matched_word() {
        let err = Config::parse("caldav_password = \"hunter2\"").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("\"password\""), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("caldav_password"), "{message}");
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.toml");
        let config = Config {
            server_url: Some("https://dav.example.com".into()),
            collection_path: Some("/u/tasks/".into()),
            username: Some("u".into()),
            keyring_backend: KeyringBackend::File,
            credential_backend: Some(ResolvedBackend::File),
        };
        config.save_to(&path).unwrap();
        assert_eq!(Config::load_from(&path).unwrap(), config);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("keyring_backend = \"file\""), "{text}");
        assert!(text.contains("credential_backend = \"file\""), "{text}");
        assert!(!text.to_lowercase().contains("password"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config.toml");
        Config::default().save_to(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "{dir_mode:o}");
    }

    #[test]
    fn writes_leave_no_temporary_files_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_private_file(&path, b"first").unwrap();
        write_private_file(&path, b"second").unwrap();
        let entries: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["config.toml".to_string()], "{entries:?}");
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn a_shorter_write_replaces_the_whole_file() {
        // A truncate-then-write would leave a tail behind on a short write.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_private_file(&path, &b"x".repeat(4096)).unwrap();
        write_private_file(&path, b"tiny").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"tiny");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_original_and_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_private_file(&path, b"original").unwrap();

        // Remove write permission from the directory so creating the temporary
        // file fails, which is the first fallible step.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let err = write_private_file(&path, b"replacement").unwrap_err();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(err.exit_code(), crate::error::exit::FAILURE);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"original",
            "the original must survive a failed write"
        );
        let entries: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["config.toml".to_string()], "{entries:?}");
    }

    #[test]
    fn snapshot_and_restore_round_trip_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        assert_eq!(read_optional(&path).unwrap(), None);
        write_private_file(&path, b"original").unwrap();
        let snapshot = read_optional(&path).unwrap();
        assert_eq!(snapshot.as_deref(), Some(&b"original"[..]));

        write_private_file(&path, b"changed").unwrap();
        restore_optional(&path, snapshot.as_ref()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"original");

        // Restoring "it was not there" removes the file.
        restore_optional(&path, None).unwrap();
        assert!(!path.exists());
        // And doing it again is not an error.
        restore_optional(&path, None).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_directory_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("existing");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o750)).unwrap();
        create_private_dir(&nested).unwrap();
        let mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "{mode:o}");
    }

    #[test]
    fn missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_from(&dir.path().join("absent.toml")).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn load_errors_mention_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "password = \"x\"").unwrap();
        let err = Config::load_from(&path).unwrap_err();
        assert!(err.to_string().contains("config.toml"), "{err}");
    }

    #[test]
    fn load_of_a_malformed_file_names_the_path_but_not_the_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "password = \"hunter2").unwrap();
        let err = Config::load_from(&path).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("config.toml"), "{message}");
        assert!(message.contains("not valid TOML"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn settings_reports_every_missing_field() {
        let err = Config::default().settings().unwrap_err();
        let message = err.to_string();
        assert!(message.contains("server_url"), "{message}");
        assert!(message.contains("collection_path"), "{message}");
        assert!(message.contains("username"), "{message}");
    }

    fn settings(url: &str, path: &str, user: &str) -> Result<Settings> {
        Config {
            server_url: Some(url.into()),
            collection_path: Some(path.into()),
            username: Some(user.into()),
            ..Default::default()
        }
        .settings()
    }

    #[test]
    fn builds_collection_url_and_account() {
        let s = settings("https://dav.example.com", "/u/tasks", "alice").unwrap();
        assert_eq!(s.collection_path, "/u/tasks/");
        assert_eq!(
            s.collection_url().unwrap().as_str(),
            "https://dav.example.com/u/tasks/"
        );
        assert_eq!(s.account(), "alice@dav.example.com");
    }

    #[test]
    fn account_includes_explicit_port() {
        let s = settings("http://127.0.0.1:8080", "/u/tasks/", "alice").unwrap();
        assert_eq!(s.account(), "alice@127.0.0.1:8080");
    }

    #[test]
    fn collection_url_ignores_a_server_url_path() {
        let s = settings("https://dav.example.com/dav", "/u/tasks/", "alice").unwrap();
        assert_eq!(
            s.collection_url().unwrap().as_str(),
            "https://dav.example.com/u/tasks/"
        );
    }

    #[test]
    fn rejects_plain_http_to_a_remote_host() {
        let err = settings("http://dav.example.com", "/u/tasks/", "a").unwrap_err();
        assert!(err.to_string().contains("must use https"), "{err}");
    }

    #[test]
    fn allows_plain_http_to_loopback() {
        for url in [
            "http://127.0.0.1:1234",
            "http://localhost:1234",
            "http://[::1]:1234",
        ] {
            assert!(settings(url, "/u/tasks/", "a").is_ok(), "{url}");
        }
    }

    #[test]
    fn rejects_credentials_embedded_in_the_url() {
        let err = settings("https://alice:hunter2@dav.example.com", "/u/tasks/", "a").unwrap_err();
        assert!(
            err.to_string().contains("must not contain a user name"),
            "{err}"
        );
        assert!(
            !err.to_string().contains("hunter2"),
            "error leaked the password: {err}"
        );
    }

    #[test]
    fn rejects_unsupported_schemes_and_queries() {
        assert!(settings("ftp://dav.example.com", "/u/", "a").is_err());
        assert!(settings("https://dav.example.com?x=1", "/u/", "a").is_err());
        assert!(settings("https://dav.example.com#f", "/u/", "a").is_err());
        assert!(settings("not-a-url", "/u/", "a").is_err());
    }

    #[test]
    fn rejects_bad_collection_paths() {
        assert!(settings("https://d.example.com", "u/tasks/", "a").is_err());
        assert!(settings("https://d.example.com", "", "a").is_err());
        assert!(settings("https://d.example.com", "/u/../etc/", "a").is_err());
        assert!(settings("https://d.example.com", "/u/tasks/?x=1", "a").is_err());
    }

    #[test]
    fn rejects_bad_usernames() {
        assert!(settings("https://d.example.com", "/u/", "").is_err());
        assert!(settings("https://d.example.com", "/u/", "a:b").is_err());
        assert!(settings("https://d.example.com", "/u/", "a\nb").is_err());
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(KeyringBackend::Auto.as_str(), "auto");
        assert_eq!(KeyringBackend::SecretService.as_str(), "secret-service");
        assert_eq!(KeyringBackend::File.as_str(), "file");
        assert_eq!(ResolvedBackend::SecretService.as_str(), "secret-service");
        assert_eq!(ResolvedBackend::File.as_str(), "file");
    }
}
