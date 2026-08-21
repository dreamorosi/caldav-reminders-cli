//! Command implementations.

pub mod auth;
pub mod reminder;

use std::io::{IsTerminal, Write};

use secrecy::SecretString;

use crate::caldav::Client;
use crate::config::{Config, ResolvedBackend, Settings};
use crate::credentials::{open_store, resolve_backend, secret_service_usable, PassphraseSource};
use crate::error::{Error, Result};
use crate::output::Printer;

/// Everything a command needs that is not its own arguments.
pub struct Context {
    /// Output renderer.
    pub printer: Printer,
    /// Whether prompting is forbidden.
    pub no_input: bool,
}

impl Context {
    /// Build a context.
    pub fn new(json: bool, no_input: bool) -> Context {
        Context {
            printer: Printer::new(json),
            no_input,
        }
    }

    /// Whether we may prompt: allowed, and a terminal is attached.
    pub fn interactive(&self) -> bool {
        !self.no_input && std::io::stdin().is_terminal()
    }

    /// How the encrypted file keyring should find its passphrase.
    pub fn passphrase_source(&self) -> PassphraseSource {
        PassphraseSource::Ambient {
            interactive: self.interactive(),
        }
    }

    /// Ask a yes/no question. Returns `None` when we may not ask.
    pub fn confirm(&self, question: &str) -> Result<Option<bool>> {
        if !self.interactive() {
            return Ok(None);
        }
        eprint!("{question} [y/N] ");
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_ascii_lowercase();
        Ok(Some(answer == "y" || answer == "yes"))
    }

    /// Prompt for a non-secret line of text.
    pub fn prompt_line(&self, label: &str, current: Option<&str>) -> Result<String> {
        if !self.interactive() {
            return Err(Error::config(format!(
                "{label} is not set and there is no terminal to ask on; pass it as a flag or \
                 put it in the config file"
            )));
        }
        loop {
            match current {
                Some(value) => eprint!("{label} [{value}]: "),
                None => eprint!("{label}: "),
            }
            std::io::stderr().flush().ok();
            let mut line = String::new();
            let read = std::io::stdin().read_line(&mut line)?;
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
            if let Some(value) = current {
                return Ok(value.to_string());
            }
            if read == 0 {
                return Err(Error::config(format!("{label} is required")));
            }
            eprintln!("A value is required.");
        }
    }
}

/// A validated configuration plus a ready CalDAV client.
pub struct Session {
    /// Connection settings.
    pub settings: Settings,
    /// CalDAV client.
    pub client: Client,
}

/// Read the stored credential and build a client.
///
/// This is the only path that touches the credential store, so `--dry-run`
/// simply never calls it.
pub fn open_session(context: &Context, config: &Config) -> Result<Session> {
    let settings = config.settings()?;
    let account = settings.account();
    let (backend, note) =
        resolve_backend(config.keyring_backend, config.credential_backend, || {
            secret_service_usable(&account)
        });
    if let Some(note) = note {
        context.printer.note(&note);
    }
    let password = read_credential(context, backend, &account)?;
    let client = Client::new(&settings, &password)?;
    Ok(Session { settings, client })
}

/// Fetch the password for `account` from `backend`.
pub fn read_credential(
    context: &Context,
    backend: ResolvedBackend,
    account: &str,
) -> Result<SecretString> {
    let store = open_store(backend, context.passphrase_source())?;
    store.retrieve(account)?.ok_or_else(|| {
        Error::credential(format!(
            "no CalDAV password is stored for {account} in the {} keyring; run \
             `reminders auth set`",
            backend.as_str()
        ))
    })
}
