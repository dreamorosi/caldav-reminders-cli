//! `reminders auth ...`

use secrecy::{ExposeSecret, SecretString};

use crate::cli::{AuthCommand, AuthSetArgs};
use crate::commands::Context;
use std::path::Path;

use crate::config::{read_optional, restore_optional, Config, KeyringBackend, ResolvedBackend};
use crate::credentials::{
    non_empty_env, open_store, prompt_secret, resolve_backend, secret_service_usable,
    CredentialSnapshot, Keystore, CALDAV_PASSWORD_ENV,
};
use crate::error::{Error, Result};
use crate::output::AuthStatus;

/// Dispatch an `auth` subcommand.
pub fn run(context: &Context, command: AuthCommand) -> Result<()> {
    match command {
        AuthCommand::Set(args) => set(context, args),
        AuthCommand::Status => status(context),
        AuthCommand::Remove => remove(context),
        AuthCommand::Keyring { backend } => keyring(context, backend),
    }
}

/// Store the connection settings and the CalDAV password.
///
/// The ordering exists to protect a working setup. Two things must stay in step:
/// the config file, which names the account, and the credential store, which is
/// indexed by it. A failure part-way through must leave either the old pair or
/// the new pair, never a mixture.
///
/// So: validate everything first, snapshot both sides, write the credential,
/// write the config, and only once the config is durably in place retire the
/// credential the *old* settings pointed at. If the config write fails, both
/// sides are put back.
fn set(context: &Context, args: AuthSetArgs) -> Result<()> {
    let config_path = Config::path()?;
    let previous_config = read_optional(&config_path)?;
    let mut config = Config::load()?;

    // What the old settings pointed at, so it can be retired afterwards. Read
    // before anything is merged in.
    let previous_pairing = config
        .credential_backend
        .zip(config.settings().ok())
        .map(|(backend, settings)| (backend, settings.account()));

    if let Some(value) = args.server_url {
        config.server_url = Some(value);
    }
    if let Some(value) = args.collection_path {
        config.collection_path = Some(value);
    }
    if let Some(value) = args.username {
        config.username = Some(value);
    }

    if config.server_url.is_none() {
        config.server_url = Some(context.prompt_line("Server URL", None)?);
    }
    if config.collection_path.is_none() {
        config.collection_path = Some(context.prompt_line("Collection path", None)?);
    }
    if config.username.is_none() {
        config.username = Some(context.prompt_line("CalDAV username", None)?);
    }

    // Validating before we ask for a password keeps typos cheap, and it
    // normalises the collection path we are about to store.
    let settings = config.settings()?;
    config.server_url = Some(
        settings
            .server_url
            .as_str()
            .trim_end_matches('/')
            .to_string(),
    );
    config.collection_path = Some(settings.collection_path.clone());
    config.username = Some(settings.username.clone());
    let account = settings.account();

    let password = read_caldav_password(context)?;

    // `auth set` is the moment the backend preference takes effect, so the
    // previously recorded backend deliberately does not influence the choice.
    let (backend, note) = resolve_backend(config.keyring_backend, None, || {
        secret_service_usable(&account)
    });
    if let Some(note) = note {
        context.printer.note(&note);
    }

    let store = open_store(backend, context.passphrase_source())?;
    // Captured before the write. The file store holds one slot, so writing a
    // credential for a *different* account still overwrites the previous one;
    // without this there would be nothing to put back.
    let snapshot = store.snapshot(&account)?;

    if let Err(err) = store.store(&account, &password) {
        // Nothing should have changed, but a partial write in some future store
        // implementation would be worse than a redundant restore.
        let _ = store.restore(&account, &snapshot);
        return Err(err);
    }

    config.credential_backend = Some(backend);
    if let Err(err) = config.save_to(&config_path) {
        undo(
            context,
            store.as_ref(),
            &account,
            &snapshot,
            &config_path,
            previous_config.as_ref(),
        );
        return Err(err);
    }

    // The new pair is durable, so the old credential can go. Doing this earlier
    // would mean a config failure left neither pair usable.
    if let Some((previous_backend, previous_account)) = previous_pairing {
        retire(
            context,
            previous_backend,
            &previous_account,
            backend,
            &account,
        );
    }

    context.printer.note(&format!(
        "configuration written to {}",
        config_path.display()
    ));
    context
        .printer
        .credential_stored(backend.as_str(), &account)
}

/// Put both sides back after a failed `auth set`.
///
/// Best effort by design: the caller is already returning the original failure,
/// and a rollback problem is reported as a warning rather than replacing it.
fn undo(
    context: &Context,
    store: &dyn Keystore,
    account: &str,
    snapshot: &CredentialSnapshot,
    config_path: &Path,
    previous_config: Option<&Vec<u8>>,
) {
    if let Err(err) = store.restore(account, snapshot) {
        context.printer.warn(&format!(
            "could not undo the credential change after the configuration failed to save: \
             {err}"
        ));
    }
    // Only rewrite the config file if it actually changed. The usual reason for
    // getting here is that the write failed, in which case the old file is
    // already intact and rewriting it would fail again for the same reason.
    let unchanged = read_optional(config_path)
        .map(|current| current.as_ref() == previous_config)
        .unwrap_or(false);
    if !unchanged {
        if let Err(err) = restore_optional(config_path, previous_config) {
            context.printer.warn(&format!(
                "could not restore the previous configuration file: {err}"
            ));
        }
    }
    context
        .printer
        .note("nothing was changed; the previous settings and credential are still in place");
}

/// Remove the credential the previous settings pointed at.
fn retire(
    context: &Context,
    previous_backend: ResolvedBackend,
    previous_account: &str,
    backend: ResolvedBackend,
    account: &str,
) {
    if previous_backend == backend {
        // The same Secret Service entry, or the same single-slot file: already
        // overwritten by the value we just wrote.
        if previous_account == account || backend == ResolvedBackend::File {
            return;
        }
    }
    match open_store(previous_backend, context.passphrase_source())
        .and_then(|old| old.delete(previous_account))
    {
        Ok(true) => context.printer.note(&format!(
            "removed the credential previously stored in the {} keyring",
            previous_backend.as_str()
        )),
        Ok(false) => {}
        Err(err) => context.printer.warn(&format!(
            "could not clean up the credential in the {} keyring: {err}",
            previous_backend.as_str()
        )),
    }
}

/// Report configuration and credential readability.
fn status(context: &Context) -> Result<()> {
    let config = Config::load()?;
    let config_path = Config::path()?;
    let mut report = AuthStatus {
        config_path: config_path.display().to_string(),
        config_exists: config_path.exists(),
        server_url: config.server_url.clone(),
        collection_path: config.collection_path.clone(),
        username: config.username.clone(),
        keyring_backend: config.keyring_backend.as_str().to_string(),
        credential_backend: config
            .credential_backend
            .map(|backend| backend.as_str().to_string()),
        active_backend: None,
        credential_readable: None,
        detail: None,
    };

    match config.settings() {
        Err(err) => {
            report.detail = Some(err.to_string());
        }
        Ok(settings) => {
            let account = settings.account();
            let (backend, note) =
                resolve_backend(config.keyring_backend, config.credential_backend, || {
                    secret_service_usable(&account)
                });
            report.active_backend = Some(backend.as_str().to_string());
            match open_store(backend, context.passphrase_source())
                .and_then(|store| store.retrieve(&account))
            {
                Ok(Some(_)) => report.credential_readable = Some(true),
                Ok(None) => {
                    report.credential_readable = Some(false);
                    report.detail = Some(format!(
                        "no credential is stored for {account}; run `reminders auth set`"
                    ));
                }
                Err(err) => report.detail = Some(err.to_string()),
            }
            if let Some(note) = note {
                report.detail = Some(match report.detail.take() {
                    Some(existing) => format!("{note}; {existing}"),
                    None => note,
                });
            }
        }
    }

    context.printer.auth_status(&report)
}

/// Remove the stored password and forget which store held it.
fn remove(context: &Context) -> Result<()> {
    let mut config = Config::load()?;
    let settings = config.settings()?;
    let account = settings.account();
    let (backend, _) = resolve_backend(config.keyring_backend, config.credential_backend, || {
        secret_service_usable(&account)
    });
    let store = open_store(backend, context.passphrase_source())?;
    let removed = store.delete(&account)?;
    if config.credential_backend.is_some() {
        config.credential_backend = None;
        config.save()?;
    }
    context
        .printer
        .credential_removed(backend.as_str(), removed)
}

/// Show or change the preferred credential store.
fn keyring(context: &Context, backend: Option<KeyringBackend>) -> Result<()> {
    let mut config = Config::load()?;
    let Some(backend) = backend else {
        return context
            .printer
            .keyring_backend(config.keyring_backend.as_str(), false);
    };

    config.keyring_backend = backend;
    config.save()?;

    if let Some(recorded) = config.credential_backend {
        let conflicts = match backend {
            KeyringBackend::Auto => false,
            KeyringBackend::SecretService => recorded != ResolvedBackend::SecretService,
            KeyringBackend::File => recorded != ResolvedBackend::File,
        };
        if conflicts {
            context.printer.note(&format!(
                "the credential is still in the {} keyring; run `reminders auth set` to store \
                 it in the {} keyring",
                recorded.as_str(),
                backend.as_str()
            ));
        }
    }
    context.printer.keyring_backend(backend.as_str(), true)
}

/// Read the CalDAV password from the environment or the terminal.
///
/// It is never accepted as a command-line argument, so it cannot end up in a
/// shell history or in another user's `ps` output.
fn read_caldav_password(context: &Context) -> Result<SecretString> {
    if let Some(value) = non_empty_env(CALDAV_PASSWORD_ENV) {
        return Ok(SecretString::from(value));
    }
    if !context.interactive() {
        return Err(Error::credential(format!(
            "the CalDAV password is required: set ${CALDAV_PASSWORD_ENV} or run \
             `reminders auth set` with a terminal attached"
        )));
    }
    let first = prompt_secret("CalDAV password: ")?;
    if first.expose_secret().is_empty() {
        return Err(Error::credential("the CalDAV password must not be empty"));
    }
    let second = prompt_secret("Confirm CalDAV password: ")?;
    if first.expose_secret() != second.expose_secret() {
        return Err(Error::credential("the passwords did not match"));
    }
    Ok(first)
}
