//! Command-line surface.

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::KeyringBackend;
use crate::model::Priority;

/// `reminders` — manage reminders in a CalDAV VTODO collection.
#[derive(Debug, Parser)]
#[command(
    name = "reminders",
    version,
    about = "Manage reminders in a CalDAV VTODO collection",
    long_about = "Manage reminders in a CalDAV VTODO collection.\n\n\
                  Configuration lives in $XDG_CONFIG_HOME/reminders/config.toml and the CalDAV \
                  password lives in the Secret Service or in an age-encrypted file. The password \
                  is never written to the config file, passed as an argument, or printed.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print machine-readable JSON on stdout instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Never prompt. Commands that would need input fail instead.
    #[arg(long, global = true)]
    pub no_input: bool,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the server connection and the stored CalDAV password.
    Auth {
        /// The auth subcommand.
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Create a reminder.
    Add(AddArgs),
    /// List reminders.
    List(ListArgs),
    /// Show one reminder.
    Get(GetArgs),
    /// Change a reminder.
    Update(UpdateArgs),
    /// Mark a reminder complete.
    Complete(IdArgs),
    /// Mark a reminder open again.
    Reopen(IdArgs),
    /// Delete a reminder.
    Delete(DeleteArgs),
}

/// `reminders auth ...`
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Store the connection settings and the CalDAV password.
    Set(AuthSetArgs),
    /// Report the configuration and whether a credential can be read.
    Status,
    /// Remove the stored CalDAV password.
    Remove,
    /// Show or change the preferred credential store.
    Keyring {
        /// The backend to prefer. Omit to print the current setting.
        #[arg(value_enum)]
        backend: Option<KeyringBackend>,
    },
}

/// `reminders auth set`
#[derive(Debug, Args)]
pub struct AuthSetArgs {
    /// Base URL of the CalDAV server.
    #[arg(
        long,
        value_name = "URL",
        help = "Base URL of the CalDAV server, for example https://dav.example.com"
    )]
    pub server_url: Option<String>,

    /// Absolute path of the VTODO collection, for example /user/tasks/.
    #[arg(long, value_name = "PATH")]
    pub collection_path: Option<String>,

    /// CalDAV user name.
    #[arg(long, value_name = "NAME")]
    pub username: Option<String>,
}

/// `reminders add`
#[derive(Debug, Args)]
pub struct AddArgs {
    /// Reminder title.
    pub title: String,

    /// Free-text notes.
    #[arg(long, value_name = "TEXT")]
    pub notes: Option<String>,

    /// Due date (YYYY-MM-DD) or due instant (RFC 3339, or with an IANA zone).
    #[arg(long, value_name = "DATE|DATETIME")]
    pub due: Option<String>,

    /// Shorthand for a timed due date and a notification at the same instant.
    #[arg(long, value_name = "DATETIME", conflicts_with_all = ["due", "remind_at"])]
    pub at: Option<String>,

    /// Notification instant.
    #[arg(long, value_name = "DATETIME")]
    pub remind_at: Option<String>,

    /// Priority.
    #[arg(long, value_enum, default_value_t = Priority::None)]
    pub priority: Priority,

    /// Validate and report the intended change without contacting the server.
    #[arg(long)]
    pub dry_run: bool,
}

/// Which reminders `list` should return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum StatusFilter {
    /// Reminders that are not complete.
    #[default]
    Open,
    /// Completed reminders.
    Complete,
    /// Cancelled reminders.
    Cancelled,
    /// Everything in the collection.
    All,
}

/// `reminders list`
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Which reminders to show.
    #[arg(long, value_enum, default_value_t = StatusFilter::Open)]
    pub status: StatusFilter,

    /// Show at most this many reminders.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,
}

/// `reminders get`
#[derive(Debug, Args)]
pub struct GetArgs {
    /// Reminder id.
    pub id: String,
}

/// `reminders complete` and `reminders reopen`
#[derive(Debug, Args)]
pub struct IdArgs {
    /// Reminder id.
    pub id: String,

    /// Validate and report the intended change without contacting the server.
    #[arg(long)]
    pub dry_run: bool,
}

/// `reminders delete`
#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Reminder id.
    pub id: String,

    /// Delete without asking for confirmation.
    #[arg(long)]
    pub force: bool,

    /// Validate and report the intended change without contacting the server.
    #[arg(long)]
    pub dry_run: bool,
}

/// `reminders update`
#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Reminder id.
    pub id: String,

    /// New title.
    #[arg(long, value_name = "TEXT")]
    pub title: Option<String>,

    /// New notes.
    #[arg(long, value_name = "TEXT", conflicts_with = "clear_notes")]
    pub notes: Option<String>,

    /// Remove the notes.
    #[arg(long)]
    pub clear_notes: bool,

    /// New due date or due instant.
    #[arg(long, value_name = "DATE|DATETIME", conflicts_with = "clear_due")]
    pub due: Option<String>,

    /// Remove the due date.
    #[arg(long)]
    pub clear_due: bool,

    /// Shorthand for a timed due date and a notification at the same instant.
    #[arg(
        long,
        value_name = "DATETIME",
        conflicts_with_all = ["due", "remind_at", "clear_due", "clear_remind_at"]
    )]
    pub at: Option<String>,

    /// New notification instant.
    #[arg(long, value_name = "DATETIME", conflicts_with = "clear_remind_at")]
    pub remind_at: Option<String>,

    /// Remove the notification.
    #[arg(long)]
    pub clear_remind_at: bool,

    /// New priority.
    #[arg(long, value_enum)]
    pub priority: Option<Priority>,

    /// Validate and report the intended change without contacting the server.
    #[arg(long)]
    pub dry_run: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn definition_is_valid() {
        Cli::command().debug_assert();
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("reminders").chain(args.iter().copied()))
    }

    #[test]
    fn add_requires_a_title() {
        assert!(parse(&["add"]).is_err());
        assert!(parse(&["add", "Buy milk"]).is_ok());
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        for args in [
            vec!["--json", "list"],
            vec!["list", "--json"],
            vec!["--no-input", "add", "x"],
            vec!["add", "x", "--no-input"],
        ] {
            let cli = parse(&args).unwrap_or_else(|err| panic!("{args:?}: {err}"));
            assert!(cli.json || cli.no_input);
        }
    }

    #[test]
    fn at_conflicts_with_due_and_remind_at() {
        assert!(parse(&[
            "add",
            "x",
            "--at",
            "2026-01-01T00:00:00Z",
            "--due",
            "2026-01-01"
        ])
        .is_err());
        assert!(parse(&[
            "add",
            "x",
            "--at",
            "2026-01-01T00:00:00Z",
            "--remind-at",
            "2026-01-01T00:00:00Z"
        ])
        .is_err());
        assert!(parse(&[
            "add",
            "x",
            "--due",
            "2026-01-01",
            "--remind-at",
            "2026-01-01T00:00:00Z"
        ])
        .is_ok());
    }

    #[test]
    fn update_rejects_setting_and_clearing_the_same_field() {
        assert!(parse(&["update", "id", "--notes", "x", "--clear-notes"]).is_err());
        assert!(parse(&["update", "id", "--due", "2026-01-01", "--clear-due"]).is_err());
        assert!(parse(&[
            "update",
            "id",
            "--remind-at",
            "2026-01-01T00:00:00Z",
            "--clear-remind-at"
        ])
        .is_err());
        assert!(parse(&[
            "update",
            "id",
            "--at",
            "2026-01-01T00:00:00Z",
            "--clear-due"
        ])
        .is_err());
    }

    #[test]
    fn list_defaults_to_open_reminders() {
        let cli = parse(&["list"]).unwrap();
        match cli.command {
            Command::List(args) => {
                assert_eq!(args.status, StatusFilter::Open);
                assert_eq!(args.limit, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn priority_accepts_the_documented_names() {
        for name in ["none", "low", "medium", "high"] {
            assert!(parse(&["add", "x", "--priority", name]).is_ok(), "{name}");
        }
        assert!(parse(&["add", "x", "--priority", "urgent"]).is_err());
    }

    #[test]
    fn keyring_accepts_the_documented_backends() {
        for name in ["auto", "secret-service", "file"] {
            assert!(parse(&["auth", "keyring", name]).is_ok(), "{name}");
        }
        assert!(parse(&["auth", "keyring"]).is_ok());
        assert!(parse(&["auth", "keyring", "kwallet"]).is_err());
    }

    #[test]
    fn there_is_no_flag_for_the_password() {
        let rendered = format!("{:?}", Cli::command().render_long_help());
        let lowered = rendered.to_lowercase();
        assert!(!lowered.contains("--password"), "{rendered}");
        for subcommand in Cli::command().get_subcommands() {
            for arg in subcommand.get_arguments() {
                let name = arg.get_id().as_str();
                assert!(!name.contains("password"), "{name}");
            }
        }
    }

    #[test]
    fn there_is_no_insecure_tls_flag() {
        let rendered = format!("{:?}", Cli::command().render_long_help()).to_lowercase();
        for forbidden in ["--insecure", "--no-verify", "--no-check-certificate", "-k "] {
            assert!(!rendered.contains(forbidden), "{forbidden} must not exist");
        }
    }

    #[test]
    fn dry_run_exists_on_every_mutating_command_only() {
        let mutating = ["add", "update", "complete", "reopen", "delete"];
        let read_only = ["list", "get"];
        let command = Cli::command();
        for name in mutating {
            let sub = command.find_subcommand(name).unwrap();
            assert!(
                sub.get_arguments().any(|arg| arg.get_id() == "dry_run"),
                "{name} needs --dry-run"
            );
        }
        for name in read_only {
            let sub = command.find_subcommand(name).unwrap();
            assert!(
                !sub.get_arguments().any(|arg| arg.get_id() == "dry_run"),
                "{name} must not have --dry-run"
            );
        }
    }

    #[test]
    fn every_documented_command_exists() {
        let command = Cli::command();
        for name in [
            "auth", "add", "list", "get", "update", "complete", "reopen", "delete",
        ] {
            assert!(command.find_subcommand(name).is_some(), "{name}");
        }
        let auth = command.find_subcommand("auth").unwrap();
        for name in ["set", "status", "remove", "keyring"] {
            assert!(auth.find_subcommand(name).is_some(), "auth {name}");
        }
    }
}
