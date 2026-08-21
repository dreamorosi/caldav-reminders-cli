//! `reminders` — a Linux command-line client for reminders held in a CalDAV
//! VTODO collection.
//!
//! The library is split so that each concern can be tested on its own:
//!
//! - [`cli`] declares the command-line surface.
//! - [`config`] reads and writes the non-secret configuration file.
//! - [`credentials`] keeps the CalDAV password in the Secret Service or in an
//!   age-encrypted file.
//! - [`datetime`] parses dates and instants, refusing naive local times.
//! - [`ical`] reads and writes RFC 5545 VTODO documents.
//! - [`caldav`] speaks CalDAV over HTTPS.
//! - [`model`] is the small reminder vocabulary the CLI exposes.
//! - [`output`] renders human and JSON output.
//! - [`commands`] wires the above together.

#![deny(missing_docs)]

pub mod caldav;
pub mod cli;
pub mod commands;
pub mod config;
pub mod credentials;
pub mod datetime;
pub mod error;
pub mod ical;
pub mod model;
pub mod output;

use cli::{Cli, Command};
use commands::Context;
use error::Result;

/// Run a parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    let context = Context::new(cli.json, cli.no_input);
    match cli.command {
        Command::Auth { command } => commands::auth::run(&context, command),
        Command::Add(args) => commands::reminder::add(&context, args),
        Command::List(args) => commands::reminder::list(&context, args),
        Command::Get(args) => commands::reminder::get(&context, args),
        Command::Update(args) => commands::reminder::update(&context, args),
        Command::Complete(args) => commands::reminder::complete(&context, args),
        Command::Reopen(args) => commands::reminder::reopen(&context, args),
        Command::Delete(args) => commands::reminder::delete(&context, args),
    }
}
