//! Entry point: parse arguments, run the command, and map failures onto stable
//! exit codes.

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser;
use reminders::cli::Cli;
use reminders::error::Error;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match reminders::run(cli) {
        Ok(()) => {
            // A closed pipe (`reminders list | head`) is not a failure.
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(err) => {
            report(&err, json);
            ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1))
        }
    }
}

/// Errors always go to stderr. In JSON mode a machine-readable envelope goes to
/// stderr too, so stdout stays a clean data channel.
///
/// Error messages are built from this crate's own prose and never quote a
/// response body, but the human form is still sanitized as a backstop: a few
/// messages name a resource path the server chose. The JSON form keeps the
/// message verbatim, because JSON string escaping already neutralises control
/// characters for a parser.
fn report(err: &Error, json: bool) {
    if json {
        let envelope = serde_json::json!({
            "error": {
                "kind": err.kind(),
                "message": err.to_string(),
                "exit_code": err.exit_code(),
            }
        });
        eprintln!("{envelope}");
    } else {
        eprintln!(
            "reminders: error: {}",
            reminders::output::sanitize_line(&err.to_string())
        );
    }
}
