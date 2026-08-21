//! `reminders add|list|get|update|complete|reopen|delete`

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use url::Url;

use crate::caldav::Resource;
use crate::cli::{AddArgs, DeleteArgs, GetArgs, IdArgs, ListArgs, StatusFilter, UpdateArgs};
use crate::commands::{open_session, Context, Session};
use crate::config::Config;
use crate::datetime::{parse_due, parse_instant, Due};
use crate::error::{Error, Result};
use crate::ical::Document;
use crate::model::{Reminder, ReminderChanges, Status};

/// Apple Reminders refreshes generic CalDAV accounts on its own schedule, so a
/// notification closer than this may simply not arrive on time.
const SHORT_NOTICE: Duration = Duration::hours(1);

/// Create a reminder.
pub fn add(context: &Context, args: AddArgs) -> Result<()> {
    let (due, remind_at) = resolve_timing(
        args.at.as_deref(),
        args.due.as_deref(),
        args.remind_at.as_deref(),
    )?;
    if let Some(remind_at) = remind_at {
        warn_on_short_notice(context, remind_at);
    }
    let title = validate_title(&args.title)?;
    let notes = args.notes.as_deref().map(str::to_string);

    let uid = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let document = Document::new_reminder(
        &uid,
        &title,
        notes.as_deref(),
        due,
        remind_at,
        args.priority,
        now,
    );

    if args.dry_run {
        let planned = document.to_reminder(None, None)?;
        return context
            .printer
            .dry_run_reminder("add", &planned, dry_run_target()?);
    }

    let config = Config::load()?;
    let session = open_session(context, &config)?;
    let created = session.client.create(&uid, &document.to_ics())?;
    let reminder = document.to_reminder(created.etag.clone(), Some(created.href.clone()))?;
    context.printer.reminder(&reminder)
}

/// List reminders.
pub fn list(context: &Context, args: ListArgs) -> Result<()> {
    let config = Config::load()?;
    let session = open_session(context, &config)?;
    let resources = session.client.list_todos()?;

    let mut reminders = Vec::with_capacity(resources.len());
    for resource in resources {
        match parse_resource(&resource) {
            Ok((_, reminder)) => reminders.push(reminder),
            // One malformed resource must not hide the rest of the collection.
            // The href is the only way to say which one, and it is the server's
            // string, so it is percent-encoded and length-capped first.
            Err(err) => context
                .printer
                .warn(&format!("skipping {}: {err}", safe_href(&resource.href))),
        }
    }

    reminders.retain(|reminder| matches_filter(reminder, args.status));
    reminders.sort_by(|left, right| {
        let key = |reminder: &Reminder| {
            (
                reminder
                    .due
                    .as_ref()
                    .map(Due::sort_key)
                    // Undated reminders sort last, deterministically.
                    .unwrap_or_else(|| DateTime::<Utc>::MAX_UTC),
                reminder.title.to_lowercase(),
                reminder.id.clone(),
            )
        };
        key(left).cmp(&key(right))
    });
    if let Some(limit) = args.limit {
        reminders.truncate(limit);
    }
    context.printer.list(&reminders)
}

/// Show one reminder.
pub fn get(context: &Context, args: GetArgs) -> Result<()> {
    let config = Config::load()?;
    let session = open_session(context, &config)?;
    let (_, reminder) = fetch(&session, &args.id)?;
    context.printer.reminder(&reminder)
}

/// Change a reminder.
pub fn update(context: &Context, args: UpdateArgs) -> Result<()> {
    let mut changes = ReminderChanges::default();
    if let Some(title) = &args.title {
        changes.title = Some(validate_title(title)?);
    }
    if args.clear_notes {
        changes.notes = Some(None);
    } else if let Some(notes) = &args.notes {
        changes.notes = Some(Some(notes.clone()));
    }

    if let Some(at) = &args.at {
        let instant = parse_instant(at)?;
        changes.due = Some(Some(Due::At(instant)));
        changes.remind_at = Some(Some(instant));
    } else {
        if args.clear_due {
            changes.due = Some(None);
        } else if let Some(due) = &args.due {
            changes.due = Some(Some(parse_due(due)?));
        }
        if args.clear_remind_at {
            changes.remind_at = Some(None);
        } else if let Some(remind_at) = &args.remind_at {
            changes.remind_at = Some(Some(parse_instant(remind_at)?));
        }
    }
    if let Some(priority) = args.priority {
        changes.priority = Some(priority);
    }

    if changes.is_empty() {
        return Err(Error::usage(
            "nothing to change; pass at least one of --title, --notes, --clear-notes, --due, \
             --clear-due, --at, --remind-at, --clear-remind-at, or --priority",
        ));
    }
    if let Some(Some(remind_at)) = changes.remind_at {
        warn_on_short_notice(context, remind_at);
    }

    if args.dry_run {
        return context.printer.dry_run(
            "update",
            json!({ "id": args.id, "changes": changes }),
            &format!("would update the reminder {}", args.id),
        );
    }

    apply_change(context, &args.id, changes)
}

/// Mark a reminder complete.
pub fn complete(context: &Context, args: IdArgs) -> Result<()> {
    set_status(context, args, Status::Complete)
}

/// Mark a reminder open again.
pub fn reopen(context: &Context, args: IdArgs) -> Result<()> {
    set_status(context, args, Status::Open)
}

fn set_status(context: &Context, args: IdArgs, status: Status) -> Result<()> {
    let operation = if status == Status::Complete {
        "complete"
    } else {
        "reopen"
    };
    if args.dry_run {
        return context.printer.dry_run(
            operation,
            json!({ "id": args.id }),
            &format!("would {operation} the reminder {}", args.id),
        );
    }
    apply_change(
        context,
        &args.id,
        ReminderChanges {
            status: Some(status),
            ..Default::default()
        },
    )
}

/// Delete a reminder.
pub fn delete(context: &Context, args: DeleteArgs) -> Result<()> {
    if args.dry_run {
        return context.printer.dry_run(
            "delete",
            json!({ "id": args.id }),
            &format!("would delete the reminder {}", args.id),
        );
    }

    let config = Config::load()?;
    let session = open_session(context, &config)?;
    let (resource, reminder) = fetch(&session, &args.id)?;
    let etag = require_etag(&resource)?;

    if !args.force {
        match context.confirm(&format!("Delete {:?} ({})?", reminder.title, reminder.id))? {
            Some(true) => {}
            Some(false) => {
                context.printer.note("cancelled");
                return Ok(());
            }
            None => {
                return Err(Error::usage(
                    "refusing to delete without confirmation; pass --force",
                ))
            }
        }
    }

    session.client.delete(&resource.href, etag)?;
    context.printer.deleted(&reminder.id)
}

/// Read, mutate, and write back one reminder under its ETag.
fn apply_change(context: &Context, id: &str, changes: ReminderChanges) -> Result<()> {
    let config = Config::load()?;
    let session = open_session(context, &config)?;
    let (resource, _) = fetch(&session, id)?;
    // Refuse before touching anything: an unguarded write could discard an
    // edit made in Apple Reminders or another client.
    let etag = require_etag(&resource)?;
    let mut document = Document::parse(&resource.data)?;
    document.apply(&changes, Utc::now());

    let saved = session
        .client
        .update(&resource.href, &document.to_ics(), etag)?;
    let reminder = document.to_reminder(saved.etag.clone(), Some(saved.href.clone()))?;
    context.printer.reminder(&reminder)
}

/// The ETag a conditional write needs, or a clear refusal.
fn require_etag(resource: &Resource) -> Result<&str> {
    resource
        .etag
        .as_deref()
        .filter(|etag| !etag.is_empty())
        .ok_or_else(|| crate::caldav::missing_etag_error(&safe_href(&resource.href)))
}

/// Fetch one reminder by id.
fn fetch(session: &Session, id: &str) -> Result<(Resource, Reminder)> {
    let resource = session.client.find_by_uid(id)?.ok_or_else(|| {
        Error::NotFound(format!(
            "no reminder with id {id} in {}",
            session.settings.collection_path
        ))
    })?;
    parse_resource(&resource)
}

fn parse_resource(resource: &Resource) -> Result<(Resource, Reminder)> {
    let document = Document::parse(&resource.data)?;
    let reminder = document.to_reminder(resource.etag.clone(), Some(resource.href.clone()))?;
    Ok((resource.clone(), reminder))
}

/// Longest resource path quoted in a diagnostic.
const HREF_LIMIT: usize = 120;

/// Make a server-supplied href safe to name in a diagnostic.
///
/// Parsing it as a URL percent-encodes anything that is not a valid path
/// character, so no control byte survives, and the result is then capped.
fn safe_href(href: &str) -> String {
    let encoded = Url::parse("http://x/")
        .ok()
        .and_then(|base| base.join(href).ok())
        .map(|url| url.path().to_string())
        .unwrap_or_else(|| "(unprintable href)".to_string());
    if encoded.len() <= HREF_LIMIT {
        return encoded;
    }
    format!("{}...", &encoded[..HREF_LIMIT])
}

fn matches_filter(reminder: &Reminder, filter: StatusFilter) -> bool {
    match filter {
        StatusFilter::All => true,
        StatusFilter::Open => reminder.status == Status::Open,
        StatusFilter::Complete => reminder.status == Status::Complete,
        StatusFilter::Cancelled => reminder.status == Status::Cancelled,
    }
}

/// Turn `--at`, `--due`, and `--remind-at` into a due date and a trigger.
///
/// `--at` is shorthand for both; a date-only due date never implies a
/// notification.
fn resolve_timing(
    at: Option<&str>,
    due: Option<&str>,
    remind_at: Option<&str>,
) -> Result<(Option<Due>, Option<DateTime<Utc>>)> {
    if let Some(at) = at {
        let instant = parse_instant(at)?;
        return Ok((Some(Due::At(instant)), Some(instant)));
    }
    let due = match due {
        Some(value) => Some(parse_due(value)?),
        None => None,
    };
    let remind_at = match remind_at {
        Some(value) => Some(parse_instant(value)?),
        None => None,
    };
    Ok((due, remind_at))
}

/// Titles must be non-empty and single-line; iCalendar can escape newlines but
/// a multi-line SUMMARY displays badly everywhere.
fn validate_title(title: &str) -> Result<String> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err(Error::usage("the title must not be empty"));
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(Error::usage(
            "the title must be a single line; use --notes instead",
        ));
    }
    Ok(trimmed.to_string())
}

fn warn_on_short_notice(context: &Context, remind_at: DateTime<Utc>) {
    if remind_at - Utc::now() < SHORT_NOTICE {
        context.printer.warn(
            "the notification is less than an hour away; Apple Reminders refreshes generic \
             CalDAV accounts on its own schedule and may not deliver it in time",
        );
    }
}

/// Best-effort target description for `--dry-run`, which must not fail just
/// because the configuration is incomplete.
fn dry_run_target() -> Result<Option<String>> {
    let config = Config::load().unwrap_or_default();
    Ok(config
        .settings()
        .ok()
        .and_then(|settings| settings.collection_url().ok())
        .map(|url| url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_sets_both_due_and_reminder() {
        let (due, remind_at) =
            resolve_timing(Some("2026-08-22T16:00:00+04:00"), None, None).unwrap();
        let instant = parse_instant("2026-08-22T12:00:00Z").unwrap();
        assert_eq!(due, Some(Due::At(instant)));
        assert_eq!(remind_at, Some(instant));
    }

    #[test]
    fn at_rejects_a_bare_date() {
        let err = resolve_timing(Some("2026-08-22"), None, None).unwrap_err();
        assert_eq!(err.exit_code(), crate::error::exit::USAGE);
    }

    #[test]
    fn date_only_due_implies_no_notification() {
        let (due, remind_at) = resolve_timing(None, Some("2026-08-22"), None).unwrap();
        assert!(matches!(due, Some(Due::Date(_))));
        assert_eq!(remind_at, None);
    }

    #[test]
    fn due_and_remind_at_are_independent() {
        let (due, remind_at) =
            resolve_timing(None, Some("2026-08-22"), Some("2026-08-21T09:00:00Z")).unwrap();
        assert!(matches!(due, Some(Due::Date(_))));
        assert_eq!(
            remind_at,
            Some(parse_instant("2026-08-21T09:00:00Z").unwrap())
        );
    }

    #[test]
    fn no_timing_flags_yields_nothing() {
        assert_eq!(resolve_timing(None, None, None).unwrap(), (None, None));
    }

    #[test]
    fn titles_are_trimmed_and_validated() {
        assert_eq!(validate_title("  Buy milk  ").unwrap(), "Buy milk");
        assert!(validate_title("").is_err());
        assert!(validate_title("   ").is_err());
        assert!(validate_title("two\nlines").is_err());
        assert!(validate_title("two\rlines").is_err());
    }

    fn reminder_with(status: Status, due: Option<&str>, title: &str) -> Reminder {
        use crate::model::Priority;
        Reminder {
            id: format!("id-{title}"),
            title: title.to_string(),
            notes: None,
            due: due.map(|value| parse_due(value).unwrap()),
            remind_at: None,
            priority: Priority::None,
            status,
            completed_at: None,
            etag: None,
            href: None,
        }
    }

    #[test]
    fn status_filter_selects_the_right_reminders() {
        let open = reminder_with(Status::Open, None, "a");
        let done = reminder_with(Status::Complete, None, "b");
        let gone = reminder_with(Status::Cancelled, None, "c");
        assert!(matches_filter(&open, StatusFilter::Open));
        assert!(!matches_filter(&done, StatusFilter::Open));
        assert!(matches_filter(&done, StatusFilter::Complete));
        assert!(matches_filter(&gone, StatusFilter::Cancelled));
        for reminder in [&open, &done, &gone] {
            assert!(matches_filter(reminder, StatusFilter::All));
        }
    }

    #[test]
    fn undated_reminders_sort_after_dated_ones() {
        let dated = reminder_with(Status::Open, Some("2030-01-01"), "z");
        let undated = reminder_with(Status::Open, None, "a");
        let dated_key = dated.due.as_ref().map(Due::sort_key).unwrap();
        let undated_key = undated
            .due
            .as_ref()
            .map(Due::sort_key)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        assert!(dated_key < undated_key);
    }
}
