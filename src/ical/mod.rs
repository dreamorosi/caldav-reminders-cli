//! iCalendar (RFC 5545) reading and writing, limited to what VTODO reminders
//! need.

pub mod lines;
pub mod vtodo;

pub use lines::{escape_text, fold, unescape_text, unfold, ContentLine};
pub use vtodo::Document;
