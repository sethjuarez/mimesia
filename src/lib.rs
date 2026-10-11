//! Mimesia: record, replay, and verify web app shells.

pub mod cdp;
pub mod record;
pub mod replay;
pub mod scan;
pub mod verify;

pub const DEFAULT_CDP: &str = "http://127.0.0.1:9333";
