//! Mimesia: record, replay, and verify web app shells.

pub mod auth;
pub mod cdp;
pub mod crawl;
pub mod matchkey;
pub mod persona;
pub mod record;
pub mod replay;
pub mod rules;
pub mod scan;
pub mod scrub;
pub mod store;
pub mod verify;

pub const DEFAULT_CDP: &str = "http://127.0.0.1:9333";
