use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mimesia",
    version,
    about = "Record, replay, and verify web app shells for demos"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List tabs in a debug-enabled browser.
    Tabs {
        /// CDP endpoint (http://host:port or ws://...).
        #[arg(long, default_value = mimesia::DEFAULT_CDP)]
        cdp: String,
    },
    /// Record one page from a signed-in tab.
    Record {
        /// Substring of the tab URL to record.
        tab: String,
        /// Output capture directory (must be ignored by Git).
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = mimesia::DEFAULT_CDP)]
        cdp: String,
        /// Seconds without new requests before the page counts as settled.
        #[arg(long, default_value_t = 3)]
        idle: u64,
        /// Real identity value to scrub (display name or UPN) when the app does not expose it.
        /// Repeatable.
        #[arg(long = "identity", value_name = "VALUE")]
        identity: Vec<String>,
    },
    /// Fail if a capture leaks tokens or credentials.
    Scan { capture: PathBuf },
    /// Replay a capture offline in a fresh browser.
    Replay {
        capture: PathBuf,
        /// Show the browser window.
        #[arg(long)]
        headed: bool,
    },
    /// Replay, screenshot, and pixel-diff against the recording.
    Verify {
        capture: PathBuf,
        /// Max fraction of differing pixels to pass.
        #[arg(long, default_value_t = 0.01)]
        threshold: f64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mimesia=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().command {
        Command::Tabs { cdp } => mimesia::cdp::print_tabs(&cdp).await,
        Command::Record {
            tab,
            out,
            cdp,
            idle,
            identity,
        } => mimesia::record::run(&cdp, &tab, &out, idle, &identity).await,
        Command::Scan { capture } => mimesia::scan::run(&capture),
        Command::Replay { capture, headed } => mimesia::replay::run(&capture, headed).await,
        Command::Verify { capture, threshold } => mimesia::verify::run(&capture, threshold).await,
    }
}
