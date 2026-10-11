//! Browser connection helpers.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::target::TargetInfo;
use chromiumoxide::handler::viewport::Viewport;
use chromiumoxide::page::Page;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// A connected browser plus the task that drives its CDP handler.
pub struct Session {
    pub browser: Browser,
    handler: JoinHandle<()>,
    profile: Option<PathBuf>,
}

impl Session {
    pub async fn connect(cdp: &str) -> Result<Self> {
        let (browser, mut handler) = Browser::connect(cdp).await.with_context(|| {
            format!(
                "cannot reach CDP at {cdp}; is the browser started with --remote-debugging-port?"
            )
        })?;
        let handler = tokio::spawn(async move { while handler.next().await.is_some() {} });
        Ok(Self {
            browser,
            handler,
            profile: None,
        })
    }

    /// Launch a fresh browser with a throwaway profile.
    pub async fn launch(opts: Launch) -> Result<Self> {
        let profile = std::env::temp_dir().join(format!(
            "mimesia-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        let mut b = BrowserConfig::builder()
            .user_data_dir(&profile)
            .window_size(opts.width, opts.height)
            .viewport(Viewport {
                width: opts.width,
                height: opts.height,
                device_scale_factor: Some(opts.dpr),
                emulating_mobile: false,
                is_landscape: false,
                has_touch: false,
            })
            .args(opts.args);
        b = if opts.headed {
            b.with_head()
        } else {
            b.new_headless_mode()
        };
        if opts.intercept {
            b = b.enable_request_intercept().disable_cache();
        }
        if let Some(exe) = browser_executable() {
            b = b.chrome_executable(exe);
        }
        if std::env::var_os("CI").is_some() {
            b = b.no_sandbox();
        }
        let config = b.build().map_err(|e| anyhow::anyhow!(e))?;
        let (browser, mut handler) = Browser::launch(config)
            .await
            .context("cannot launch browser; set MIMESIA_BROWSER to an Edge/Chrome executable")?;
        let handler = tokio::spawn(async move { while handler.next().await.is_some() {} });
        Ok(Self {
            browser,
            handler,
            profile: Some(profile),
        })
    }

    /// Page tabs (not workers, extensions, or devtools).
    pub async fn tabs(&mut self) -> Result<Vec<TargetInfo>> {
        let targets = self.browser.fetch_targets().await?;
        Ok(targets.into_iter().filter(|t| t.r#type == "page").collect())
    }

    /// Attach to the first tab whose URL contains `needle`.
    pub async fn find_tab(&mut self, needle: &str) -> Result<Page> {
        let tabs = self.tabs().await?;
        let matches: Vec<_> = tabs.iter().filter(|t| t.url.contains(needle)).collect();
        let target = match matches.as_slice() {
            [] => bail!(
                "no tab URL contains '{needle}'. Open tabs:\n{}",
                tabs.iter()
                    .map(|t| format!("  {}", t.url))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            [one] => *one,
            [first, ..] => {
                tracing::warn!(count = matches.len(), url = %first.url, "several tabs match; using the first");
                *first
            }
        };
        // Attachment happens asynchronously after discovery; poll briefly.
        for _ in 0..50 {
            if let Ok(page) = self.browser.get_page(target.target_id.clone()).await {
                return Ok(page);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("could not attach to tab {}", target.url)
    }

    /// Detach without closing the user's browser.
    pub fn detach(self) {
        self.handler.abort();
    }

    /// Close a browser we launched ourselves.
    pub async fn close(mut self) {
        let _ = self.browser.close().await;
        let _ = self.browser.wait().await;
        self.handler.abort();
        if let Some(p) = self.profile {
            let _ = std::fs::remove_dir_all(p);
        }
    }
}

pub struct Launch {
    pub headed: bool,
    pub width: u32,
    pub height: u32,
    pub dpr: f64,
    /// Answer requests ourselves via `Fetch.requestPaused`.
    pub intercept: bool,
    pub args: Vec<String>,
}

impl Default for Launch {
    fn default() -> Self {
        Self {
            headed: false,
            width: 1280,
            height: 800,
            dpr: 1.0,
            intercept: false,
            args: Vec::new(),
        }
    }
}

/// `MIMESIA_BROWSER`, else Edge on Windows, else chromiumoxide's own detection.
fn browser_executable() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("MIMESIA_BROWSER") {
        return Some(PathBuf::from(p));
    }
    if cfg!(windows) {
        for base in ["ProgramFiles(x86)", "ProgramFiles"] {
            if let Some(b) = std::env::var_os(base) {
                let p = PathBuf::from(b).join(r"Microsoft\Edge\Application\msedge.exe");
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

pub async fn print_tabs(cdp: &str) -> Result<()> {
    let mut session = Session::connect(cdp).await?;
    for t in session.tabs().await? {
        println!("{}\t{}", t.title, t.url);
    }
    session.detach();
    Ok(())
}
