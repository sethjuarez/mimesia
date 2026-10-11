//! Browser connection helpers.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use chromiumoxide::browser::Browser;
use chromiumoxide::cdp::browser_protocol::target::TargetInfo;
use chromiumoxide::page::Page;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// A connected browser plus the task that drives its CDP handler.
pub struct Session {
    pub browser: Browser,
    handler: JoinHandle<()>,
}

impl Session {
    pub async fn connect(cdp: &str) -> Result<Self> {
        let (browser, mut handler) = Browser::connect(cdp).await.with_context(|| {
            format!(
                "cannot reach CDP at {cdp}; is the browser started with --remote-debugging-port?"
            )
        })?;
        let handler = tokio::spawn(async move { while handler.next().await.is_some() {} });
        Ok(Self { browser, handler })
    }

    pub fn from_parts(browser: Browser, handler: JoinHandle<()>) -> Self {
        Self { browser, handler }
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
    }
}

pub async fn print_tabs(cdp: &str) -> Result<()> {
    let mut session = Session::connect(cdp).await?;
    for t in session.tabs().await? {
        println!("{}\t{}", t.title, t.url);
    }
    session.detach();
    Ok(())
}
