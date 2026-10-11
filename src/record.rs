//! `mimesia record`: capture one page from a signed-in tab.
//!
//! Bodies are buffered in memory, scrubbed, and only then written. Identity values are learned
//! in memory from the live MSAL cache and bearer tokens and are never persisted.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chromiumoxide::cdp::browser_protocol::fetch::{
    self, ContinueRequestParams, EventRequestPaused, GetResponseBodyParams, RequestPattern,
    RequestStage,
};
use chromiumoxide::cdp::browser_protocol::network::{
    self, EventLoadingFailed, EventLoadingFinished, EventRequestWillBeSent, EventWebSocketCreated,
    RequestId, SetBypassServiceWorkerParams, SetCacheDisabledParams,
};
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, FrameTree, GetFrameTreeParams, ReloadParams,
};
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::Value;

use crate::cdp::Session;
use crate::matchkey;
use crate::persona::Persona;
use crate::rules::{Class, classify};
use crate::scan::{ScanReport, scan};
use crate::scrub::{IdentityMap, Scrubber, is_text, keep_header};
use crate::store::{Capture, Entry, FORMAT_VERSION, Inventory, Manifest, StorageItem, Viewport};

/// Upper bound on how long we wait for the page to settle.
const MAX_WAIT: Duration = Duration::from_secs(90);
/// Minimum time after reload before idle can count.
const MIN_WAIT: Duration = Duration::from_secs(2);
/// Requests open longer than this are treated as long-polls and don't block idle.
const LONG_POLL: Duration = Duration::from_secs(15);
/// Bound on any single CDP command, so record can never hang on the user's tab.
const CDP_TIMEOUT: Duration = Duration::from_secs(15);

async fn bounded<T>(what: &str, f: impl Future<Output = T>) -> Result<T> {
    tokio::time::timeout(CDP_TIMEOUT, f)
        .await
        .map_err(|_| anyhow::anyhow!("{what} timed out"))
}

pub const STILL_CSS: &str = "*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}";

pub async fn run(cdp: &str, tab: &str, out: &Path, idle: u64) -> Result<()> {
    ensure_git_ignored(out)?;
    let mut session = Session::connect(cdp).await?;
    let page = session.find_tab(tab).await?;
    let result = record_page(&page, out, Duration::from_secs(idle), Persona::default()).await;
    session.detach();
    let report = result?;
    for f in &report.findings {
        println!("LEAK {:<14} {}", f.kind, f.location);
    }
    if !report.ok {
        bail!(
            "recorded, but scan found {} potential leak(s); replay will refuse this capture",
            report.findings.len()
        );
    }
    println!("recorded {} (scan ok)", out.display());
    Ok(())
}

/// Record `page` into `out`. Always releases interception on the page, even on error.
pub async fn record_page(
    page: &Page,
    out: &Path,
    idle: Duration,
    persona: Persona,
) -> Result<ScanReport> {
    if out.exists() && fs::read_dir(out)?.next().is_some() {
        bail!("{} is not empty", out.display());
    }
    let result = record_inner(page, out, idle, persona).await;
    let fetch_off = bounded(
        "Fetch.disable",
        page.execute(fetch::DisableParams::default()),
    )
    .await;
    let _ = bounded(
        "bypass",
        page.execute(SetBypassServiceWorkerParams::new(false)),
    )
    .await;
    let _ = bounded("cache", page.execute(SetCacheDisabledParams::new(false))).await;
    if !matches!(fetch_off, Ok(Ok(_))) {
        tracing::error!("could not release request interception; close the tab to recover");
    }
    if result.is_err() && !out.join("scan.json").exists() {
        let _ = fs::remove_dir_all(out);
    }
    result
}

#[derive(Deserialize)]
struct Snapshot {
    url: String,
    origin: String,
    width: u32,
    height: u32,
    dpr: f64,
    ua: String,
    storage: Vec<StorageItem>,
}

const SNAPSHOT_JS: &str = r#"(() => {
  const storage = [];
  for (const area of ['localStorage', 'sessionStorage']) {
    try {
      const s = window[area];
      for (let i = 0; i < s.length; i++) { const key = s.key(i); storage.push({ area, key, value: s.getItem(key) }); }
    } catch (_) {}
  }
  return { url: location.href, origin: location.origin, width: innerWidth, height: innerHeight,
           dpr: devicePixelRatio, ua: navigator.userAgent, storage };
})()"#;

struct Raw {
    method: String,
    url: String,
    resource_type: String,
    status: i64,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    request_body: Option<Vec<u8>>,
}

#[derive(Default)]
struct State {
    raws: Vec<Raw>,
    inv: Inventory,
    /// Claims from bearer tokens on live requests (memory only).
    bearer_claims: Vec<Value>,
    /// Fetch handlers still running.
    in_flight: usize,
    /// Network requests started but not finished, with start time.
    pending: HashMap<RequestId, (Instant, String)>,
    /// Finished ids, since separate event streams can deliver the finish before the start.
    done: HashSet<RequestId>,
    last_activity: Option<Instant>,
}

impl State {
    fn touch(&mut self) {
        self.last_activity = Some(Instant::now());
    }

    fn finish(&mut self, id: &RequestId) {
        self.pending.remove(id);
        self.done.insert(id.clone());
        self.touch();
    }

    fn settled(&self, idle: Duration) -> bool {
        self.in_flight == 0
            && self.pending.values().all(|(t, _)| t.elapsed() >= LONG_POLL)
            && self.last_activity.is_some_and(|t| t.elapsed() >= idle)
    }
}

async fn record_inner(
    page: &Page,
    out: &Path,
    idle: Duration,
    persona: Persona,
) -> Result<ScanReport> {
    let snap: Snapshot = page
        .evaluate(SNAPSHOT_JS)
        .await?
        .into_value()
        .context("cannot read page state")?;
    tracing::info!(url = %snap.url, "arming");

    let state = Arc::new(Mutex::new(State::default()));
    let mut paused = page.event_listener::<EventRequestPaused>().await?;
    let mut sockets = page.event_listener::<EventWebSocketCreated>().await?;
    let mut sent = page.event_listener::<EventRequestWillBeSent>().await?;
    let mut finished = page.event_listener::<EventLoadingFinished>().await?;
    let mut failed = page.event_listener::<EventLoadingFailed>().await?;

    page.execute(network::EnableParams::default()).await?;
    page.execute(SetCacheDisabledParams::new(true)).await?;
    page.execute(SetBypassServiceWorkerParams::new(true))
        .await?;
    page.execute(
        fetch::EnableParams::builder()
            .pattern(
                RequestPattern::builder()
                    .url_pattern("*")
                    .request_stage(RequestStage::Response)
                    .build(),
            )
            .build(),
    )
    .await?;

    let listener = {
        let page = page.clone();
        let state = state.clone();
        tokio::spawn(async move {
            // Dropping the set (when this task is aborted) aborts any handler still running;
            // Fetch.disable then releases whatever they had paused.
            let mut handlers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(ev) = paused.next() => {
                        let page = page.clone();
                        let state = state.clone();
                        {
                            let mut s = state.lock().unwrap();
                            s.in_flight += 1;
                            s.touch();
                        }
                        handlers.spawn(async move {
                            match bounded("handle", handle(&page, &ev, &state)).await {
                                Ok(Err(e)) | Err(e) => {
                                    tracing::debug!("handle: {e:#}");
                                    state.lock().unwrap().inv.skipped.push((ev.request.url.clone(), "error".into()));
                                }
                                Ok(Ok(())) => {}
                            }
                            let _ = bounded(
                                "continue",
                                page.execute(ContinueRequestParams::new(ev.request_id.clone())),
                            )
                            .await;
                            let mut s = state.lock().unwrap();
                            s.in_flight -= 1;
                            s.touch();
                        });
                    }
                    Some(ev) = sent.next() => {
                        let mut s = state.lock().unwrap();
                        // Identity/telemetry are never recorded, so they must not hold up idle.
                        let ignored = matches!(classify(&ev.request.url), Class::Identity | Class::Telemetry);
                        if !ignored && !s.done.contains(&ev.request_id) {
                            s.pending.insert(ev.request_id.clone(), (Instant::now(), ev.request.url.clone()));
                        }
                        s.touch();
                    }
                    Some(ev) = finished.next() => state.lock().unwrap().finish(&ev.request_id),
                    Some(ev) = failed.next() => state.lock().unwrap().finish(&ev.request_id),
                    Some(ws) = sockets.next() => {
                        let mut s = state.lock().unwrap();
                        if classify(&ws.url) == Class::Identity {
                            s.inv.identity_excluded += 1;
                        } else {
                            s.inv.websockets.push(ws.url.clone());
                        }
                    }
                    Some(_) = handlers.join_next(), if !handlers.is_empty() => {}
                    else => break,
                }
            }
        })
    };

    page.execute(ReloadParams::builder().ignore_cache(true).build())
        .await?;
    let started = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if started.elapsed() >= MIN_WAIT && state.lock().unwrap().settled(idle) {
            break;
        }
        if started.elapsed() >= MAX_WAIT {
            let s = state.lock().unwrap();
            tracing::warn!(
                in_flight = s.in_flight,
                pending = s.pending.len(),
                "page did not settle; recording what we have"
            );
            break;
        }
    }

    // Release interception before anything else so the tab is never left paused.
    bounded(
        "Fetch.disable",
        page.execute(fetch::DisableParams::default()),
    )
    .await??;
    listener.abort();
    let png = bounded("screenshot", still_screenshot(page)).await??;

    let frames = page.execute(GetFrameTreeParams::default()).await?;
    let mut frame_urls = Vec::new();
    collect_frames(&frames.result.frame_tree, &mut frame_urls, true);

    let state = std::mem::take(&mut *state.lock().unwrap());
    finalize(out, snap, state, frame_urls, png, persona)
}

/// Screenshot with animations and carets frozen.
pub async fn still_screenshot(page: &Page) -> Result<Vec<u8>> {
    page.evaluate(format!(
        "(() => {{ const s = document.createElement('style'); s.id = '__mimesia_still'; s.textContent = {css:?}; document.documentElement.appendChild(s); }})()",
        css = STILL_CSS
    ))
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let png = page
        .screenshot(
            ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .build(),
        )
        .await?;
    page.evaluate("document.getElementById('__mimesia_still')?.remove()")
        .await?;
    Ok(png)
}

fn collect_frames(t: &FrameTree, out: &mut Vec<String>, root: bool) {
    if !root {
        out.push(t.frame.url.clone());
    }
    for c in t.child_frames.iter().flatten() {
        collect_frames(c, out, false);
    }
}

fn header_pairs(h: &impl serde::Serialize) -> Vec<(String, String)> {
    match serde_json::to_value(h) {
        Ok(Value::Object(m)) => m
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok()
}

async fn handle(page: &Page, ev: &EventRequestPaused, state: &Mutex<State>) -> Result<()> {
    let url = ev.request.url.clone();
    let host = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let class = classify(&url);
    if class == Class::Identity {
        // Count only: identity hosts and paths are never written anywhere.
        state.lock().unwrap().inv.identity_excluded += 1;
        return Ok(());
    }
    let req_headers = header_pairs(&ev.request.headers);
    {
        let mut s = state.lock().unwrap();
        *s.inv.hosts.entry(host).or_default() += 1;
        for (k, v) in &req_headers {
            if k.eq_ignore_ascii_case("authorization")
                && let Some(c) = v.split_whitespace().nth(1).and_then(jwt_claims)
            {
                s.bearer_claims.push(c);
            }
        }
    }

    if class == Class::Telemetry {
        state.lock().unwrap().inv.telemetry_excluded += 1;
        return Ok(());
    }

    let Some(status) = ev.response_status_code else {
        let reason = ev
            .response_error_reason
            .as_ref()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| "no response".into());
        state.lock().unwrap().inv.skipped.push((url, reason));
        return Ok(());
    };
    let headers: Vec<(String, String)> = ev
        .response_headers
        .iter()
        .flatten()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    if content_type.contains("text/event-stream") {
        state.lock().unwrap().inv.event_streams.push(url);
        return Ok(());
    }

    let request_body = ev.request.post_data_entries.as_ref().map(|entries| {
        let mut buf = Vec::new();
        for e in entries {
            if let Some(Value::String(b)) =
                e.bytes.as_ref().and_then(|b| serde_json::to_value(b).ok())
            {
                buf.extend(STANDARD.decode(b).unwrap_or_default());
            }
        }
        buf
    });

    let (status, body) = if class == Class::Photo {
        (404, None)
    } else if (300..400).contains(&status) || status == 204 {
        (status, None)
    } else {
        let r = page
            .execute(GetResponseBodyParams::new(ev.request_id.clone()))
            .await
            .context("getResponseBody")?;
        let bytes = if r.result.base64_encoded {
            STANDARD.decode(&r.result.body)?
        } else {
            r.result.body.clone().into_bytes()
        };
        (status, Some(bytes))
    };

    state.lock().unwrap().raws.push(Raw {
        method: ev.request.method.clone(),
        url,
        resource_type: format!("{:?}", ev.resource_type),
        status,
        headers,
        body,
        request_body,
    });
    Ok(())
}

fn learn_identity(snap: &Snapshot, st: &State, persona: &Persona) -> IdentityMap {
    let mut ids = IdentityMap::default();
    for item in &snap.storage {
        let Ok(v) = serde_json::from_str::<Value>(&item.value) else {
            continue;
        };
        ids.learn_from_msal(&v, persona);
        if v.get("credentialType").and_then(Value::as_str) == Some("IdToken")
            && let Some(c) = v.get("secret").and_then(Value::as_str).and_then(jwt_claims)
        {
            ids.learn_from_msal(&c, persona);
        }
    }
    for c in &st.bearer_claims {
        ids.learn_from_msal(c, persona);
    }
    // Graph /me style responses.
    for r in &st.raws {
        if !r.url.contains("graph.microsoft.com") || !r.url.contains("/me") {
            continue;
        }
        let Some(v) = r
            .body
            .as_ref()
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        else {
            continue;
        };
        for (k, fake) in [
            ("id", &persona.oid),
            ("userPrincipalName", &persona.upn),
            ("mail", &persona.upn),
            ("displayName", &persona.name),
        ] {
            if let Some(real) = v.get(k).and_then(Value::as_str) {
                ids.add(real, fake);
            }
        }
    }
    ids
}

fn finalize(
    out: &Path,
    snap: Snapshot,
    st: State,
    frames: Vec<String>,
    png: Vec<u8>,
    persona: Persona,
) -> Result<ScanReport> {
    let ids = learn_identity(&snap, &st, &persona);
    if ids.is_empty() {
        bail!(
            "could not learn the signed-in identity (no MSAL cache or bearer tokens seen); refusing to record unscrubbed data"
        );
    }
    let scrubber = Scrubber::new(persona.clone(), ids);
    let check = |what: &str, ct: &str, text: &str| -> Result<()> {
        if scrubber.identity_left(ct, text) {
            bail!("identity value survived scrubbing in {what}; refusing to write");
        }
        Ok(())
    };
    let mut inv = st.inv;

    fs::create_dir_all(out)?;
    let cap = Capture::new(out);
    let mut entries = Vec::new();
    for r in st.raws {
        let url = scrubber.text(&r.url);
        check("a URL", "", &url)?;
        let headers: Vec<(String, String)> = r
            .headers
            .iter()
            .filter(|(k, _)| keep_header(k))
            .map(|(k, v)| (k.to_ascii_lowercase(), scrubber.text(v)))
            .collect();
        let ct = headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let text = r
            .body
            .as_ref()
            .filter(|_| is_text(&ct))
            .and_then(|b| std::str::from_utf8(b).ok());
        let body = match (text, &r.body) {
            (Some(s), _) => {
                let s = scrubber.body(&ct, s);
                check("a response body", &ct, &s)?;
                Some(cap.put_blob(s.as_bytes())?)
            }
            // Binary or non-UTF-8: can't rewrite safely, so drop it if it names the user.
            (None, Some(b)) if scrubber.bytes_have_identity(b) => {
                inv.skipped
                    .push((url.clone(), "identity in binary body".into()));
                None
            }
            (None, Some(b)) => Some(cap.put_blob(b)?),
            (None, None) => None,
        };
        let req_body = r
            .request_body
            .map(|b| scrubber.text(&String::from_utf8_lossy(&b)).into_bytes());
        entries.push(Entry {
            key: matchkey::exact(&r.method, &url, req_body.as_deref()),
            loose_key: matchkey::loose(&r.method, &url),
            method: r.method,
            url,
            resource_type: r.resource_type,
            status: r.status,
            headers,
            body,
        });
    }

    let mut storage = Vec::new();
    let mut dropped = 0;
    for item in snap.storage {
        let key = scrubber.text(&item.key);
        match scrubber.storage_value(&item.value) {
            Some(value) => {
                check("storage", "", &key)?;
                check("storage", "application/json", &value)?;
                storage.push(StorageItem {
                    area: item.area,
                    key,
                    value,
                });
            }
            None => dropped += 1,
        }
    }
    if dropped > 0 {
        tracing::warn!(
            dropped,
            "dropped storage entries that could not be made safe (encrypted MSAL cache?)"
        );
    }

    for f in frames {
        if classify(&f) == Class::Identity {
            inv.identity_excluded += 1;
        } else {
            inv.frames.push(f);
        }
    }
    let inv: Inventory = serde_json::from_str(&scrubber.text(&serde_json::to_string(&inv)?))?;
    check("inventory", "", &serde_json::to_string(&inv)?)?;

    let manifest = Manifest {
        version: FORMAT_VERSION,
        url: scrubber.text(&snap.url),
        origin: snap.origin,
        captured_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64,
        viewport: Viewport {
            width: snap.width,
            height: snap.height,
            dpr: snap.dpr,
        },
        user_agent: snap.ua,
        persona,
        storage,
        dropped_storage: dropped,
    };
    check("manifest", "", &serde_json::to_string(&manifest)?)?;

    tracing::info!(
        entries = entries.len(),
        identity_excluded = inv.identity_excluded,
        websockets = inv.websockets.len(),
        event_streams = inv.event_streams.len(),
        frames = inv.frames.len(),
        "recorded"
    );
    cap.write_entries(&entries)?;
    cap.write_json("manifest.json", &manifest)?;
    cap.write_json("inventory.json", &inv)?;
    fs::write(cap.path("record.png"), png)?;
    scan(&cap)
}

/// Refuse an output directory that Git would track. Fails closed when unsure.
pub fn ensure_git_ignored(out: &Path) -> Result<()> {
    let abs = std::path::absolute(out)?;
    let mut probe_dir = abs.as_path();
    while !probe_dir.exists() {
        probe_dir = probe_dir
            .parent()
            .context("output path has no existing ancestor")?;
    }
    let in_repo = probe_dir.ancestors().any(|a| a.join(".git").exists());
    let inside = std::process::Command::new("git")
        .arg("-C")
        .arg(probe_dir)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();
    match inside {
        Ok(o) if o.status.success() => {}
        Ok(_) if !in_repo => return Ok(()),
        Err(_) if !in_repo => return Ok(()),
        _ => bail!(
            "cannot confirm {} is git-ignored (is git installed?); refusing to record",
            out.display()
        ),
    }
    // Check every artifact path, not a stand-in, so a child-only ignore rule can't fool us.
    let artifacts = crate::store::REQUIRED
        .iter()
        .chain(["scan.json", "blobs/0"].iter())
        .map(|n| abs.join(n));
    for p in artifacts {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(probe_dir)
            .args(["check-ignore", "-q", "--no-index"])
            .arg(&p)
            .status()?;
        if !status.success() {
            bail!(
                "{} is inside a Git repository and not ignored; use a path under captures/ or outside the repo",
                out.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_guard() {
        assert!(ensure_git_ignored(Path::new("captures/x")).is_ok());
        assert!(ensure_git_ignored(Path::new("src/not-ignored")).is_err());
    }
}
