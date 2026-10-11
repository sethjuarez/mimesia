//! Offline replay: a fresh browser whose every request is answered from the capture.
//!
//! Nothing reaches the network. Chrome runs behind Mimesia's own reject-everything proxy, so a
//! request that slips past interception fails and is reported as `escaped` instead of leaking; identity hosts get [`crate::auth`] stubs, telemetry gets
//! 204, and everything else is served from recorded fixtures. A bootstrap script pins the clock,
//! seeds the fake MSAL session, and parks service workers, WebSockets, and EventSource.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chromiumoxide::cdp::browser_protocol::fetch::{
    self, EventRequestPaused, FailRequestParams, FulfillRequestParams, HeaderEntry, RequestPattern,
    RequestStage,
};
use chromiumoxide::cdp::browser_protocol::network::{
    self, ErrorReason, ResourceType, SetBypassServiceWorkerParams, SetCacheDisabledParams,
};
use chromiumoxide::cdp::browser_protocol::page::{
    AddScriptToEvaluateOnNewDocumentParams, FrameId, NavigateParams,
};
use chromiumoxide::page::Page;
use futures::StreamExt;
use serde::Serialize;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use url::Url;

use crate::auth;
use crate::cdp::{Launch, Session};
use crate::matchkey;
use crate::persona::Persona;
use crate::record::{header_pairs, post_body};
use crate::rules::{Class, classify};
use crate::scan::require_clean;
use crate::store::{Capture, Entry, Manifest};

/// Quiet period (no intercepted requests) that counts as settled.
const QUIET: Duration = Duration::from_millis(1500);
/// Upper bound on settling.
const MAX_SETTLE: Duration = Duration::from_secs(60);

#[derive(Debug, Default, Clone, Serialize)]
pub struct Stats {
    pub hits: usize,
    pub identity_stubbed: usize,
    pub telemetry_stubbed: usize,
    pub preflight_stubbed: usize,
    pub blank_frames: usize,
    /// `METHOD url` of requests with no fixture; these failed.
    pub misses: Vec<String>,
    /// First line of requests that bypassed interception and hit the reject proxy.
    pub escaped: Vec<String>,
}

/// Fixtures indexed by exact then loose key. Repeated keys are served in recorded order,
/// then the last one repeats.
struct Index {
    entries: Vec<Entry>,
    exact: HashMap<String, Vec<usize>>,
    loose: HashMap<String, Vec<usize>>,
    cursor: HashMap<String, usize>,
}

impl Index {
    fn new(entries: Vec<Entry>) -> Self {
        let mut exact: HashMap<String, Vec<usize>> = HashMap::new();
        let mut loose: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            exact.entry(e.key.clone()).or_default().push(i);
            loose.entry(e.loose_key.clone()).or_default().push(i);
        }
        Self {
            entries,
            exact,
            loose,
            cursor: HashMap::new(),
        }
    }

    fn lookup(&mut self, method: &str, url: &str, body: Option<&[u8]>) -> Option<&Entry> {
        let exact = matchkey::exact(method, url, body);
        let (key, list) = match self.exact.get(&exact) {
            Some(l) => (exact, l),
            None if matches!(method, "GET" | "HEAD") => {
                let loose = matchkey::loose(method, url);
                let l = self.loose.get(&loose)?;
                (format!("~{loose}"), l)
            }
            None => return None,
        };
        let n = self.cursor.entry(key).or_insert(0);
        let i = list[(*n).min(list.len() - 1)];
        *n += 1;
        Some(&self.entries[i])
    }
}

struct State {
    cap: Capture,
    index: Index,
    persona: Persona,
    origin: String,
    main_frame: Option<FrameId>,
    stats: Stats,
    in_flight: usize,
    last: Instant,
}

pub struct Replay {
    pub session: Session,
    pub page: Page,
    state: Arc<Mutex<State>>,
    listener: tokio::task::JoinHandle<()>,
    proxy: tokio::task::JoinHandle<()>,
}

impl Replay {
    /// Launch a browser and start replaying `capture`. Refuses captures that fail the leak scan.
    pub async fn start(capture: &Path, headed: bool) -> Result<Self> {
        let cap = Capture::new(capture);
        require_clean(&cap)?;
        let manifest = cap.manifest()?;
        let index = Index::new(cap.entries()?);
        let escaped = Arc::new(Mutex::new(Vec::new()));
        let (proxy_addr, proxy) = reject_proxy(escaped.clone()).await?;

        let session = Session::launch(Launch {
            headed,
            width: manifest.viewport.width,
            height: manifest.viewport.height,
            dpr: manifest.viewport.dpr,
            intercept: false,
            args: vec![
                // Anything not intercepted goes to our reject proxy instead of the network.
                format!("--proxy-server=http://{proxy_addr}"),
                "--proxy-bypass-list=<-loopback>".into(),
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
                // Keep cross-origin iframes in-process so their requests are intercepted too.
                "--disable-features=IsolateOrigins,site-per-process".into(),
            ],
        })
        .await?;
        let page = session.browser.new_page("about:blank").await?;
        page.execute(network::EnableParams::default()).await?;
        page.execute(SetBypassServiceWorkerParams::new(true))
            .await?;
        page.execute(SetCacheDisabledParams::new(true)).await?;
        page.execute(AddScriptToEvaluateOnNewDocumentParams::new(bootstrap(
            &manifest,
        )?))
        .await?;
        if !manifest.user_agent.is_empty() {
            page.set_user_agent(&manifest.user_agent).await?;
        }

        let state = Arc::new(Mutex::new(State {
            cap,
            index,
            persona: manifest.persona.clone(),
            origin: manifest.origin.clone(),
            main_frame: page.mainframe().await?,
            stats: Stats::default(),
            in_flight: 0,
            last: Instant::now(),
        }));
        let mut paused = page.event_listener::<EventRequestPaused>().await?;
        page.execute(
            fetch::EnableParams::builder()
                .pattern(
                    RequestPattern::builder()
                        .url_pattern("*")
                        .request_stage(RequestStage::Request)
                        .build(),
                )
                .build(),
        )
        .await?;
        let listener = {
            let page = page.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let mut handlers = tokio::task::JoinSet::new();
                while let Some(ev) = paused.next().await {
                    // Decide in event order so sequenced fixtures are served deterministically.
                    let action = {
                        let mut s = state.lock().unwrap();
                        s.in_flight += 1;
                        s.last = Instant::now();
                        decide(&ev, &mut s)
                    };
                    let page = page.clone();
                    let state = state.clone();
                    handlers.spawn(async move {
                        let id = ev.request_id.clone();
                        let sent = match action {
                            Ok(Some(reply)) => page
                                .execute(reply.into_params(id, &ev.request.method))
                                .await
                                .map(|_| ()),
                            Ok(None) => page
                                .execute(FailRequestParams::new(id, ErrorReason::BlockedByClient))
                                .await
                                .map(|_| ()),
                            Err(e) => {
                                tracing::debug!("answer {}: {e:#}", ev.request.url);
                                page.execute(FailRequestParams::new(id, ErrorReason::Failed))
                                    .await
                                    .map(|_| ())
                            }
                        };
                        if let Err(e) = sent {
                            tracing::debug!("fetch command for {}: {e}", ev.request.url);
                        }
                        let mut s = state.lock().unwrap();
                        s.in_flight -= 1;
                        s.last = Instant::now();
                    });
                    while handlers.try_join_next().is_some() {}
                }
            })
        };

        state.lock().unwrap().last = Instant::now();
        page.execute(NavigateParams::new(manifest.url.clone()))
            .await
            .context("navigate")?;
        // Escapes are reported through the shared stats.
        let st = state.clone();
        let proxy = tokio::spawn(async move {
            let _guard = proxy;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut e = escaped.lock().unwrap();
                if !e.is_empty() {
                    st.lock().unwrap().stats.escaped.append(&mut e);
                }
            }
        });
        Ok(Self {
            session,
            page,
            state,
            listener,
            proxy,
        })
    }

    /// Wait until nothing is in flight for a quiet period and the document has loaded, then
    /// for fonts. Errors (with what is still pending) if that never happens.
    pub async fn settle(&self) -> Result<()> {
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let (idle, in_flight) = {
                let s = self.state.lock().unwrap();
                (s.in_flight == 0 && s.last.elapsed() >= QUIET, s.in_flight)
            };
            if idle {
                let complete = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.page.evaluate("document.readyState"),
                )
                .await
                .ok()
                .and_then(|r| r.ok())
                .and_then(|r| r.into_value::<String>().ok())
                .is_some_and(|s| s == "complete");
                if complete {
                    break;
                }
            }
            if start.elapsed() >= MAX_SETTLE {
                bail!("replay did not settle in {MAX_SETTLE:?} ({in_flight} request(s) in flight)");
            }
        }
        tokio::time::timeout(
            Duration::from_secs(10),
            self.page
                .evaluate("document.fonts ? document.fonts.ready.then(() => true) : true"),
        )
        .await
        .context("fonts did not load")??;
        Ok(())
    }

    pub fn stats(&self) -> Stats {
        self.state.lock().unwrap().stats.clone()
    }

    pub async fn close(self) {
        self.listener.abort();
        self.proxy.abort();
        self.session.close().await;
    }
}

/// Choose the response for a paused request. `None` means fail it as a miss.
fn decide(ev: &EventRequestPaused, s: &mut State) -> Result<Option<Reply>> {
    let method = ev.request.method.as_str();
    let url = ev.request.url.as_str();
    let body = post_body(&ev.request);
    let req_headers = header_pairs(&ev.request.headers);
    let req_header = |name: &str| {
        req_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    match classify(url) {
        Class::Identity => {
            s.stats.identity_stubbed += 1;
            let st = auth::identity(method, url, body.as_deref(), &s.persona);
            return Ok(Some(Reply::new(st.status, st.headers, st.body)));
        }
        Class::Telemetry => {
            s.stats.telemetry_stubbed += 1;
            return Ok(Some(Reply::new(204, cors_any(), Vec::new())));
        }
        _ => {}
    }
    if let Some(e) = s.index.lookup(method, url, body.as_deref()) {
        let (status, headers, blob) = (e.status, e.headers.clone(), e.body.clone());
        let bytes = match blob {
            Some(h) => s.cap.blob(&h)?,
            None => Vec::new(),
        };
        s.stats.hits += 1;
        return Ok(Some(Reply::new(status, headers, bytes)));
    }
    if method == "OPTIONS" {
        s.stats.preflight_stubbed += 1;
        let mut h = vec![("vary".into(), "origin".into())];
        match req_header("origin") {
            Some(o) => {
                h.push(("access-control-allow-origin".into(), o));
                h.push(("access-control-allow-credentials".into(), "true".into()));
            }
            None => h.push(("access-control-allow-origin".into(), "*".into())),
        }
        if let Some(m) = req_header("access-control-request-method") {
            h.push(("access-control-allow-methods".into(), m));
        }
        if let Some(ask) = req_header("access-control-request-headers") {
            h.push(("access-control-allow-headers".into(), ask));
        }
        h.push(("access-control-max-age".into(), "600".into()));
        return Ok(Some(Reply::new(204, h, Vec::new())));
    }
    // Same-origin subframes nobody recorded are typically MSAL redirect targets: blank is what
    // the real app serves there. Anything else is a genuine miss.
    let subframe = s.main_frame.as_ref().is_some_and(|m| *m != ev.frame_id);
    let same_origin = Url::parse(url).is_ok_and(|u| u.origin().ascii_serialization() == s.origin);
    if ev.resource_type == ResourceType::Document && subframe && same_origin {
        s.stats.blank_frames += 1;
        return Ok(Some(Reply::new(
            200,
            vec![("content-type".into(), "text/html".into())],
            b"<!doctype html><html><body></body></html>".to_vec(),
        )));
    }
    s.stats.misses.push(format!("{method} {url}"));
    Ok(None)
}

fn cors_any() -> Vec<(String, String)> {
    vec![("access-control-allow-origin".into(), "*".into())]
}

struct Reply {
    status: i64,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn new(status: i64, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    fn into_params(self, id: fetch::RequestId, method: &str) -> FulfillRequestParams {
        let no_body = method == "HEAD" || matches!(self.status, 100..=199 | 204 | 205 | 304);
        let mut p = FulfillRequestParams::new(id, self.status);
        p.response_headers = Some(
            self.headers
                .into_iter()
                .map(|(k, v)| HeaderEntry::new(k, v))
                .collect(),
        );
        if !self.body.is_empty() && !no_body {
            p.body = Some(STANDARD.encode(self.body).into());
        }
        p
    }
}

/// A loopback proxy that refuses everything and records what tried to get out.
async fn reject_proxy(
    escaped: Arc<Mutex<Vec<String>>>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let escaped = escaped.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let line = head.lines().next().unwrap_or("(no request line)");
                escaped.lock().unwrap().push(line.to_string());
                // Dropping the socket refuses the request.
            });
        }
    });
    Ok((addr, task))
}

/// Script injected into every document before page scripts run.
fn bootstrap(m: &Manifest) -> Result<String> {
    let cfg = json!({
        "now": m.captured_at_ms,
        "origin": m.origin,
        "storage": m.storage,
    });
    Ok(BOOTSTRAP.replace("__MIMESIA_CFG__", &serde_json::to_string(&cfg)?))
}

const BOOTSTRAP: &str = r#"(() => {
  if (window.__mimesia) return;
  const cfg = __MIMESIA_CFG__;
  window.__mimesia = { replay: true, capturedAt: cfg.now };

  // Clock: start at capture time, then tick normally.
  const RealDate = Date;
  const offset = cfg.now - RealDate.now();
  const now = () => RealDate.now() + offset;
  function MimesiaDate(...args) {
    if (!new.target) return new RealDate(now()).toString();
    return Reflect.construct(RealDate, args.length ? args : [now()], new.target);
  }
  MimesiaDate.prototype = RealDate.prototype;
  MimesiaDate.now = now;
  MimesiaDate.parse = RealDate.parse;
  MimesiaDate.UTC = RealDate.UTC;
  Object.setPrototypeOf(MimesiaDate, RealDate);
  window.Date = MimesiaDate;

  // Fake session: seed storage once, on the recorded origin only.
  try {
    if (location.origin === cfg.origin && !sessionStorage.getItem('__mimesia_seeded')) {
      for (const { area, key, value } of cfg.storage) {
        try { window[area].setItem(key, value); } catch (_) {}
      }
      sessionStorage.setItem('__mimesia_seeded', '1');
    }
  } catch (_) {}

  // No service workers: they would bypass interception.
  try {
    if (navigator.serviceWorker) {
      navigator.serviceWorker.register = () =>
        Promise.reject(new DOMException('disabled by mimesia', 'SecurityError'));
    }
  } catch (_) {}

  // Push channels stay connecting forever: quiet, never erroring.
  class Parked extends EventTarget {
    constructor(url) {
      super();
      this.url = String(url);
      this.readyState = 0;
      this.onopen = this.onmessage = this.onerror = this.onclose = null;
    }
    send() {}
    close() { this.readyState = 2; }
  }
  class FakeWebSocket extends Parked {}
  Object.assign(FakeWebSocket, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 });
  Object.assign(FakeWebSocket.prototype, { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3, protocol: '', extensions: '', bufferedAmount: 0, binaryType: 'blob' });
  class FakeEventSource extends Parked {}
  Object.assign(FakeEventSource, { CONNECTING: 0, OPEN: 1, CLOSED: 2 });
  Object.assign(FakeEventSource.prototype, { CONNECTING: 0, OPEN: 1, CLOSED: 2, withCredentials: false });
  window.WebSocket = FakeWebSocket;
  window.EventSource = FakeEventSource;

  // Transports that bypass HTTP interception entirely.
  for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'WebTransport']) {
    if (name in window) {
      window[name] = function () { throw new DOMException(name + ' disabled by mimesia', 'NotSupportedError'); };
    }
  }
})();"#;

pub async fn run(capture: &Path, headed: bool) -> Result<()> {
    let replay = Replay::start(capture, headed).await?;
    replay.settle().await?;
    let s = replay.stats();
    println!(
        "replayed: {} hits, {} identity stubbed, {} telemetry stubbed, {} preflights, {} blank frames, {} misses",
        s.hits,
        s.identity_stubbed,
        s.telemetry_stubbed,
        s.preflight_stubbed,
        s.blank_frames,
        s.misses.len()
    );
    for m in &s.misses {
        println!("MISS {m}");
    }
    for e in &s.escaped {
        println!("ESCAPED {e}");
    }
    if headed {
        println!("replaying; press Ctrl-C to stop");
        tokio::signal::ctrl_c().await?;
    }
    replay.close().await;
    if !s.escaped.is_empty() {
        bail!("{} request(s) bypassed interception", s.escaped.len());
    }
    if !s.misses.is_empty() {
        bail!(
            "{} request(s) had no fixture; re-record or add them to the scenario",
            s.misses.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(method: &str, url: &str, body: &str) -> Entry {
        Entry {
            key: matchkey::exact(method, url, None),
            loose_key: matchkey::loose(method, url),
            method: method.into(),
            url: url.into(),
            resource_type: "Fetch".into(),
            status: 200,
            headers: Vec::new(),
            body: Some(body.into()),
        }
    }

    #[test]
    fn exact_then_loose_then_sequence() {
        let mut ix = Index::new(vec![
            entry("GET", "https://a/x?q=1", "one"),
            entry("GET", "https://a/x?q=1", "two"),
            entry("GET", "https://a/y?q=1", "why"),
        ]);
        let mut next = |u: &str| ix.lookup("GET", u, None).and_then(|e| e.body.clone());
        assert_eq!(next("https://a/x?q=1").as_deref(), Some("one"));
        assert_eq!(next("https://a/x?q=1").as_deref(), Some("two"));
        assert_eq!(next("https://a/x?q=1").as_deref(), Some("two"));
        assert_eq!(next("https://a/y?q=2").as_deref(), Some("why"));
        assert_eq!(next("https://a/z").as_deref(), None);
        let mut ix = Index::new(vec![entry("POST", "https://a/x", "p")]);
        assert!(
            ix.lookup("POST", "https://a/x?id=2", None).is_none(),
            "no loose POST"
        );
    }
}
