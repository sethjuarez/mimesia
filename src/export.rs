//! Static export: a capture as a plain folder any static host can serve.
//!
//! Shell files land at their recorded paths, so `<script>`, `<link>`, and `<img>` load them
//! as usual. Data calls (fetch/XHR) are answered in-page by a small shim from
//! `_mimesia/b/<hash>` files, with replay's match rules. No service worker, no server code:
//! the data files are the demo data.

use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use percent_encoding::percent_decode_str;
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::record::ensure_git_ignored;
use crate::replay::bootstrap;
use crate::scan::require_clean;
use crate::store::Capture;

/// Export-owned folder inside the site.
pub const MARK: &str = "_mimesia";
/// Resource types issued by page code (fetch/XHR) rather than by tags.
const DATA_TYPES: &[&str] = &["Xhr", "Fetch", "Other", "Ping", "EventSource"];
/// Headers that describe the original transfer or session, not the body we serve.
const DROP_HEADERS: &[&str] = &[
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "set-cookie",
    "content-security-policy",
    "strict-transport-security",
];
const MAX_REQ_BODY: usize = 256 * 1024;

#[derive(Debug, Default, Serialize)]
pub struct Exported {
    /// Shell files written at their recorded paths.
    pub files: usize,
    /// Fetch/XHR responses the shim answers.
    pub data: usize,
    /// Path and query of the start page within the site.
    pub start: String,
    /// Recorded hostname; serve the site at `<host>.localhost` or a domain that contains it.
    pub host: String,
    /// Site file served for routes that have no file of their own.
    pub fallback: String,
    /// Shell files that could not be placed (unsafe names, path clashes). Counts only.
    pub skipped: usize,
}

pub fn export(capture: &Path, out: &Path) -> Result<Exported> {
    let cap = Capture::new(capture);
    require_clean(&cap)?;
    ensure_git_ignored(out)?;
    prepare(out)?;
    let m = cap.manifest()?;
    let mut ex = Exported::default();
    let mut index = Vec::new();
    let mut blobs = BTreeSet::new();
    // URL paths of written shell files: the only local GETs the shim lets through.
    let mut shell = BTreeSet::new();

    for e in cap.entries()? {
        let Ok(u) = Url::parse(&e.url) else { continue };
        let same = u.origin().ascii_serialization() == m.origin;
        let get = e.method == "GET";
        if e.resource_type == "Document" {
            if same && get && e.status == 200 && ex.start.is_empty() {
                let Some(rel) = local_path(u.path(), true) else {
                    bail!("start page path cannot be written as a file");
                };
                let html = cap.blob(e.body.as_deref().context("start page has no body")?)?;
                write(out, &rel, &inject(&html))?;
                ex.fallback = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
                ex.start = match u.query() {
                    Some(q) => format!("{}?{q}", u.path()),
                    None => u.path().to_string(),
                };
                ex.host = u.host_str().unwrap_or_default().to_string();
            }
            continue;
        }
        let static_file = same
            && get
            && u.query().is_none()
            && (200..300).contains(&e.status)
            && !DATA_TYPES.contains(&e.resource_type.as_str());
        if static_file {
            if let Some(h) = &e.body {
                match local_path(u.path(), false) {
                    // `_mimesia/` belongs to the export.
                    Some(rel) if rel.starts_with(MARK) => ex.skipped += 1,
                    Some(rel) if !out.join(&rel).exists() => {
                        match write(out, &rel, &cap.blob(h)?) {
                            Ok(()) => {
                                ex.files += 1;
                                shell.insert(u.path().to_string());
                            }
                            Err(err) => {
                                tracing::debug!("skip shell file: {err:#}");
                                ex.skipped += 1;
                            }
                        }
                    }
                    Some(_) => {}
                    None => ex.skipped += 1,
                }
            }
            continue;
        }
        let req = match &e.req_body {
            Some(h) => {
                let b = cap.blob(h)?;
                (b.len() <= MAX_REQ_BODY)
                    .then(|| String::from_utf8(b).ok())
                    .flatten()
            }
            None => None,
        };
        let headers: Vec<_> = e
            .headers
            .iter()
            .filter(|(k, _)| !DROP_HEADERS.contains(&k.to_ascii_lowercase().as_str()))
            .collect();
        if let Some(h) = &e.body {
            blobs.insert(h.clone());
        }
        index.push(json!({
            "m": e.method, "u": e.url, "s": e.status, "h": headers, "b": e.body, "q": req,
        }));
    }
    if ex.start.is_empty() {
        bail!("capture has no same-origin start page to export");
    }

    let dir = out.join(MARK).join("b");
    fs::create_dir_all(&dir)?;
    for h in &blobs {
        fs::write(dir.join(h), cap.blob(h)?)?;
    }
    ex.data = index.len();
    let data = json!({ "origin": m.origin, "entries": index });
    let shim = fill(
        SHIM,
        &[
            (
                "__MIMESIA_TELEMETRY__",
                serde_json::to_string(crate::rules::TELEMETRY_SUFFIXES)?,
            ),
            ("__MIMESIA_START__", serde_json::to_string(&ex.start)?),
            ("__MIMESIA_SHELL__", serde_json::to_string(&shell)?),
            ("__MIMESIA_INDEX__", serde_json::to_string(&data)?),
        ],
    );
    let boot = format!("{}\n{shim}", bootstrap(&m, false, true)?);
    fs::write(out.join(MARK).join("boot.js"), boot)?;
    // Deep links and refreshes on other routes get the app document; the router takes over.
    let swa = json!({
        "navigationFallback": { "rewrite": ex.fallback, "exclude": [format!("/{MARK}/*")] },
    });
    fs::write(
        out.join("staticwebapp.config.json"),
        serde_json::to_vec_pretty(&swa)?,
    )?;
    fs::write(
        out.join(MARK).join("export.json"),
        serde_json::to_vec_pretty(&ex)?,
    )?;
    Ok(ex)
}

/// Replace each placeholder in `template` in one pass; inserted values are never rescanned.
fn fill(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some((at, k, v)) = vars
        .iter()
        .filter_map(|(k, v)| rest.find(k).map(|at| (at, *k, v)))
        .min_by_key(|(at, _, _)| *at)
    {
        out.push_str(&rest[..at]);
        out.push_str(v);
        rest = &rest[at + k.len()..];
    }
    out.push_str(rest);
    out
}

/// Clear a previous export; refuse to clobber anything else.
fn prepare(out: &Path) -> Result<()> {
    if out.exists() {
        let empty = fs::read_dir(out)?.next().is_none();
        let ours = export_json(out).is_ok_and(|v| v["start"].is_string() && v["host"].is_string());
        if ours {
            fs::remove_dir_all(out).context("clear previous export")?;
        } else if !empty {
            bail!(
                "{} exists and is not a mimesia export; pick an empty directory",
                out.display()
            );
        }
    }
    fs::create_dir_all(out)?;
    Ok(())
}

fn write(out: &Path, rel: &Path, bytes: &[u8]) -> Result<()> {
    let p = out.join(rel);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&p, bytes).with_context(|| format!("write {}", rel.display()))
}

/// A URL path as a safe relative file path; directories and `dir_index` pages get
/// `index.html`. `None` for anything that could escape the site or is unwritable on Windows.
pub fn local_path(url_path: &str, dir_index: bool) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for seg in url_path.split('/').filter(|s| !s.is_empty()) {
        let seg = percent_decode_str(seg).decode_utf8().ok()?;
        let bad = seg == "."
            || seg == ".."
            || seg.ends_with('.')
            || seg.ends_with(' ')
            || seg
                .chars()
                .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
            || is_reserved(&seg);
        if bad {
            return None;
        }
        rel.push(seg.as_ref());
    }
    if dir_index || url_path.ends_with('/') || rel.as_os_str().is_empty() {
        rel.push("index.html");
    }
    Some(rel)
}

fn is_reserved(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Load the boot script first in `<head>`, before any app script.
fn inject(html: &[u8]) -> Vec<u8> {
    const TAG: &[u8] = b"<script src=\"/_mimesia/boot.js\"></script>";
    let lower = html.to_ascii_lowercase();
    let at = lower
        .windows(5)
        .position(|w| w == b"<head")
        .and_then(|i| {
            lower[i..]
                .iter()
                .position(|&c| c == b'>')
                .map(|j| i + j + 1)
        })
        .unwrap_or(0);
    [&html[..at], TAG, &html[at..]].concat()
}

/// Serve `dir` like a plain static host: GET/HEAD only, `index.html` for directories,
/// type by extension, and the export's fallback document for extensionless misses (as
/// `staticwebapp.config.json` does on Azure). Returns the bound address.
pub async fn serve(dir: &Path, port: u16) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = listener.local_addr()?;
    let dir = dir.to_path_buf();
    let task = tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let dir = dir.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(sock, &dir).await {
                    tracing::debug!("serve: {e:#}");
                }
            });
        }
    });
    Ok((addr, task))
}

async fn handle(mut sock: TcpStream, dir: &Path) -> Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = sock.read(&mut chunk).await?;
        if n == 0 || buf.len() > 64 * 1024 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let mut parts = head.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let path = target.split(['?', '#']).next().unwrap_or("/");
    // Links inside the site must not lead out of it.
    let root = dir.canonicalize()?;
    let inside = |p: PathBuf| {
        p.canonicalize()
            .ok()
            .filter(|c| c.starts_with(&root) && c.is_file())
    };
    let file = local_path(path, false).and_then(|rel| {
        let p = dir.join(&rel);
        inside(if p.is_dir() { p.join("index.html") } else { p })
    });
    let route = !path.rsplit('/').next().unwrap_or("").contains('.');
    let file = match file {
        Some(p) => Some(p),
        None if route => fallback(dir).and_then(inside),
        None => None,
    };
    let (status, ctype, body) = match (method, file) {
        ("GET" | "HEAD", Some(p)) => ("200 OK", content_type(&p), fs::read(&p)?),
        ("GET" | "HEAD", _) => ("404 Not Found", "text/plain", b"not found".to_vec()),
        _ => (
            "405 Method Not Allowed",
            "text/plain",
            b"static site".to_vec(),
        ),
    };
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(head.as_bytes()).await?;
    if method != "HEAD" {
        sock.write_all(&body).await?;
    }
    sock.shutdown().await.ok();
    Ok(())
}

fn content_type(p: &Path) -> &'static str {
    match p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs" | "cjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub fn run(capture: &Path, out: &Path) -> Result<()> {
    let ex = export(capture, out)?;
    println!(
        "exported {} shell files and {} data responses to {} ({} skipped)",
        ex.files,
        ex.data,
        out.display(),
        ex.skipped
    );
    println!(
        "serve it from the site root, e.g. `mimesia serve {}`, then open http://{}.localhost:8080{}",
        out.display(),
        ex.host,
        ex.start
    );
    Ok(())
}

pub async fn run_serve(dir: &Path, port: u16) -> Result<()> {
    let (start, host) = site_info(dir)?;
    let (addr, task) = serve(dir, port).await?;
    println!(
        "serving {} at http://{host}.localhost:{}{start}; Ctrl-C to stop",
        dir.display(),
        addr.port()
    );
    tokio::signal::ctrl_c().await?;
    task.abort();
    Ok(())
}

/// Start path and recorded host of an export. Sites are opened at `<host>.localhost`:
/// browsers resolve that to loopback, and apps that check their own hostname still see it.
fn site_info(dir: &Path) -> Result<(String, String)> {
    let v = export_json(dir)?;
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    Ok((s("start"), s("host")))
}

fn export_json(dir: &Path) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(
        &fs::read(dir.join(MARK).join("export.json")).context("not a mimesia export")?,
    )?)
}

fn fallback(dir: &Path) -> Option<PathBuf> {
    let v = export_json(dir).ok()?;
    let rel = local_path(v["fallback"].as_str()?, false)?;
    Some(dir.join(rel)).filter(|p| p.is_file())
}

#[derive(Debug, Default, Serialize, serde::Deserialize)]
pub struct ShimStats {
    pub hits: u64,
    #[serde(default)]
    pub telemetry: u64,
    pub near: Vec<String>,
    pub misses: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SiteReport {
    pub diff_ratio: f64,
    pub threshold: f64,
    pub pass: bool,
    pub stats: ShimStats,
    /// Requests that tried to leave loopback (reject proxy).
    pub escaped: Vec<String>,
}

/// Serve an exported site, load it headless with the network cut off, screenshot, and
/// pixel-diff against the capture's recording. Writes `<capture>/verify-export/`.
pub async fn verify_site(capture: &Path, site: &Path, threshold: f64) -> Result<SiteReport> {
    use crate::cdp::{Launch, Session};
    use crate::record::still_screenshot;
    use crate::replay::reject_proxy;
    use crate::verify::compare;
    use image::ImageFormat;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let cap = Capture::new(capture);
    let m = cap.manifest()?;
    let out = cap.path("verify-export");
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    let recorded = image::load_from_memory_with_format(
        &fs::read(cap.path("record.png")).context("read record.png")?,
        ImageFormat::Png,
    )?
    .to_rgba8();
    let (start, host) = site_info(site)?;

    let (addr, server) = serve(site, 0).await?;
    let escaped = Arc::new(Mutex::new(Vec::new()));
    let (proxy_addr, proxy) = reject_proxy(escaped.clone()).await?;
    let session = Session::launch(Launch {
        headed: false,
        width: m.viewport.width,
        height: m.viewport.height,
        dpr: m.viewport.dpr,
        intercept: false,
        args: vec![
            format!("--proxy-server=http://{proxy_addr}"),
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        ],
    })
    .await?;
    let result = async {
        let page = session.browser.new_page("about:blank").await?;
        if !m.user_agent.is_empty() {
            page.set_user_agent(&m.user_agent).await?;
        }
        page.goto(format!("http://{host}.localhost:{}{start}", addr.port())).await?;
        // Settle: document complete and the shim's hit count unchanged for a quiet period.
        let begin = Instant::now();
        let (mut last, mut since) = (u64::MAX, Instant::now());
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let v: serde_json::Value = page
                .evaluate("({ ready: document.readyState, hits: (window.__mimesia && window.__mimesia.export || {}).hits || 0 })")
                .await?
                .into_value()?;
            let hits = v["hits"].as_u64().unwrap_or(0);
            if hits != last {
                (last, since) = (hits, Instant::now());
            }
            if v["ready"] == "complete" && since.elapsed() >= Duration::from_secs(3) {
                break;
            }
            if begin.elapsed() >= Duration::from_secs(90) {
                bail!("exported site did not settle");
            }
        }
        page.evaluate("document.fonts ? document.fonts.ready.then(() => true) : true")
            .await?;
        let shot = still_screenshot(&page).await?;
        let stats: ShimStats = page
            .evaluate("window.__mimesia && window.__mimesia.export || {hits:0,near:[],misses:[]}")
            .await?
            .into_value()?;
        Ok::<_, anyhow::Error>((shot, stats))
    }
    .await;
    session.close().await;
    server.abort();
    proxy.abort();
    let (shot, stats) = result?;
    let replayed = image::load_from_memory_with_format(&shot, ImageFormat::Png)?.to_rgba8();
    let (diff_ratio, diff) = compare(&recorded, &replayed);
    fs::create_dir_all(&out)?;
    fs::write(out.join("site.png"), &shot)?;
    diff.save_with_format(out.join("diff.png"), ImageFormat::Png)?;
    let escaped = escaped.lock().unwrap().clone();
    let report = SiteReport {
        diff_ratio,
        threshold,
        pass: diff_ratio <= threshold && stats.misses.is_empty() && escaped.is_empty(),
        stats,
        escaped,
    };
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    Ok(report)
}

pub async fn run_verify(capture: &Path, site: &Path, threshold: f64) -> Result<()> {
    let r = verify_site(capture, site, threshold).await?;
    println!(
        "{}: {:.3}% pixels differ (threshold {:.3}%), {} hits ({} near), {} telemetry dropped, {} misses, {} escaped",
        if r.pass { "PASS" } else { "FAIL" },
        r.diff_ratio * 100.0,
        r.threshold * 100.0,
        r.stats.hits,
        r.stats.near.len(),
        r.stats.telemetry,
        r.stats.misses.len(),
        r.escaped.len()
    );
    for n in &r.stats.near {
        println!("NEAR {n}");
    }
    for m in &r.stats.misses {
        println!("MISS {m}");
    }
    for e in &r.escaped {
        println!("ESCAPED {e}");
    }
    println!("wrote {}", capture.join("verify-export").display());
    if !r.pass {
        bail!("export verify failed");
    }
    Ok(())
}

/// In-page data layer: answers fetch/XHR from the exported index with replay's rules
/// (exact, then loose GET, then nearest JSON body for other methods). Unmatched same-origin
/// calls go to the static host; unmatched cross-origin calls get an empty 204 so nothing
/// reaches a real backend.
const SHIM: &str = r#"(() => {
  if (window.__mimesia_shim) return;
  window.__mimesia_shim = true;
  // Deep links get the recorded document, whose embedded state belongs to the start route.
  // Hydrate there, then hand the wanted route to the app's router like a back/forward step.
  const START = __MIMESIA_START__;
  const route = u => (u.pathname.replace(/\/+$/, '') || '/') + u.search;
  if (route(location) !== route(new URL(START, location.origin))) {
    const want = location.pathname + location.search + location.hash;
    history.replaceState(history.state, '', START);
    const go = () => {
      history.replaceState(null, '', want);
      dispatchEvent(new PopStateEvent('popstate', { state: null }));
    };
    let n = 0;
    const t = setInterval(() => {
      const r = window.__reactRouterDataRouter || window.__remixRouter;
      const ready = r ? r.state && r.state.initialized && r.state.navigation.state === 'idle' : n >= 20;
      if ((ready && document.readyState === 'complete') || ++n > 150) { clearInterval(t); go(); }
    }, 100);
  }
  const SHELL = new Set(__MIMESIA_SHELL__);
  const X = __MIMESIA_INDEX__;
  const stats = (window.__mimesia = window.__mimesia || {}).export = { hits: 0, telemetry: 0, near: [], misses: [] };
  const TEL = __MIMESIA_TELEMETRY__;
  // Mirrors rules::classify Telemetry: answered with 204, never counted as a miss.
  const telemetry = raw => {
    try {
      const u = new URL(raw, location.href);
      const h = u.hostname.toLowerCase(), p = u.pathname.toLowerCase();
      return TEL.some(s => h === s || h.endsWith('.' + s))
        || p.endsWith('/v2/track') || p.endsWith('/v2.1/track')
        || p.split('/').some(s => /^(client|[a-z0-9]+-)?telemetry$/.test(s));
    } catch (_) { return false; }
  };
  const realFetch = window.fetch.bind(window);
  const VOL = new Set(['_', '_t', 'ts', 'timestamp', 'nonce', 'cb', 'cachebust', 'rnd', 'random']);
  const VOL_NUM = new Set(['t', 'v']);
  const PER = new Set(['sessionid', 'requestid', 'clientrequestid', 'correlationid', 'traceid', 'spanid']);
  const ISO = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?/g;
  const NULL_BODY = new Set([101, 103, 204, 205, 304]);
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  const canon = raw => {
    const u = new URL(raw, location.href);
    const local = u.host === location.host;
    const pairs = [...u.searchParams]
      .filter(([k, v]) => { const l = k.toLowerCase(); return !(VOL.has(l) || (VOL_NUM.has(l) && /^[0-9]+$/.test(v))); })
      .sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]));
    return { base: (local ? X.origin : u.origin) + u.pathname, query: new URLSearchParams(pairs).toString(), local };
  };
  const stable = v => {
    if (typeof v === 'string') return v.replace(ISO, '<time>');
    if (typeof v === 'number') return Number.isInteger(v) && v >= 1e12 && v < 1e13 ? '<ms>' : v;
    if (Array.isArray(v)) return v.map(stable);
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) {
        const l = k.toLowerCase();
        if (!VOL.has(l)) o[k] = PER.has(l) ? '<id>' : stable(x);
      }
      return o;
    }
    return v;
  };
  // Same leaves as matchkey::leaves: scalar arrays are sets.
  const leaves = text => {
    if (text == null) return null;
    let v;
    try { v = JSON.parse(text); } catch (_) { return null; }
    const out = new Map();
    const flat = (p, v) => {
      if (Array.isArray(v)) {
        if (v.length && v.every(x => x === null || typeof x !== 'object')) v.forEach(x => out.set(p + '[]\0' + JSON.stringify(x), ''));
        else v.forEach((x, i) => flat(p + '[' + i + ']', x));
      } else if (v && typeof v === 'object') {
        for (const [k, x] of Object.entries(v)) flat(p + '.' + k, x);
      } else out.set(p, JSON.stringify(v));
    };
    flat('$', stable(v));
    return out;
  };

  // Mirrors matchkey::stable_body for the exact key: stable JSON with sorted keys, else raw text.
  const sorted = v => Array.isArray(v) ? v.map(sorted)
    : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sorted(v[k])])) : v;
  const bodyKey = text => {
    if (text == null || text === '') return '';
    try { return ' #' + JSON.stringify(sorted(stable(JSON.parse(text)))); } catch (_) { return ' #' + text; }
  };
  const exact = new Map(), loose = new Map(), rpc = new Map(), cursor = new Map();
  const add = (m, k, i) => (m.get(k) || m.set(k, []).get(k)).push(i);
  X.entries.forEach((e, i) => {
    const c = canon(e.u);
    if (e.m === 'GET' || e.m === 'HEAD') {
      add(exact, e.m + ' ' + c.base + '?' + c.query, i);
      add(loose, e.m + ' ' + c.base, i);
    } else {
      const k = e.m + ' ' + c.base + '?' + c.query;
      add(rpc, k, i);
      add(exact, k + bodyKey(e.q), i);
      e.l = leaves(e.q);
    }
  });
  const next = (key, list) => {
    const n = cursor.get(key) || 0;
    cursor.set(key, n + 1);
    return X.entries[list[Math.min(n, list.length - 1)]];
  };
  const redact = raw => {
    try {
      const u = new URL(raw, location.href);
      const keys = [...u.searchParams.keys()];
      return u.origin + u.pathname + (keys.length ? '?' + keys.join('&') : '');
    } catch (_) { return '<url>'; }
  };
  const lookup = (method, url, body) => {
    const c = canon(url);
    const k = method + ' ' + c.base + '?' + c.query;
    if (method === 'GET' || method === 'HEAD') {
      if (exact.has(k)) return next(k, exact.get(k));
      const lk = method + ' ' + c.base;
      return loose.has(lk) ? next('~' + lk, loose.get(lk)) : null;
    }
    const ek = k + bodyKey(body);
    if (exact.has(ek)) return next(ek, exact.get(ek));
    // Same call, different body: the recorded body sharing the most fields (replay's near).
    const list = rpc.get(k);
    if (!list) return null;
    const want = leaves(body);
    const score = i => {
      const l = X.entries[i].l;
      let eq = 0;
      if (want && l) for (const [p, v] of want) if (l.get(p) === v) eq++;
      return eq;
    };
    const scores = list.map(score);
    const best = Math.max(...scores);
    stats.near.push(method + ' ' + redact(url));
    return next('@' + k + '#' + best, list.filter((_, j) => scores[j] === best));
  };
  const miss = (method, url) => {
    if (telemetry(url)) { stats.telemetry++; return; }
    const s = method + ' ' + redact(url);
    stats.misses.push(s);
    console.warn('[mimesia] miss', s);
  };
  const bodyOf = e => e.b
    ? realFetch('/_mimesia/b/' + e.b).then(r => { if (!r.ok) throw new Error('mimesia data ' + r.status); return r.arrayBuffer(); })
    : Promise.resolve(new ArrayBuffer(0));
  const EMPTY = { s: 204, h: [], b: null };
  const shellGet = (method, url) => {
    if (method !== 'GET' || !canon(url).local) return false;
    const p = new URL(url, location.href).pathname;
    if (SHELL.has(p)) return true;
    try { return SHELL.has(decodeURI(p)); } catch (_) { return false; }
  };

  window.fetch = async function (input, init) {
    const req = new Request(input, init);
    const method = req.method.toUpperCase();
    const body = method === 'GET' || method === 'HEAD' ? null : await req.clone().text().catch(() => null);
    let e = lookup(method, req.url, body);
    if (!e) {
      // Only GETs of files the export wrote go to the static host.
      if (shellGet(method, req.url)) {
        const u = new URL(req.url);
        const r = u.protocol === location.protocol ? req : new Request(location.origin + u.pathname + u.search, req);
        return realFetch(r);
      }
      miss(method, req.url);
      e = EMPTY;
    } else stats.hits++;
    const buf = await bodyOf(e);
    const status = e.s >= 200 && e.s <= 599 ? e.s : 200;
    const res = new Response(NULL_BODY.has(status) || method === 'HEAD' ? null : buf, { status, headers: e.h });
    Object.defineProperty(res, 'url', { value: req.url });
    return res;
  };

  const XP = XMLHttpRequest.prototype;
  const xOpen = XP.open, xSend = XP.send, xAbort = XP.abort;
  XP.open = function (method, url, ...rest) {
    this.__mimesia = { method: String(method).toUpperCase(), url: new URL(String(url), location.href).href };
    return xOpen.call(this, method, url, ...rest);
  };
  XP.abort = function () {
    if (this.__mimesia) this.__mimesia.aborted = true;
    return xAbort.call(this);
  };
  XP.send = function (body) {
    const r = this.__mimesia;
    if (!r) return xSend.call(this, body);
    let e = lookup(r.method, r.url, typeof body === 'string' ? body : null);
    if (!e) {
      if (shellGet(r.method, r.url)) return xSend.call(this, body);
      miss(r.method, r.url);
      e = EMPTY;
    } else stats.hits++;
    const x = this;
    const def = (k, v) => Object.defineProperty(x, k, { configurable: true, get: () => v });
    const fire = (type, n) => x.dispatchEvent(type === 'readystatechange' ? new Event(type) : new ProgressEvent(type, { loaded: n, total: n, lengthComputable: true }));
    bodyOf(e).then(buf => {
      if (r.aborted) return;
      const text = new TextDecoder().decode(buf);
      const ct = (e.h.find(([k]) => k.toLowerCase() === 'content-type') || ['', ''])[1];
      const rt = x.responseType;
      let response = text;
      if (rt === 'json') { try { response = JSON.parse(text); } catch (_) { response = null; } }
      else if (rt === 'arraybuffer') response = buf;
      else if (rt === 'blob') response = new Blob([buf], { type: ct });
      else if (rt === 'document') response = new DOMParser().parseFromString(text, ct.includes('xml') ? 'application/xml' : 'text/html');
      const lines = e.h.map(([k, v]) => k.toLowerCase() + ': ' + v).join('\r\n');
      def('readyState', 4); def('status', e.s); def('statusText', e.s === 200 ? 'OK' : '');
      def('responseURL', r.url); def('response', response);
      if (rt === '' || rt === 'text') def('responseText', text);
      x.getAllResponseHeaders = () => (lines ? lines + '\r\n' : '');
      x.getResponseHeader = n => {
        const v = e.h.filter(([k]) => k.toLowerCase() === String(n).toLowerCase()).map(([, v]) => v);
        return v.length ? v.join(', ') : null;
      };
      fire('readystatechange'); fire('load', buf.byteLength); fire('loadend', buf.byteLength);
    }, () => {
      if (r.aborted) return;
      def('readyState', 4); def('status', 0);
      fire('readystatechange'); fire('error', 0); fire('loadend', 0);
    });
  };

  // Beacons bypass fetch; drop them (telemetry) instead of letting them leave.
  if (navigator.sendBeacon) navigator.sendBeacon = () => true;
})();"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_paths_are_safe() {
        let p = |s: &str| local_path(s, false).map(|p| p.to_string_lossy().replace('\\', "/"));
        assert_eq!(p("/a/b.js").as_deref(), Some("a/b.js"));
        assert_eq!(p("/a/").as_deref(), Some("a/index.html"));
        assert_eq!(p("/").as_deref(), Some("index.html"));
        assert_eq!(p("/a%20b/c,d.css").as_deref(), Some("a b/c,d.css"));
        assert_eq!(
            local_path("/r/x", true).map(|p| p.to_string_lossy().replace('\\', "/")),
            Some("r/x/index.html".into())
        );
        for bad in [
            "/../x",
            "/a/%2e%2e/x",
            "/a%2fb",
            "/a%5cb",
            "/c:x",
            "/con.js",
            "/x.",
        ] {
            assert_eq!(p(bad), None, "{bad}");
        }
    }

    #[test]
    fn fill_never_rescans_values() {
        let out = fill("a=A;b=B;a=A", &[("A", "B".into()), ("B", "\"A\"".into())]);
        assert_eq!(out, "a=B;b=\"A\";a=B");
    }

    #[test]
    fn prepare_only_clears_real_exports() {
        let t = tempfile::tempdir().unwrap();
        let out = t.path().join("site");
        fs::create_dir_all(out.join(MARK)).unwrap();
        fs::write(out.join("keep.txt"), "x").unwrap();
        assert!(prepare(&out).is_err());
        assert!(out.join("keep.txt").exists());
        fs::write(
            out.join(MARK).join("export.json"),
            r#"{"start":"/","host":"h"}"#,
        )
        .unwrap();
        prepare(&out).unwrap();
        assert!(!out.join("keep.txt").exists());
    }

    #[test]
    fn boot_script_goes_first_in_head() {
        let out = inject(b"<!doctype html><HTML><Head lang=x><script>app()</script>");
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("<Head lang=x><script src=\"/_mimesia/boot.js\"></script><script>app()")
        );
        let out = inject(b"<p>no head</p>");
        assert!(out.starts_with(b"<script src=\"/_mimesia/boot.js\">"));
    }
}
