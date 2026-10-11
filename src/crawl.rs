//! Shell crawl: fetch the lazy chunks a page did not load during recording.
//!
//! SPAs split code into chunks fetched on navigation or hover-prefetch. A replay missing
//! them fails the import and the app often hard-reloads. Static assets are public, so after
//! recording we follow every same-origin asset reference in recorded JS/CSS (and the
//! React Router / Remix manifest) and fetch it **without credentials**.

use std::collections::{HashSet, VecDeque};
use std::sync::LazyLock;

use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use chromiumoxide::Page;
use regex::Regex;
use serde::Deserialize;
use url::Url;

/// Safety limits for one crawl.
const MAX_FILES: usize = 4000;
const MAX_BYTES: usize = 300 * 1024 * 1024;
const BATCH: usize = 24;
const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);

/// Quoted or `url(...)` references to static assets. Bare names must look hashed
/// (`name-AbC123xy.js`) to avoid probing every `"foo.js"` string literal.
static REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"["'`(]((?:/|\./|\.\./)(?:[\w.~@-]+/)*[\w.~@-]+\.(?:m?js|css|svg|png|webp|gif|ico|woff2?|ttf)|(?:[\w.~@-]+/)+[\w.~@-]+\.(?:m?js|css)|[\w.~@-]+-[\w-]{8}\.(?:m?js|css))((?:\?[^"'`)\s]*)?)["'`)]"#,
    )
    .unwrap()
});

/// Is this recorded resource worth scanning for references?
pub fn scannable(url: &str, content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    let path = Url::parse(url)
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    ct.contains("javascript")
        || ct.contains("text/css")
        || path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".css")
}

/// Same-origin asset URLs referenced from `body`, which was served from `from`.
pub fn refs(from: &str, origin: &str, body: &str) -> Vec<String> {
    let (Ok(from), Ok(root)) = (Url::parse(from), Url::parse(origin)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut add = |u: Result<Url, url::ParseError>| {
        if let Ok(mut u) = u
            && u.origin() == root.origin()
        {
            u.set_fragment(None);
            let s = u.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    };
    for c in REF.captures_iter(body) {
        let r = format!("{}{}", &c[1], &c[2]);
        if !(r.starts_with('/') || r.starts_with("./") || r.starts_with("../"))
            && c[1].contains('/')
        {
            // Vite `__vite__mapDeps` paths are relative to the app base (origin root), but
            // other bundlers resolve against the importer; try both, 404s are skipped.
            add(root.join(&r));
        }
        add(from.join(&r));
    }
    out
}

#[derive(Deserialize)]
pub struct Fetched {
    pub url: String,
    pub status: i64,
    pub headers: Vec<(String, String)>,
    /// Base64 body.
    pub body: String,
}

/// Scrubbing is chosen by content type, so text assets served as binary (or untyped)
/// must be relabelled from their extension, or credentials in them would go unscrubbed.
fn force_text_type(f: &mut Fetched) {
    let path = Url::parse(&f.url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    let want = if path.ends_with(".js") || path.ends_with(".mjs") {
        "text/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else {
        return;
    };
    let has_text = f
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && crate::scrub::is_text(v));
    if !has_text {
        f.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        f.headers.push(("content-type".into(), want.into()));
    }
}

// The app may wrap `window.fetch` (telemetry, auth queues) and those wrappers can stall or log our
// requests, so fetch through a pristine `fetch` from a hidden same-origin iframe.
const FETCH_JS: &str = r#"async (urls) => {
  let f = window.__mimesiaFetch;
  if (!f) {
    const fr = document.createElement('iframe');
    fr.style.display = 'none';
    document.documentElement.appendChild(fr);
    f = window.__mimesiaFetch = fr.contentWindow.fetch.bind(fr.contentWindow);
  }
  return Promise.all(urls.map(async (url) => {
  try {
    const r = await f(url, { credentials: 'omit', cache: 'no-store', redirect: 'manual', signal: AbortSignal.timeout(15000) });
    const buf = new Uint8Array(await r.arrayBuffer());
    let bin = '';
    for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    return { url, status: r.status, headers: [...r.headers.entries()], body: btoa(bin) };
  } catch (e) {
    return { url, status: 0, headers: [], body: '' };
  }
}));
}"#;

/// Keep a tab running when its window is hidden or occluded. Edge freezes such tabs
/// (timers and fetches never settle), which stalls crawls and recordings. Best effort;
/// the override lasts while our CDP session stays attached.
pub async fn keep_awake(page: &Page) {
    use chromiumoxide::cdp::browser_protocol::emulation::SetFocusEmulationEnabledParams;
    use chromiumoxide::cdp::browser_protocol::page::{
        SetWebLifecycleStateParams, SetWebLifecycleStateState,
    };
    if let Err(e) = page
        .execute(SetWebLifecycleStateParams::new(
            SetWebLifecycleStateState::Active,
        ))
        .await
    {
        tracing::debug!(error = %e, "setWebLifecycleState failed");
    }
    let _ = page
        .execute(SetFocusEmulationEnabledParams::new(true))
        .await;
}

const MANIFEST_JS: &str =
    "JSON.stringify(window.__reactRouterManifest || window.__remixManifest || null)";

/// Crawl from `seeds` (url, content-type, body). `known` URLs are already recorded.
/// Returns successfully fetched assets (status 200 only).
pub async fn crawl(
    page: &Page,
    origin: &str,
    seeds: Vec<(String, String, Vec<u8>)>,
    known: &HashSet<String>,
) -> Result<Vec<(Fetched, Vec<u8>)>> {
    let mut seen: HashSet<String> = known.clone();
    let mut queue: VecDeque<String> = VecDeque::new();
    let push = |urls: Vec<String>, seen: &mut HashSet<String>, q: &mut VecDeque<String>| {
        for u in urls {
            if seen.insert(u.clone()) {
                q.push_back(u);
            }
        }
    };

    keep_awake(page).await;
    if let Ok(m) = page.evaluate(MANIFEST_JS).await
        && let Ok(Some(json)) = m.into_value::<Option<String>>()
    {
        push(refs(origin, origin, &json), &mut seen, &mut queue);
    }
    for (url, ct, body) in &seeds {
        if scannable(url, ct) {
            push(
                refs(url, origin, &String::from_utf8_lossy(body)),
                &mut seen,
                &mut queue,
            );
        }
    }

    let (mut out, mut bytes, mut failed) = (Vec::new(), 0usize, 0usize);
    while !queue.is_empty() {
        if out.len() >= MAX_FILES || bytes >= MAX_BYTES {
            tracing::warn!(
                files = out.len(),
                bytes,
                left = queue.len(),
                "crawl limit reached"
            );
            break;
        }
        let batch: Vec<String> = queue.drain(..queue.len().min(BATCH)).collect();
        // Under the CDP request timeout (30s), so one slow batch costs a warning, not the recording.
        let call = page.evaluate_function(format!(
            "() => ({FETCH_JS})({})",
            serde_json::to_string(&batch)?
        ));
        let got: Vec<Fetched> = match tokio::time::timeout(BATCH_TIMEOUT, call).await {
            Ok(Ok(r)) => r.into_value()?,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, size = batch.len(), "crawl batch failed; skipped");
                failed += batch.len();
                continue;
            }
            Err(_) => {
                tracing::warn!(size = batch.len(), "crawl batch timed out; skipped");
                failed += batch.len();
                continue;
            }
        };
        for mut f in got {
            if f.status != 200 {
                failed += 1;
                continue;
            }
            let body = STANDARD.decode(&f.body)?;
            bytes += body.len();
            force_text_type(&mut f);
            let ct = f
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if scannable(&f.url, &ct) {
                push(
                    refs(&f.url, origin, &String::from_utf8_lossy(&body)),
                    &mut seen,
                    &mut queue,
                );
            }
            out.push((f, body));
        }
    }
    tracing::info!(
        files = out.len(),
        bytes,
        not_found = failed,
        "crawled shell"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const O: &str = "https://app.test";

    #[test]
    fn finds_vite_and_css_refs() {
        let js = r#"const m=["assets/Foo-AbC123xy.js","assets/Foo-AbC123xy.css"];
            import("./Bar-ZZZZZZZZ.js"); x("Baz-12345678.js"); y("/images/illcons/Error.svg");
            z("react.js"); w("https://cdn.other/x-12345678.js"); u('./img/a.png')"#;
        let got = refs("https://app.test/assets/main-11111111.js", O, js);
        assert_eq!(
            got,
            vec![
                "https://app.test/assets/Foo-AbC123xy.js",
                "https://app.test/assets/assets/Foo-AbC123xy.js",
                "https://app.test/assets/Foo-AbC123xy.css",
                "https://app.test/assets/assets/Foo-AbC123xy.css",
                "https://app.test/assets/Bar-ZZZZZZZZ.js",
                "https://app.test/assets/Baz-12345678.js",
                "https://app.test/images/illcons/Error.svg",
                "https://app.test/assets/img/a.png",
            ]
        );
        let css = "a{background:url(/fonts/x.woff2)} b{src:url('../img/y.png')}";
        assert_eq!(
            refs("https://app.test/assets/s.css", O, css),
            vec![
                "https://app.test/fonts/x.woff2",
                "https://app.test/img/y.png"
            ]
        );
    }

    #[test]
    fn keeps_query_and_relabels_text() {
        assert_eq!(
            refs(O, O, r#"x("/a/b.js?v=42")"#),
            vec!["https://app.test/a/b.js?v=42"]
        );
        let mut f = Fetched {
            url: "https://app.test/a/b.js".into(),
            status: 200,
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: String::new(),
        };
        force_text_type(&mut f);
        assert_eq!(
            f.headers,
            vec![("content-type".into(), "text/javascript".into())]
        );
    }

    #[test]
    fn manifest_paths_are_absolute() {
        let m = r#"{"routes":{"r":{"module":"/assets/route-ABCDEFGH.js","imports":["/assets/c-12345678.js"],"css":["/assets/r-87654321.css"]}}}"#;
        assert_eq!(refs(O, O, m).len(), 3);
    }
}
