mod common;

use std::time::Duration;

use common::*;
use mimesia::cdp::{Launch, Session};
use mimesia::persona::Persona;
use mimesia::record::record_page;

fn grep_dir(dir: &std::path::Path, needles: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for e in walk(dir) {
        let bytes = std::fs::read(&e).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for n in needles {
            if text.contains(n) {
                hits.push(format!("{} contains {n}", e.display()));
            }
        }
    }
    hits
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            v.extend(walk(&p));
        } else {
            v.push(p);
        }
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn record_scrubs_and_excludes_login() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let fx = Fixture::start().await;
    let session = Session::launch(Launch::default()).await.unwrap();
    let page = signed_in_page(&session, &format!("{}/", fx.app)).await;

    let tmp = tempdir();
    let out = tmp.join("cap");
    let report = record_page(
        &page,
        &out,
        Duration::from_millis(500),
        Persona::default(),
        &[],
    )
    .await
    .unwrap();
    session.close().await;
    fx.stop();

    assert!(report.ok, "scan findings: {:#?}", report.findings);

    let leaks = grep_dir(
        &out,
        &[
            REAL_OID,
            REAL_TID,
            REAL_UPN,
            REAL_NAME,
            "SECRETsig",
            "realsessioncookie",
            "realrefreshtokenvalue",
            "cmVhbHNpZ25hdHVyZXJl",
        ],
    );
    assert!(leaks.is_empty(), "{leaks:#?}");

    // Identity paths may appear in app code, but never in what we wrote about the traffic.
    for f in [
        "requests.jsonl",
        "inventory.json",
        "manifest.json",
        "scan.json",
    ] {
        let t = std::fs::read_to_string(out.join(f)).unwrap();
        assert!(
            !t.contains("oauth2") && !t.contains("fixture-tenant"),
            "{f}"
        );
    }
    let reqs = std::fs::read_to_string(out.join("requests.jsonl")).unwrap();
    assert!(!reqs.contains("/oauth2/"), "identity call recorded");
    for must in ["/app.js", "/lazy.js", "/api/me", "/api/items", "/logo.svg"] {
        assert!(reqs.contains(must), "missing {must}");
    }
    assert!(out.join("record.png").exists());

    // Tampering after the scan must be caught.
    let cap = mimesia::store::Capture::new(&out);
    mimesia::scan::require_clean(&cap).unwrap();
    let blob = cap.blob_names().unwrap().remove(0);
    std::fs::write(cap.blobs().join(&blob), b"tampered").unwrap();
    assert!(mimesia::scan::require_clean(&cap).is_err());

    if std::env::var_os("MIMESIA_KEEP").is_some() {
        eprintln!("kept {}", out.display());
    } else {
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
