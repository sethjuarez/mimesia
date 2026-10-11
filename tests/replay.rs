mod common;

use std::time::Duration;

use common::*;
use mimesia::cdp::{Launch, Session};
use mimesia::persona::Persona;
use mimesia::record::record_page;
use mimesia::replay::Replay;

async fn text(page: &chromiumoxide::Page, js: &str) -> String {
    page.evaluate(js).await.unwrap().into_value().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_runs_offline_with_fake_session() {
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
    // The origin is gone: replay must be fully offline.
    fx.stop();
    assert!(report.ok);

    let replay = Replay::start(&out, false).await.unwrap();
    replay.settle().await.unwrap();
    let page = &replay.page;
    let mut ready = String::new();
    for _ in 0..50 {
        ready = text(page, "document.body.dataset.ready || ''").await;
        if !ready.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let who = text(page, "document.querySelector('#who')?.textContent || ''").await;
    let items = text(page, "String(document.querySelectorAll('li').length)").await;
    let lazy = text(page, "document.querySelector('#lazy')?.textContent || ''").await;
    let year = text(page, "String(new Date().getFullYear())").await;
    let stats = replay.stats();
    replay.close().await;

    assert_eq!(ready, "1", "app never became ready; stats {stats:#?}");
    let p = Persona::default();
    assert!(
        who.contains(&p.name) && who.contains(&p.upn),
        "who = {who:?}"
    );
    assert_eq!(items, "3");
    assert!(!lazy.is_empty(), "lazy chunk did not run");
    assert!(stats.misses.is_empty(), "misses: {:#?}", stats.misses);
    assert!(stats.escaped.is_empty(), "escaped: {:#?}", stats.escaped);
    assert!(stats.identity_stubbed >= 1, "{stats:#?}");
    assert!(stats.hits >= 5, "{stats:#?}");
    let cap_year = {
        let m = mimesia::store::Capture::new(&out).manifest().unwrap();
        (1970 + m.captured_at_ms / 31_557_600_000).to_string()
    };
    assert_eq!(year, cap_year, "clock not pinned");

    if std::env::var_os("MIMESIA_KEEP").is_some() {
        eprintln!("kept {}", out.display());
    } else {
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
