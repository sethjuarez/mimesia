mod common;

use std::time::Duration;

use common::*;
use mimesia::cdp::{Launch, Session};
use mimesia::persona::Persona;
use mimesia::record::record_page;

#[tokio::test(flavor = "multi_thread")]
async fn verify_replay_matches_recording() {
    let fx = Fixture::start().await;
    let session = Session::launch(Launch::default()).await.unwrap();
    let page = signed_in_page(&session, &format!("{}/", fx.app)).await;
    let tmp = tempdir();
    let out = tmp.join("cap");
    record_page(&page, &out, Duration::from_millis(500), Persona::default())
        .await
        .unwrap();
    session.close().await;
    fx.stop();

    let r = mimesia::verify::verify(&out, 0.02).await.unwrap();
    for f in ["replay.png", "diff.png", "report.json"] {
        assert!(out.join("verify").join(f).exists(), "{f}");
    }
    // Only the signed-in name differs: real user while recording, persona on replay.
    assert!(r.pass, "{r:#?}");
    assert!(
        r.diff_ratio > 0.0,
        "persona swap should show up in the diff"
    );
    // The verify output must not invalidate the capture.
    mimesia::scan::require_clean(&mimesia::store::Capture::new(&out)).unwrap();

    if std::env::var_os("MIMESIA_KEEP").is_some() {
        eprintln!("kept {}", out.display());
    } else {
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
