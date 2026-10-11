//! Leak scan. Replay refuses a capture until this passes.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::scrub::{Finding, keep_header, leaks};
use crate::store::{Capture, Inventory};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub ok: bool,
    pub digest: String,
    pub findings: Vec<Finding>,
}

pub fn scan(cap: &Capture) -> Result<ScanReport> {
    let digest = cap.digest()?;
    let mut findings = Vec::new();
    let manifest = cap.manifest()?;
    findings.extend(leaks(&manifest.url, "manifest.url"));
    for (i, s) in manifest.storage.iter().enumerate() {
        findings.extend(leaks(&s.key, &format!("manifest.storage[{i}].key")));
        findings.extend(leaks(&s.value, &format!("manifest.storage[{i}].value")));
    }
    let blobs: HashSet<String> = cap.blob_names()?.into_iter().collect();
    for (i, e) in cap.entries()?.iter().enumerate() {
        let at = format!("requests[{i}]");
        findings.extend(leaks(&e.url, &format!("{at}.url")));
        findings.extend(leaks(&e.key, &format!("{at}.key")));
        for (k, v) in &e.headers {
            if !keep_header(k) {
                findings.push(Finding {
                    kind: "header".into(),
                    location: format!("{at}.headers"),
                });
            }
            findings.extend(leaks(v, &format!("{at}.headers")));
        }
        for h in [&e.body, &e.req_body].into_iter().flatten() {
            if !blobs.contains(h) {
                bail!("{at} references missing blob {h}");
            }
        }
    }
    // Every blob, whatever its declared type: a mislabeled body must not slip through.
    for name in &blobs {
        let body = cap.blob(name)?;
        findings.extend(leaks(
            &String::from_utf8_lossy(&body),
            &format!("blobs/{name}"),
        ));
    }
    let inv: Inventory = cap.read_json("inventory.json")?;
    findings.extend(leaks(&serde_json::to_string(&inv)?, "inventory.json"));
    let report = ScanReport {
        ok: findings.is_empty(),
        digest,
        findings,
    };
    cap.write_json("scan.json", &report)?;
    Ok(report)
}

/// Error unless scan.json passed and the capture hasn't changed since.
pub fn require_clean(cap: &Capture) -> Result<()> {
    let report: ScanReport = cap
        .read_json("scan.json")
        .map_err(|_| anyhow::anyhow!("capture not scanned; run `mimesia scan` first"))?;
    if !report.ok {
        bail!("capture failed its leak scan; see scan.json");
    }
    if report.digest != cap.digest()? {
        bail!("capture changed since its last scan; run `mimesia scan` again");
    }
    Ok(())
}

pub fn run(capture: &Path) -> Result<()> {
    let report = scan(&Capture::new(capture))?;
    for f in &report.findings {
        println!("LEAK {:<14} {}", f.kind, f.location);
    }
    if !report.ok {
        bail!("{} potential leak(s)", report.findings.len());
    }
    println!("scan ok");
    Ok(())
}
