//! Verify: replay headless, screenshot, and pixel-diff against the recording.
//!
//! Output goes to `<capture>/verify/` (`replay.png`, `diff.png`, `report.json`). Pixels are
//! compared with pixelmatch's perceptual YIQ distance, without its anti-alias detection, so
//! font rasterization differences count. `diff.png` is a mask: it never reproduces recorded
//! pixels, which may show the real signed-in user.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use image::{ImageFormat, Rgba, RgbaImage};
use serde::Serialize;

use crate::record::still_screenshot;
use crate::replay::{Replay, Stats};
use crate::store::Capture;

/// Per-pixel colour distance (0..1) above which a pixel counts as different.
pub const PIXEL_THRESHOLD: f64 = 0.1;

#[derive(Debug, Serialize)]
pub struct Report {
    /// Fraction of pixels that differ (1.0 when sizes differ).
    pub diff_ratio: f64,
    pub threshold: f64,
    pub pass: bool,
    pub width: u32,
    pub height: u32,
    pub stats: Stats,
}

pub async fn verify(capture: &Path, threshold: f64) -> Result<Report> {
    if !(0.0..=1.0).contains(&threshold) {
        bail!("threshold must be between 0 and 1");
    }
    let cap = Capture::new(capture);
    let out = cap.path("verify");
    // Never leave a previous run's report looking current.
    if out.exists() {
        fs::remove_dir_all(&out).context("clear previous verify output")?;
    }
    let recorded = image::load_from_memory_with_format(
        &fs::read(cap.path("record.png")).context("read record.png")?,
        ImageFormat::Png,
    )?
    .to_rgba8();

    let replay = Replay::start(capture, false).await?;
    let shot = async {
        replay.settle().await?;
        still_screenshot(&replay.page).await
    }
    .await;
    let stats = replay.stats().await;
    replay.close().await;
    let shot = shot?;
    let replayed = image::load_from_memory_with_format(&shot, ImageFormat::Png)?.to_rgba8();

    let (diff_ratio, diff) = compare(&recorded, &replayed);
    fs::create_dir_all(&out)?;
    fs::write(out.join("replay.png"), &shot)?;
    diff.save_with_format(out.join("diff.png"), ImageFormat::Png)?;
    let report = Report {
        diff_ratio,
        threshold,
        pass: diff_ratio <= threshold && stats.misses.is_empty() && stats.escaped.is_empty(),
        width: replayed.width(),
        height: replayed.height(),
        stats,
    };
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    Ok(report)
}

pub async fn run(capture: &Path, threshold: f64) -> Result<()> {
    let r = verify(capture, threshold).await?;
    println!(
        "{}: {:.3}% pixels differ (threshold {:.3}%), {} hits ({} near), {} misses, {} escaped",
        if r.pass { "PASS" } else { "FAIL" },
        r.diff_ratio * 100.0,
        r.threshold * 100.0,
        r.stats.hits,
        r.stats.near.len(),
        r.stats.misses.len(),
        r.stats.escaped.len()
    );
    for n in &r.stats.near {
        println!("NEAR {n}");
    }
    for m in &r.stats.misses {
        println!("MISS {m}");
    }
    for e in &r.stats.escaped {
        println!("ESCAPED {e}");
    }
    println!("wrote {}", capture.join("verify").display());
    if !r.pass {
        bail!("verify failed");
    }
    Ok(())
}

/// Fraction of differing pixels and a mask: differences red, everything else white.
pub fn compare(a: &RgbaImage, b: &RgbaImage) -> (f64, RgbaImage) {
    let (w, h) = (a.width().max(b.width()), a.height().max(b.height()));
    if a.dimensions() != b.dimensions() {
        return (1.0, RgbaImage::from_pixel(w, h, Rgba([255, 0, 0, 255])));
    }
    let max = 35215.0 * PIXEL_THRESHOLD * PIXEL_THRESHOLD;
    let mut diff = RgbaImage::new(w, h);
    let mut n = 0u64;
    for (x, y, pa) in a.enumerate_pixels() {
        let pb = b.get_pixel(x, y);
        let out = if yiq_delta(pa, pb) > max {
            n += 1;
            Rgba([255, 0, 0, 255])
        } else {
            Rgba([255, 255, 255, 255])
        };
        diff.put_pixel(x, y, out);
    }
    let total = u64::from(w) * u64::from(h);
    let ratio = if total == 0 {
        0.0
    } else {
        n as f64 / total as f64
    };
    (ratio, diff)
}

/// Composite over white.
fn blend(p: &Rgba<u8>) -> [f64; 3] {
    let a = f64::from(p[3]) / 255.0;
    [0, 1, 2].map(|i| 255.0 + (f64::from(p[i]) - 255.0) * a)
}

fn yiq([r, g, b]: [f64; 3]) -> (f64, f64, f64) {
    (
        r * 0.29889531 + g * 0.58662247 + b * 0.11448223,
        r * 0.59597799 - g * 0.27417610 - b * 0.32180189,
        r * 0.21147017 - g * 0.52261711 + b * 0.31114694,
    )
}

/// Squared perceptual distance, as in pixelmatch (max 35215).
fn yiq_delta(a: &Rgba<u8>, b: &Rgba<u8>) -> f64 {
    let (y1, i1, q1) = yiq(blend(a));
    let (y2, i2, q2) = yiq(blend(b));
    let (dy, di, dq) = (y1 - y2, i1 - i2, q1 - q2);
    0.5053 * dy * dy + 0.299 * di * di + 0.1957 * dq * dq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_near_and_different() {
        let a = RgbaImage::from_pixel(10, 10, Rgba([200, 200, 200, 255]));
        assert_eq!(compare(&a, &a).0, 0.0);

        let mut b = a.clone();
        b.put_pixel(0, 0, Rgba([201, 200, 199, 255]));
        assert_eq!(compare(&a, &b).0, 0.0, "imperceptible change counted");

        b.put_pixel(1, 1, Rgba([0, 0, 0, 255]));
        let (r, d) = compare(&a, &b);
        assert!((r - 0.01).abs() < 1e-9);
        assert_eq!(d.get_pixel(1, 1), &Rgba([255, 0, 0, 255]));

        let c = RgbaImage::new(10, 11);
        assert_eq!(compare(&a, &c).0, 1.0);
    }
}
