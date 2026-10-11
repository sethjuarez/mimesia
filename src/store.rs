//! On-disk capture format.
//!
//! ```text
//! <capture>/
//!   manifest.json    page, viewport, persona, storage snapshot (scrubbed)
//!   requests.jsonl   one Entry per recorded response
//!   blobs/<sha256>   content-addressed bodies
//!   inventory.json   what was seen but not stored
//!   record.png       reference screenshot
//!   scan.json        leak-scan result; replay requires ok + matching digest
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::persona::Persona;

pub const FORMAT_VERSION: u32 = 1;

/// Files every capture must have (besides blobs).
pub const REQUIRED: [&str; 4] = [
    "manifest.json",
    "requests.jsonl",
    "inventory.json",
    "record.png",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
    pub dpr: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    /// `localStorage` or `sessionStorage`.
    pub area: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub url: String,
    pub origin: String,
    pub captured_at_ms: i64,
    pub viewport: Viewport,
    pub user_agent: String,
    pub persona: Persona,
    pub storage: Vec<StorageItem>,
    /// Storage entries dropped because they could not be made safe (e.g. encrypted MSAL v4).
    pub dropped_storage: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub key: String,
    pub loose_key: String,
    pub method: String,
    pub url: String,
    pub resource_type: String,
    pub status: i64,
    pub headers: Vec<(String, String)>,
    /// sha256 of the body in `blobs/`, if any.
    pub body: Option<String>,
    /// sha256 of the scrubbed request body in `blobs/`, if any. Used for nearest-body matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_body: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Inventory {
    /// Requests per non-identity host (recorded or not).
    pub hosts: BTreeMap<String, usize>,
    /// Identity requests seen and excluded. A count only: their URLs are never written.
    pub identity_excluded: usize,
    pub telemetry_excluded: usize,
    pub websockets: Vec<String>,
    pub event_streams: Vec<String>,
    pub frames: Vec<String>,
    /// Requests seen but not stored, with reason.
    pub skipped: Vec<(String, String)>,
    /// Static assets fetched by the shell crawl (not loaded by the page itself).
    #[serde(default)]
    pub crawled: usize,
}

pub struct Capture {
    pub dir: PathBuf,
}

impl Capture {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    pub fn blobs(&self) -> PathBuf {
        self.dir.join("blobs")
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        let hash = hex::encode(Sha256::digest(bytes));
        let p = self.blobs().join(&hash);
        if !p.exists() {
            fs::create_dir_all(self.blobs())?;
            fs::write(&p, bytes)?;
        }
        Ok(hash)
    }

    pub fn blob(&self, hash: &str) -> Result<Vec<u8>> {
        fs::read(self.blobs().join(hash)).with_context(|| format!("missing blob {hash}"))
    }

    pub fn write_json<T: Serialize>(&self, name: &str, v: &T) -> Result<()> {
        fs::write(self.path(name), serde_json::to_vec_pretty(v)?)?;
        Ok(())
    }

    pub fn read_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<T> {
        let p = self.path(name);
        let bytes = fs::read(&p).with_context(|| format!("cannot read {}", p.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn write_entries(&self, entries: &[Entry]) -> Result<()> {
        let mut f = fs::File::create(self.path("requests.jsonl"))?;
        for e in entries {
            serde_json::to_writer(&mut f, e)?;
            f.write_all(b"\n")?;
        }
        Ok(())
    }

    pub fn entries(&self) -> Result<Vec<Entry>> {
        let f = fs::File::open(self.path("requests.jsonl"))
            .with_context(|| format!("{} is not a capture", self.dir.display()))?;
        std::io::BufReader::new(f)
            .lines()
            .map(|l| Ok(serde_json::from_str(&l?)?))
            .collect()
    }

    pub fn manifest(&self) -> Result<Manifest> {
        self.read_json("manifest.json")
    }

    /// Every blob name, sorted.
    pub fn blob_names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        if self.blobs().exists() {
            for e in fs::read_dir(self.blobs())? {
                let e = e?;
                if !e.file_type()?.is_file() {
                    bail!("unexpected entry in blobs/: {}", e.path().display());
                }
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Digest over the content of everything scan checks; replay refuses captures whose
    /// digest changed. Fails if a required file is missing or a blob's name is not its hash.
    pub fn digest(&self) -> Result<String> {
        let mut h = Sha256::new();
        for name in REQUIRED {
            let p = self.path(name);
            let bytes = fs::read(&p).with_context(|| format!("missing {}", p.display()))?;
            h.update(name.as_bytes());
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(&bytes);
        }
        for name in self.blob_names()? {
            let bytes = fs::read(self.blobs().join(&name))?;
            if hex::encode(Sha256::digest(&bytes)) != name {
                bail!("blob {name} does not match its hash");
            }
            h.update(name.as_bytes());
        }
        Ok(hex::encode(h.finalize()))
    }
}
