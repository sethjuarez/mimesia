//! Request match keys.
//!
//! `exact` = method + origin + path + stable query + body hash.
//! `loose` = method + origin + path. Replay tries exact first.

use sha2::{Digest, Sha256};
use url::Url;

/// Cache-busters, always dropped.
const VOLATILE: &[&str] = &[
    "_",
    "_t",
    "ts",
    "timestamp",
    "nonce",
    "cb",
    "cachebust",
    "rnd",
    "random",
];
/// Dropped only when the value is all digits (otherwise it may be meaningful, e.g. `t=type`).
const VOLATILE_IF_NUMERIC: &[&str] = &["t", "v"];

fn volatile(k: &str, v: &str) -> bool {
    let k = k.to_ascii_lowercase();
    VOLATILE.contains(&k.as_str())
        || (VOLATILE_IF_NUMERIC.contains(&k.as_str())
            && !v.is_empty()
            && v.bytes().all(|b| b.is_ascii_digit()))
}

pub fn exact(method: &str, url: &str, body: Option<&[u8]>) -> String {
    let (base, query) = split(url);
    let mut key = format!("{} {base}", method.to_ascii_uppercase());
    if !query.is_empty() {
        key.push('?');
        key.push_str(&query);
    }
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        key.push_str(" #");
        key.push_str(&hex::encode(Sha256::digest(b))[..12]);
    }
    key
}

pub fn loose(method: &str, url: &str) -> String {
    format!("{} {}", method.to_ascii_uppercase(), split(url).0)
}

fn split(url: &str) -> (String, String) {
    let Ok(u) = Url::parse(url) else {
        return (url.to_string(), String::new());
    };
    let base = format!("{}{}", u.origin().ascii_serialization(), u.path());
    let mut pairs: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, v)| !volatile(k, v))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    pairs.sort();
    // Re-encode so `a=x%26b%3Dy` and `a=x&b=y` stay distinct.
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    (base, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_and_drops_volatile() {
        assert_eq!(
            exact("get", "https://a.com/x?b=2&_=123&a=1#frag", None),
            "GET https://a.com/x?a=1&b=2"
        );
    }

    #[test]
    fn no_collisions_and_meaningful_t_kept() {
        assert_ne!(
            exact("GET", "https://a.com/x?a=x%26b%3Dy", None),
            exact("GET", "https://a.com/x?a=x&b=y", None)
        );
        assert_eq!(
            exact("GET", "https://a.com/x?t=agents&v=17000", None),
            "GET https://a.com/x?t=agents"
        );
    }

    #[test]
    fn body_changes_key() {
        let a = exact("POST", "https://a.com/x", Some(b"{\"q\":1}"));
        let b = exact("POST", "https://a.com/x", Some(b"{\"q\":2}"));
        assert_ne!(a, b);
        assert_eq!(loose("POST", "https://a.com/x?z=1"), "POST https://a.com/x");
    }
}
