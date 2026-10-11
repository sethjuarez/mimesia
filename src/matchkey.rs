//! Request match keys.
//!
//! `exact` = method + origin + path + stable query + body hash.
//! `loose` = method + origin + path. Replay tries exact first.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;
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
        key.push_str(&hex::encode(Sha256::digest(stable_body(b)))[..12]);
    }
    key
}

static ISO_TIME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?").unwrap()
});

/// Body keys whose values identify one call or session, not what is asked for.
const PER_CALL_IDS: &[&str] = &[
    "sessionid",
    "requestid",
    "clientrequestid",
    "correlationid",
    "traceid",
    "spanid",
];

/// JSON bodies with per-call values (per-call id keys, timestamps, epoch-ms numbers,
/// volatile keys) blanked, so polling and session-scoped calls match their recording.
/// UUIDs elsewhere are kept: they usually name the resource asked for. Non-JSON is unchanged.
fn stable_body(b: &[u8]) -> Vec<u8> {
    match stable_value(b) {
        Some(v) => serde_json::to_vec(&v).unwrap_or_else(|_| b.to_vec()),
        None => b.to_vec(),
    }
}

/// Separates a scalar-array path (`$.ids[]`) from its member value in [`leaves`] keys.
pub const MEMBER: char = '\0';

/// A leaf key made safe for logs: set members dropped, and any object key that is not a
/// plain identifier (GUIDs, emails, names, long numbers) replaced with `*`.
pub fn display_path(key: &str) -> String {
    static PLAIN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z_$][A-Za-z_$]*[0-9]{0,3}((\[[0-9]*\])*)$").unwrap());
    static INDEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\[[0-9]*\])*$").unwrap());
    let path = key.split(MEMBER).next().unwrap_or_default();
    path.split('.')
        .map(|seg| {
            if PLAIN.is_match(seg) {
                seg.to_string()
            } else {
                // Keep only a trailing run of array indices, never the key itself.
                let idx = INDEX.find(seg).map(|m| m.as_str()).unwrap_or("");
                format!("*{idx}")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Flattened `path -> value` leaves of a stable JSON body, for nearest-body matching.
/// Arrays of scalars are sets (`$.ids[]\0"x"`): apps often sort or batch id lists, so
/// one shifted element must not make every position differ. `None` when not JSON.
pub fn leaves(b: &[u8]) -> Option<BTreeMap<String, String>> {
    fn flat(p: &str, v: &Value, out: &mut BTreeMap<String, String>) {
        match v {
            Value::Object(o) => o
                .iter()
                .for_each(|(k, v)| flat(&format!("{p}.{k}"), v, out)),
            Value::Array(a)
                if !a.is_empty() && a.iter().all(|v| !v.is_object() && !v.is_array()) =>
            {
                for v in a {
                    out.insert(format!("{p}[]{MEMBER}{v}"), String::new());
                }
            }
            Value::Array(a) => a
                .iter()
                .enumerate()
                .for_each(|(i, v)| flat(&format!("{p}[{i}]"), v, out)),
            _ => {
                out.insert(p.to_string(), v.to_string());
            }
        }
    }
    let v = stable_value(b)?;
    let mut out = BTreeMap::new();
    flat("$", &v, &mut out);
    Some(out)
}

fn stable_value(b: &[u8]) -> Option<Value> {
    fn walk(v: &mut Value) {
        match v {
            Value::String(s) => {
                *s = ISO_TIME.replace_all(s, "<time>").into_owned();
            }
            Value::Number(n) => {
                if n.as_u64()
                    .is_some_and(|x| (1_000_000_000_000..10_000_000_000_000).contains(&x))
                {
                    *v = Value::from("<ms>");
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            Value::Object(o) => {
                o.retain(|k, _| !VOLATILE.contains(&k.to_ascii_lowercase().as_str()));
                for (k, v) in o.iter_mut() {
                    if PER_CALL_IDS.contains(&k.to_ascii_lowercase().as_str()) {
                        *v = Value::from("<id>");
                    } else {
                        walk(v);
                    }
                }
            }
            _ => {}
        }
    }
    let mut v = serde_json::from_slice::<Value>(b).ok()?;
    walk(&mut v);
    Some(v)
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
    fn display_path_hides_members_and_id_like_keys() {
        let k = |s: &str| display_path(s);
        assert_eq!(k("$.params.queries[0].url"), "$.params.queries[0].url");
        assert_eq!(k("$.params.ids[]\0\"a1b2c3d4\""), "$.params.ids[]");
        assert_eq!(
            k("$.users.a1b2c3d4-1111-2222-3333-444444444444.on"),
            "$.users.*.on"
        );
        assert_eq!(k("$.by.a@b.com[2]"), "$.by.*.com[2]");
        assert_eq!(k("$.m.Seth Juarez"), "$.m.*");
        assert_eq!(k("$.m.a1b2c3d4abcd"), "$.m.*");
    }

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

    #[test]
    fn json_body_ignores_per_call_values() {
        let k = |b: &str| exact("POST", "https://a.com/x", Some(b.as_bytes()));
        assert_eq!(
            k(
                r#"{"sessionId":"0f8fad5b-d9cb-469f-a165-70867728950e","at":"2026-10-11T10:00:00.123Z","t":1791716259479,"q":"a","nonce":"x"}"#
            ),
            k(
                r#"{"sessionId":"7c9e6679-7425-40de-944b-e07fc1f90ae7","at":"2026-10-12T11:22:33Z","t":1791716999999,"q":"a","nonce":"y"}"#
            )
        );
        // UUIDs outside per-call keys name a resource, so they still distinguish calls.
        assert_ne!(
            k(r#"{"agent":"0f8fad5b-d9cb-469f-a165-70867728950e"}"#),
            k(r#"{"agent":"7c9e6679-7425-40de-944b-e07fc1f90ae7"}"#)
        );
        assert_ne!(k(r#"{"q":"a"}"#), k(r#"{"q":"b"}"#));
        assert_ne!(k(r#"{"n":5}"#), k(r#"{"n":6}"#));
        assert_ne!(k("a=1"), k("a=2"));
        assert_eq!(
            k(r#"{"sessionId":"5e1b2c3d4e5f60718293a4b5c6d7e8f9","agentId":"a"}"#),
            k(r#"{"sessionId":"00000000000000000000000000000000","agentId":"a"}"#)
        );
    }
}
