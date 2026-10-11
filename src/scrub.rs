//! Credential and identity scrubbing, plus leak detection.

use std::sync::LazyLock;

use regex::{Captures, Regex, RegexBuilder};
use serde_json::Value;

use crate::persona::{FAR_FUTURE, Persona, fake_jwt_prefix};

static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*").unwrap()
});
/// Credential-bearing URL parameters (also matches `&amp;`, `\u0026` and `%26` separators).
static URL_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)((?:[?&#]|&amp;|\\u0026|%26)(?:sig|signature|access_token|id_token|refresh_token|client_secret|token|sas_?token|api[-_]?key|subscription-key|code_verifier)=)([^&#\s\x22'<\\]+)",
    )
    .unwrap()
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{20,})").unwrap());
/// JSON fields that hold secrets, in snake_case or camelCase.
static TOKEN_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)("(?:access_?token|refresh_?token|id_?token|client_?secret|sas_?token|sas_?url|token|api_?key|primary_?key|secondary_?key|password|connection_?string|sig)"\s*:\s*")([^"]{8,})(")"#,
    )
    .unwrap()
});

pub const REDACTED: &str = "REDACTED";

/// Response headers safe and useful to keep.
const KEEP_HEADERS: &[&str] = &[
    "content-type",
    "content-disposition",
    "content-language",
    "location",
    "access-control-allow-origin",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "x-content-type-options",
];

pub fn keep_header(name: &str) -> bool {
    KEEP_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

pub fn is_text(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("text/")
        || [
            "json",
            "javascript",
            "ecmascript",
            "xml",
            "svg",
            "html",
            "x-www-form-urlencoded",
        ]
        .iter()
        .any(|t| ct.contains(t))
}

pub fn is_script_or_style(content_type: &str) -> bool {
    let ct = content_type.to_ascii_lowercase();
    ct.contains("javascript") || ct.contains("ecmascript") || ct.contains("text/css")
}

/// Real identity values (from the live MSAL cache) and what replaces them.
#[derive(Debug, Default, Clone)]
pub struct IdentityMap {
    /// (real, fake, trusted). Untrusted values are scrubbed but prove nothing.
    pairs: Vec<(String, String, bool)>,
    /// First/last name words: replaced case-sensitively, in text only, at any length.
    parts: Vec<(String, String)>,
}

/// Shorter values are only replaced where they are a whole JSON string.
const MIN_FREE_TEXT: usize = 4;

impl IdentityMap {
    /// A real value known to belong to the signed-in user.
    pub fn add(&mut self, real: &str, fake: &str) {
        if self.add_weak(real, fake)
            && let Some(p) = self
                .pairs
                .iter_mut()
                .find(|(r, _, _)| r.eq_ignore_ascii_case(real.trim()))
        {
            p.2 = true;
        }
    }

    /// A value to scrub that only probably belongs to the user; it never satisfies
    /// `has_fake`. Returns whether the value is usable.
    pub fn add_weak(&mut self, real: &str, fake: &str) -> bool {
        let real = real.trim();
        if real.len() < 2 || real.eq_ignore_ascii_case(fake) {
            return false;
        }
        if !self
            .pairs
            .iter()
            .any(|(r, _, _)| r.eq_ignore_ascii_case(real))
        {
            self.pairs.push((real.to_string(), fake.to_string(), false));
        }
        true
    }

    pub fn reals(&self) -> impl Iterator<Item = &str> {
        self.pairs.iter().map(|(r, _, _)| r.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Whether a trusted real value maps to `fake`.
    pub fn has_fake(&self, fake: &str) -> bool {
        self.pairs.iter().any(|(_, f, t)| *t && f == fake)
    }

    /// A display name, plus its first and last words (apps often greet by first name).
    pub fn add_name(&mut self, real: &str, p: &Persona) {
        self.add(real, &p.name);
        let words: Vec<&str> = real.split_whitespace().collect();
        if words.len() > 1 {
            let (first, last) = p.name_parts();
            for (r, f) in [(words[0], first), (words[words.len() - 1], last)] {
                if r != f && !self.parts.iter().any(|(x, _)| x == r) {
                    self.parts.push((r.to_string(), f.to_string()));
                }
            }
        }
    }

    /// A UPN or email, plus its local part (apps key storage and paths by alias).
    pub fn add_upn(&mut self, real: &str, p: &Persona) {
        self.add(real, &p.upn);
        if let Some((alias, _)) = real.split_once('@') {
            self.add(alias, p.alias());
        }
    }

    fn add_upn_weak(&mut self, real: &str, p: &Persona) {
        self.add_weak(real, &p.upn);
        if let Some((alias, _)) = real.split_once('@') {
            self.add_weak(alias, p.alias());
        }
    }

    /// Route a free-form `--identity` value: emails are UPNs, multi-word values names,
    /// single words aliases/handles.
    pub fn add_given(&mut self, real: &str, p: &Persona) {
        if real.contains('@') {
            self.add_upn(real, p);
        } else if real.trim().contains(char::is_whitespace) {
            self.add_name(real, p);
        } else {
            self.add(real, p.alias());
        }
    }

    /// Learn real identity values from MSAL account / idToken claims JSON.
    pub fn learn_from_msal(&mut self, v: &Value, p: &Persona) {
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        if let Some(h) = s("homeAccountId") {
            self.add(h, &p.home_account_id());
            if let Some((oid, tid)) = h.split_once('.') {
                self.add(oid, &p.oid);
                self.add(tid, &p.tid);
            }
        }
        for (k, fake) in [
            ("localAccountId", &p.oid),
            ("oid", &p.oid),
            ("sub", &p.oid),
            ("realm", &p.tid),
            ("tenantId", &p.tid),
            ("tid", &p.tid),
        ] {
            if let Some(real) = s(k) {
                self.add(real, fake);
            }
        }
        for k in [
            "username",
            "upn",
            "preferred_username",
            "unique_name",
            "email",
        ] {
            if let Some(real) = s(k) {
                self.add_upn(real, p);
            }
        }
        if let Some(real) = s("name") {
            self.add_name(real, p);
        }
        if let Some(c) = v.get("idTokenClaims") {
            self.learn_from_msal(c, p);
        }
    }

    /// Learn from arbitrary API JSON: ARM `systemData` user fields (weak: may be a
    /// colleague, so scrubbed but never trusted), and name/email
    /// fields of any object that also holds an already-learned oid or UPN.
    pub fn learn_from_json(&mut self, v: &Value, p: &Persona) {
        match v {
            Value::Array(a) => a.iter().for_each(|x| self.learn_from_json(x, p)),
            Value::Object(o) => {
                let s = |k: &str| o.get(k).and_then(Value::as_str);
                for by in ["createdBy", "lastModifiedBy"] {
                    if s(&format!("{by}Type")) == Some("User")
                        && let Some(real) = s(by).filter(|r| r.contains('@'))
                    {
                        self.add_upn_weak(real, p);
                    }
                }
                let owns = ["id", "oid", "objectId", "userId", "localAccountId"]
                    .into_iter()
                    .chain(["userPrincipalName", "upn", "mail", "email"])
                    .filter_map(&s)
                    .any(|x| {
                        self.pairs.iter().any(|(r, f, t)| {
                            *t && r.eq_ignore_ascii_case(x.trim()) && (*f == p.oid || *f == p.upn)
                        })
                    });
                if owns {
                    for k in ["userPrincipalName", "upn", "mail", "email"] {
                        if let Some(real) = s(k).filter(|r| r.contains('@')) {
                            self.add_upn(real, p);
                        }
                    }
                    if let Some(real) = s("displayName") {
                        self.add_name(real, p);
                    }
                }
                o.values().for_each(|x| self.learn_from_json(x, p));
            }
            _ => {}
        }
    }

    /// Word-bounded, case-insensitive regex over the values `keep` selects, also matching
    /// their percent-encoded forms.
    fn regex(&self, keep: impl Fn(&str) -> bool) -> Option<Regex> {
        let reals: Vec<&str> = self.reals().filter(|r| keep(r)).collect();
        Some(
            RegexBuilder::new(&bounded(&reals)?)
                .case_insensitive(true)
                .build()
                .unwrap(),
        )
    }

    fn parts_regex(&self) -> Option<Regex> {
        let parts: Vec<&str> = self.parts.iter().map(|(r, _)| r.as_str()).collect();
        Some(Regex::new(&bounded(&parts)?).unwrap())
    }

    fn part_fake(&self, real: &str) -> &str {
        self.parts
            .iter()
            .find(|(r, _)| r == real)
            .map_or(REDACTED, |(_, f)| f.as_str())
    }

    fn fake_for(&self, real: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(r, _, _)| r.eq_ignore_ascii_case(real.trim()))
            .map(|(_, f, _)| f.as_str())
    }
}

/// An escape sequence directly before a value (`%22`, `\u0022`, `\x22`). Its last hex
/// digit is a word character, so a plain `\b` would miss e.g. `%22<guid>`.
const ESC_PREFIX: &str = r"%25[0-9A-Fa-f]{2}|%[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}";

/// `(?P<pre>escape)?(?P<v>values)`, longest first, with once- and twice-percent-encoded
/// variants.
/// Boundaries are checked by [`id_matches`], since `\b` treats `_` and hex escapes as words.
fn bounded(values: &[&str]) -> Option<String> {
    let mut all: Vec<String> = Vec::new();
    for v in values {
        let once = [pct_encode(v, false), pct_encode(v, true)];
        let twice = once
            .iter()
            .map(|x| pct_encode(x, false))
            .collect::<Vec<_>>();
        for x in std::iter::once(v.to_string()).chain(once).chain(twice) {
            if !all.contains(&x) {
                all.push(x);
            }
        }
    }
    if all.is_empty() {
        return None;
    }
    all.sort_by_key(|r| std::cmp::Reverse(r.len()));
    let alt = all
        .iter()
        .map(|r| regex::escape(r))
        .collect::<Vec<_>>()
        .join("|");
    Some(format!(r"(?P<pre>{ESC_PREFIX})?(?P<v>{alt})"))
}

fn is_word(c: Option<char>) -> bool {
    c.is_some_and(char::is_alphanumeric)
}

/// Matches of a [`bounded`] regex whose value is not glued to a letter or digit
/// (an escape prefix counts as a boundary).
fn id_matches<'a>(re: &'a Regex, s: &'a str) -> impl Iterator<Item = Captures<'a>> + 'a {
    let mut pos = 0;
    std::iter::from_fn(move || {
        while pos <= s.len() {
            let c = re.captures_at(s, pos)?;
            let v = c.name("v").unwrap();
            let before = s[..v.start()].chars().next_back();
            let after = s[v.end()..].chars().next();
            if (c.name("pre").is_some() || !is_word(before)) && !is_word(after) {
                pos = c.get(0).unwrap().end().max(pos + 1);
                return Some(c);
            }
            pos = v.start() + s[v.start()..].chars().next().map_or(1, char::len_utf8);
        }
        None
    })
}

fn replace_ids(re: &Regex, s: &str, f: impl Fn(&Captures) -> String) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for c in id_matches(re, s) {
        let m = c.get(0).unwrap();
        out.push_str(&s[last..m.start()]);
        out.push_str(&f(&c));
        last = m.end();
    }
    out.push_str(&s[last..]);
    out
}

/// Percent-encode everything but RFC 3986 unreserved characters; `plus` writes space as `+`.
fn pct_encode(s: &str, plus: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b' ' if plus => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode `%XX` and `+`; returns the decoded text and whether it was encoded with `+`.
fn pct_decode(s: &str) -> Option<(String, bool)> {
    if !s.contains('%') && !s.contains('+') {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).ok()?, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some((String::from_utf8(out).ok()?, s.contains('+')))
}

/// Replace one regex match from [`bounded`], keeping its escape prefix and encoding depth.
fn swap(c: &Captures, fake: impl Fn(&str) -> Option<String>) -> String {
    let pre = c.name("pre").map_or("", |m| m.as_str());
    let v = &c["v"];
    let out = fake(v)
        .or_else(|| {
            let (once, plus) = pct_decode(v)?;
            fake(&once).map(|f| pct_encode(&f, plus)).or_else(|| {
                let (twice, plus) = pct_decode(&once)?;
                fake(&twice).map(|f| pct_encode(&pct_encode(&f, plus), false))
            })
        })
        .unwrap_or_else(|| REDACTED.to_string());
    format!("{pre}{out}")
}

/// Values that cannot be a code identifier or keyword (GUIDs, UPNs, "First Last").
fn distinctive(v: &str) -> bool {
    v.len() >= 6
        && v.chars()
            .any(|c| !c.is_alphanumeric() && c != '_' && c != '$')
}

pub struct Scrubber {
    persona: Persona,
    ids: IdentityMap,
    /// For free text (HTML, URLs, headers).
    text_re: Option<Regex>,
    /// For scripts and styles: distinctive values only, so code is never corrupted.
    code_re: Option<Regex>,
    /// Name words, case-sensitive, for text only.
    part_re: Option<Regex>,
    fake_jwt: String,
}

impl Scrubber {
    pub fn new(persona: Persona, ids: IdentityMap) -> Self {
        let text_re = ids.regex(|r| r.len() >= MIN_FREE_TEXT);
        let code_re = ids.regex(distinctive);
        let part_re = ids.parts_regex();
        let fake_jwt = persona.jwt("mimesia");
        Self {
            persona,
            ids,
            text_re,
            code_re,
            part_re,
            fake_jwt,
        }
    }

    pub fn persona(&self) -> &Persona {
        &self.persona
    }

    fn credentials(&self, s: &str) -> String {
        let prefix = fake_jwt_prefix();
        let s = JWT.replace_all(s, |c: &Captures| {
            if c[0].starts_with(&prefix) {
                c[0].to_string()
            } else {
                self.fake_jwt.clone()
            }
        });
        let s = URL_SECRET.replace_all(&s, |c: &Captures| {
            if c[2].starts_with(&prefix) {
                c[0].to_string()
            } else {
                format!("{}{REDACTED}", &c[1])
            }
        });
        let s = BEARER.replace_all(&s, |c: &Captures| {
            if c[2].starts_with(&prefix) || &c[2] == REDACTED {
                c[0].to_string()
            } else {
                format!("{}{REDACTED}", &c[1])
            }
        });
        TOKEN_FIELD
            .replace_all(&s, |c: &Captures| {
                if c[2].starts_with(&prefix) || &c[2] == REDACTED {
                    c[0].to_string()
                } else {
                    format!("{}{REDACTED}{}", &c[1], &c[3])
                }
            })
            .into_owned()
    }

    fn ids_with(&self, re: &Option<Regex>, s: String) -> String {
        match re {
            Some(re) => replace_ids(re, &s, |c| {
                swap(c, |v| self.ids.fake_for(v).map(str::to_string))
            }),
            None => s,
        }
    }

    /// Scrub credentials and identity values from free text.
    pub fn text(&self, s: &str) -> String {
        let s = self.credentials(s);
        // Name words first, so a surname that equals the alias still reads as a name.
        let s = match &self.part_re {
            Some(re) => replace_ids(re, &s, |c| {
                swap(c, |v| {
                    let f = self.ids.part_fake(v);
                    (f != REDACTED).then(|| f.to_string())
                })
            }),
            None => s,
        };
        self.ids_with(&self.text_re, s)
    }

    fn text_has_identity(&self, s: &str) -> bool {
        [&self.text_re, &self.part_re]
            .into_iter()
            .flatten()
            .any(|r| id_matches(r, s).next().is_some())
    }

    /// Scrub a body by content type. Scripts/styles only get distinctive identity values
    /// replaced; JSON is rewritten structurally so short values are caught as whole strings.
    pub fn body(&self, content_type: &str, s: &str) -> String {
        if is_script_or_style(content_type) {
            return self.ids_with(&self.code_re, self.credentials(s));
        }
        if content_type.contains("json")
            && let Ok(mut v) = serde_json::from_str::<Value>(s)
        {
            self.json(&mut v);
            return v.to_string();
        }
        self.text(s)
    }

    fn json(&self, v: &mut Value) {
        match v {
            Value::String(s) => {
                *s = match self.ids.fake_for(s) {
                    Some(f) => f.to_string(),
                    None => self.text(s),
                }
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.json(x)),
            Value::Object(o) => {
                let old = std::mem::take(o);
                for (k, mut x) in old {
                    // Secret-bearing fields first, on the raw JSON pair.
                    if x.is_string() {
                        let pair = serde_json::json!({ k.clone(): x.clone() }).to_string();
                        let scrubbed = self.credentials(&pair);
                        if scrubbed != pair
                            && let Ok(Value::Object(m)) = serde_json::from_str(&scrubbed)
                            && let Some((_, y)) = m.into_iter().next()
                        {
                            x = y;
                        }
                    }
                    self.json(&mut x);
                    o.insert(self.text(&k), x);
                }
            }
            _ => {}
        }
    }

    /// Identity values still present after scrubbing, judged the same way `body` scrubs.
    pub fn identity_left(&self, content_type: &str, s: &str) -> bool {
        if is_script_or_style(content_type) {
            return self
                .code_re
                .as_ref()
                .is_some_and(|r| id_matches(r, s).next().is_some());
        }
        if content_type.contains("json")
            && let Ok(v) = serde_json::from_str::<Value>(s)
        {
            return self.json_has_identity(&v);
        }
        self.text_has_identity(s)
    }

    fn json_has_identity(&self, v: &Value) -> bool {
        match v {
            Value::String(s) => self.ids.fake_for(s).is_some() || self.text_has_identity(s),
            Value::Array(a) => a.iter().any(|x| self.json_has_identity(x)),
            Value::Object(o) => o
                .iter()
                .any(|(k, x)| self.text_has_identity(k) || self.json_has_identity(x)),
            _ => false,
        }
    }

    /// Whether raw bytes (binary or non-UTF-8 bodies) contain a distinctive identity value,
    /// as UTF-8 or UTF-16LE, ignoring ASCII case.
    pub fn bytes_have_identity(&self, b: &[u8]) -> bool {
        let hay = b.to_ascii_lowercase();
        self.ids.reals().filter(|r| distinctive(r)).any(|r| {
            let lower = r.to_ascii_lowercase();
            let utf16: Vec<u8> = lower.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let pct = pct_encode(&lower, false).to_ascii_lowercase();
            let pct2 = pct_encode(&pct, false).to_ascii_lowercase();
            contains(&hay, lower.as_bytes())
                || contains(&hay, &utf16)
                || contains(&hay, pct.as_bytes())
                || contains(&hay, pct2.as_bytes())
        })
    }

    /// Rewrite one storage value. MSAL credentials get fake secrets and far-future expiry.
    /// Returns `None` when the value must be dropped (e.g. encrypted MSAL v4 entries).
    pub fn storage_value(&self, value: &str) -> Option<String> {
        let Ok(mut v) = serde_json::from_str::<Value>(value) else {
            return Some(self.text(value));
        };
        if let Some(obj) = v.as_object_mut() {
            if obj.contains_key("nonce") && obj.contains_key("data") && obj.contains_key("id") {
                return None;
            }
            if let Some(kind) = obj.get("credentialType").and_then(Value::as_str) {
                let aud = obj
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("mimesia")
                    .to_string();
                let secret = match kind.to_ascii_lowercase().as_str() {
                    "refreshtoken" => "mimesia-fake-refresh-token".to_string(),
                    _ => self.persona.jwt(&aud),
                };
                obj.insert("secret".into(), Value::String(secret));
                for k in ["expiresOn", "extendedExpiresOn", "refreshOn"] {
                    if obj.contains_key(k) {
                        obj.insert(k.into(), Value::String(FAR_FUTURE.to_string()));
                    }
                }
            }
            if obj.contains_key("idTokenClaims") {
                obj.insert("idTokenClaims".into(), self.persona.claims("mimesia"));
            }
        }
        Some(self.body("application/json", &v.to_string()))
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A suspected leak. Never holds the matched value, only where it was found.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub kind: String,
    pub location: String,
}

/// Look for credentials that survived scrubbing.
pub fn leaks(text: &str, location: &str) -> Vec<Finding> {
    let prefix = fake_jwt_prefix();
    let mut kinds = Vec::new();
    if JWT
        .find_iter(text)
        .any(|m| !m.as_str().starts_with(&prefix))
    {
        kinds.push("jwt");
    }
    if URL_SECRET
        .captures_iter(text)
        .any(|c| &c[2] != REDACTED && !c[2].starts_with(&prefix))
    {
        kinds.push("url-secret");
    }
    if BEARER
        .captures_iter(text)
        .any(|c| &c[2] != REDACTED && !c[2].starts_with(&prefix))
    {
        kinds.push("bearer");
    }
    if TOKEN_FIELD
        .captures_iter(text)
        .any(|c| &c[2] != REDACTED && !c[2].starts_with(&prefix))
    {
        kinds.push("secret-field");
    }
    kinds
        .into_iter()
        .map(|k| Finding {
            kind: k.into(),
            location: location.into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_jwt() -> String {
        // header {"alg":"RS256"} . payload {"oid":"x"} . sig
        "eyJhbGciOiJSUzI1NiJ9.eyJvaWQiOiJ4In0xxxxxxxx.c2lnbmF0dXJl".into()
    }

    fn scrubber() -> Scrubber {
        let mut ids = IdentityMap::default();
        ids.learn_from_msal(
            &serde_json::json!({
                "homeAccountId": "11111111-2222-3333-4444-555555555555.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "username": "real.person@fabrikam.com",
                "name": "Real Person",
            }),
            &Persona::default(),
        );
        Scrubber::new(Persona::default(), ids)
    }

    #[test]
    fn learns_from_api_json() {
        let p = Persona::default();
        let mut ids = IdentityMap::default();
        ids.add("11111111-2222-3333-4444-555555555555", &p.oid);
        let v = serde_json::json!({
            "systemData": {"createdBy": "realp@fabrikam.com", "createdByType": "User"},
            "other": {"createdBy": "svc@fabrikam.com", "createdByType": "Application"},
            "assignment": {"principalId": "11111111-2222-3333-4444-555555555555", "name": "proj-1"},
            "user": {"objectId": "11111111-2222-3333-4444-555555555555", "displayName": "Real Person"},
        });
        ids.learn_from_json(&v, &p);
        // ARM creators are scrubbed but may be colleagues, so they prove nothing.
        assert!(ids.has_fake(&p.name) && !ids.has_fake(&p.upn));
        let s = Scrubber::new(p.clone(), ids);
        let out = s.text("Welcome, Real Person / Hi Real / realp@fabrikam.com / azureAI.realp.x");
        assert_eq!(
            out,
            "Welcome, Demo User / Hi Demo / demo.user@contoso.com / azureAI.demo.user.x"
        );
        assert_eq!(s.text("svc@fabrikam.com proj-1"), "svc@fabrikam.com proj-1");
    }

    #[test]
    fn encoded_and_glued_ids_scrubbed() {
        let p = Persona::default();
        let mut ids = IdentityMap::default();
        ids.add("3f6a1c2e-9b4d-4e1a-8c7f-2d5e6b7a8c90", &p.tid);
        ids.add_upn("real.person@fabrikam.com", &p);
        ids.add_name("Real Person", &p);
        let s = Scrubber::new(p.clone(), ids);
        let html = "x=%7B%22tid%22%3A%223f6a1c2e-9b4d-4e1a-8c7f-2d5e6b7a8c90%22%7D \
                    \\u00223f6a1c2e-9b4d-4e1a-8c7f-2d5e6b7a8c90 \
                    u=real.person%40fabrikam.com n=Real+Person m=Real%20Person";
        let out = s.text(html);
        assert!(s.identity_left("text/html", html));
        assert!(!s.identity_left("text/html", &out), "{out}");
        assert!(out.contains(&format!("%22{}%22", p.tid)), "{out}");
        assert!(out.contains(&pct_encode(&p.upn, false)), "{out}");
        assert!(out.contains(&pct_encode(&p.name, true)), "{out}");
        assert_eq!(
            s.text("user.3f6a1c2e-9b4d-4e1a-8c7f-2d5e6b7a8c90_AiStudio"),
            format!("user.{}_AiStudio", p.tid)
        );
        assert!(s.bytes_have_identity(b"real.person%40fabrikam.com"));
        // Double-encoded (a URL inside a URL).
        let dbl = "r=%25223f6a1c2e-9b4d-4e1a-8c7f-2d5e6b7a8c90%2522&u=real.person%2540fabrikam.com";
        let out = s.text(dbl);
        assert!(!s.identity_left("text/html", &out), "{out}");
        assert!(out.contains(&format!("%2522{}%2522", p.tid)), "{out}");
        assert!(
            out.contains(&pct_encode(&pct_encode(&p.upn, false), false)),
            "{out}"
        );
        assert!(s.bytes_have_identity(b"real.person%2540fabrikam.com"));
        // Still never matches inside a longer word.
        assert_eq!(s.text("RealPersonal"), "RealPersonal");
    }

    #[test]
    fn weak_upn_does_not_anchor_user_objects() {
        let p = Persona::default();
        let mut ids = IdentityMap::default();
        ids.learn_from_json(
            &serde_json::json!([
                {"createdBy": "colleague@fabrikam.com", "createdByType": "User"},
                {"mail": "colleague@fabrikam.com", "displayName": "Col League"},
            ]),
            &p,
        );
        assert!(!ids.has_fake(&p.name));
    }

    #[test]
    fn short_name_parts_scrubbed_in_text_only() {
        let p = Persona::default();
        let mut ids = IdentityMap::default();
        ids.add_name("Li Xu", &p);
        let s = Scrubber::new(p, ids);
        let html = "<h1>Welcome, Li</h1><p>Xu</p><p>Lima, Lisbon</p>";
        let out = s.body("text/html", html);
        assert_eq!(out, "<h1>Welcome, Demo</h1><p>User</p><p>Lima, Lisbon</p>");
        assert!(s.identity_left("text/html", html));
        assert!(!s.identity_left("text/html", &out));
        // Case-sensitive, and never inside scripts.
        assert_eq!(s.text("li, xu"), "li, xu");
        assert_eq!(s.body("application/javascript", "var Li=1"), "var Li=1");
        assert_eq!(
            s.body("application/json", r#"{"n":"Li"}"#),
            r#"{"n":"Demo"}"#
        );
    }

    #[test]
    fn given_identity_routes_by_shape() {
        let p = Persona::default();
        let mut ids = IdentityMap::default();
        ids.add_given("Real Person", &p);
        ids.add_given("real.person@fabrikam.com", &p);
        ids.add_given("realhandle", &p);
        assert!(ids.has_fake(&p.name) && ids.has_fake(&p.upn));
        let s = Scrubber::new(p, ids);
        assert_eq!(s.text("img-realhandle-1"), "img-demo.user-1");
    }

    #[test]
    fn scrubs_credentials() {
        let s = scrubber();
        let input = format!(
            r#"{{"t":"{}","u":"https://x.blob.core.windows.net/c/b?sv=1&sig=abc%2Bdef","h":"Bearer abcdefghijklmnopqrstuvwxyz","access_token":"opaque-token-value-123"}}"#,
            real_jwt()
        );
        let out = s.text(&input);
        assert!(leaks(&input, "in").len() >= 4);
        assert!(leaks(&out, "out").is_empty(), "{out}");
        assert!(out.contains("sig=REDACTED"));
    }

    #[test]
    fn scrubs_identity() {
        let s = scrubber();
        let out = s.text(
            r#"{"user":"REAL.PERSON@fabrikam.com","tid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","display":"Real Person"}"#,
        );
        assert!(out.contains("demo.user@contoso.com"));
        assert!(out.contains(&Persona::default().tid));
        assert!(out.contains("Demo User"));
        assert!(!s.identity_left("text/plain", &out), "{out}");
    }

    #[test]
    fn scripts_only_lose_distinctive_values() {
        let mut ids = IdentityMap::default();
        ids.add("Real Person", "Demo User");
        ids.add("Admin", "Demo");
        let s = Scrubber::new(Persona::default(), ids);
        assert_eq!(
            s.body(
                "application/javascript",
                "var u='Real Person';if(isAdmin||Admin)x()"
            ),
            "var u='Demo User';if(isAdmin||Admin)x()"
        );
        assert_eq!(s.text("realtime Real Personal"), "realtime Real Personal");
    }

    #[test]
    fn json_short_values_replaced_whole() {
        let mut ids = IdentityMap::default();
        ids.add("Li", "Demo User");
        let s = Scrubber::new(Persona::default(), ids);
        let out = s.body(
            "application/json",
            r#"{"name":"li","city":"Lima","tag":"<li>"}"#,
        );
        assert_eq!(out, r#"{"name":"Demo User","city":"Lima","tag":"<li>"}"#);
        assert!(!s.identity_left("application/json", &out));
        assert!(s.identity_left("application/json", r#"{"n":"Li"}"#));
    }

    #[test]
    fn opaque_secrets() {
        let s = scrubber();
        for (input, gone) in [
            ("https://a.com/x?access_token=opaque123&y=1", "opaque123"),
            ("<a href=\"/d?sv=1&amp;sig=abc%2Bdef\">", "abc%2Bdef"),
            (r#"{"sasToken":"sv=2024&sig=zzzzzzzz"}"#, "zzzzzzzz"),
            (r#"{"primaryKey":"Zm9vYmFyYmF6cXV4"}"#, "Zm9vYmFyYmF6cXV4"),
        ] {
            assert!(!leaks(input, "in").is_empty(), "{input}");
            let out = s.body("application/json", input);
            assert!(!out.contains(gone), "{out}");
            assert!(leaks(&out, "out").is_empty(), "{out}");
        }
    }

    #[test]
    fn binary_identity_detected() {
        let s = scrubber();
        let utf16: Vec<u8> = "x REAL.person@fabrikam.com"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(s.bytes_have_identity(&utf16));
        assert!(!s.bytes_have_identity(b"\x89PNG nothing here"));
    }

    #[test]
    fn msal_credential_rewritten() {
        let s = scrubber();
        let entry = serde_json::json!({
            "credentialType": "AccessToken",
            "homeAccountId": "11111111-2222-3333-4444-555555555555.aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "secret": real_jwt(),
            "expiresOn": "1700000000",
            "target": "https://management.azure.com/.default",
        });
        let out = s.storage_value(&entry.to_string()).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["expiresOn"], FAR_FUTURE.to_string());
        assert!(
            v["secret"]
                .as_str()
                .unwrap()
                .starts_with(&fake_jwt_prefix())
        );
        assert!(
            v["homeAccountId"]
                .as_str()
                .unwrap()
                .starts_with(&Persona::default().oid)
        );
        assert!(leaks(&out, "x").is_empty());
    }

    #[test]
    fn msal_encrypted_dropped() {
        let s = scrubber();
        assert!(
            s.storage_value(r#"{"id":"1","nonce":"n","data":"d","lastUpdatedAt":"1"}"#)
                .is_none()
        );
    }
}
