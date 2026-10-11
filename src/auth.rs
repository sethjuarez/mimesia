//! Fake identity endpoints for replay.
//!
//! The fake MSAL cache should satisfy `acquireTokenSilent` on its own. These stubs catch what
//! leaks through: discovery, token refresh, and hidden-iframe `authorize` calls. Authorize
//! redirects back with a code whose token response echoes the request nonce, so MSAL's
//! nonce check passes.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use url::Url;

use crate::persona::{Persona, sign};

pub struct Stub {
    pub status: i64,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Stub {
    fn json(v: Value) -> Self {
        Self {
            status: 200,
            headers: cors(vec![("content-type".into(), "application/json".into())]),
            body: v.to_string().into_bytes(),
        }
    }

    pub fn empty(status: i64) -> Self {
        Self {
            status,
            headers: cors(Vec::new()),
            body: Vec::new(),
        }
    }
}

fn cors(mut h: Vec<(String, String)>) -> Vec<(String, String)> {
    h.push(("access-control-allow-origin".into(), "*".into()));
    h
}

/// Answer one identity request.
pub fn identity(method: &str, url: &str, body: Option<&[u8]>, p: &Persona) -> Stub {
    let Ok(u) = Url::parse(url) else {
        return Stub::empty(204);
    };
    if method.eq_ignore_ascii_case("OPTIONS") {
        let mut s = Stub::empty(204);
        s.headers
            .push(("access-control-allow-headers".into(), "*".into()));
        s.headers
            .push(("access-control-allow-methods".into(), "*".into()));
        return s;
    }
    let path = u.path().to_ascii_lowercase();
    let origin = u.origin().ascii_serialization();
    let tenant = u
        .path_segments()
        .and_then(|mut s| s.next())
        .filter(|s| !s.is_empty())
        .unwrap_or("common")
        .to_string();
    let base = format!("{origin}/{tenant}");

    if path.ends_with("/.well-known/openid-configuration") {
        return Stub::json(json!({
            "issuer": format!("https://login.microsoftonline.com/{}/v2.0", p.tid),
            "authorization_endpoint": format!("{base}/oauth2/v2.0/authorize"),
            "token_endpoint": format!("{base}/oauth2/v2.0/token"),
            "end_session_endpoint": format!("{base}/oauth2/v2.0/logout"),
            "jwks_uri": format!("{base}/discovery/v2.0/keys"),
            "response_modes_supported": ["query", "fragment"],
            "response_types_supported": ["code", "id_token", "code id_token", "id_token token"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "tenant_region_scope": "NA",
        }));
    }
    if path.contains("/discovery/instance") {
        return Stub::json(json!({
            "tenant_discovery_endpoint": format!("{base}/v2.0/.well-known/openid-configuration"),
            "api-version": "1.1",
            "metadata": [{
                "preferred_network": "login.microsoftonline.com",
                "preferred_cache": "login.windows.net",
                "aliases": ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com", "sts.windows.net"],
            }],
        }));
    }
    if path.contains("/discovery/") && path.ends_with("/keys") {
        return Stub::json(json!({ "keys": [] }));
    }
    if path.ends_with("/oauth2/v2.0/token") || path.ends_with("/oauth2/token") {
        return token(body, p);
    }
    if path.ends_with("/oauth2/v2.0/authorize") || path.ends_with("/oauth2/authorize") {
        return authorize(&u, p);
    }
    // Login page assets and anything else: empty, never a real sign-in UI.
    Stub::empty(204)
}

fn token(body: Option<&[u8]>, p: &Persona) -> Stub {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.unwrap_or_default())
        .into_owned()
        .collect();
    let client_id = form.get("client_id").cloned().unwrap_or_default();
    let scope = form
        .get("scope")
        .cloned()
        .unwrap_or_else(|| "openid profile".into());
    let (resource, scp) = resource_of(&scope);
    let resource = resource.unwrap_or_else(|| client_id.clone());
    let mut at = p.claims(&resource);
    at["azp"] = Value::String(client_id.clone());
    at["scp"] = Value::String(scp);
    let mut id_claims = p.claims(&client_id);
    if let Some(nonce) = form
        .get("code")
        .and_then(|c| c.strip_prefix("mimesia."))
        .and_then(|n| URL_SAFE_NO_PAD.decode(n).ok())
        .and_then(|n| String::from_utf8(n).ok())
    {
        id_claims["nonce"] = Value::String(nonce);
    }
    Stub::json(json!({
        "token_type": "Bearer",
        "scope": scope,
        "expires_in": 86399,
        "ext_expires_in": 86399,
        "access_token": sign(&at),
        "id_token": sign(&id_claims),
        "refresh_token": "mimesia-fake-refresh-token",
        "client_info": p.client_info(),
    }))
}

fn authorize(u: &Url, p: &Persona) -> Stub {
    let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
    let Some(redirect) = q.get("redirect_uri") else {
        return Stub::empty(204);
    };
    let nonce = q.get("nonce").cloned().unwrap_or_default();
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair(
        "code",
        &format!("mimesia.{}", URL_SAFE_NO_PAD.encode(nonce)),
    );
    params.append_pair("client_info", &p.client_info());
    if let Some(state) = q.get("state") {
        params.append_pair("state", state);
    }
    let params = params.finish();
    // OAuth's default for code is query; MSAL.js asks for fragment or query explicitly.
    let sep = match q.get("response_mode").map(String::as_str) {
        Some("fragment") => '#',
        _ if redirect.contains('?') => '&',
        _ => '?',
    };
    Stub {
        status: 302,
        headers: cors(vec![(
            "location".into(),
            format!("{redirect}{sep}{params}"),
        )]),
        body: Vec::new(),
    }
}

const OIDC: &[&str] = &["openid", "profile", "offline_access", "email"];

/// Split requested scopes into the access token's audience and `scp`.
/// `https://management.azure.com/.default` -> (`https://management.azure.com`, ``);
/// `api://x/access_as_user` -> (`api://x`, `access_as_user`); bare `User.Read` -> Graph.
fn resource_of(scope: &str) -> (Option<String>, String) {
    let mut resource = None;
    let mut scp = Vec::new();
    for s in scope.split_whitespace().filter(|s| !OIDC.contains(s)) {
        let (res, perm) = match s.rfind('/') {
            Some(i) if i > 0 => (&s[..i], &s[i + 1..]),
            _ => ("https://graph.microsoft.com", s),
        };
        resource.get_or_insert_with(|| res.to_string());
        if perm != ".default" && !perm.is_empty() {
            scp.push(perm);
        }
    }
    let scp = if scp.is_empty() {
        "user_impersonation".to_string()
    } else {
        scp.join(" ")
    };
    (resource, scp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(jwt: &str) -> Value {
        let part = jwt.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn authorize_then_token_echoes_nonce() {
        let p = Persona::default();
        let a = identity(
            "GET",
            "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=c&redirect_uri=https%3A%2F%2Fapp%2Fblank&nonce=N1&state=S1",
            None,
            &p,
        );
        assert_eq!(a.status, 302);
        let loc = &a.headers.iter().find(|(k, _)| k == "location").unwrap().1;
        assert!(loc.starts_with("https://app/blank?code=mimesia."), "{loc}");
        assert!(loc.contains("state=S1"));
        let code = Url::parse(loc)
            .unwrap()
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let body = format!(
            "client_id=c&grant_type=authorization_code&scope=openid%20api%3A%2F%2Fx%2F.default&code={code}"
        );
        let t = identity(
            "POST",
            "https://login.microsoftonline.com/t/oauth2/v2.0/token",
            Some(body.as_bytes()),
            &p,
        );
        let v: Value = serde_json::from_slice(&t.body).unwrap();
        let id = claims(v["id_token"].as_str().unwrap());
        assert_eq!(id["nonce"], "N1");
        assert_eq!(id["aud"], "c");
        let at = claims(v["access_token"].as_str().unwrap());
        assert_eq!(at["aud"], "api://x");
        assert_eq!(at["azp"], "c");
    }

    #[test]
    fn resources() {
        assert_eq!(
            resource_of("openid https://management.azure.com/.default"),
            (
                Some("https://management.azure.com".into()),
                "user_impersonation".into()
            )
        );
        assert_eq!(
            resource_of("api://x/a api://x/b offline_access"),
            (Some("api://x".into()), "a b".into())
        );
        assert_eq!(
            resource_of("User.Read"),
            (
                Some("https://graph.microsoft.com".into()),
                "User.Read".into()
            )
        );
        assert_eq!(resource_of("openid profile").0, None);
    }

    #[test]
    fn fragment_when_asked() {
        let s = identity(
            "GET",
            "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?redirect_uri=https%3A%2F%2Fapp%2F&response_mode=fragment",
            None,
            &Persona::default(),
        );
        assert!(
            s.headers
                .iter()
                .any(|(k, v)| k == "location" && v.starts_with("https://app/#code="))
        );
    }

    #[test]
    fn discovery() {
        let p = Persona::default();
        let s = identity(
            "GET",
            "https://login.microsoftonline.com/common/discovery/instance?api-version=1.1",
            None,
            &p,
        );
        let v: Value = serde_json::from_slice(&s.body).unwrap();
        assert!(v["metadata"].is_array());
    }
}
