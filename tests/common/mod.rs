//! Offline fixture site: an "app" origin and a cross-origin "API", with an MSAL-shaped
//! sign-in, a lazy chunk, an identity call, and credential bait for the scrubber.

#![allow(dead_code)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const REAL_OID: &str = "11111111-2222-3333-4444-555555555555";
pub const REAL_TID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
pub const REAL_UPN: &str = "real.person@fabrikam.com";
pub const REAL_NAME: &str = "Real Person";
pub const CLIENT_ID: &str = "fixture-client";

pub fn real_jwt() -> String {
    let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let p = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "oid": REAL_OID, "tid": REAL_TID, "upn": REAL_UPN, "name": REAL_NAME,
            "exp": 1_900_000_000u64
        })
        .to_string(),
    );
    format!("{h}.{p}.cmVhbHNpZ25hdHVyZXJlYWxzaWduYXR1cmU")
}

pub struct Fixture {
    pub app: String,
    pub api: String,
    tasks: Vec<JoinHandle<()>>,
}

impl Fixture {
    pub async fn start() -> Self {
        let app_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = format!("http://127.0.0.1:{}", app_l.local_addr().unwrap().port());
        // Different host name => different origin => CORS preflight for the bearer call.
        let api = format!("http://localhost:{}", api_l.local_addr().unwrap().port());
        let api2 = api.clone();
        let tasks = vec![
            tokio::spawn(serve(app_l, move |m: &str, p: &str| app_route(m, p, &api2))),
            tokio::spawn(serve(api_l, api_route)),
        ];
        Self { app, api, tasks }
    }

    /// Stop serving so replay must be self-contained.
    pub fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
    }

    /// JS that signs the page in by seeding an MSAL-shaped cache.
    pub fn sign_in_js() -> String {
        let home = format!("{REAL_OID}.{REAL_TID}");
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let jwt = real_jwt();
        let account_key = format!("{home}-login.windows.net-{REAL_TID}");
        let id_key = format!("{home}-login.windows.net-idtoken-{CLIENT_ID}-{REAL_TID}---");
        let at_key = format!(
            "{home}-login.windows.net-accesstoken-{CLIENT_ID}-{REAL_TID}-api://fixture/.default--"
        );
        let rt_key = format!("{home}-login.windows.net-refreshtoken-{CLIENT_ID}----");
        let items = serde_json::json!([
            [format!("msal.token.keys.{CLIENT_ID}"), serde_json::json!({"idToken":[id_key],"accessToken":[at_key],"refreshToken":[rt_key]}).to_string()],
            ["msal.account.keys", serde_json::json!([account_key]).to_string()],
            [account_key, serde_json::json!({"homeAccountId":home,"environment":"login.windows.net","realm":REAL_TID,"localAccountId":REAL_OID,"username":REAL_UPN,"name":REAL_NAME,"authorityType":"MSSTS"}).to_string()],
            [id_key, serde_json::json!({"credentialType":"IdToken","homeAccountId":home,"environment":"login.windows.net","clientId":CLIENT_ID,"realm":REAL_TID,"secret":jwt}).to_string()],
            [at_key, serde_json::json!({"credentialType":"AccessToken","homeAccountId":home,"environment":"login.windows.net","clientId":CLIENT_ID,"realm":REAL_TID,"target":"api://fixture/.default","secret":jwt,"expiresOn":exp.to_string(),"extendedExpiresOn":exp.to_string(),"cachedAt":"1700000000","tokenType":"Bearer"}).to_string()],
            [rt_key, serde_json::json!({"credentialType":"RefreshToken","homeAccountId":home,"environment":"login.windows.net","clientId":CLIENT_ID,"secret":"0.AAAArealrefreshtokenvalue"}).to_string()],
            ["app.theme", "light"],
        ]);
        format!(
            "(() => {{ for (const [k, v] of {items}) localStorage.setItem(k, v); return true; }})()"
        )
    }
}

type Resp = (u16, &'static str, Vec<u8>);

fn app_route(method: &str, path: &str, api: &str) -> Resp {
    let path = path.split('?').next().unwrap_or("");
    match (method, path) {
        ("GET", "/") => (200, "text/html; charset=utf-8", INDEX.into()),
        ("GET", "/app.css") => (200, "text/css", CSS.into()),
        ("GET", "/app.js") => (200, "text/javascript", APP_JS.replace("__API__", api).into()),
        ("GET", "/lazy.js") => (200, "text/javascript", LAZY_JS.into()),
        ("GET", "/logo.svg") => (200, "image/svg+xml", LOGO.into()),
        ("GET", "/api/me") => (
            200,
            "application/json",
            serde_json::json!({"id": REAL_OID, "displayName": REAL_NAME, "userPrincipalName": REAL_UPN})
                .to_string()
                .into(),
        ),
        ("POST", "/fixture-tenant/oauth2/v2.0/token") => (
            200,
            "application/json",
            serde_json::json!({"access_token": real_jwt(), "token_type": "Bearer"})
                .to_string()
                .into(),
        ),
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

fn api_route(method: &str, path: &str) -> Resp {
    match method {
        "OPTIONS" => (204, "text/plain", Vec::new()),
        _ if path.starts_with("/api/items") => (
            200,
            "application/json",
            serde_json::json!({
                "items": [{"name": "Alpha"}, {"name": "Beta"}, {"name": "Gamma"}],
                "download": "https://x.blob.core.windows.net/c/b.txt?sv=2024&sig=SECRETsig%2Bvalue",
                "token": real_jwt(),
                "owner": REAL_UPN,
            })
            .to_string()
            .into(),
        ),
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

async fn serve<F>(l: TcpListener, route: F)
where
    F: Fn(&str, &str) -> Resp + Send + Sync + 'static + Clone,
{
    loop {
        let Ok((mut sock, _)) = l.accept().await else {
            return;
        };
        let route = route.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let Ok(n) = sock.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.eq_ignore_ascii_case("content-length") {
                        v.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let Ok(n) = sock.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let mut first = head.lines().next().unwrap_or("").split_whitespace();
            let method = first.next().unwrap_or("").to_string();
            let path = first.next().unwrap_or("/").to_string();
            let (status, ct, body) = route(&method, &path);
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: {ct}\r\ncontent-length: {}\r\naccess-control-allow-origin: *\r\naccess-control-allow-headers: authorization, content-type\r\ncache-control: no-store\r\nset-cookie: session=realsessioncookie\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        });
    }
}

const INDEX: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Fixture</title><link rel="stylesheet" href="/app.css"><link rel="icon" href="data:,"></head>
<body>
<header><img src="/logo.svg" width="40" height="40" alt=""><span id="who">loading…</span></header>
<ul id="items"></ul>
<footer id="lazy"></footer>
<script src="/app.js"></script>
</body></html>"#;

const CSS: &str = "body{font:16px Segoe UI,Arial,sans-serif;margin:24px;background:#fafafa}header{display:flex;gap:12px;align-items:center;font-weight:600}li{padding:4px 0}footer{margin-top:24px;color:#0f6cbd}";

const LOGO: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#0f6cbd"/><text x="20" y="27" font-size="18" text-anchor="middle" fill="#fff">M</text></svg>"##;

const LAZY_JS: &str = "export function render(el) { el.textContent = 'lazy chunk loaded'; }";

const APP_JS: &str = r#"(async () => {
  const API = '__API__';
  const b64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); return atob(s + '='.repeat((4 - s.length % 4) % 4)); };
  const who = document.getElementById('who');
  const keys = JSON.parse(localStorage.getItem('msal.token.keys.fixture-client') || '{}');
  const at = keys.accessToken && JSON.parse(localStorage.getItem(keys.accessToken[0]) || 'null');
  if (!at || Number(at.expiresOn) < Date.now() / 1000) { who.textContent = 'SIGNED OUT'; return; }
  // Silent renew, like MSAL would do. Must never be recorded.
  fetch('/fixture-tenant/oauth2/v2.0/token', { method: 'POST', body: 'grant_type=refresh_token' }).catch(() => {});
  const claims = JSON.parse(b64(at.secret.split('.')[1]));
  const me = await (await fetch('/api/me')).json();
  who.textContent = 'Signed in as ' + me.displayName + ' (' + claims.upn + ')';
  const items = await (await fetch(API + '/api/items?_=' + Date.now(), { headers: { Authorization: 'Bearer ' + at.secret } })).json();
  document.getElementById('items').innerHTML = items.items.map(i => '<li>' + i.name + '</li>').join('');
  const m = await import('/lazy.js');
  m.render(document.getElementById('lazy'));
  document.body.dataset.ready = '1';
})();"#;
