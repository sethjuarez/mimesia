//! Persona (fake user/tenant) and fake tokens.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Far-future expiry: 2100-01-01T00:00:00Z.
pub const FAR_FUTURE: i64 = 4_102_444_800;

/// Header of every token Mimesia mints. Scan treats JWTs with this header as safe.
pub const FAKE_JWT_HEADER: &str = r#"{"alg":"none","typ":"JWT","kid":"mimesia"}"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Persona {
    pub name: String,
    pub upn: String,
    pub oid: String,
    pub tid: String,
}

impl Default for Persona {
    fn default() -> Self {
        Self {
            name: "Demo User".into(),
            upn: "demo.user@contoso.com".into(),
            oid: "00000000-0000-4000-8000-0000000000a1".into(),
            tid: "00000000-0000-4000-8000-0000000000b1".into(),
        }
    }
}

impl Persona {
    pub fn home_account_id(&self) -> String {
        format!("{}.{}", self.oid, self.tid)
    }

    pub fn claims(&self, aud: &str) -> serde_json::Value {
        json!({
            "aud": aud,
            "iss": format!("https://login.microsoftonline.com/{}/v2.0", self.tid),
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": FAR_FUTURE,
            "name": self.name,
            "oid": self.oid,
            "tid": self.tid,
            "sub": self.oid,
            "upn": self.upn,
            "preferred_username": self.upn,
            "unique_name": self.upn,
            "ver": "2.0",
        })
    }

    /// Unsigned JWT carrying persona claims.
    pub fn jwt(&self, aud: &str) -> String {
        sign(&self.claims(aud))
    }

    /// MSAL `client_info`: base64url `{"uid","utid"}`.
    pub fn client_info(&self) -> String {
        URL_SAFE_NO_PAD.encode(json!({ "uid": self.oid, "utid": self.tid }).to_string())
    }
}

/// Unsigned JWT with the given claims and Mimesia's marker header.
pub fn sign(claims: &serde_json::Value) -> String {
    format!(
        "{}.{}.mimesia",
        fake_jwt_prefix(),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

pub fn fake_jwt_prefix() -> String {
    URL_SAFE_NO_PAD.encode(FAKE_JWT_HEADER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_shape() {
        let t = Persona::default().jwt("api://x");
        let parts: Vec<_> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(t.starts_with("eyJ"));
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["exp"], FAR_FUTURE);
    }
}
