//! Host and path classification.

use std::sync::LazyLock;

use regex::Regex;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Sign-in traffic. Never recorded; stubbed on replay.
    Identity,
    /// Telemetry beacons. Not recorded; answered with 204 on replay.
    Telemetry,
    /// User photo endpoints. Recorded as 404 so the app falls back to initials.
    Photo,
    Normal,
}

const IDENTITY_HOSTS: &[&str] = &[
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "login.windows.net",
    "sts.windows.net",
];
const IDENTITY_SUFFIXES: &[&str] = &[".msauth.net", ".msftauth.net"];
const IDENTITY_PATHS: &[&str] = &["/oauth2/", "/.well-known/openid-configuration"];

const TELEMETRY_SUFFIXES: &[&str] = &[
    "events.data.microsoft.com",
    "applicationinsights.azure.com",
    "dc.services.visualstudio.com",
    "js.monitor.azure.com",
    "clarity.ms",
];

pub fn classify(url: &str) -> Class {
    let Ok(u) = Url::parse(url) else {
        return Class::Normal;
    };
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = u.path().to_ascii_lowercase();

    if IDENTITY_HOSTS.contains(&host.as_str())
        || host.starts_with("aadcdn")
        || IDENTITY_SUFFIXES.iter().any(|s| host.ends_with(s))
        || IDENTITY_PATHS.iter().any(|p| path.contains(p))
    {
        return Class::Identity;
    }
    if TELEMETRY_SUFFIXES
        .iter()
        .any(|s| host == *s || host.ends_with(&format!(".{s}")))
    {
        return Class::Telemetry;
    }
    // Same-origin beacons, e.g. Foundry's `/nextgen/clientTelemetry` and
    // `/foundry-telemetry/v2/track` (App Insights ingestion proxied).
    if path.ends_with("/v2/track")
        || path.ends_with("/v2.1/track")
        || path.split('/').any(|s| TELEMETRY_SEGMENT.is_match(s))
    {
        return Class::Telemetry;
    }
    if host == "graph.microsoft.com" && (path.contains("/photo/") || path.contains("/photos/")) {
        return Class::Photo;
    }
    // App proxies for the signed-in user's photo, e.g. Foundry's
    // `POST /nextgen/api/query?getMyProfileImageResolver`. Whole segments/keys only.
    let query = u.query().unwrap_or_default();
    if path
        .split('/')
        .chain(
            query
                .split('&')
                .map(|kv| kv.split('=').next().unwrap_or_default()),
        )
        .any(|s| PHOTO.is_match(s))
    {
        return Class::Photo;
    }
    Class::Normal
}

static TELEMETRY_SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(client|[a-z0-9]+-)?telemetry$").unwrap());

static PHOTO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(get)?(my|user)?profile(image|photo|picture)(resolver)?$|^(get)?(my|user)(photo|avatar|picture)(resolver)?$",
    )
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity() {
        for u in [
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "https://aadcdn.msftauth.net/shared/1.0/x.js",
            "https://logincdn.msauth.net/a.js",
            "https://example.com/tenant/oauth2/authorize",
            "https://example.com/.well-known/openid-configuration",
        ] {
            assert_eq!(classify(u), Class::Identity, "{u}");
        }
    }

    #[test]
    fn telemetry_and_photo() {
        assert_eq!(
            classify("https://browser.events.data.microsoft.com/OneCollector/1.0/"),
            Class::Telemetry
        );
        assert_eq!(
            classify("https://westus-0.in.applicationinsights.azure.com/v2/track"),
            Class::Telemetry
        );
        for u in [
            "https://ai.azure.com/nextgen/clientTelemetry",
            "https://ai.azure.com/foundry-telemetry/v2/track",
            "https://ai.azure.com/x/v2/track",
        ] {
            assert_eq!(classify(u), Class::Telemetry, "{u}");
        }
        for u in [
            "https://ai.azure.com/docs/telemetryGuide",
            "https://ai.azure.com/api/v2/tracks",
        ] {
            assert_eq!(classify(u), Class::Normal, "{u}");
        }
        assert_eq!(
            classify("https://graph.microsoft.com/v1.0/me/photo/$value"),
            Class::Photo
        );
        assert_eq!(
            classify("https://ai.azure.com/nextgen/api/query?getMyProfileImageResolver"),
            Class::Photo
        );
        for u in [
            "https://ai.azure.com/docs/profileImageCustomization",
            "https://ai.azure.com/api/x?profileImageEnabled=true",
            "https://ai.azure.com/images/avatar.svg",
        ] {
            assert_eq!(classify(u), Class::Normal, "{u}");
        }
    }

    #[test]
    fn normal() {
        assert_eq!(classify("https://ai.azure.com/api/projects"), Class::Normal);
        assert_eq!(
            classify("https://management.azure.com/subscriptions"),
            Class::Normal
        );
        assert_eq!(
            classify("https://graph.microsoft.com/v1.0/me"),
            Class::Normal
        );
    }
}
