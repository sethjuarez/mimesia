# Spike 03: Static export

Goal: render the clone as a plain static site (no service worker, no CDP, no server code), hydrated from recorded JSON. Sanitized: counts only.

## Run

| Step | Command |
|---|---|
| 1 | `mimesia export captures/foundry-05 --out captures/foundry-05-site` |
| 2 | `mimesia verify-export captures/foundry-05 captures/foundry-05-site` |
| 3 | `mimesia serve captures/foundry-05-site`, open `http://ai.azure.com.localhost:8080<start>` |

## Layout

| Path | Holds |
|---|---|
| `<recorded path>` | shell files, byte-identical, where the app expects them |
| `<start path>/index.html` | recorded document with `<script src="/_mimesia/boot.js">` first in `<head>` |
| `_mimesia/boot.js` | bootstrap (clock, fake MSAL session, SW block) + fetch/XHR shim + data index |
| `_mimesia/b/<hash>` | recorded response bodies (the demo data) |
| `_mimesia/export.json` | start, host, fallback, counts |
| `staticwebapp.config.json` | deep-link fallback for Azure Static Web Apps |

## Results

| Measure | Value |
|---|---|
| Export | 3,183 shell files, 257 data responses |
| `verify-export` | PASS, 0.03–0.08% pixels differ, 28 hits, 0 misses, 0 escaped |
| 25-step walk (network cut off) | all SPA navigation, 241 hits, 14 near, 0 misses |
| Cold deep link to `/home` | renders real Home page, 0 misses |

## Findings

| Finding | Handling |
|---|---|
| Foundry's API client rejects calls unless the page host contains `ai.azure.` | serve at `<recorded-host>.localhost` (Chromium resolves `*.localhost` to loopback); no JS rewrite |
| Unmatched same-origin GETs got the HTML fallback with 200, hiding misses | shim lets only exported shell paths through; everything else is a miss + 204 |
| Remix single-fetch: a deep link served the start document, whose embedded state belongs to another route ("No result found for routeId") | shim hydrates on the recorded route, then hands the wanted URL to the router via `popstate` |
| Repeated POSTs to one resolver (GraphQL-style `?xResolver`) | exact key includes the stable body; nearest body only when no exact match |

## Limits

| Limit | Note |
|---|---|
| Must be served at the site root | shell paths are absolute |
| Host must contain the recorded host for apps that check it | Azure: custom domain such as `ai.azure.<yours>` |
| Cross-origin images/fonts still go to the network | not intercepted by fetch/XHR |
| WebSocket/EventSource | parked (never open) |
| Recorded data is real tenant data | gitignored; the scenario layer must replace it before sharing |
