# Spike 01: Microsoft Foundry

Goal: record one Foundry page, replay it offline as the persona, and verify it visually. Results go here **sanitized**: counts and observations only, no URLs with IDs, tenant data, or screenshots.

## Run

| Step | Command / action |
|---|---|
| 1 | Start Edge: `msedge --remote-debugging-port=9333 --user-data-dir=%TEMP%\mimesia-edge` |
| 2 | Sign in to ai.azure.com; open the target page; wait until loaded |
| 3 | `mimesia tabs` → pick a URL fragment for the tab |
| 4 | `mimesia record <fragment> --out captures/foundry-01 --identity "<Display Name>" --identity <upn>` |
| 5 | `mimesia scan captures/foundry-01` (must pass) |
| 6 | `mimesia verify captures/foundry-01` |
| 7 | `mimesia replay captures/foundry-01 --headed`; click around |
| 8 | Close the debug Edge; delete `%TEMP%\mimesia-edge` |

## Questions this answers

| Risk | Evidence | Result |
|---|---|---|
| Fake MSAL session | replay shows persona, no login redirect; `identity_stubbed` count | Not exercised: Foundry home renders from a cookie-session BFF (SSR + `/api/query`); 0 identity calls on replay |
| MSAL cache shape | storage keys seeded vs keys MSAL wrote (v4 encrypted cache cannot be seeded) | Encrypted cache: 4 entries dropped; only oid/tid learnable from active-account filters |
| Push channels / frames / workers | `inventory.json`: websockets, event streams, frames | None on this page |
| Multi-origin hosts | host count in inventory; zero misses | 2 hosts (app origin + 1 telemetry); 0 misses |
| Lazy chunks | misses after clicking around in `--headed` | Not tested yet (single-page spike) |
| Volatile params | misses that differ from a recorded URL only by query | RPC POSTs (`/api/query?<resolver>`) vary by body → body-ignoring fallback |
| Leaks | `scan` result; manual grep of capture for name/UPN/tenant | First run leaked name (SSR HTML) and UPN (ARM `systemData`, storage keys); fixed; grep now clean |
| Visual fidelity | `verify` diff ratio; what the mask highlights | 0.57% (persona name/avatar + endpoints card variant) |

## Results

Project home page, one recording: 285 requests, 2 hosts, 0 websockets/streams/frames.

| Finding | Fix |
|---|---|
| Name/UPN never in tokens (cookie BFF, encrypted MSAL) | `--identity`; record fails closed without trusted name + UPN |
| Name in SSR HTML and Remix turbo-stream (not JSON) | free-text + case-sensitive name-part scrubbing |
| UPN in ARM `systemData` and storage keys | learned from JSON; ARM creators weak (scrubbed, untrusted) |
| Photo via `POST /api/query?getMyProfileImageResolver` | Photo rule on path segments / query keys → 404 → initials |
| Headless hid scrollbars → 6.6% layout shift | launch `--headless=new` without `--hide-scrollbars` |
| Window resized between snapshot and screenshot | viewport measured at screenshot time |
| Same-origin telemetry (`/clientTelemetry`, `/foundry-telemetry/v2/track`) | classified as telemetry |
| RPC POST bodies differ per run | match on method + URL + query, body ignored |

Final `verify`: **PASS**, 0.57% diff, 290 hits, 0 misses, 0 escaped. Remaining diff: persona name/avatar (expected) and the endpoints card rendering a different variant (open).

Next: click-through for lazy chunks; an MSAL-token page (e.g. ARM-backed) to exercise the fake session.
