# Mimesia

Clone the **shell** of a large web app for demos, swap in demo data, project future features into it, and re-sync cheaply when the live site changes.

Built for Microsoft demoers working with apps like Microsoft Foundry (ai.azure.com) and the M365 admin center.

## Idea

**Record and replay. Don't rebuild.** Mimesia captures the real app's static bundles as served and answers its data calls from editable fixtures. Minified JS is never rewritten.

| Layer | What | When the site changes |
|---|---|---|
| Shell | HTML, JS, CSS, fonts (content-addressed) | recapture wholesale |
| Contract | baseline API responses + inferred schemas | re-record, diff schemas |
| Scenario | demo data as patches on the baseline, plus a persona | rebase patches |
| Projections | future features: flags, injected components, invented endpoints | check anchors + visuals |

See [docs/DESIGN.md](docs/DESIGN.md).

## Status

Live Foundry replays offline as a fake persona: a 25-page click-through with 0 misses and 0.029% pixel diff ([spike 01](docs/spikes/01-foundry.md), [spike 02](docs/spikes/02-foundry-clickthrough.md)). It also exports as a plain static site hydrated from the recorded JSON, with the same 25-page walk at 0 misses ([spike 03](docs/spikes/03-static-export.md)).

| Command | Does |
|---|---|
| `mimesia tabs` | list tabs in a debug-enabled browser |
| `mimesia record` | capture a signed-in tab (auth excluded); `--explore` records while you click, then crawls lazy chunks |
| `mimesia scan` | fail if a capture leaks tokens or tenant data |
| `mimesia replay` | serve the capture offline in a fresh browser |
| `mimesia verify` | replay, screenshot, pixel-diff vs recording |
| `mimesia export` | write a static site: shell files + `_mimesia/` data and shim |
| `mimesia serve` | host an export locally at `<recorded-host>.localhost` |
| `mimesia verify-export` | serve an export offline, screenshot, pixel-diff vs recording |

## Quick start

```powershell
# 1. Start Edge with a debug port and a throwaway profile, then sign in.
& "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" --remote-debugging-port=9333 --user-data-dir=$env:TEMP\mimesia-edge

# 2. Find the tab, record, check, verify (replay --headed to click around).
cargo run -- tabs
cargo run -- record ai.azure.com --out captures/foundry --identity "Your Name" --identity you@contoso.com
cargo run -- scan captures/foundry
cargo run -- verify captures/foundry

# 3. Static site: export, check, open http://ai.azure.com.localhost:8080<start>.
cargo run -- export captures/foundry --out captures/foundry-site
cargo run -- verify-export captures/foundry captures/foundry-site
cargo run -- serve captures/foundry-site
```

## Safety

- Sign-in is excluded and recording fails closed: identity traffic is dropped, credential headers are never stored, and a capture is unusable until `scan` passes.
- `record` fails unless it knows your display name and UPN. Apps with cookie sessions or encrypted MSAL caches don't expose them, so pass `--identity` (repeatable; also accepts aliases/handles).
- Exports contain recorded tenant data; keep them under `captures/` until the scenario layer replaces it.
- Replay is offline: unmatched requests fail and are reported; anything that slips past interception hits a reject proxy.
- `record.png` and `verify/replay.png` are real screenshots. `captures/` is gitignored, and `record` refuses an output path Git would track. Never commit raw captures.
