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

Spike 01: the CLI records one page over CDP, replays it offline, and diffs screenshots. Proven end to end on a local fixture app; the live Foundry run is next ([runbook](docs/spikes/01-foundry.md)).

| Command | Does |
|---|---|
| `mimesia tabs` | list tabs in a debug-enabled browser |
| `mimesia record` | capture one page from a signed-in tab (auth excluded) |
| `mimesia scan` | fail if a capture leaks tokens or tenant data |
| `mimesia replay` | serve the capture offline in a fresh browser |
| `mimesia verify` | replay, screenshot, pixel-diff vs recording |

## Quick start

```powershell
# 1. Start Edge with a debug port and a throwaway profile, then sign in.
& "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" --remote-debugging-port=9333 --user-data-dir=$env:TEMP\mimesia-edge

# 2. Find the tab, record, check, verify (replay --headed to click around).
cargo run -- tabs
cargo run -- record ai.azure.com --out captures/foundry
cargo run -- scan captures/foundry
cargo run -- verify captures/foundry
```

## Safety

- Sign-in is excluded and recording fails closed: identity traffic is dropped, credential headers are never stored, and a capture is unusable until `scan` passes.
- Replay is offline: unmatched requests fail and are reported; anything that slips past interception hits a reject proxy.
- `record.png` and `verify/replay.png` are real screenshots. `captures/` is gitignored, and `record` refuses an output path Git would track. Never commit raw captures.
