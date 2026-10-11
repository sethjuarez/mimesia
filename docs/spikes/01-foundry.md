# Spike 01: Microsoft Foundry

Goal: record one Foundry page, replay it offline as the persona, and verify it visually. Results go here **sanitized**: counts and observations only, no URLs with IDs, tenant data, or screenshots.

## Run

| Step | Command / action |
|---|---|
| 1 | Start Edge: `msedge --remote-debugging-port=9333 --user-data-dir=%TEMP%\mimesia-edge` |
| 2 | Sign in to ai.azure.com; open the target page; wait until loaded |
| 3 | `mimesia tabs` → pick a URL fragment for the tab |
| 4 | `mimesia record <fragment> --out captures/foundry-01` |
| 5 | `mimesia scan captures/foundry-01` (must pass) |
| 6 | `mimesia verify captures/foundry-01` |
| 7 | `mimesia replay captures/foundry-01 --headed`; click around |
| 8 | Close the debug Edge; delete `%TEMP%\mimesia-edge` |

## Questions this answers

| Risk | Evidence | Result |
|---|---|---|
| Fake MSAL session | replay shows persona, no login redirect; `identity_stubbed` count | |
| MSAL cache shape | storage keys seeded vs keys MSAL wrote (v4 encrypted cache cannot be seeded) | |
| Push channels / frames / workers | `inventory.json`: websockets, event streams, frames | |
| Multi-origin hosts | host count in inventory; zero misses | |
| Lazy chunks | misses after clicking around in `--headed` | |
| Volatile params | misses that differ from a recorded URL only by query | |
| Leaks | `scan` result; manual grep of capture for name/UPN/tenant | |
| Visual fidelity | `verify` diff ratio; what the mask highlights | |

## Results

Not run yet.
