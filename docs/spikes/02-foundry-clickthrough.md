# Spike 02: Foundry click-through

Goal: a replay you can click around, not just one page. Sanitized: counts only.

## Run

| Step | Command / action |
|---|---|
| 1 | Debug Edge signed in to ai.azure.com, as in [spike 01](01-foundry.md) |
| 2 | `mimesia record <fragment> --out captures/foundry-05 --identity ... --explore` |
| 3 | Click every page you want in the clone; press Enter in the recorder (don't type anything else while armed) |
| 4 | Recorder crawls the lazy shell chunks, then scrubs and scans |
| 5 | `mimesia verify captures/foundry-05`; `mimesia replay captures/foundry-05 --headed` |

## Results

| Measure | Value |
|---|---|
| Recorded entries | 3,525 |
| Shell files crawled | 1,995 in ~20 s |
| `verify` | PASS, 0.029% pixels differ, 743 hits, 0 near, 0 misses |
| Headed walk | 25 pages (project, agents, traces, monitor, evals, models, tools, knowledge, guardrails, data, services, fine-tune, manage, playground), all SPA navigation, 0 misses |
| Visible differences | replay badge, persona avatar, scrubbed tenant id |

## Findings

| Finding | Fix |
|---|---|
| Clicking a page not seen while recording missed lazy JS chunks | Crawl: after explore, fetch every chunk named in the loaded bundles |
| Crawl fetches hung: Edge freezes hidden or occluded tabs (timers never fire) | `keep_awake`: `Page.setWebLifecycleState active` + focus emulation, held for the CDP session |
| App's patched `fetch` interfered with crawl | Fetch from a pristine hidden iframe, credentials omitted |
| Identity hidden as percent-encoded or glued into other tokens | Scrubber decodes and matches inside tokens |
| RPC POST bodies carry per-call ids and clock-relative windows | JSON body normalization, then **near** match: same method + URL, most equal leaves |
| Identity lookups sorted then batched by 5; persona id shifts every batch | Scalar arrays compare as sets |
| Request bodies could carry identity | Scrubbed JSON-aware and leak-checked; binary bodies with identity dropped |
| Near-match logs could print ids (set members, id-like keys) | Logged paths hide members and replace id-like keys with `*` |
| Typing in the recorder terminal ended explore early | Documented: any line is Enter |

## Open

| Item | Notes |
|---|---|
| Id-batch shift | ~1 of 5 identities per shifted batch still unresolved; fix in the scenario layer (id map) |
| Time-window near matches | `timespan`, `parentRequestId` vary per call; harmless, could normalize |
| Crawl memory | 4,000 files / 300 MB caps are counted, not strictly bounded |
| Encodings | HTML-entity and base64 identity not scrubbed yet |
