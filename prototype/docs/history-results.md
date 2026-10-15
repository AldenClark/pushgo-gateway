# Native C2 history resource results

Source f57357c; fixture Release SHA256 `2611b966f30837854a08c3a36ee5982a1e0c258c78b615270d067cd8ea32fc10`. The two explicit history experiments instead run the Release native-test executable SHA256 `287af27c68ce318e8515efdf83516114f022e8c9fe29a773388482ec5a4ccbe0`, retained with its commands in OUT/final-history-execution.json. Native64passed/0failed and strict Clippy passed (root receipts). Full source-bound calculations and raw data: [final analysis](../../../history-analysis-final.md), [calculations](../../../history-analysis-final.json), [history receipt](../../../history-final-f573/history-results.json), and [width/reuse receipt](../../../history-width-final-f573/history-width-results.json).

Full30-day identity retention is user-selected, distinct from existing Small7-day retention. There is no history count/byte quota or fixed hard-disk ceiling. Fully ACKed recipients1/16/32 leave one compact identity and zero bodies/targets; fanout does not multiply compact history.

| op ID width | Measured identity + indices B/row |
|---:|---:|
| 16 | 363.643–366.510 |
| 46 | 426.435–429.425 |
| 128 | 610.099–611.656 |

Default generated IDs are46bytes; channel IDs26bytes, delivery/message IDs32bytes. Six native100k-row cases compare lexical and deterministic-random layouts. These are fixture-specific observations, not general bounds.

| Business rate | Default46 identity history after30d,GB |
|---:|---:|
| 1/s | 1.105–1.113 |
| 64/s | 70.740–71.236 |
| 128/s | 141.481–142.473 |
| 256/s | 282.962–284.946 |
| 10k/day | 0.128–0.129 |
| 100k/day | 1.279–1.288 |
| 1m/day | 12.793–12.883 |

Active target/index layout measured535.3472B/recipient using163B synthetic tokens and one448B shared message body. For M unACKed messages, targets≈M×recipients×535.3472B; body storage≈M×actual canonical body bytes, once per message. Default body lifetime7d, explicitTTL up to30d. Token/body measurements are not size limits; backlog arithmetic is not admissible-capacity evidence.

At1m synthetic-seeded compact history,50actual-store samples each: status p50/p95=41/49us; duplicate114/162us; acceptance235/293us. This did not execute1m production admissions.40maintenance commits delete10k identities at≤256/commit; p50/p95/max982/2961/3210us. dbstat was available.

Deletion made960pages/3,932,160B reusable but left DB400,166,912B unchanged; WAL4,144,752→0B after checkpoint. Six10k-row reinsertion cases consumed594–1451free pages; lexical DBs did not grow, random layouts needed8/24/40KiB extra. No VACUUM. Logical deletion, reusable pages and physical file shrink are distinct.

Native FULL13 verifies store admission failure, no success counter and prior accepted identity preservation after reopen. Deferred-COMMIT787 additionally exercises actual HTTP503/success=false and preserves prior ACK state. Actual OS ENOSPC, generic IO errors and power loss remain NOT RUN. Successful vmmap receipts exist; no RSS-only leak claim is made.
