# Gateway main convergence, 2026-10-28

The current source target is `5eba92c1941cf3e467bdcc80da1c0145b8b1667b` plus this documentation and the portable integration fixture. It descends from main `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`; all existing main commits remain in history, including Watch reminder expiry `0c0365e` and removal of unused dispatch profiles `dfb6b7c`. This is source convergence, not a release or deployment receipt.

## Current contracts and latest fixes

- Ordinary ingress, replay and terminal ACK facts use the existing product ledger. HTTP V2 Pull continues to require explicit delivery IDs for ACK. Bounded scoped continuation can advance past an unACKable page; selection does not constitute ACK.
- The entire HTTP JSON request body is limited to 49,152 bytes. The paired Private frame/WELCOME limit is 131,072 bytes. These limits do not describe only the message body or include HTTP headers/TLS records.
- `d35b42c` removes the process-wide MQTT fallback dedupe cache. Reusing a QoS1 packet ID after PUBACK is a new application message, including DUP=1. Each publish reaches authenticated durable submission; explicit `op_id` still uses durable business identity. No replacement cache or timer was added.
- `6cc96e8` removes global resume sweeps from send/admission. Existing maintenance reclaims expired offline state, including fewer than 128 records; target-local TTL validation prevents delayed GC from extending a stale capability. Online state and the existing TTL remain authoritative.
- `5eba92c` removes implicit cumulative settlement from HELLO maximum sequence hints. A failed save of seq8 followed by HELLO max9 must leave seq8 pending with its body intact. Wire ACKs still match both sequence and delivery identity.
- The negotiated handoff freezes the prior outbound owner, drains its ordered frames and processes their explicit ACKs before candidate activation. Preparation has no candidate business outbound authority. Epoch/session/nonce/expiry fences handle cancellation and late completion. The state is bounded within existing sessions, without a new persistent queue, schema or worker.

Gateway's three direct Warp dependencies and lock use exact revision `344a0486a69764da2e52441618d481fdcb43fbcf`. No new protocol architecture or dependency upgrade is part of this convergence. Old clients retain ordinary recovery but do not acquire the new handoff ordering guarantee. Clients without an explicit offer receive no extension tail; a new client lacking server capability does not attempt an unconfirmed hot switch. Replay remains possible after ACK loss; this is not wire/callback exactly-once.

## Evidence retained from the exact source

Rust 1.97.1, macOS ARM64, offline/locked, jobs1. These are reused prior results, not newly rerun suites:

| Check | Result | Bound |
| --- | --- | --- |
| `cargo test --offline --locked -j1 --lib private:: -- --nocapture --test-threads=1` | 78 passed, 0 failed/ignored | Includes handoff6 and registry4; synthetic SQLite and loopback production modules |
| `cargo clippy --offline --locked -j1 --lib --tests -- -D warnings` | passed | Normal product configuration, separate from the overlay |
| `cargo test --offline --locked -j1 --lib mqtt:: -- --nocapture --test-threads=1` | 48 passed, 0 failed/ignored | MQTT sources unchanged after `d35b42c`; QoS1 seven are a subset |
| Actual Warp client + Gateway server modules | 2 passed, 0 failed/ignored | Loopback WebSocket framing, actual ordinary SQLite, synthetic client SQLite |

The combined cases prove that a blocked seq8 save cannot be overtaken by seq9, callbacks have one active owner, failed save gets no successful ACK, and reconnect/replay preserves business identity. A negative SQL trigger retains both pending targets/bodies; recovery creates nine unique rows. Separate Gateway cases cover a real dropped wire ACK and Storage/session owner close/reopen. Original pre-fix failures are preserved in the local audit, not overwritten by later green results.

The portable [integration fixture](../tests/support/handoff_integration/README.md) retains the exact previously tested two methods, source pinning, fixture-only visibility seam and reproducible staging. The convergence preparation copied 387 exact source/Cargo inputs and produced 389 staged files; every staged byte except the deliberately unresolved lock seed matched the prior passing overlay. No compilation or product test was repeated for this documentation-only addition. Compact receipt identities are in [the evidence index](../tests/support/handoff_integration/evidence.json).

This does not prove TLS connectors, the outer client reconnect loop, Android/Windows installed applications, Apple/Watch decoders, real Providers, physical devices, full transport matrices, power loss, long-run performance or production capacity. Older fixed-load failures remain historical failures. No current release matrix is inferred from focused tests.

## Delivery and retained history

At the read-only remote check, origin main was `3cf3a7a75f9c68dff3deda6763314f6af34dc72f`; local main was two commits ahead, and the candidate another 114 commits ahead. Every non-backup branch except the deliberate scan-control is an ancestor of the candidate. Historical `backup/main-before-squash-20260321-221202` has 18 non-ancestor commits across an old repository layout and is retained as historical provenance; it is not merged into current product source. `codex/gateway-c-client-loop-scan-control-20261015` has one deliberate pre-optimization query control, also not a product fix. Neither should be described as lost changes or blindly merged.

The existing stash `pre-rewrite-author-1778477420` changes four release checkout actions from v4 to v6. Current release checkout actions are already immutable SHA-pinned v7.0.1, so that patch is superseded; preserve the stash/patch in an archive before any separately coordinated removal. Both extant Gateway source worktrees were clean, with no untracked source changes. Seven older registered worktrees point at already missing paths; prune only their metadata after preserving refs, not evidence directories.

The checked-in release workflow triggers only on `v*` tags and can publish binaries, container images and GitHub releases. PR-quality runs on pull requests/manual dispatch. There is no main-push deploy/release trigger in these two workflows, and convergence creates no tag. Read-only GitHub checks returned `404 Branch not protected` for main and an empty effective branch-rules list. This does not audit remote runtime hooks. No repository setting or release workflow was changed.
