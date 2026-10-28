# Real Warp/Gateway handoff regression

This keeps the two previously passing cross-repository tests reconstructible from Git. It adds no normal product dependency, public API, feature, trust root or runtime switch. The existing fixture in Gateway and private Warp client functions are connected only in a new caller-selected staging directory. The fixture visibility and dependency cycle seams remain outside both source checkouts.

Requirements: Python 3.11+, Git, Rust 1.97.1 and the ordinary dependency cache. Obtain Gateway commit `5eba92c1941cf3e467bdcc80da1c0145b8b1667b` and Warp commit `344a0486a69764da2e52441618d481fdcb43fbcf` from their source remotes. A full checkout containing those objects suffices; working tree contents are never copied. Supply actual checkout paths and a new empty output location:

```sh
python3.13 tests/support/handoff_integration/prepare.py \
  --gateway "$GATEWAY_CHECKOUT" --warp "$WARP_CHECKOUT" \
  --output "$NEW_OVERLAY_DIRECTORY"
```

Preparation copies pinned tracked source blobs, applies only test seams, and emits `receipt.json` with 387 input hashes. It does not resolve dependencies, compile or test. It refuses an existing output directory. The two source checkouts are read-only; no Git config, user data, system trust or production services are used.

Add `--run` with an ordinary populated `CARGO_HOME` and a suitably bounded `CARGO_TARGET_DIR` to resolve **offline**, ensure no Gateway locked package name/version disappears, and run exactly:

```sh
cargo +1.97.1 test --offline --locked --manifest-path "$NEW_OVERLAY_DIRECTORY/warp/Cargo.toml" \
  -j1 -p warp-link --lib combined_handoff_tests -- --nocapture --test-threads=1
```

The resolver starts from Gateway's lock because the test-only dev cycle shares the exact Warp source across both repositories; it may add test packages. The normal manifests/lock are not modified. Failed metadata or tests stop with their original exit and retained staging/logs. No fallback download or retry is performed. A fresh machine must populate its ordinary dependencies explicitly before offline execution. Review `test.log` for exactly two passed methods; an exit code alone is not a coverage count.

Cases: block seq8 persistence while seq9 is admitted, then verify ordered saves, one callback owner and explicit ACK settlement; reject seq8 with a real SQLite trigger, retain pending bodies, close/join owners and replay the same business identities. They exercise actual production Warp receive/handoff and Gateway server/ordinary ledger modules through loopback WebSocket frames. They do not exercise TLS connectors, the outer reconnect loop, installed apps or real Providers.

The retained test module SHA256 is `2c2c6444991e57a49c9491ffe8907c0781fc60da77af0082259b97ebfbac6133`. The original overlay produced nine unused-fixture warnings; normal product strict Clippy was a separate passing check. Preparation was reverified byte-for-byte during convergence; the two tests were reused from prior passing evidence rather than rebuilt.
