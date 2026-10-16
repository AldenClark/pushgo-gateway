# Ordinary product implementation

C10 moves ordinary runtime ownership into the normal `pushgo-gateway` crate under
`src/ordinary`. This directory no longer implements a Gateway, HTTP router,
control authority, database lifecycle, Private session owner or delivery scheduler.
Its library only re-exports `pushgo_gateway::ordinary`.

`free_architecture_fixture` is a small launcher for an explicitly selected normal
Gateway binary. On Unix it replaces its process with that binary. On other hosts
it waits for the one Gateway child and returns its exit status. It does not open
an HTTP listener or database.

```sh
free_architecture_fixture --product-binary /absolute/path/pushgo-gateway -- --help
```

The binary path may instead be set with `PUSHGO_GATEWAY_PRODUCT_BINARY`. Arguments
after `--` are forwarded unchanged to normal Gateway `Args`; product configuration,
credentials and lifecycle have exactly the normal product owners. The old synthetic
fixture flags and `__fixture` administration endpoints are not supported.

The C1–C9 reports, manifests and validation tools retained here are historical
references. They describe their original fixture and cannot be run against this
launcher to produce comparable C9 capacity results. The frozen C9 worktree remains
under the main Gateway checkout at
`build/quality-results/c-single-ledger-contract-20261015/workspace-final`
(see `git worktree list`),
branch `codex/gateway-c-ordinary-final-20261015`, commit
`86e073dec487903cb27f2e67d6e5cbdcb06a6900`. Its source, binaries, failures, databases
and external evidence are unchanged. The deleted duplicate runtime and historical
fixture tests are also recoverable from that commit.

See [the C10 source boundary](docs/c10-product-source-cutover.md) for the exact
removal and preservation list. Historical tests are not counted as current product
passes; focused product tests live with the normal implementation.
