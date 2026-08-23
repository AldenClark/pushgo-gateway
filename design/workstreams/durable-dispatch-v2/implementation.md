# Durable dispatch v2 implementation

## Outcome

Implement the target architecture in `design/gateway-durable-adaptive-dispatch-final-design.md`: durable cross-channel submission identity, durable provider attempts, recovery-cache-before-send, private durability-before-realtime, provider-owned adaptive lanes, fenced recovery, and forward-compatible migration.

## Acceptance

- No correctness-bearing payload exists only in an in-process queue after acceptance.
- Mixed private/MQTT/provider fanout survives cancellation and restart under one operation/delivery identity.
- Direct and wakeup recovery-capable provider sends require a durable pull copy.
- Private realtime delivery requires a durable private outbox row first.
- Provider retries release scheduler capacity; adapter calls are single-attempt.
- Claims and results are fenced by owner and generation for the supported single instance; feature-epoch fencing is deferred until multi-instance support.
- SQLite, PostgreSQL, and MySQL expose equivalent logical behavior and migration checks.
- Existing HTTP/MQTT/MCP and legacy/v2 pull/ACK wire contracts remain compatible.

## Outcome slices

1. Store types, schema v12 migration, and backend conformance.
2. Submission/target materialization and dedupe settlement.
3. Durable provider scheduler, rate/concurrency ownership, retry and shutdown.
4. Producer cutover, private fast-path correction, Widget/Live Activity conversion.
5. Compatibility, overload, fault, load, and cross-client verification.

## Evidence

Focused state/store tests precede integration checks. Final evidence must include Rust format/lint/tests, three-backend migration/conformance where available, process-kill/restart oracles, and explicit NOT RUN status for unavailable real-provider or production gates.

## Implemented runtime envelope (2026-08-21)

Provider throughput is independent of the `small`/`public` storage profile. The current compiled lane envelopes are APNs 2-64, Live Activity 1-8, Widget 1-8, FCM 2-64, and WNS 1-32, with 1,024-entry in-process wake-hint channels. Hints are accelerators only; the durable provider outbox is authoritative. Idle workers poll the outbox every second, the adaptive controller evaluates every 500 ms, leases cover one provider attempt for 20 seconds, and provider terminal reconciliation runs about every two seconds.

The provider adapters perform one network attempt. APNs 5xx retries are not scheduled earlier than 15 minutes. FCM 408/5xx retries use at least 10 seconds and 429 uses at least 60 seconds. WNS 406/429 is retryable with at least 60 seconds, while WNS 408/5xx uses at least 10 seconds; valid `Retry-After` can extend these floors. Four consecutive retryable lane failures open a one-second process-local probe circuit, and a success closes it immediately. This circuit bounds fast connection-refusal loops; it is not the credential-scoped/distributed quota system described as a production target in the architecture document.

Shutdown closes each lane when its hint sender disconnects, re-checks closure after adaptive/circuit waits, completes only already-claimed attempts, and leaves unclaimed durable backlog for restart. A 128-row due-backlog regression test and a real 4,000-row Ctrl-C/restart test cover this invariant.

The final local evidence set is recorded in `progress.md`. In particular, the three real database backends passed the same final suite. Real provider/device acceptance, exact release-artifact restore-clone recovery, Apple cross-system ingestion, and production canary behavior remain external release gates and must not be inferred from mocks. Multi-instance quota/feature-epoch operation is an unsupported future topology, not a current release gate.
