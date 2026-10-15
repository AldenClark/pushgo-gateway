# C8 finite capacity and bounded content evidence

All four formal lanes passed exact COMMIT coverage, identity/wire/Pull/ACK, 30s post-ACK idle, and clean shutdown. Every failed/unfinished/unknown/late target remains part of the oracle; all are zero in these four successful lanes. This is one finite lane per backend/input, not stable production capacity or a backend ranking. SQLite40k capacity was NOT RUN.

| Lane | Offered / exact accepted targets | Offer→COMMIT p95 | p99 | Last callback from first offer | Slack to original190s cutoff |
|---|---:|---:|---:|---:|---:|
| MySQL original small | 40960 / 40960 | 159.791023s | 171.664790s | 182.850651s | 7.147049s |
| PG original small v2 | 40960 / 40960 | 132.898174s | 136.948825s | 147.853199s | 42.140654s |
| MySQL large content | 64 / 64 | 0.124866s | 0.129746s | 7.614083s | 182.381740s |
| PG large content v2 | 64 / 64 | 0.071356s | 0.072920s | 7.580330s | 182.418660s |

Original small input:256messages/s×10s=2,560messages×16targets=40,960; body1024ASCIIbytes,H32perprovider/Q32,8HTTPcallers,20ms Mock, original190s absolute Mach cutoff. MySQL all HTTP accepts completed47.050664s after first offer; PG42.478149s. Exact target drain after planned10s input172.850651s/137.853199s. SQL polling complete markers are upper witnesses, not precise last-callback timestamps.

Large content input is separate: four complete JSON requests of exactly49,152bytes at0/2.5/5/7.5s withplannedend10s,64targets. Cases cover ASCII, UTF8 Unicode, quote/backslash JSON expansion, and scalar metadata. Both backends witnessed64 bounded wakeup Provider messages (maximum1,792wirebytes≤4,096),64 full Pull body-hash verifications, and all ACKs. No complete request body or full Pull response was logged; only hashes/sizes/identities. Large cohort last callbacks occurred before planned10s inputend; this is content evidence, not the original throughput workload.

| Lane | Cold Gateway RSS | Overall sampled peak RSS | Post-ACK idle RSS | Post malloc in-use / reserved | Gateway offer→SQL-witness CPU / one-core average |
|---|---:|---:|---:|---:|---:|
| MySQL original small | 15,695,872B | 23,855,104B | 23,855,104B | 1,297,120 / 41,943,040B | 17.586608CPU-s / 9.5627% over183.909325s |
| PG original small v2 | 14,172,160B | 21,905,408B | 21,905,408B | 1,141,664 / 37,748,736B | 17.849378CPU-s / 12.0200% over148.497419s |
| MySQL large content | 15,712,256B | 17,481,728B | 17,481,728B | 1,455,952 / 33,554,432B | 0.059063CPU-s / 0.5734% over10.300552s |
| PG large content v2 | 14,204,928B | 15,941,632B | 15,941,632B | 1,300,304 / 33,554,432B | 0.049142CPU-s / 0.4812% over10.213038s |

Post-ACK RSS remained at the listed value throughout each30s idle; it did not return to cold RSS. Zone in-use bytes were low while zone reservation remained higher. These are measured zone/RSS observations, not proof of a leak or identification of Rust object lifetimes; malloc zones exclude other VM mappings. Once-per-second fixture STATS heartbeat is included. Idle observation had0Gateway HTTP calls. Interrupt/package idle counters are specific kernel counters, not all wakeups. Full exact counter deltas and phase samples are in each resource-summary.json.

Every sampled DB connection boundary showed2caseconnections including1observer, hence1non-observer pinned connection; this is not peak connections or per-connection memory. Provider owners/owned attempts/receipts returned to zero at postidle; generic runtime heartbeat tasks remained before shutdown. Small network-inflight is transport.send including credential owner/HTTP/bounded reply parsing, not exact HTTP request concurrency. Producer queue is offered-minus-started (excludes inflight8), distinct from durable pending/running target counts. MySQLsmall sampled producerqueuepeak1,808/durabletargetpeak33,436.

DB OS measurements remain separate from Gateway RSS. MySQLsmall whole-server PID1 sampled RSS cold464,801,792B, drainpeak482,451,456B, postidle482,365,440B; the same server retains functional cases/caches. MySQLlarge postidle486,486,016B. PG PID1 is only the main process (small postidle9,703,424B), omitting backend/shared mappings; never compare it to a whole MySQL server as total physical RAM. PGsmall drain/postidle coarse engine CPU is UNAVAILABLE due PID churn; do not fill it with zero. Large PG coarse process TIME has whole-second resolution and±14s endpoint bound across7processes, so0s cannot prove zero engine cost.

| Profile interior | Receipt samples | Receipt gate hold | SQL-inclusive | COMMIT | Gate wait (concurrent sum) |
|---|---:|---:|---:|---:|---:|
| MySQL original small (181.001s) | 40486 | 133.714250s | 40.619113s | 77.362991s | 4499.924159s |
| PG original small v2 (147.001s) | 40651 | 54.720625s | 37.599272s | 4.451776s | 2838.687026s |
| MySQL large content (6.000s) | 32 | 0.134847s | 0.049354s | 0.074027s | 0.909144s |
| PG large content v2 (6.002s) | 32 | 0.033961s | 0.024247s | 0.003017s | 0.157767s |

Profiles are conservative first/last natural STATS deltas inside Provider activity, not exact whole-window totals. Large interiors cover only32of64receipt completions. Nested phases and concurrent waits overlap; never sum them as wall time. Histogram percentile bucket upper bounds are not exact latency percentiles. MySQL pool acquire includes owner RPC; PG acquire covers its mutex, so they are not equivalent work. Receipt Usage is a four-SQL bundle; Counters.sql nominal charging is not total engine operations. PG track=all trigger-nested statement times may overlap parent queries and must not be added as wall time.

Whole-lane DB statement boundaries include setup/warmup/idle/ACK and observation. MySQLsmall before2/after28digestrows,lost0; MySQLlarge2/27,lost0. PGsmall before23/after69rows,dealloc46→49; PGlarge0/63,dealloc49→52, same stats_reset14:30:15.748097Z. Missing/evicted rows and scope differences are not zero SQL. MySQLsmall post-completion prepared-instance cache contains60surviving statements as lifetime lower bounds: CLAIM_ONE_SQL61,693exec/122,928examined; NEXT_DUE_SQL4,026/3,908;58unmapped rows retain numeric669,832exec/2,290,675examined. These are not offer-window deltas or full-cache coverage.

Sanitized host sampling recorded external swift-frontend in37PGsmall samples, swift-plugin-server15, and SWBBuildService/ibtoold1each. No arguments/environment/other project inspection or intervention occurred. Start-time quiet snapshots do not prove whole-run host quiet, and observed processes do not causally explain timing differences. Historical PG25s and C4 timing differences remain UNEXPLAINED; current runs do not rebuild a matched old-source control.

First PG attempt remains a separate OBSERVER_SCHEMA_SESSION_FAILURE at warmup with0formaloffers, cleanexit: duplicatePGOPTIONS lostsearch_path. Its original source/run/case are preserved. Independent source review accepted only combining search_path with existing5000ms statement timeout into onePGOPTIONS; bounded outermin(7,remaining) and original190s unchanged. V2 uses a new exact PGcase. No product SQL or input was changed to resolve that observation error.

Every formal pre/post host/disk4GiB+1GiB growth guard passed. PGsmall preguest643,399,680B exceeded465,965,056B prior40kgrowth+margin; after357,281,792B. PGlarge used a separately approved160MiB admission estimate for only64targets (64MiBwrite-amplification allowance+64MiBWALheadroom+32MiBsetup), not an allocation guarantee; after355,885,056B. No drops/purges/resizes occurred. Environment owner independently verified quiet and paused both exact engines, preserving all cases; receipt env/final-paused-quiet-receipt.json SHA5ab0ff7cec0041b8f954b41fa3fcfbd77f2df3c382f58d42dce05aaa0a13da62. No further DB operations were performed.

Source/be3bc95c58500ee9913dbc2d9b442d5eb6a74227, tree6c43d62eb33adf333768d36eaf7eaa23665ace99; normalb771b79a93b24025a037ca61c7056ea5a743ba52627a417dbee7f90d9d9efe44; tests8702e505b58db5cbdd787f0e1b07ec92951ee394f11750d4db9c6d0eb40da041; observera77c754c15f78fb725e4f22ae4b46981959744f0659b074c16d585372d8bf9eb. Rust1.97.1 release/offline/locked; immutable Git+8sparseoverlay proof and complete byte/mode restoration retained. Final20unique-source list and HERE-layout aliases: capacity/c8-final-stable-source-archive-list.json. Only source/provenance/reports are intended for validation archive; no URLs/config/cert/binary/log/DB files.

Raw [combined receipts](../../../../c8-private48-20261015/capacity/final-be3bc95/combined-four-lane-results.json). Runtime source is be3bc95; validation and report commits do not replace its artifact identity.
