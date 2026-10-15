# C3 final synthetic history/storage evidence

Contract: full30-day identity retention with no identity count/byte quota and no early eviction. ACK/completion releases shared body and queue targets; compact identity persists until retention. Consequently there is no fixed hard-disk ceiling.

Provenance: see execution.json for frozen source/tree and native binary hashes, first-run exit status, commands and runtime binding. schema_version=1 is the prototype manifest value; layout/schema.sql is the verbatim schema. Python supplemental SQLite version: 3.54.0. Native SQLx SQLite version: 3.46.0.

## Measured compact identity + indexes

|op bytes|order|table B/message|index B/message|total B/message|
|---:|---|---:|---:|---:|
|16|lexical|228.147|138.363|366.510|
|46|lexical|256.614|172.810|429.425|
|128|lexical|342.221|267.878|610.099|
|16|deterministic-random|228.147|135.496|363.643|
|46|deterministic-random|256.614|169.820|426.435|
|128|deterministic-random|342.221|269.435|611.656|

Measured six100k histories. Actual26B channel,32B delivery/message IDs,64B fingerprint; op16/46/128 cover controlled legal widths including generated46. Empty-table dbstat baselines subtracted. Order/field distributions affect layout. Fully ACKed identities hold0 body bytes and0 targets; recipient count does not multiply identity history.

## Thirty-day arithmetic extrapolation

|business messages/s|identities30d|op16 GB range|default op46 GB range|op128 GB range|
|---:|---:|---:|---:|---:|
|1|2592000|0.943–0.950|1.105–1.113|1.581–1.585|
|64|165888000|60.324–60.800|70.740–71.236|101.208–101.466|
|128|331776000|120.648–121.599|141.481–142.473|202.416–202.933|
|256|663552000|241.296–243.198|282.962–284.946|404.833–405.865|

GB means10^9bytes. Extrapolations are not30-day soak or admission/delivery capacity evidence. WAL, fragmentation, directory/filesystem overhead and operational headroom remain additional.

## Measured active targets and shared body

Native10k-target internal physical row-layout probe: **884.3264B/target including all indexes**, cold subtracted. Includes pull_owner, owner_generation, control_epoch and owner/token indexes. Native provider token fixture163B; target/device IDs32B. The product allows at most32 channel subscribers; direct SQL10k-target seeding exceeds that API contract and measures only physical row layout, never valid single-message API workload or completion rate.

- sqlite_autoindex_targets_1: 83.5584B/target.
- targets: 316.2112B/target.
- targets_device: 90.9312B/target.
- targets_due: 67.1744B/target.
- targets_owner_delivery: 120.8320B/target.
- targets_token_retirement: 205.6192B/target.

Python fixed-schema probe uses256 business messages per case and includes identical owner/generation/epoch columns plus triggers; direct SQL probe is storage layout only. Body448B/1KiB/4KiB is shared once per message. The message+index column includes the shared body and all message metadata/index page overhead; logical body sizes remain separate. Differences from native10k-target B/target reflect page fill, fixture key distribution, row counts and SQLite version; none is a universal bound. The direct SQL release is not native ACK evidence.

|fanout|body B/message|messages|targets|target B/target|message+index B/message|
|---:|---:|---:|---:|---:|---:|
|1|448|256|256|864.000|1040.000|
|16|448|256|4096|903.000|1040.000|
|32|448|256|8192|897.000|1040.000|
|16|1024|256|4096|903.000|1584.000|
|16|4096|256|4096|903.000|4816.000|

Active demand arithmetic for legal fanout1/16/32,7d/30d holds and all requested rates is in active-fanout-projections.csv. Formula:M=business messages/s×hold_seconds; targets=M×fanout; shared body=M×body_bytes; target disk≈targets×measured native B/target. Active admission backpressure can refuse these hypothetical backlogs; this is not a promise to accept them.

## Native operation cost and expiry cleanup

|seeded identities|actual rows|DB B|status p50/p95/max us|duplicate p50/p95/max us|accept p50/p95/max us|
|---:|---:|---:|---|---|---|
|10000|10050|4096000|35/41/83|122/162/176|236/358/1854|
|100000|100100|39997440|35/44/50|122/142/175|236/257/259|
|1000000|1000150|400183296|37/43/52|124/149/181|239/447/1684|

Each timing cell has50 actual sequential native-store samples; fresh acceptance has1 recipient and is followed by native ACK. History was inserted via bounded500-row direct seed batches, not1m production admissions. At each measured scale, native actual accept+ACK left0 target rows and0 logical body bytes while preserving10,050/100,100/1,000,150 identity rows. Warm local short-run evidence; no sustained throughput, network/provider latency or production capacity claim.

Native maintenance deleted10000 eligible rows in40 commits of at most256. Timings:{'max_us': 2942, 'n': 40, 'p50_us': 908, 'p95_us': 2457, 'total_us': 40132}. DB after logical deletion:400183296B, free pages:960. After TRUNCATE checkpoint:{'db_bytes': 400183296, 'shm_bytes': 32768, 'wal_bytes': 0}. Other identities retain full30d.

Freelist pages remain physically allocated. Native width cases reinsert10k same identities and show actual free-page consumption. Every case returns from90,000 to100,000 identities with0 targets/body bytes. No VACUUM ran. Physical DB shrink is not claimed.

|op bytes|order|free pages after delete|pages consumed by10k reinserts|DB growth B|
|---:|---|---:|---:|---:|
|16|lexical|881|879|0|
|46|lexical|1035|1018|0|
|128|lexical|1476|1451|0|
|16|deterministic-random|594|594|40960|
|46|deterministic-random|663|663|24576|
|128|deterministic-random|875|875|8192|

Limit: local synthetic database/storage and native API evidence only. No30d soak, OS ENOSPC, power-loss recovery or production/provider capacity acceptance.
