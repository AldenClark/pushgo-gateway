# C5：普通消息三后端合同与 MySQL 功能验证

本文记录隔离候选的产品合同及已完成的功能基线；最后的 MySQL 领取索引访问路径修复已通过同一 frozen test executable 的默认、PG、MySQL 验证；最终 wire 四例与 native-03 六个 loop 均已通过并在各自所属范围 QUIET；最终容量两 raw 已收到且各自 QUIET：PG 全目标完成但较 baseline 变慢原因未决，MySQL 190 秒 deadline FAIL；C5 owned 数据库环境已清理并 QUIET，详见最终环境收据。性能另见 [C5 容量报告](c5-capacity.md)。范围为普通消息、FCM/APNs、共享 axum/Tokio runtime，以及单台 Unix 主机上的一个 owner。新增 MySQL 代码不代表旧主线数据迁移、版本升级回退、断电恢复、真实 Provider、物理设备后台或部署验收。

证据根为 `gateway/build/quality-results/c5-mysql-ordinary-20261015/`。最终产品 commit 为 `651bf7e7e4691bd5a78b36625ff34b693be83590`。normal artifact 为 `binaries/c5-final-ordinary-sqlite-pg-mysql`，SHA256 `3204f8ac126282e74980eaffec386ab9ffc67f028f8bbcd15f47c9eb284f8298`；test artifact 为 `binaries/c5-final-shared-native-tests`，SHA256 `173d98eab6eb7a9b4ba287471ef519219d5ee1fa2675d2e5693f09e527aae032`。

| 最后索引修复验证 | 同一 frozen test artifact 的结果 |
|---|---|
| 默认 Rust / SQLite | `tests-default-index-final.log`：86 passed、0 failed、4 ignored，8.62 秒。PG/MySQL 两项 ignored 已如下显式运行；另外两个 history 实验未重复。 |
| PostgreSQL aggregate | `tests-pg-index-final.log`：1 passed，3.14 秒。 |
| MySQL aggregate | `tests-mysql-index-repair-aggregate-first.log`：1 passed，8.43 秒；新增索引修复/unknown-signature/metadata-lock-timeout/recovery oracle 首次通过。 |
| 最终 native attempt-03 | `native/attempt-03-summary.json`：PG/MySQL 各 Apple 8 invocation、Android 3 方法且 zero skip、Gateway restart，共六 loop PASS；全部绑定 651bf7 / 3204。`native/attempt-03-quiet.json` 仅覆盖 native 拥有的进程、emulator、lease、六个 case DB。 |
| 最终 wire / process | `fault/final-index-results.json`：四个新 fresh case PASS，全部绑定最终 651bf7 / 3204 artifact；`fault/final-index-quiet.json`：所属进程退出、proxy/provider tasks 已 join、四个 owned case DB 已 drop，其他 case 未触碰。 |
| 独立 source review | 最后小修无阻塞问题；不替代运行收据；最终容量 FAIL 与未决性能原因仍单列，客户端/进程重验已有独立结果。 |

最终四项分别为 `final-index-before`（HTTP503、failstop70、入口关闭，同 op 重启 new，一次 Provider 请求）、`final-index-after`（真实 COMMIT OK `00000002000000` 丢失，HTTP503/failstop70，同 op 重启 duplicate_completed，一次请求）、`final-index-process`（未知外部结果，重启 duplicate_completed，累计两次请求）和 `final-index-released`（失去数据库锁后 retained OS fence）。最终收据固定 harness hash 与每个 receipt hash，343 份产品输入和 normal binary 前后不变；所属 wire、native、容量 QUIET 分别限定各自资源；最终 C5 owned 数据库环境另由 env/final-cleanup.json 与 final-quiet.json 证明清理。

以下 753a / e7b6d59 的身份、功能与 wire/native 收据是保存的 before-baseline，不能当作 651bf7 最终 normal artifact 的 wire/native 执行：

已通过功能基线的产品源码 commit `753a1836b134915b2c6af2ef9fa6d075f52125a3`，normal fixture SHA256 为 `7324bc7ac546a2825c749b9f339c410dbeb6560129786b856a904873b39d0161`，身份清单位于 `binaries/c5-ordinary-identity.json`。test-only oracle commit 为 `e7b6d59ae8d615df86c23da2f3940eccb5a4fe2e`，该功能基线测试可执行文件 SHA256 为 `055fde93d44abde498bd47248650433bb76eb1c84d1fac18e7583e82f9a0866d`。下表默认、PG、MySQL 三项均使用这一 frozen test executable；普通 fixture 与测试 executable 分别绑定，不能互换身份：

| 项目 | e7b6d59 功能基线证据（不替代后续索引修复验收） |
|---|---|
| 默认 Rust / SQLite 测试 | `tests-default-final.log`：86 passed、4 ignored。四项中 PG/MySQL 两个 aggregate 已显式另跑，另外两个 history 实验未重复，不计入本轮新增验收。 |
| PostgreSQL 共享及原生 aggregate | `tests-pg-final.log`：真实新建合成库 1 passed，2.64 秒。 |
| MySQL 共享及原生 aggregate | `tests-mysql-final-all-metadata-aggregate.log`：真实 InnoDB 合成库 1 passed，5.30 秒；共享业务、原生事务回滚/取消、owner session、H32 背压/恢复、实际 EXPLAIN、索引/generated/NO PAD 检查通过。 |
| 静态检查 | 最终 fmt、src diff 检查、clippy exit 0。clippy 未使用 `-D warnings`，保留 3 个 parent WNS dead-code 和 3 个 test claim-wrapper warning；不能称零 warning。 |
| 外部 wire / 进程故障 | `fault/final-results.md`：四个 fresh case 均首轮 PASS，产品源码输入及 normal fixture hash 前后不变。 |
| 原生客户端/控制面 | `native/attempt-02-matrix-result.json`：PG/MySQL 各 Apple、Android、Gateway control/restart，共六个 loop 全部 PASS；每后端 Apple 8 phase、Android 3 方法和 Gateway 控制/重启。 |
| 性能与环境总清理 | 最终 PG 完成全部目标，MySQL 190 秒 deadline FAIL；两 raw 已收到且各自 QUIET，细节由容量报告单列。wire/native/容量的所属清理与最终 env/final-cleanup.json、env/final-quiet.json 分别绑定；C5 owned 数据库环境已清理且 QUIET，不表示其他项目停止。 |

首次失败保留：`tests-mysql-first.log` 的原生 1044 新建测试库 grant、临时故障 trigger 的 1419 trust、I_S 观察 PROCESS 权限的 1227，均保留原始失败及独立环境修复记录；1044 调整见 `env/environment-adjustment-prefix-grants.json`。首次 compile / metadata 解码失败及后续修正日志也保留，不因最终通过覆盖或删除。原生 attempt-01 的 observer schema `42P01` 出现在任何 native 测试执行前，属于 observer 前置条件失败，不能冒充客户端或产品失败；Android 首次 build wrapper 失败、连接校准失败见 attempt-02 matrix 所引用收据。

首轮共享失败来自新测试把 `devices WHERE provider_token=...` 的全部行误当作当前有效 owner。现行合同保留旧 coalesced 设备的 token，旧行属于历史身份；修正为只计 `retired_at IS NULL AND coalesced_to IS NULL`，并额外断言旧设备的 `coalesced_to` 精确指向新 owner。没有为使测试通过而清空历史 token 或改产品语义。`tests-default-first.log` 与修正后的执行分别保留；C4 早期未标注阶段的超时和原约五秒高负载耗时差异没有被本轮追认为已通过。

MySQL 首个 startup 根因是 SQLx 对 `_bin` VARCHAR 的 wire `BINARY_FLAG` 类型兼容检查拒绝 Rust String，并非非法 UTF-8 或 NO PAD 存储值错误。产品行读取使用 `get_unchecked` 绕过该 metadata compatibility gate，String Decode 仍经 `from_utf8` 验证；scalar 的 CAST 仅改变 SELECT projection 的驱动类型表达，不改持久列、绑定比较或 NO PAD 身份语义。全局无符号变量按 SIGNED projection 解码，避免把 unsigned globals 的驱动解码失败误写为 durability 配置不满足。

C5 I_S 首轮观察以 5 ms 间隔、2 秒总预算未看到真实锁等待。MySQL 8.4.11 官方源码的 I_S 事务缓存仅在 `last_read > 100 ms` 时刷新；环境原生负控得到 5 ms 轮询 263 次全空，而 150 ms 间隔在约 157 ms 可见真实等待。最终 test-only oracle 按精确 owner connection ID 查询 I_S，观察间隔改为 150 ms，总预算仍为 2 秒，未延长 deadline 或重试产品事务。源码依据与负控分别保存在 `env/mysql-is-observer-cache-source.json`、`env/mysql-trx-cache-negative-control.json`；最终同 executable aggregate 通过。此因果证据只解释本轮 MySQL I_S 观察失败，不反写 C4 SQLite 未标注 timeout 或原约五秒高负载耗时差异。

## 共享业务入口与持久合同

`ordinary_store.rs` 的具体 `OrdinaryStore` facade 选择 SQLite、PostgreSQL、MySQL。HTTP 和 Provider pump 调用完整操作；没有 SQLx Any、跨库 SQL DSL、通用事务接口或自动事务重放。MySQL 原生实现在 `mysql_store.rs`、`mysql_control.rs`、`mysql_schema.sql`；测试通过 test-only extractor 读取原生连接，不让 HTTP/runtime 获得数据库 executor。

三库共用请求规范化、fingerprint、响应形状、配置、计数器、Ticket / ClaimBatch、Provider transport 和预算调度。普通接纳同事务保存 message_id / delivery_id / op_id、频道、fingerprint、首次时间、绝对 TTL、正文及完整有效 fanout；只在 COMMIT 成功后返回新接纳。鉴权先于去重。相同 op_id、频道与规范化内容返回首次身份；跨频道和内容冲突保留各自错误。省略 op_id 每次生成新身份。

默认正文 TTL 为七天，显式 TTL 是绝对毫秒并限于首次接纳后最多三十天。过去 TTL 不转成未来，重启或重复请求不延长首次时间。身份、fingerprint 和 Sender 状态默认保留 `accepted_at + 30 天`，配置仍允许 `dedupe_retention_ms >= 30 天`；ACK、Provider 终态和正文到期不能提前驱逐未到期身份。没有身份数量或字节硬配额，也没有历史满额提前淘汰策略，数据库总磁盘占用没有固定上限。

Provider 结果、客户端 ACK、Sender 状态和正文保留分别推进。Receipt 按冻结的 `(delivery_id, device_key, running, attempt_id)` 条件应用；已发出的旧 attempt 只能结算自己的 durable 行。Coalescing 改 retained `pull_owner` 并把旧 `owner_generation` 置为失效，不重写冻结的 receipt device key。Pull 和 ACK 跟随当前 owner；旧 owner 不再能读取或确认，而已授权的旧回执仍可结算。路由 generation 阻止 A→B→A 复活旧授权；退休 token 的 control_epoch 只覆盖旧 epoch，重新绑定产生的新 epoch 不被旧 marker 清除。旧 coalesced 设备行可保留 token，不能因此把它算成有效路由 owner。

V2 Pull 非破坏性，batch 读 201 项、返回前 200 项和 has_more；精确 Pull 不展开设备全部积压。ACK 按新增确认的 delivery ID 数返回，同一 ID 的多个 coalesced target 仍只计一，重复或外设备 ACK 为零。running ACK 保留结果义务直到 receipt；legacy Pull 在同事务确认实际返回项。register / route / channel 控制保留既有 revision、generation、十分钟登记 alias、频道订阅限额及 sync_channels 逐项部分成功合同。

## MySQL owner、session 和事务

MySQL 要求专用数据库。所有普通表使用 InnoDB；pinned session 显式设置 `READ COMMITTED`、`STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION`，原生行锁与 metadata lock 等待预算各三秒。建立物理连接预算为五秒，这不是整个 schema 初始化或 recovery 的墙钟上限。启动还检查 `innodb_flush_log_at_trx_commit=1` 和 `sync_binlog=1`；配置检查不是断电耐久性实测。

启动用服务端 `DATABASE()` 生成 bootstrap `GET_LOCK` 名，串行化 `authority_metadata` 的首次创建；其中保存不可变 dataset_uuid 与 schema_version。随后同一 session 持有 `GET_LOCK('pushgo-c-dataset-' + uuid, 0)`，再释放 bootstrap 锁。schema 初始化、running recovery 前取得 `/tmp/pushgo-c-mysql-{uuid}.owner` Unix OS 文件锁。不同 DSN、用户名、localhost 别名或连接参数指向同一 dataset 时，UUID 与本机锁仍相同。

全部 SQL 通过 `Arc<Mutex<Option<MySqlConnection>>>` 使用这条物理 session；没有连接池补连、连接替换、运行中重抢锁或后台重放。每次取得连接检查 `IS_USED_LOCK(...) = CONNECTION_ID()`。观察到 session / owner 丢失后锁存 Health 首次失败，后续入口不可用。数据库 session 消失会释放 GET_LOCK，但旧进程的 OS owner 锁继续存在，防止旧 Provider future 尚存时另一个本机 owner 开始 recovery。需要同一主机、同一 `/tmp` 可见性和未被替换的 dataset 身份；这不是跨主机、隔离容器命名空间或数据库克隆恢复协议。非 Unix 平台没有这套保证。

写操作保留 mutation gate，并在业务事务最前锁定 `ledger_usage` singleton `FOR UPDATE`。数据库事务不等待 Provider I/O；原生 1062、1213、1205 不自动重放。SQLx Transaction 在错误或取消时排队整笔 ROLLBACK，下一次连接使用先排空协议与回滚，再检查 owner。`innodb_rollback_on_timeout=OFF` 时，MySQL 原生 1205 只回滚失败语句，应用仍必须撤销整个 accept；这由专门的真实锁冲突 oracle 验证，不能把默认引擎行为当成应用事务原子性。

正常停机先停止并 join HTTP handler，再 join pump、关闭 pinned session、最后释放 OS owner。停机丢弃正在等待的 Provider/receipt future，保留 durable running 义务供显式重启恢复；旧 ACK 的 running 不再重发，其余未知结果变为 retry_wait 并在新 claim 递增 attempt_id。已授权网络请求可能已发生外部效果，文件锁和数据库事务不能撤销它。

COMMIT 结果未知不等于回滚，也不能向客户端伪造成功。上层恢复使用原 op_id 和原规范化内容查询或重试接纳：已提交则复用原身份，未提交则在新 owner 下正常接纳；不能换 op_id 重发网络请求来探测结果。接纳重试本身不直接发送 Provider HTTP，持久 job 由恢复后的 pump 按 attempt 合同执行。未知 Provider 结果仍可能需要一次恢复发送，不宣称网络恰好一次。外部 wire proxy 已分别在真实 COMMIT 转发前及服务端 COMMIT 成功响应后截断，逐项结果见下方 wire 收据表。

## 最后的 MySQL 领取索引访问路径修复（功能验证通过）

上述 753a / e7b6d59 / 7324 / 055fde 功能基线均保留。后续容量 baseline 的原始失败另行保存，不能因为功能测试通过而删除，也不能以修复后的小查询诊断替代该失败工作量。最后小修对 `targets_due` 增加完整排序尾键：从旧 C5 的 `(provider, state, next_attempt_at, delivery_id)` 改为 `(provider, state, next_attempt_at, delivery_id, device_key)`。生产 `CLAIM_ONE_SQL`、四个绑定参数、业务谓词、ORDER BY 和 LIMIT 均不变；这次调整改变数据库可用访问路径，不改变领取的 owner、TTL、退休 epoch、attempt 或预算语义。单次诊断查询约 0.0647 ms 仅是那个查询/夹具的观测，不能报告为吞吐提升、整体尾延迟收益或容量验收。

新建 schema 直接声明五列索引。已存在的同版 C5 数据库不能由 `CREATE TABLE IF NOT EXISTS` 自动更新，因此启动在取得 dataset GET_LOCK 和 OS owner 后、任何 running recovery / 业务事务前调用 `ensure_due_index`，检查 information_schema 的实际定义。只接受精确四列旧定义或精确五列新定义：顺序、完整列无 prefix、ASC、non-unique、BTREE、visible、非 expression 都必须匹配。精确五列无需 DDL；精确四列仅执行一个原生原子语句 `ALTER TABLE targets DROP INDEX targets_due, ADD INDEX targets_due(provider,state,next_attempt_at,delivery_id,device_key)`，不分拆为先 DROP 后 ADD，也不放入应用事务冒充事务化迁移。

未知或不匹配的签名明确 fail closed，返回 `unsupported MySQL targets_due definition`；不会猜测修复任意用户索引。原生 metadata-lock 等待超时保留 1205，open 不返回 READY store，关闭 pinned session 并释放本轮 owner；因为 DDL 检查先于 recovery，已 accepted 身份和 running 义务尚未被 recovery 改写。该路径没有隐式重试。

新增 native oracle 源码覆盖三列未知签名拒绝且 running 保留、恢复精确四列后用独立 metadata reader 阻塞启动 DDL、要求原生 1205 且消息/running 仍在，释放阻塞后重新显式 open，验证五列签名与相同 op 的身份/TTL/control epoch、旧 attempt 失效和恢复 attempt 递增。以上新增 oracle 已在最终 `651bf7e7` 的 frozen test artifact 首次运行通过，完整 MySQL aggregate 为 1 pass、8.43 秒，原生 metadata-lock timeout 保持 1205、未延长预算或隐藏重试。最终产品、normal 和 test artifact 身份及三库结果见开头表；native-03 六个 loop 与 wire 四例均已取得最终 artifact PASS 与各自所属 QUIET 收据，不把 before-baseline 结果移植为新二进制通过。此修复仅针对明确的旧 C5 四列索引，不扩大为主线旧库迁移、任意 schema 升级/回退或断电恢复承诺。

## 原生 schema、字节身份与容量计数

MySQL 普通文本使用 `utf8mb4_0900_bin` 的 NO PAD collation，保持大小写、Unicode 码点及尾空格的存储身份。API 先执行各字段既有 trim / normalization；例如 op_id 和 FCM token 外部空白按合同消除，不能把 API 归一化误写成数据库 PAD SPACE 等价。APNs token 继续按规范化规则转小写。

message_id / delivery_id / device_key 为 32 字符，频道 ID 26 字符，op_id 最多 128 字节；FCM token 最多 4096 字节，频道名称最多 128 Unicode scalar，密码为 8–128 UTF-8 字节。共享 oracle 覆盖最大 op_id、128 字节完整 Unicode 密码、128 scalar 名称、4096 字节 Unicode token，以及长 token 只在最后一个字节不同的情况，检查 devices / targets 全值保留。密码保存既有加盐 hash，不截短合法输入或降为 ASCII。

`devices_token`、`targets_token_retirement`、`retired_token` 只为长 token 建 256 字符前缀索引。前缀是候选过滤，所有业务比较仍绑定完整 token；前缀不建立 token 唯一性。退休 marker 使用独立 marker_id，单 owner 与 singleton 行锁下按完整 `(platform, provider_token)` 查询/更新/插入，避免前缀相同的不同 token 被合并。

MySQL 产品 schema 不安装 trigger。应用是唯一容量维护者：在同事务、singleton 锁下，对单个已冻结 fanout（最多 32）重新计算未 ACK 的 pending/running/retry_wait target 数，使用消息保存的 `pending_targets` / `usage_payload_bytes` 与当前值差额更新 ledger_usage。删除消息先扣消息/目标/字节，再执行 FK cascade；不依赖 MySQL cascade 触发子表 trigger。测试临时注入的 AFTER INSERT trigger 仅用于制造原生故障，不属于产品 schema。SQLite 和 PostgreSQL 保留其各自现有 trigger 计数实现，不能对 MySQL 再叠加同一套计数。

`messages.has_payload` 是 `payload_bytes > 0` 的 STORED generated 列；`messages_expiry(has_payload, expires_at, delivery_id)` 让正文到期查询先跳过已清空正文的 retained history。原生测试单独检查 generated 表达式、STORED 属性、索引完整有序列、可见性与非前缀属性。其他索引覆盖 Pull owner / 顺序、due claim、精确 owner-delivery、身份期限、退休设备、alias、设备订阅和 token retirement。索引存在不代表优化器一定选用，更不代表大历史下成本已验收。

## 有界清理、资源与计划证据

正文到期先用生产 `EXPIRY_BATCH_SQL` 按 `(expires_at, delivery_id)` 锁定最多 256 个 ID，后续失败计数、ACK、状态、正文释放与 target 删除共享同一 keyset。共享 oracle 用 257 条相同 TTL 的消息检查首轮恰好处理同一有序 256 条，第二轮处理剩余一条，每行只推进一次。身份 GC 另选最多 256 条已过 dedupe_until、无正文、无 running 的 ID；各退休/alias 类别有自己的批次。批次限制选中集合和内存，不保证整个 maintenance 仅修改 256 行、只扫描 256 行或固定耗时。

启动 recovery 用 `delivery_id > cursor` 的稳定 keyset 分批读取最多 256 个 running 消息 ID；每批不保留整个历史，初始化恢复整体仍在一个事务内完成，启动总工作和锁持有时间随旧 running 数增长。退休 token、当前 owner 条件和索引过滤的成本也与数据量有关。

默认每 Provider H32 / Q32，总 handler 128、32 KiB 请求正文、活跃消息 10,000、目标 1,000,000；retained bytes 配置默认 i64::MAX，身份没有 quota。claim 先预留位置后读正文，owned attempt 从领取接管保留到 receipt COMMIT。原生 runtime oracle 安排 40 个 target、32 个已发结果，独立 MySQL session 锁住 ledger_usage；验证 pending receipt 占满 H，另八个不能继续 claim，回滚释放锁后才完成。等待期间观察独立连接和原子计数器，不能用已经被阻塞的 owner session 做验证查询。

性能计时也有明确覆盖边界。固定 profiling 标签的 samples 表示被包装的调用次数，不是 MySQL 引擎执行语句总数；例如 Usage 可包装四条 SQL 的 bundle。MySQL 没有产品 trigger，标签耗时仍包含 SQLx 驱动、协议与数据库网络 RTT，不能改名为纯引擎 CPU 或 server execution。当前 control 审查发现 delete_route、unsubscribe、rename、sync omission 清理中部分 acquire / begin / commit 和 lock_usage 原生 SQL 未单独打点；gate_hold 与 HTTP 总时长覆盖这些操作，但 control 阶段 histogram 只有部分覆盖，不能据此重建完整 SQL 操作数或把未列出耗时视为零。最终产品已给 receipt reconcile / release 加固定标签；Usage 为四条 SQL 的 bundle，仍须按 frozen revision 的实际标签覆盖解释各阶段百分位。

相同 Phase 标签在三库中不代表完全相同的内部工作，不能直接比较 PoolAcquire 百分位后归因为“数据库连接池竞争”：

| 后端 | Phase::PoolAcquire 实际被计时的边界 | 独立 Statement 样本的边界 |
|---|---|---|
| SQLite | SQLx pool.acquire，包括可用连接等待及驱动 checkout；不是 MySQL 式 owner RPC。 | SQLite 标签覆盖被包装的原生调用；trigger 内部工作包含在引发它的调用耗时中，不单独计语句。 |
| PostgreSQL | pinned connection mutex 等待和本地健康/连接存在检查，没有每次 acquire 的数据库 owner 查询。 | SQLx 原生调用及其网络/调度耗时；trigger 内部工作不单列。原生 lock_usage 未独立计 Statement。 |
| MySQL | pinned mutex 等待，加真实 `SELECT IS_USED_LOCK(...)=CONNECTION_ID()` 的 SQLx、调度、协议和 RPC 耗时；不是纯 mutex、普通 pool checkout 或纯 server 时间。 | owner check 不进入 statement_inclusive；原生 lock_usage 也未独立计入。应用计数没有 trigger，但 bundle 仍可能包含多条 SQL 及多个 RTT。 |

上述未单列工作仍由相应 gate_hold / 端到端时长覆盖。阶段可能包含子阶段，不能把 overlapping inclusive 标签相加作为精确总时间；跨库归因须结合实际边界、SQL/RTT 及完整 E2E，不能只看标签同名。

一条 pinned SQL session 限制数据库并行度；H32 是网络/结果安全预算，并非 MySQL 吞吐承诺。Provider I/O、回复上限、连接复用和退避继续使用共同 runtime/transport，未新增常驻睡眠 worker。小集合、连接数和配置预算不构成 RSS、数据库 buffer、日志、排序临时空间或磁盘硬上限。

MySQL 原生测试为生产 `PULL_BATCH_SQL`、`PULL_EXACT_SQL`、`CLAIM_ONE_SQL`、`RECOVERY_BATCH_SQL`、`EXPIRY_BATCH_SQL`、`RETIRE_TOKEN_TARGETS_SQL` 绑定参数执行 `EXPLAIN FORMAT=JSON`，输出真实计划；定义/可见性/collation 另行验证。没有要求 tiny fixture 选择指定索引，也没有以替代查询的计划证明生产语句。最终同 executable native aggregate 已采集真实计划，并通过所有 metadata projection CAST 后的 index/generated/NO PAD 实库检查；最终完整 JSON 在 `tests-mysql-index-repair-aggregate-first.log`；旧 `tests-mysql-final-all-metadata-aggregate.log` 仅为 before-baseline。这些是 tiny fixture 功能和 schema 证据，不是生产基数计划或性能证明。

## 最终容量结果与未决原因

两条最终容量 raw 收据均已收到，所属 lane 均 QUIET；详细输入、观测器身份、阶段及 OS 采样见 [C5 容量报告](c5-capacity.md)。功能验证通过不代表容量目标满足：

| 后端 | 接纳与目标结果 | offer→post-COMMIT 延迟及边界 |
|---|---|---|
| PostgreSQL final | 2560 次 HTTP 全部持久 accepted，40960/40960 个 target 完成 COMMIT。 | 完整成功集合 p95 / p99 = 133143.957 / 137232.582 ms；全部 SQL 完成约在 offer 后 149.6 秒。baseline 为 124.446 秒，约 25 秒变慢原因未决。 |
| MySQL final | 190 秒 deadline FAIL。2560 次 HTTP 全部持久 accepted、HTTP error=0，但目标仅 7169/40960（17.5024%）完成；unfinished=33791，其中 pending=33736、running=55；late=0。 | 已成功子集的条件 p95 / p99 = 172601.739 / 184705.326 ms；不是全部 offered target 的总体百分位。没有全排空、ACK 或 post-ACK 回落阶段。 |

新增 sampler 提供有效 OS 观测，但尚不能把它认定为 PostgreSQL 相对 baseline 变慢的唯一原因；这个约 25 秒差异与 C4 旧约五秒高负载耗时差异分别未决。MySQL 五列索引目前只证明受控 fresh copy 上相同生产 SQL 可以去掉 sort，最终容量仍 FAIL，不能报告实际瓶颈已修复、吞吐收益或给两库严格性能比率。条件成功延迟不能掩盖 33791 个未完成 target，HTTP 接纳零错误也不等于投递全完成。

## 可执行测试范围与原生收据

`backend_contract_tests.rs` 通过相同 run_oracles 覆盖三库字段/TTL/鉴权/身份、HTTP prefix 和 Direct/Pull 投影、原子容量、ACK/receipt 两种顺序、257 条 Pull/GC/expiry、重启、控制面 omission、coalescing/frozen receipt/current owner、退休 epoch、频道上限及字节拒收。数据库语法只在测试 fixture native helper 明确分支。

MySQL ignored aggregate 为 `backend_contract_tests::mysql_native_tests::mysql_shared_ordinary_contract_and_native_failures`，要求 `C5_MYSQL_TEST_URL`、`C5_MYSQL_DISPOSABLE=YES_NEW_SYNTHETIC`，严格 loopback、无 DSN query/fragment host override，并且 base 数据库名以 `c5_synthetic_` 开头。每例新建数据库，cleanup 只删除本次 CREATE 成功记录的名称。PG guard 允许严格命名的 `c4_synthetic_` / `c5_synthetic_`；没有任意用户库授权。

原生 MySQL 另含真实 1062 唯一冲突、1213 双 session 死锁、1205 行锁超时；AFTER INSERT 故障验证 accept 完整回滚及 usage 等式，且保留原 errno；按 owner connection ID 查询 `information_schema.innodb_trx` 观察真实等待后取消 SQL，验证排空回滚；KILL 精确 owner session 后证明 GET_LOCK 释放但 retained OS fence 拒绝同库/别名/连接参数第二 owner；H32/40 receipt 背压、正常 shutdown 和恢复 attempt。MySQL 没有 PostgreSQL 式延迟约束 COMMIT 故障，不能移用 PG 测试作为 MySQL COMMIT 证据。

外部 MySQL wire/process 四例均在 fresh case 首次运行通过，见 `fault/final-results.md`：

| Case | 实际故障与恢复结果 |
|---|---|
| `final-before-first` | 观察实际 plaintext handshake 与 SQLx COM_QUERY COMMIT，在首个消息事务 COMMIT 转发前截住。HTTP 503、failstop 70、接纳端点关闭；session 关闭后无消息/target、Provider 请求零。直接重启同库、同 op 首次创建身份，只发送一次，再 Pull/ACK 释放 message/target/byte 容量。 |
| `final-after-first` | COMMIT 已转发，真实 server OK payload `00000002000000` 被观察并截住。HTTP 503、failstop 70、端点关闭，持久消息/target 已存在、Provider 请求零。重启同库、同 op 返回 duplicate_completed，message/delivery ID、首次时间、绝对 TTL、dedupe、dataset metadata、owner/control/route epoch、pull owner 全保留；重启后只发一次，Pull/ACK 释放容量。 |
| `final-process-first` | 同 URL、localhost alias 加参数的第二 owner 被拒绝。首个真实捕获的合成 Provider 请求等待无响应；live owner SIGSTOP、精确 session 被 kill，旧 PID 尚活时第二 owner 仍拒绝。旧进程 SIGKILL 后重启保留身份/时间/TTL/epoch/owner，attempt_id 1→2，累计两次实际请求。这只在已有真实请求的 unknown external outcome 下暴露有限重复，不能称网络恰好一次。 |
| `final-released-session-fence-first` | 聚焦补充：旧 PID SIGSTOP、owner session kill，服务端 `IS_USED_LOCK` 明确 NULL；alias 加参数第二 owner 仍 OwnerContention，server lock 保持 NULL。杀掉旧 PID 后新 owner 立即 READY。 |

proxy 识别目标消息真实 prepared statement 之后的 COMMIT，不伪造 SQL error 或 OK 包；plaintext CLIENT_SSL 缺失由实际握手确认。四例前后检查 343 个产品源码/构建输入 hash 和 normal fixture SHA 不变；各自数据库在拥有的连接/进程关闭后删除，`quiet.json` 只证明所捕获 wire 进程已退出。环境为 RAM-backed InnoDB，共享 Unix `/tmp` 锁命名空间；未测试断电、跨隔离锁命名空间 owner 或持久磁盘故障。

原生 attempt-02 六个 loop 的共同 normal fixture 身份与产品 commit 记录于 `native/attempt-02-matrix-result.json`。PG/MySQL 各 Apple 8 phase、Android 3 方法及 Gateway control/restart 全 PASS，包含真实 owner merge 后 current Pull owner、frozen receipt、GRDB / Room / AndroidKeystore 持久化、ACK outbox 与新进程恢复。旧 cache 的合并身份缺口由新的 C5 test staging 补证：Android 使用隔离 test APK，离线路径构建 45 秒；克隆路径使生产 Kotlin dependency tasks 重新编译，安装的 cached main APK/JNI 没有替换。Apple 使用已有 cached bundle，未执行 Apple native build，通过 C5 多 phase 入口扩展验证；626 个 native cache hash 复核，旧 C4 cache 不改写。matrix 同时记录依赖下载发生，不能把整个准备过程称为零下载。

最终 native attempt-03 使用 651bf7 / 3204 同一 normal artifact，PG/MySQL 各 Apple 8 invocation、Android 3 方法 zero skip、Gateway restart 六 loop 全 PASS。Apple 实际退避恢复分别为 PG 62.515 秒、MySQL 62.235 秒；Android Room/outbox 两库均为 5/1→进程重启后 6/0→owner 合并后 7/0，旧 owner Pull 被拒、旧 ACK removed_count=0，当前 owner 持久化后 Pull/入库/ACK，迟到旧 receipt 正确结算且没有复活旧授权。收据为 `native/attempt-03-summary.json`，旧 attempt-02 仅保留 before-baseline。

attempt-03 无新 native build、download 或产品断言重试，复用精确 cached Apple bundle、原 main APK/JNI 与冻结 C5 test APK `c95c2dda1bcdf16461636e9af8fc04613044fde9809a3ffee4f98febbccb31e2`。旧 cache 626、clone 生产源 191、执行 adapter 文件 216 及最终 Gateway/test APK hash 前后复核不变。`native/attempt-03-quiet.json` 证明 25 个 owned host PID 已离开、所属 5580 emulator 停止、lease 释放，六个 case 库导出后 drop；不包含 root-owned DB environment、容量 lane 或共享 adb server 的生命周期。Android 导出只证明关闭后复制的 main 文件精确行，不宣称任意 live-WAL 快照完整。Gateway restart 使用合成 HTTP clients，真实 native owner 合并另由 Apple controller/Android repository 的存储与 ACK 收据证明。

客户端限制仍保留：Apple 为 macOS host controller / GRDB，不是 iOS/Watch/UI 或 OS 后台；Android 为 API37 emulator、显式 ACK drain，不是真实 FCM/WorkManager 调度；cached JNI 精确源码 revision 未核实，private channel journey 未使用。均为合成 Provider，没有真实 APNs/FCM、物理设备、release/deploy 或生产验收。attempt-01 observer 失败及 Android wrapper 首失败没有被 attempt-02 通过覆盖。

753a / e7b6d59 基线完成三库普通合同、新建合成 MySQL 原生事务/owner/runtime 与限定客户端恢复功能验证；最后五列领取索引修复已取得 651bf7 最终 artifact 的三库功能收据。最终 wire 四例与 native-03 六 loop 已通过并在各自范围 QUIET；最终容量 PG 全目标完成、MySQL deadline FAIL，两个 lane 均 QUIET；C5 owned 数据库环境已有最终清理/QUIET 收据。性能结论由 [C5 容量报告](c5-capacity.md) 单列，C5 owned 环境清理已由独立 env 收据完成，交付 review/commit 由 root 收口；不把合成环境 QUIET 外推到其他项目。新库测试不能外推为旧库导入、升级/回退、断电、持续吞吐或正式发布。下一步先审查 ordinary Private 缺口及容量问题，不自动扩大其他消息类型；完整主线替换还受真实 Provider/后台、旧库兼容、断电与 supervisor 验收阻塞。

## 最终 owned 环境清理

`env/final-cleanup.json`、`env/final-quiet.json` 确认 C5 synthetic database environment 已 QUIET：剩余六个 owned case 数据库全部 drop；按精确 container ID / UUID 匹配移除 PG/MySQL 两个 owned container；自有 runtime 资源归零、OrbStack 为 Stopped，loopback 32768 / 32769 均拒绝连接。合成 URL 文件全部删除，凭据随其库/容器删除失效。镜像保留，没有操作 volume 或其他项目/容器。

wire 的八个 PID / 四 case、native 的二十五个 PID / 六 case / emulator / lease、容量 lane 的 QUIET 各有自身收据；最终 env QUIET 补齐剩余 C5 数据库环境清理，不把其中任一收据冒充整机所有进程停止。清理前观察到另一项目 Aegir 的本机 cargo/rustc 构建，未触碰，且其不使用 Docker。没有证明测量全程不存在其他本机 build 或外部负载；该清理时点观测不能解释 PG final 约 25 秒差异或 C4 旧约五秒差异，二者原因仍未决。
