# C4：普通消息 SQLite / PostgreSQL 存储边界

本文记录当前隔离候选的实现合同，不替代实库测试收据。范围为普通消息、FCM/APNs、axum/Tokio，以及单台 Unix 主机上的单个 owner。没有接入 MySQL、Event、Thing、Watch、WNS 或 Private 数据面；没有证明旧主线库导入、升级回退、真实 Provider、设备后台或部署就绪。

## 共享入口与后端所有权

`ordinary_store.rs` 的 `OrdinaryStore` 是具体 facade，内部只有 SQLite / PostgreSQL 两种 backend。`sqlite:` 进入既有 `DeliveryStore`；`postgres:` / `postgresql:` 进入 `PgDeliveryStore`。HTTP 和 runtime 调用完整业务操作，不取得数据库驱动、事务或 SQL executor。

共享操作包括 register、route、subscribe、channel 控制，accept、claim、发送前授权、settle、Pull、legacy Pull、ACK、status 和 maintenance。`Config`、`Counters`、`Ticket`、`ClaimBatch`、通知和健康 fence 贯穿两库；Provider transport、H/Q 预算及 pump 调度继续共用。SQLite 的 direct-pool 白盒测试由 test-only extractor 保留，不要求 PG 模拟 SQLite 的错误码、WAL 或文件锁故障。

PG 使用 `pg_store.rs`、`pg_control.rs` 和独立的 `pg_schema.sql`。产品中保存原生 `$n` SQL，没有运行时字符串替换、SQLx Any、通用数据库框架或自动事务重试。

## 单实例：数据库 session 与本机文件两道 owner

PG 启动先以五秒预算建立一条物理 `PgConnection`。同一条连接调用 `pg_try_advisory_lock(1346852687,1129271876)`；未取得锁即拒绝启动。当前只有固定的 `pushgo_c` schema，因此数据库中这一普通 ledger 只有一个 advisory owner，不能通过 DSN、主机别名或用户名变化取得第二个 session owner。

在 advisory lock 下创建或读取私有 `authority_metadata`，保存不可变 `dataset_uuid` 与 `schema_version`。同一 dataset 的 UUID 用来取得 `/tmp/pushgo-c-pg-{dataset_uuid}.owner` 本机排他文件锁；这一步在 schema 初始化和 running recovery 之前完成。不同 URL 指向同一 dataset 时仍使用相同本机锁名。当前 PG 候选在非 Unix 平台明确报不支持，不能用每用户临时目录宣称实现跨用户的本机 owner 排他。

全部 SQL 通过 `Arc<Mutex<Option<PgConnection>>>` 访问这条 pinned session。没有连接池补连、失效后替换连接或运行中重新抢锁。数据库 session 丢失后，即使 PG 已释放 advisory lock，旧进程仍持有本机锁；第二个本机进程不能在旧 Provider future 尚存时恢复同一 dataset。文件锁要求所有候选进程看到同一台主机的 `/tmp` 和同一 dataset 身份；它不是跨主机协调、容器隔离命名空间协调或数据库克隆/恢复协议。

共享 `Health` 是不可逆 fence，保留首次失败原因。Facade 对连接类 SQLx 错误、PG `08xxx` 和 `57P01` / `57P02` / `57P03` 错误锁存失败；pump 失败或 runtime 被直接 drop 也锁存。业务入口、取得 gate/连接后和写入 COMMIT 前检查健康状态，排队请求不能在已经观察到的致命故障后继续提交新接纳。原始数据库错误仍返回给首次失败调用方；后续调用得到不可用状态。普通参数、鉴权、容量及业务冲突不等于数据库 session 失效。

正常停机要求调用方先停止并 join HTTP handler，再 join Provider pump，关闭 pinned connection，最后显式释放 owner 文件锁。异常 drop 不提前释放文件锁；进程退出由 OS 回收。已经授权并发出的 Provider 请求仍可能产生外部效果；owner 锁不能撤销网络投递，恢复继续使用既有 unknown-outcome 和 attempt fencing 合同，不能据此宣称网络恰好一次。

## 事务与生命周期

PG pinned session 显式设置 `default_transaction_isolation = 'read committed'`。写入口保留共享 mutation gate；事务首先对 `ledger_usage` singleton 执行 `SELECT ... FOR UPDATE`，然后才执行该业务写入。连接串行化及 singleton 锁没有替代冻结路由、attempt_id 或退休 epoch 的条件校验。数据库事务内不等待 Provider I/O。

| 操作 | 当前原子边界 |
| --- | --- |
| accept / fanout | 规范化后进入 gate 和事务；先鉴权，再检查 op_id 的范围和完整 fingerprint。新操作同事务写不可变身份、原始正文、首次时间、绝对 TTL、冻结 target 和容量增量；COMMIT 成功后才返回新接纳。重复请求复用首次身份；重复分支不生成新正文或 target。 |
| claim | runtime 先预留位置，事务内维护到期状态、读取 durable cooldown，按 pending / retry_wait 交替选取不超过 grant 的 target，置 running 并递增 attempts / attempt_id。COMMIT 后才交给 Provider；不会预取超过已预留数量的正文。 |
| authorize / settle | 发送前再次读当前 owner、route generation、TTL、退休 marker 和 running attempt。回执按冻结 device_key、delivery_id、running、attempt_id 条件更新；同事务更新结果计数、Sender 状态、精确 invalid-token 订阅清理及可释放正文。既有 cooldown 写入即使回执已失效也保留。 |
| Pull / ACK | V2 Pull 为读取；批次查询 201 项，返回前 200 项及 has_more。ACK 按当前 Pull owner 和 delivery_id 更新，按新增确认的 ID 数计数；同一 ID 的多个 coalesced target 只计一。running row 保留到回执结算；重复或外设备 ACK 为零。legacy Pull 在一个事务中读取并 ACK 实际返回项，批次上限 512。 |
| 控制面 | register / route / retirement / subscribe 等完整写操作各自成事务；保留 route_revision、实际变化的 generation、control_epoch 和十分钟注册 alias。sync_channels 逐项调用订阅事务，全部项成功后另一个事务清理不在期望集合中的订阅；整个列表不是一个大事务。 |
| recovery | 取得两道 owner 后初始化；已 ACK 的旧 running row 不再重发，其余旧 running 变为 retry_wait。没有网络事务或额外 lease / SKIP LOCKED。 |
| maintenance | 在一个事务中处理退休 token、退休设备、alias、正文到期与身份到期。PG 正文到期先按 `(expires_at, delivery_id)` 锁定最多 256 个 ID，后续计数、ACK、状态、target 删除、正文释放共用该 keyset，避免 MVCC 更新后多次 LIMIT 选中不同集合。 |

Coalescing 只迁移 retained Pull owner，并把旧任务的 owner_generation 标记为失效；冻结的 receipt key 不变。旧未授权任务不能从新 owner 启动，已经授权的回执仍按旧 frozen key 结算。Provider 接受、客户端 ACK、Sender 状态和正文保留不是同一个状态。

## 原生类型、索引与计数

PG 使用固定私有 `pushgo_c` schema，连接固定 `search_path`，不写主线 public 表。毫秒时间、generation/revision/epoch、计数和 attempt 字段使用 `BIGINT`；正文为 `BYTEA`，直接保存序列化字节，不经 JSONB 重编码；文本键显式 `COLLATE "C"`。数据库保存 op_id、delivery_id、message_id 的唯一约束以及 `(delivery_id, device_key)` target 主键。

PG 保留 due claim、Pull owner 顺序、消息身份到期、正文到期、设备退休、alias 到期、设备订阅和 token retirement 索引。索引存在不等于查询计划已验收；SQLite 的 CROSS JOIN 固定 join 顺序不适用于 PG，PG 使用原生 JOIN，计划须由实际 PG EXPLAIN 单列证明。

`pg_schema.sql` 的 row triggers 是唯一容量计数维护者。正文/消息 trigger 维护 retained bytes 和 `pending_targets>0` 的消息数；target trigger 维护未 ACK 且处于 pending / running / retry_wait 的目标数，并增减消息 pending_targets；BEFORE INSERT trigger 填入初始 Pull owner、owner_generation 和 control_epoch。应用没有叠加另一套显式容量增量。

适配中特定 SQL 包括：`ON CONFLICT ... DO NOTHING` 代替允许忽略的 subscription 插入；`GREATEST` 保存 cooldown 最大值；空 `BYTEA` 代替 SQLite 空 BLOB；退休 marker 按复合键有界删除，不使用 SQLite rowid。这些变化保持业务唯一键及 affected-row 合同。

## 预算与限制

默认每 Provider H32、claim quantum 32；默认 HTTP handler 128、body 32 KiB、活跃消息容量 10,000、目标容量 1,000,000。配置仍允许既有正数预算范围；本文不把 H32 解释为最优或可持续吞吐证明。默认正文 TTL 七天，单条上限三十天；显式 TTL 仍为绝对时间，不在重启或重复提交时延长。

身份保留默认为首次 accepted_at 加三十天，既有 `dedupe_retention_ms >= 30 天` 配置继续允许；本文不把它改写为只能三十天。ACK 只释放可释放 target / 正文，不提前驱逐身份。没有身份数量/字节硬配额，因此总磁盘占用没有固定上限。

各维护类别保留 256 项批次边界；它限制所选消息或 target 的数量，不保证每次 SQL 恒定工作量，也不保证全部类别总共只修改 256 行。正文到期一次可处理 256 条消息的所有关联 target；PG expire keyset 在内存中最多 256 个 ID。Pull、claim、退休集合和历史深度的实际计划与空间成本需要实测。

继承的具体预算（没有为PG另开一套HTTP/Provider默认值）：

| 资源 | 当前默认/边界 |
|---|---|
| HTTP连接/HTTP2 | 128个连接，创建连接task前取得permit；每连接1个并发stream，stream/connection初始窗口各65535字节。 |
| handler/控制 | 总128个，非/message控制子预算16；等待控制permit的请求已经占总permit，响应Body释放前仍持permit。JSON正文32KiB。 |
| Provider | 每Provider H32/Q32；网络与receipt等待共用owned预算，grant预留在领取前完成；回复应用缓冲最多16KiB，超限/截断仍保留收到的status/retry header。连接建立5秒，总请求15秒，无redirect。 |
| 空闲Provider连接 | 每provider idle上限随既有预算，连续工作复用；已证明无当下work且owned排空后quiesce释放client，不预建所有worker或为退避任务占执行槽。 |
| PG连接/缓存 | 一条pinned session，SQLx0.8.6默认prepared-statement cache100项（不是身份缓存；显式DSN配置另计）；所有读写复用，丢失不重连。 |
| 集合/历史 | Pull201读/200返回、legacy512、ACK及维护沿用既有批次；expiry内存keyset最多256；history不载整个30天窗口。 |

这些是当前候选默认配置及有限集合上界，不是整机RSS/磁盘硬配额。字段/令牌长度、数据库索引/排序/缓存与配置变化仍影响实际占用，PG长期工作量及物理存储性能没有由小fixture证明。

PG 连接建立预算五秒，session `lock_timeout` 三秒，`synchronous_commit=on`。候选不新增固定三秒 `statement_timeout`，继承数据库 server / role 的语句时间限制。连接建立预算不是整个 schema 初始化或启动过程的墙钟上限。死锁、锁等待超时、连接中断和写入失败不自动重放事务；COMMIT 结果不明时，恢复使用相同 op_id 查询原身份，不能换身份重投。

## 验证收据入口

本文件仅解释代码。共同 oracle、实际 PG 类型/trigger/事务、故障、owner session-loss、EXPLAIN、容量及完整差异审查的实测结论见 [C4 结果](c4-results.md)：

- 实测结果文档：[C4 结果与身份](c4-results.md)，最终实现f8ed62f、fixture8d458bbf、SQLite测试修正d925b97；真实PG七个新库已通过，具体限制仍逐项保留。
- 本机 C4 证据根：`gateway/build/quality-results/c4-sqlite-postgres-20261015/`；首次失败与修复后的收据分别保留。
- 前序已确认合同与适配计划：[C3 结果](c3-results.md)、[下一阶段适配计划](next-adapters.md)。旧计划中的 MySQL、迁移与更大范围验收不会因 C4 的实现自动完成。

任何 SQLite、合成 PG 或短 Mock 通过都不能单独证明旧数据迁移、断电恢复、真实 Provider、真实客户端 OS 后台、持续吞吐或部署验收。
