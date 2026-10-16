# C10 普通消息产品整合边界

本文只记录当前源码的所有权、替换关系和运行边界，不代替测试收据，也不作吞吐、长期内存或发布就绪承诺。C 内核来源为冻结 C9 `86e073dec487903cb27f2e67d6e5cbdcb06a6900`；迁入正常 crate 的是必要运行模块。历史 fixture、报告和测试的总行数不是产品精简收益指标。

## 正常产品入口与唯一接纳

正常入口为 [`src/main.rs`](../src/main.rs)，使用正常 Args、RuntimeTuning、Storage 和 router。HTTP [`services/message.rs`](../src/services/message.rs)、MCP [`mcp/rpc/message.rs`](../src/mcp/rpc/message.rs)、MQTT [`ingress_server.rs`](../src/mqtt/server/ingress_server.rs) 的普通发送共同进入 [`submit_command → submit_message`](../src/delivery_core/submit.rs)，经既有频道授权后调用 [`accept_ordinary_message`](../src/delivery_core/execution/submit_runtime.rs) → [`OrdinaryStore::accept_authorized`](../src/ordinary/application.rs)。该分支不先执行旧身份预留、sender status 或 dispatch submission 写入。

[`MessageSend::prepare`](../src/domain_model/message.rs) 保留普通输入的纯校验及投影；`thing_id + occurred_at` 仍是普通消息关联，不转成 Thing 业务。三个具体后端在同一接纳事务中检查频道、身份及冲突、冻结目标、预留容量并保存正文；COMMIT 成功才形成接纳成功。持久 identity 同时保留 `thing_id` scope、首次时间和绝对 expiry。普通 APNs、FCM、WNS、WatchOS 的目标选择和 wire 投影复用现有能力，Watch alert deadline 在目标冻结时保存，见 [`transport.rs`](../src/ordinary/transport.rs)。

## 权威数据与控制边界

| 数据 | 唯一持久来源 | 含义 |
| --- | --- | --- |
| 设备、频道、订阅、路由 | 正常 `devices`、`channels`、`channel_subscriptions` | 没有第二套 C 控制表；Registry/cache 仅为提交后投影 |
| 普通身份、首次时间、到期及一份正文 | `ordinary_messages` | `op_id`、fingerprint、scope 和 30 天身份保留不随正文 ACK 释放 |
| 冻结投递与当前读取能力 | `ordinary_targets` | `device_key` 是 frozen receipt owner；`pull_owner` 可以随身份合并迁移，不能混为一个所有者 |
| 责任/占用计数 | `ordinary_ledger_usage`、`ordinary_private_usage` | 事务内计数；Private waiting 仍算已接受责任，不能当成已领取数量；不是第二份消息队列或历史硬配额 |
| 退避及迟到请求 fencing | `ordinary_provider_cooldowns`、`ordinary_retired_provider_tokens` | 调度/退休账本状态，不复制设备或订阅规范来源 |
| 既有 Widget 刷新的待派生工作 | `ordinary_widget_refresh` | 同接纳事务保存无正文 marker，复用正常 dispatch acceptance clock；不算普通投递目标/成功、不保留 Pull 正文 |
| C 查询控制记录的接口 | `ordinary_device_routes`、`ordinary_channel_routes`、`ordinary_subscriptions` | 非物化 view，直接读取正常控制表，不双写同步 |

原生定义分别见 [`store.rs`](../src/ordinary/store.rs)、[`pg_schema.sql`](../src/ordinary/pg_schema.sql)、[`mysql_schema.sql`](../src/ordinary/mysql_schema.sql)。正常 `devices.ordinary_route_generation` 只在新路由或真实路由变化时获得单调代际；重复 sync 的正常 `route_revision` 更新不使已发行投递失效。真正离开路由、退休或删除及重建会 fence 旧能力。Private 清空频道只终结被清的旧 Private targets、提升 target epoch，不强制断开仍有效的现连接。

[`Storage`](../src/storage/storage/ordinary.rs) 将 C 与正常控制写入放在同一 `durable_write_gate` 下；三个后端在正常控制事务中执行必要的目标迁移、退休及清理 hook。控制 COMMIT 后才更新缓存、通知和 Registry 投影。取消订阅不重新展开或撤回首次已冻结目标；发送前仍检查当前授权、路由代际和退休 epoch。运行中的 Provider receipt 维持冻结身份直到 settle，不因 Pull owner 迁移而改写。

ACK、过期及合法终结释放相应队列/正文占用；仍有其他有效消费者时保留正文。Private `InvalidPayload` 是持久负结果并计入 `private_rejected_count`，不是成功 ACK；`Error` 保留重试语义。`acked_at` 沿用技术终结标记用途，不能把所有非空值统计成客户端成功确认。

## 退出的普通旧路径与保留部分

| 路径 | C10 的边界 |
| --- | --- |
| 普通 semantic reservation、旧 sender status、dispatch submission/manifest、普通 Provider outbox 生产 | 正常普通 submit 不再进入；[`legacy_dispatch_entity_type`](../src/api/handlers/message/dispatch/mod.rs) 在旧生产/恢复入口拒绝 `message`，不作隐式回退；既有 `APNS_WIDGETS` 派生刷新仍复用共享 outbox，不能作为普通身份/正文权威 |
| 旧 Provider workers、submission recovery | 保留服务 Event、Thing 及共享补充投递；没有普通消息第二消费者 |
| 旧 `private_payloads`、`private_outbox`、`provider_pull_queue`、hot cache、fallback scheduler | 保留其他模型；普通正文和待确认工作直接由 C 提供，不复制进去 |
| 普通 Pull/ACK/status | [`pull.rs`](../src/api/handlers/core/pull.rs)、[`ack.rs`](../src/api/handlers/core/ack.rs)、[`send_status.rs`](../src/api/handlers/send_status.rs) 接 C；旧数据源仅用于保留的非普通模型，启动 guard 不允许遗留普通记录成为 fallback |
| 原独立 prototype 服务 | [`prototype` library](../prototype/src/lib.rs) 只 re-export 产品模块；[`free_architecture_fixture`](../prototype/src/bin/free_architecture_fixture.rs) 只启动显式指定的正常产品二进制，Unix 使用 exec；没有第二 router、数据库或运行内核 |

因此保留 Storage、dispatch、Private 共享模块不代表保留普通双写。Event、Thing、Live Activity、Widget 等功能没有迁入 C，也没有扩展业务。原 prototype 重复运行源码退出清单及冻结 C9 证据位置见 [`c10-product-source-cutover.md`](../prototype/docs/c10-product-source-cutover.md)；历史容量 harness 不再能以新 launcher 冒充原型对照。

普通消息既有 Unread/WatchSummary Widget 刷新由同事务 marker 恢复，[`widget_refresh.rs`](../src/ordinary/widget_refresh.rs) 按当前正常 Widget 订阅逐页投影到共享 `APNS_WIDGETS` job；job 不带普通 `op_id`/dedupe，重复投影以共享 acceptance order 去重。marker 不复制用户正文，普通 ACK 不删除 marker；没有普通 Provider/Private 目标但存在匹配 Widget 的新消息也保留该既有派生行为。它不是第二条普通完成链，不能用刷新成功冒充普通投递成功。

三个后端均以 `UNIQUE(channel_id)` 在普通接纳事务内保留每频道最新的一条待刷新 marker，更新其 delivery、共享顺序、首次接纳与绝对到期元数据；不改变普通身份或冻结目标。重复 `op_id` 不改 marker 或到期；已过期的新请求不取代有效待刷新状态。最新请求的到期可短于旧请求，沿用既有 latest-state Widget job 被新状态替代的意义，不延长新消息的 TTL。每个平台/token 的实际派生 job 仍独立。派生 outbox 满时保留一个频道 marker 等待，不新增拒收或逐请求责任行。

唯一生产投影者是正常生命周期已有的 `SubmissionRecoveryWorker`：接纳 COMMIT 后发送已有 wake，worker 串行处理最多 8 个频道、每页最多 128 个目标，并保留原 5 秒恢复检查。HTTP/MCP/MQTT 请求不在接纳后继续持有 Widget fanout 或派生写事务。投影期间新接纳可以替换同频道 marker，旧 snapshot 的精确 `complete(delivery, order)` 删除零行是正常 superseded，不误删新状态，也不触发 fail-stop；未知 COMMIT 仍失败停止并在重启后从最新 marker 恢复。既有终态清理保持原合同；若未完成 marker 的旧派生历史经正常 GC 清除，恢复可有限重复无正文刷新，不承诺外部 exactly-once。

marker 行数随待刷新频道数增长，不随同频道请求数增长；这不是全局频道或历史磁盘硬配额。30 天普通身份仍逐消息保留。投影 SQL 的排序/扫描随当前 Widget 订阅规模变化，页大小只限定加载到内存的对象数。最终三库及恢复收据另列，当前说明不宣称整合 ready。

## 会话、预算与背压

正常 [`PrivateState/PrivateHub`](../src/private/state/mod.rs) 是唯一会话、连接、resume 和 ACK 所有者；[`hub/ordinary.rs`](../src/private/hub/ordinary.rs) 只为该 Hub 增加 C 数据源。TCP/TLS、QUIC、WSS 和 MQTT 复用原运输入口，没有并排 C PrivateRuntime。普通活跃正文按需编码，共享 `Arc` 给在途重传；总活跃 work 和每设备 work 由正常 profile 派生的有限 slots 限制，空闲连接不预分配最大帧。

[`ProviderBudgets`](../src/dispatch/budget.rs) 在 [`app.rs`](../src/app.rs) 创建一次，由普通 runtime 和保留的 workers 共用。普通 APNs、Live Activity、Widget 共用 APNs semaphore；FCM、WNS 各自共用一个预算。凭据及 HTTP 连接仍由正常 Provider clients 所有，[`ProductProviders`](../src/ordinary/transport.rs) 只适配请求，不再创建凭据或独立 H32。

获取顺序是先等待公平 Provider semaphore，再进入 C gate/claim SQL；等待预算时不持数据库 gate。领取前已预留，网络和等待 receipt COMMIT 的工作继续占用同一 permit。未到期 retry 留在 SQL，不占网络执行位置；内存 work 按预算创建，不按积压量创建。保留共享使用者以同一公平 semaphore 获取执行机会，无新增伸缩控制器。H32 是保留的对照基线，实际产品限额来自 RuntimeTuning，不被声明为最终统一上限。

普通接纳在同事务检查系统待执行目标责任预算 `max_targets=1,000,000`：计入 Private 等待/已领取但未 ACK，以及 Provider pending/running/retry；完整 fanout 一次预留。Provider 独立活跃目标容量仍合计 C 和旧非普通工作。Provider 已接受后留给 Pull 的正文不计该待执行目标数，继续按原 TTL、ACK 释放和 30 天身份语义保存，没有新增正文/身份数量拒收。

Private 全局及单设备限制都是执行窗口。任一窗口满时，新的 C targets 在 SQL 中等待，健康 Provider 目标可先执行；领取事务取两个剩余窗口的较小值，0 时不加载正文。两个窗口均扣除对应旧非普通 pending/claimed/sent 及 C 已发行、未终结的 distinct claim，等待本身不算执行位置。`ordinary_private_usage.pending` 保留全部 Private 责任供观测，不作为执行窗口配额。显式 Provider → Private 路由迁移保留原容量检查，同 Private sync/重连不会因已有 waiting 超过执行窗口而拒绝。

旧非普通 Provider coalescible 记录从终态重新激活的既有分支未新增容量拒收，不能据此宣称所有产品写入已有同一严格硬配额。没有新增正文/身份 history-full 拒收。30 天保留是时间合同，不是磁盘字节上限。历史、正文和数据库可复用空间仍需容量规划；有界内存、队列和清理批次不能证明磁盘固定有界。

## 三库事务与产品生命周期

[`driver/ordinary.rs`](../src/storage/database/driver/ordinary.rs) 明确分派三个后端，接入正常 Storage 的 pool、gate 和关闭流程，不引入通用 SQL dialect 框架。

| 后端 | C 数据事务/连接 | 控制与独占所有者 |
| --- | --- | --- |
| SQLite | 正常 core database/pool，`BEGIN IMMEDIATE`；保留原 dispatch/delivery sidecar 给其他业务 | 原生控制事务及 trigger；规范路径文件 owner 防同数据集第二进程 |
| PostgreSQL | 正常 pool；C 数据事务显式 READ COMMITTED，`lock_timeout=3s`、`synchronous_commit=on` 为 transaction-local，归还连接不改其他业务 session | 原生 row/unique/transaction 约束；控制 hook 在正常事务内局部设限；另持固定物理 advisory-lock session |
| MySQL | 从正常 pool 固定借出一条 C data session，计入原 pool 最大连接数；C session 局部 lock timeout/strict mode 不回流其他使用者，关闭时显式关闭该连接；不透明重连 | InnoDB 原生事务及锁；控制 hook 同正常事务；另持固定物理 `GET_LOCK` owner session |

实现见 [`pg_store.rs`](../src/ordinary/pg_store.rs)、[`mysql_store.rs`](../src/ordinary/mysql_store.rs)、[`ProductOwner`](../src/ordinary/owner.rs)。PG/MySQL owner 同时使用数据集身份的机器文件锁作为失去数据库会话后的同机接管屏障；监测验证原物理 session 的实际锁，不把新连接当成原锁。当前文件锁实现有平台边界，Windows OS 接管/进程验收仍是发布待办，不据 host 构建推定。

启动顺序为：获取 owner → 正常 schema/Storage 初始化及旧普通 cutover guard → attach 单份 C ledger、恢复及正常会话/共享资源 → 开放入口。失锁、C 致命任务或 COMMIT 失败/未知使共享 health 失败，停止新接纳/领取并唤醒正常 main 失败路径；未知外部结果由持久身份和重启恢复处理，不在数据库重试中重发外部请求。

关闭由 [`main.rs`](../src/main.rs) 和 [`AppShutdown`](../src/app.rs) 排序：停止入口/新领取、结束 Private/MQTT 生产及会话、排空其他 workers 和 C 在途 receipt、关闭 C data resources 和正常 pools，最后释放 owner。异常超时或取消不走正常释放捷径，机器锁保留到进程退出，避免旧工作尚存时接管。

## 已授权合同与发布前置

| 项目 | 当前口径 |
| --- | --- |
| HTTP 尺寸 | 整个 `/message` JSON 为 48 KiB（49,152 bytes），由该 route 单独设限；控制 router 仍为 32 KiB。GET/query、MCP、MQTT 各自原解析/运输边界不能按此推定放宽 |
| Private 尺寸 | 完整 frame 为 128 KiB（131,072 bytes），计入 type/flags 两字节，不计 TCP/QUIC 四字节长度前缀；WELCOME 同值。MQTT packet 有独立配置上限；QUIC 流控窗口不是消息上限 |
| TTL 变化（已授权） | 普通绝对 expiry `<= now` 时仍成功保存身份，但不创建投递/不新外发；0/负数不再沿旧在线 Private/MQTT 路径实时发送。缺省/null/空值取正常配置首次到期，重试不续期；不改变 Event/Thing |
| 空集合变化（已授权） | 首次接纳的空目标集合也冻结；以后增订阅再用同 `op_id` 返回原 IDs/首次时间且仍空，需要新 `op_id` 才冻结新收件人。旧 NoAttempted 路径曾可清 dispatch dedupe 后重新展开 |
| Private 执行窗口满（已授权） | 保留普通 Private 责任持久等待及健康 Provider 先发；单设备/全局执行窗口满均不直接拒绝整个新普通接纳，由系统待执行目标责任预算原子限制等待量。执行窗口、待执行目标预算均不是正文/身份历史配额 |

尺寸决定继续要求 Gateway、Warp、Android JNI、Windows 配套版本。旧 Private 客户端可能在 WELCOME 阶段拒绝连接；无旧版协商、兼容旁路或 WSS 兜底。建议先准备并发布新版客户端再切换 Gateway，本任务不执行发布。Private 扩容不扩大 APNs/FCM/WNS 独立供应商限制，也不允许静默截断。

现阶段 guard 对尚未迁移的旧普通身份历史和待投递状态拒绝启动，不双账本读取、不双调度、不回退。面向已有用户库的上线必须先完成显式旧库迁移、回滚和恢复验收；本轮新库正确性不能替代它们。真实 APNs、物理 Watch 后台、断电持久性、Windows OS 及 Android/Windows 客户端 QUIC/WSS 仍列发布前验收。当前文档不填入未运行的结果，不把 C9 原型能力或单次有限窗口解释为产品 SLA。

本轮早期尚未带频道唯一约束的 C10 测试库也不能静默复用：三库初始化会验证真实单列频道唯一约束，缺失时在开放入口前拒绝启动。后续显式离线迁移须在独占所有者下保留每频道最大 acceptance order 的 marker，再建立唯一约束，并保持普通身份、正文、目标与已派生 job 不变；配合 ordinary Widget token key 的旧派生映射/取消验收一并验证。当前实现不自动合并、删除旧候选数据或伪装已有 `CREATE TABLE IF NOT EXISTS` 已完成迁移；新的实库测试必须使用全新 synthetic 数据库。
