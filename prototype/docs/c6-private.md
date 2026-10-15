# C6 ordinary Private：实现与验证边界

Private 接入源码为 `e3de1ebe1caac618ecdcc293e040752e36752fe4`，其三库账本来自 `74bca98`；后续 `9fc812b40880e0ffd2375b4c83bb920292bdf880` 仅优化 MySQL receipt 重复核对和 next_due 查询，Private wire/runtime、SQLite/PG 路径未改。Private 默认关闭；仅显式启用后接入普通 Message，不扩展 MQTT publisher、Will、Event、Thing、Watch 或 WNS。以下“已实现”不自动表示每种客户端、TLS 或容量场景均已验收。

## 生产协议与 C 接入

生产依据为 Gateway 现行 `src/private/`、`src/mqtt/server.rs`、`src/mqtt/server/private_receiver.rs`，及锁定的 Warp `dbae3a80c8b796969cadc9045ee982a0a60c4d27`，不以工作区另一 Warp HEAD 代替依赖版本。

| 传输 | 保持的合同 | C 接入 |
| --- | --- | --- |
| QUIC | TLS，ALPN `pushgo-quic` | 自有 endpoint/JoinSet；公开 Warp session engine |
| TCP | TLS ALPN `pushgo-tcp`，或明确的 edge/offload plaintext | 自有 listener/JoinSet；公开 framing/session engine |
| WSS | 共享 HTTP listener；`/<basepath>/private/ws`；必须协商 `pushgo-private.v1` | 实际 HTTP auth/router 与有界、可 join 的 upgrade owner |
| MQTT5 receiver | CONNECT、既有频道订阅/退订、QoS1 JSON 下行、PUBACK | 单独协议 adapter，共用同一个 Private runtime/账本能力；当前 TCP listener 与 main 路径一致 |

Warp wire v2、payload v1、postcard framing/版本协商/heartbeat 仍由锁定公开库负责。HELLO 验证设备当前 Private route、未退休/合并，以及与 HTTP 一致的共享 token 策略；配置 token 先哈希并恒时比较。Refresh/InBandReauth 和 route wake 重新核对 owner/generation；每次出站还核对持久 grant。频道操作走既有控制入口。

Canonical JSON 只在出站边界转成 `{payload_version:1,data:Map<String,String>}`；用 BTreeMap 序列化保持稳定字节顺序，公开 profile 可直接解码。外层 delivery ID 权威；message ID、base URL、时间、绝对 TTL 和完整普通字段沿用同一接受记录。

MQTT 与 Warp 的确认不同：MQTT topic 是裸 channel ID，JSON schema 是 `pushgo.mqtt.delivery.v1`；CONNECT username 承载共享 token，必须先验 token 再按 `mqtt` platform 注册，必要时 CONNACK 返回 assigned client identifier。SUBSCRIBE 只允许一个既有频道、QoS1 和 `pushgo-password`，拒绝 wildcard/shared filter、subscription identifier、No Local/retained options；既有原子 subscribe 的 ID 分支不会创建未知频道。UNSUBSCRIBE 走真实控制面。仅成功 PUBACK 通过 packet ID 映射终结已 issued 的持久能力，非成功或未知 PUBACK 不消费；Warp 的 ACK OK 和 invalid_payload 都可终结，Error 不消费。拒绝 CONNACK 也必须编码 MQTT5 Property Length；不能以直接 EOF 代替认证错误。

MQTT 保留 main 的 CONNECT 120 秒、server keepalive 上限 120 秒、读期限 `ceil(1.5 × effective_keepalive)` 且至少 2 秒；wire inflight 上限/CONNACK receive maximum 为 128，与 runtime Small 的 96 逻辑窗口分开。未鉴权读可被 shutdown 取消。

## 三库唯一账本与身份

`OrdinaryStore.private_route/claim/authorize/ack/release` 分别落在 SQLite、PostgreSQL、MySQL 原生实现。完整 Provider/Private fanout 与 accept 同事务提交；没有第二套私有消息身份或异步补写接受结果。Private-only 成功接受的 wire `dispatch_status=attempted_accepted`，持久 `messages.status=sent`；此时仍可有未 ACK 的 Private 消费义务。混合消息只等真正 Provider pending/running/retry work，Private enqueue 不冒充 Provider accepted。

- `messages` 保留 op/message/delivery ID、正文、accepted_at、expires_at、dedupe_until，以及冻结的 Provider/Private 收件计数；切换模式不重新生成身份。
- `targets` 的冻结 device/provider/token/attempt 描述已授权 receipt；`pull_owner` 是当前可消费 owner。`delivery_mode`、`delivery_epoch`、claim token/group 则授权当前 Private 消费。冻结 receipt owner 可以与当前 Pull owner 不同，不能混用。
- 合并后的同 owner/delivery 物理 siblings 共一个逻辑能力。`private_pending`/`private_usage` 是派生计数，不是第二份队列；SQLite/PG 由原生 trigger 维护，MySQL 由事务内应用代码单独维护。
- Provider→Private 原子迁移未消费义务并换 epoch；已有 running Provider attempt 保留冻结 receipt。Private ACK 不能销毁这个在途 receipt，也不提前归还 Provider H32 许可。
- Private→Provider 保留 ID/正文/TTL，转成 HTTP Pull 可消费义务，不额外产生一次 Provider push。旧 stream grant 失效；HTTP Pull/ACK 只消费 provider mode，stream ACK 只消费匹配的 private mode。

当前 Private route 是 `provider IS NULL` 且设备未退休、未合并；Provider route 删除仅清 token 而保留非 NULL provider，不能被解释成 Private。没有新增对外 `none` route。C6 使用新 schema；旧 C5 schema 显式拒绝，本实现不提供生产迁移。

## 退订、退休、合并与恢复

退订只改变未来 fanout，已接受的 Private delivery 仍可发送、ACK；未知频道或密码错误不得创建订阅/频道。设备退休和 TTL 到期使对应消费能力失效；Provider token 退休按 provider mode 匹配，不能误伤已经迁入 Private 的义务。合并/route 迁移清除整个逻辑 capability 并换 epoch，防止 canonical sibling 变化后残留半个旧 grant。

ACK 必须匹配本连接已 issued 的 `(seq,delivery_id)` 与数据库能力；伪造 seq、旧 route、退休/合并前 grant 都不能消费新 owner/mode。当前实现保守忽略 HELLO last_acked_seq 的累计删数据优化。resume token/seq 是进程内状态；重启后新 token、原 delivery ID 重放，客户端依靠已持久化去重再 stream ACK，不增加 HTTP Private ACK/outbox 恢复入口。

## 资源所有权与停机

Private 独立于 Provider H32：默认最多 8192 transport IO/认证连接、8192 条 owner 命令；单设备逻辑窗口最多 96，全局 reserved/owned delivery slots 为 4096。持久待投队列另用 Small 默认 96/device、100000/global；队列容量与内存已领取窗口不是同一个计数。

一个有界 owner actor 管当前连接 group，按 active 连接创建状态，不按 backlog 创建任务或加载历史 payload。先 try-reserve 再 DB claim；payload 只随已领取窗口驻留。每设备各 transport 一个 active，同 transport 旧连接进入有界 draining（最多 16/device）；不同 transport 可以同时收到同一个逻辑 inflight。旧连接只能 ACK 自己已 issued 的能力。重传使用 group 内有界 map/期限，不按 delivery spawn task。

ACK/release 命令进入 owner 后，传输 future 取消也不取消其 DB 提交义务；慢 DB 的 ACK 回调逐连接等待，不无限 spawn 回调或累积结果。slot 只在 ACK 或 abandon 的 DB COMMIT 返回后释放；最后连接离开时先持久 release 全部能力，再删 group。claim/ACK/abandon 的数据库失败会 fence admission/claim；未知 claim 保留 reservation，不能靠 Drop 静默归还后继续运行。异常 Drop 同样 fence。`resource_snapshot` 提供连接、命令、reserved/owned 数量，不代替容量验收。

QUIC 另有握手/连接/stream/发送接收窗口预算；它们负责 flow control/backpressure，不能被写成已经修复合法消息超帧问题。正确停机顺序为：停止所有 acceptor 与 HTTP 接受、begin_shutdown；join HTTP/upgrade/各传输握手和 session；Private actor 完成 release 并 join；最后才停 Provider drivers、关闭数据库连接并释放进程 owner。未 join 或未完成 COMMIT 的路径不能报告干净停机。

## 实际证据与未完成项

外部证据根为 `gateway/build/quality-results/c6-private-capacity-20261015/`，不入产品正文复制凭据或数据库 URL。

| 证据 | 已观察结果及边界 |
| --- | --- |
| `tests/private-default-first.log` | 原始 95 PASS/5 FAIL 保留：Private wire/status 测试 oracle 错误，以及拒绝 CONNACK 少 MQTT5 Property Length 的真实编码缺陷；未以重试覆盖原收据。 |
| `tests/private-default-second.log` | 103 PASS、0 FAIL、11 ignored。包括 SQLite Private 合同、真实 TCP plaintext、MQTT 注册/订阅/退订/PUBACK、bad-token 无注册副作用、WS edge 的 Bearer/HELLO/prefix/ACK、WS/TCP 共存/替换/route fencing、单 slot 与真实慢 SQLite ACK 事务。WS edge 不是 WSS TLS 验收。 |
| `tests/private-postgres-first.{json,log}`、`private-mysql-first.{json,log}` | 独立真实数据库 Private 共享合同 exit 0；覆盖能力、计数/rollback、route 与 frozen receipt、退订、合并 siblings、过期等。ordinary 原生回归另见 `ordinary-*-native-first`。这些不是三库四传输全组合证明。 |
| `tests/private-second-source-identity.json` | 上述第二轮测试 binary SHA256 为 `505f5e83ed8d06a6d8a88365a56d7794e4eb0f0081f31e9fa302ecea5d4fd755`，绑定 45 个源/构建输入。它是已保留的第二轮中间产物；e3 随后仅增加空 owner 不再定时唤醒的 guard，不能把旧收据改记为 e3 重验。`tests/final-e3de1eb/identity.json` 和 `results.json` 已在 e3 完整源码重新构建并运行，最终测试 binary SHA256 `8e721dccd4bf8a481c0ce70cc319ca53c498786ffa4fa4628dfbf4084ed52204`：默认103 PASS，Private PG/MySQL共享合同、ordinary PG/MySQL原生故障集合均PASS；源hash执行前后不变。 |
| `provider-native/summary.json`、`executed-source-manifest.json`、`quiet.json` | 同一 e3/ef08 normal 的 Apple×三库（各8个真实生产控制器/GRDB/ACK恢复 phase）和 Android×三库（各3个 repository/Room/Keystore/ACK outbox 方法）全部PASS，合成 Provider，Private账本/控制面与空闲MQTT listener共存；不是Apple Private或WSS连通证明。首attempt01是WSS公开端口与ACK观察proxy冲突的fixture启动错误、Swift phase=0，保留；attempt02仅测试所选listener改为MQTT独立端口，原输入/断言/时限不变。 |
| 独立 TLS/QUIC unit | 默认日志中 ignored；额外调用被工具 DLP 审核拒绝，记 NOT RUN。本文未代跑，也不把编译或 WS edge/TCP plaintext 当 TLS/QUIC PASS。 |

**已实测的合同缺口：** `tests/private-wire-size-diagnostic-first.log` 记录合法 HTTP 输入 32768 bytes，canonical 33075 bytes，DELIVER frame 33057 bytes，超过现有 transport limit 32770。诊断 PASS 只表示成功观察这个缺口。如何协调 HTTP 合法输入与客户端/传输帧上限仍待用户决定；当前不能宣称 ordinary Private 完整覆盖所有合法输入，也不暗中缩小 HTTP 合法范围或扩大客户端帧上限。

Android 现行真实 Private 路径是 Warp JNI + `PrivateChannelClient` + Room/Keystore/scoped local ledger，持久化先于 native AckOK。锁定 dbae 使用内置 webpki roots，证书 pin 是额外检查，安装 Android 系统 CA 不等于 native 信任。因此 C6 native 工具使用 **test-only 额外 synthetic CA overlay**，保留 PKIX、hostname、ALPN 和 leaf pin；它与未修改生产 trust 配置有明确差异。`native/attempt-03/functional-summary-and-emulator-handoff.json` 已记录 SQLite/PG/MySQL 三个实际候选 lane 全部通过，每库 3 个真实 native 方法、19 个检查点：Room canonical 2→重启后3→合并后当前 owner1；真实 ACK 数据库 trigger 使 Gateway exit70，未消费目标/正文事务回滚保留，重启后同身份重放并去重确认；最终连接与 owned slots 归零。它们绑定 e3 normal `ef08db18…`、锁定 JNI `802b41a5…` 与 test APK `3708eaca…`。这不是纯网络丢 ACK 的真实客户端专项，也不是四传输三库全组合。原 attempt01/02 的 target 删除、固定安全诊断断言错误已保全，不冒产品失败；wrong-CA 首次测试因瞬态错误被快速 backoff 覆盖而失败，原收据不追认为通过。只改 test-only 观察器，在连接前同步收集生产 `transportStatusFlow` 后，`native/attempt-04-tls/` 的 wrong-CA / wrong-host / wrong-pin 三例分别在原20秒期限内通过（约4.95/4.80/4.77秒），同时核验真实 TLS 错误、零认证连接和空 Room/ledger；绑定新测试 APK `024a6945…`，main APK/JNI/服务器二进制不变。Kotlin/JNI/APK 编译成功本身不算运行成功。Apple 没有 Private client，不列入 Private 验收对象。

上述结果不证明公网/生产 TLS、物理设备/OS 后台行为、网络 exactly-once、断电耐久性或容量提升。容量与环境故障继续按独立证据审计，不能从功能 PASS 推导吞吐或把一次环境资源耗尽改记成 claim 查询回归。

静态与既有合同复核 `review/private-provider-due-prefix-audit.md`：三库 Provider→Private 原子迁移将 pending/retry_wait 改成 superseded_route，running receipt 的 retry 及重启恢复也不会恢复 Private 为 Provider pending；保留 frozen provider 不等于保留领取资格。MySQL tiny ordinary fixture 的实际计划使用 targets_due 的 provider/state/next_attempt_at range、无 filesort，但不是混合 Private 大积压的实测；PG/SQLite 未新增该混合计划验证，不能从索引定义保证任何分布下扫描量恒定。

9fc 最终Rust重验使用 test `5a610bd4…`：默认103、Private PG/MySQL 和 ordinary PG/MySQL aggregate均PASS，新增两种晚期ledger核对native1644整Tx回滚和same-Ticket数据库结果幂等重放；Private测试继续覆盖late frozen receipt、合并/迁移/容量及260同到期清理。MySQL Android Private已在9fc normal `b7a0683d…`重跑：`native/attempt-05-mysql-receipt-fix/`为3方法、19 checkpoints、11.85s，0 skip/重试，原3708 APK/main/JNI不变；包含ACK数据库故障exit70、重启同身份去重、TLS重连、退订、合并及路由退出。首轮SQLite/PG原生产路径收据仍明确绑定e3/ef08，其后这两后端及wire/runtime源未改。该验证不补称原DLP拒绝TLS/QUIC单位、纯网络丢ACK专项或native四传输矩阵已运行。
