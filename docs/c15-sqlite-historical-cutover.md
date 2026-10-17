# C15：SQLite 缺失指纹历史的小范围接管

本轮完成固定旧 main 的两条正常 API 零目标历史 → 离线迁移 → 正常 C 产品拒绝不可核验重放 → 新消息交付、ACK、重启恢复的小闭环。**这不是通用旧库迁移，也不具备阻止直接运行旧二进制的完整降级保护。** 不适用于仍有投递责任的库；不据此批准上线或宣布 PG/MySQL 迁移通过。

## 版本与证据

- 工作树：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c10-product-ordinary-20261016/workspace`；分支 `codex/gateway-c-product-ordinary-20261016`。
- 起点 `eeec9fb959c79d7664dbef68c6543a2bceb0d81e`，当时干净；原运行源码 `0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886`。main 仍为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`，没有修改。
- 本轮运行实现提交 `0c436d8aaf1e87521aa9943e315182f212ff52d3`。最终文档/工具提交及工作区状态见下述 `audit/final-state.json`，避免在本文内嵌自身提交 hash。
- C15OUT：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c15-sqlite-history-20261017`。`audit/verification-catalog.json`、`artifact-manifest.json` 记录路径、命令、退出码和 hash；原始数据库、日志及失败目录保留在该根下，不提交二进制或数据库。

| 正常产品二进制 | 源码/构建 | SHA256 |
| --- | --- | --- |
| C15 `binaries/pushgo-gateway-final` | 上述实现；Rust1.97.1、aarch64-apple-darwin、dev/default features/noQA、`CARGO_INCREMENTAL=0` | `1c2552928267ab61429d2afefdede57757cfc975f21990d6b5bb020bff6f68ee` |
| 封存 `M-main` | 固定 main，同工具链/正常产品构建；本轮只校验并执行，没有修改旧 main | `5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077` |

349 项运行源码清单在最终测试/构建前后完全一致，包含新增 cutover 模块和源 schema；清单 SHA256 `2a790c3d50776635729f0b0c0f4711453fedf44c088058cd25151b853f4c6926`。最终所有产品旅程、强杀测试均使用上述 C15 二进制。环境为本机 macOS/arm64、SQLite 文件库；没有外部数据库或真实 Provider。磁盘始终高于 4GiB+512MiB，本轮没有清理数据或证据。

## 支持条件与责任核对

只接受固定 main 的 `2026-08-20-gateway-v12`：逐对象匹配 `sqlite_master` 白名单、migration ID/checksum/success、已完成的 sidecar 布局及原生完整性检查。未知 schema、额外触发器、损坏关系、模糊 scope、旧 C 候选数据库均拒绝，不静默升级。

以下条件全部成立才转换：

1. 旧服务和发送进程已停止并 join，切换期间禁止其自动重启；取得 C ProductOwner，`lsof` 检查完整 family 无其他进程句柄，取得原生文件事务锁后再次检查。缺少或无法执行 `lsof` 就拒绝。不能把 C 锁解释为旧 main 会遵守的锁。
2. **所有模型**的 `dispatch_submission`、`provider_dispatch_outbox`、`private_payloads`、`private_outbox`、`provider_pull_queue` 在 core/delivery/dispatch/可选 runtime 每个实际文件中均为空，包含 retained ACK/终态行。这里比仅“普通责任已排空”更严格；不主动删除共享目标来制造满足条件的库。
3. 没有任何普通 `dispatch_op_dedupe`；其他模型 op 只允许 terminal `sent` 且 run token/owner/lease 均 NULL。Provider job/outbox、发送中、重试、Private claim、等待 ACK、Pull、未知结果及孤立责任由这些存储位置共同检查，不能靠单个状态字段判定安全。
4. 每条普通 semantic identity 与一个且仅一个 sender status 匹配 message/op/channel，状态严格为 `failed/not_attempted`，无 run token；scope、原 ID、时间和来源均可核验。普通 `sent`、`partially_failed`、`pending` 即使没有可见队列也拒绝；本轮没有宣称它们已迁移。
5. 独立 `delivery:<id>` 防碰撞记录仅接受规范 ID/键且状态 `sent`，原样保留，不推测属于哪条消息。其他没有关系证据的记录拒绝。

固定 main 的普通责任来源：semantic registry 保存消息身份；sender status 保存接纳/状态；dispatch op 保存指纹、run token/owner/lease；submission 保存输入、冻结目标；Provider outbox 保存持久 job；Private payload/outbox 保存正文、claim/attempt/ACK；Provider Pull 队列保存正文获取责任。MQTT/Private 在线会话属于旧进程内存状态，必须先退出；退出本身不证明外部请求没有生效，因此本轮不转换未知或 target-bearing 记录。所有这些条件验证通过后，没有未完成旧普通责任需要新调度器接管。

迁移只删除已转换的普通 semantic/status 行并写入唯一的 `ordinary_messages`；保留独立 collision 记录及 Event/Thing/Live Activity/Widget 的共享数据。非普通 semantic/op/status、Live Activity 与 Widget 元数据在四文件 native 测试中逐项快照一致；这是合成共存测试，不是这些业务的全面 API/平台验收。

## 最小身份表示与保留期

SQLite `ordinary_messages` 增加 `identity_state`。`live` 继续要求真实 delivery/fingerprint/TTL；`legacy_unverifiable` 强制它们为 NULL，正文为空、目标及计数为零，状态为 `historical_unverifiable`。CHECK 约束不允许把 NULL 历史伪装成 live。没有第二张普通权威表、旧链旁路、双写或调度器。

接纳先检查历史身份；同内容、不同内容、旧键大小写别名及换频道/Thing scope 的同 op 都返回 HTTP409、`historical_identity_unverifiable`，不会生成目标。保留原 op 字面值、message ID、scope、首次接纳/更新时间。状态查询明确呈现不可核验历史、NULL delivery/消息 TTL、`not_attempted`，不声称已送达。新 live op 的既有大小写与幂等行为保持不变；历史别名检查使用部分索引，EXPLAIN 验证没有全表扫描。

**源配置不能从数据库推断。** 必须提供可追溯的旧 `small|public` 配置。本轮实际旧 main 命令使用 Small：semantic 清理期限是原 `created_at + 7天`；Public 是 `created_at + 30天`，由固定源码及 native 配置边界测试核实，未另跑旧 Public API 旅程。C14 文档笼统的“30天”不代表 Small 的有效配置。本轮不从迁移日起重算，也不把 semantic `expires_at=NULL` 当永不清理。sender status 期限不冒充消息 TTL；原请求已丢失的消息 TTL 保持 NULL。

新 C 接纳仍是30天身份窗口。目标运行配置的旧 collision 清理期限不得短于源期限（Public 源→Small 运行拒绝）；独立 collision 原值/时间不改，新 delivery 分配用原主键查询保留值，最多4次尝试，失败不留部分接纳。历史清理按 op 而非 NULL delivery 分页，每批最多256；260条同到期时间测试无跳过。迁移的 status 临时关联索引落盘、读取每批≤256，不将整个历史窗口加载内存；没有新增磁盘硬配额。

## 离线操作与回滚边界

以下是接口示例，**不是本轮操作真实库的授权**。保持所有旧进程停止，不自动重启；先保留原二进制与真实源配置，备份父目录必须已存在，备份目标必须全新：

```sh
pushgo-gateway --db-url sqlite:///isolated/gateway.sqlite --ordinary-cutover plan --ordinary-cutover-backup /isolated/backup-new --ordinary-source-profile small
pushgo-gateway --db-url sqlite:///isolated/gateway.sqlite --ordinary-cutover run --ordinary-cutover-backup /isolated/backup-new --ordinary-source-profile small
# 仅在尚未启动正常 C 时，才允许恢复同一份已验证备份：
pushgo-gateway --db-url sqlite:///isolated/gateway.sqlite --ordinary-cutover restore --ordinary-cutover-backup /isolated/backup-new --ordinary-source-profile small
```

CLI 在正常 Provider/网络初始化之前退出，不开放业务入口。它 checkpoint 并检查 busy，持有各文件 EXCLUSIVE 事务，备份完整 core/delivery/dispatch/可选 runtime 及存在的 WAL/SHM，逐文件 hash、fsync；目录0700、文件0600。不是只复制 core，更不是声称跨文件 COMMIT 自动原子。任何 backup/DDL/多文件提交失败都由持久 `prepared` 阶段阻止启用，显式完整 restore 后才重跑。

core 相邻 `*.ordinary-cutover.json` 与 `*.ordinary-cutover.json.next` 是切换证据的一部分，必须连同原路径和备份保全；擅自删除/迁移标记、改名 family、直接 SQL 操作不在支持入口内。阶段为 prepared→complete→activated；恢复有 restoring。重复 complete/activated run 同一备份/配置不重复转换。normal C 在 Storage/维护/ACK/任何网络之前持久写 activated，保守地把**尝试启动正常运行**作为不可恢复旧快照的边界，即便操作者没有发送新 HTTP。

阶段中断拒绝启动/续跑，支持显式 restore 全 family 后重跑。截断的 staged JSON 只允许严格 EOF 情形的显式恢复；正常启动始终拒绝。无稳定标记时，还必须证明完整备份及当前 family 字节一致；稳定 activated 或合法 staged activated 永不恢复。损坏备份/非EOF乱 JSON 拒绝，不猜测完成。

**A 已实测：** complete 后且尚未正常启动，restore 逐表/逐值恢复旧库，再由旧 main 读取原身份、状态、首次时间。**B 已实测：** 正常启动后的 restore 命令拒绝。越界后须停止入口/领取/发送、收束在途，保全当前 family/WAL/标记、新增事实及二进制/配置，再由理解该库的版本前向修复；不提供反向迁移或恢复旧快照。

**未解决的降级保护：** 固定旧 main 不读此标记。把 activated family 和标记复制到本轮独立副本后，旧 main 实际仍能启动；仅状态读取返回旧/新 op 都404。没有发送测试请求，也没有改动正在验证的 C 库。故不能声称旧二进制被可靠拒启；本轮保护只在新 C 启动与 cutover/restore 入口成立。旧程序被运维直接启动/自动拉起仍需发布前独立解决。`lsof`/文件锁也不能提供“任何时刻旧程序绝不会被管理员重启”的保证。

## 实际验收

| 范围 | 结果及证据（相对 C15OUT） |
| --- | --- |
| 旧 main 同内容、不同内容、订阅变化重放 | 本轮新库、未来绝对 TTL，两个原 op：前两种都200并保留 message ID；新增离线订阅者后同 op 重放也200，生成2个新的 Private pending/正文/op责任。见 `product-journey-final-verified/*-replay.json`、`changed-content-reuse.json`、`added-offline-subscriber-same-content.json`；这是实测，不是仅源码推论 |
| C14同类两条正常API样本 | 注册→Private路由→订阅→退订→两次合法发送，无业务SQL注入；实际迁入2个原身份，零正文/目标/关联；保留两个独立collision；计划不改变业务逻辑快照，重复run不变。见 `product-journey-final-verified/candidate-journey-result.json` |
| 旧 writer 及路径绕过 | 旧 main 打开时 plan/run 均退出1、不建立备份；final symlink alias 正常 C 在 HTTP 前拒绝且标记不变。见该目录下 source replay 与 symlink 收据 |
| 迁入后正常产品闭环 | 五类历史提交精确409；新 op 实际MQTT QoS1完整接收→PUBACK→目标0/正文0；另一条未ACK断开→正常SIGINT退出→重启→相同delivery重投→PUBACK清空。见 `migrate-normal-product/candidate-live-journey.json`；不冒充真实客户端持久存储或平台验收 |
| native cutover | 12通过：260条分页/Thingscope/四文件共享保留、反例拒绝、真实core先提交中断、备份损坏、torn stage、配置/时间/内存/别名边界。`audit/cutover-unit-final.log` |
| ordinary产品SQLite/维护/main | 11+1+26通过；PG/MySQL维护2项显式ignored。`audit/product-sqlite-final.log`、`maintenance-final.log`、`main-startup-final.log`；共50项passed，不把filtered项算通过 |
| 实际进程强杀 | `process-kill-final-retry/result.json`：512条明确SQL故障注入+2条API历史，prepared可见后SIGKILL(-9)；续跑/正常启动拒绝；完整恢复快照一致；重跑514身份无重复/虚构目标。另有native实际部分COMMIT用例；均不是断电验收 |
| 构建/共用类型 | 正常产品离线构建exit0；PG/MySQL相关共用代码编译，但未展开其迁移实现/实库矩阵 |
| 共享业务 | 合成非普通shared记录快照不变；正常发送原有聚焦单元测试保留。没有声称Event/Thing/LA/Widget全面业务闭环已跑 |

所有首错均保留，不从失败库补写成功收据。初次 Rust 编译错误（字符串/摘要格式）已修；旅程工具先后误判尚未创建的 targets 表、旧公开状态字段、缺少 occurred_at、把3600当绝对TTL而非时长、occurred_at序列化类型、bytes收据JSON编码，均有独立失败目录，不能当成 Gateway 退化。最终 `product-journey-final-verified` 使用未来绝对 TTL、最终工具及最终二进制独立跑通。强杀工具首轮因自身sqlite句柄未关闭，被产品正确拒绝；修工具后全新根重跑通过。早期字面TTL样本仍保留，仅用于故障窗口，不替代最终有效未来TTL旅程。完整清单见 verification catalog。

## 结论与后续

本轮授权的 SQLite 极窄闭环已完成，没有通过猜测或丢弃未完成责任接管。可以结束这一小闭环并评审。不可把它宣传为普遍旧库升级：target-bearing/完成历史等更广形态不支持，原配置不可证明时拒绝；旧 C候选schema迁移另需明确方案；直接旧二进制降级仍是发布阻塞。

值得把**同一不可核验历史身份契约**用于后续PG/MySQL评审，前提仍是固定源版本、严格责任核对与原生备份/恢复验收；不能把SQLite文件标记/事务机械翻译过去。本轮不开始该工作。

发布前依次保留：切换/旧二进制降级与真实旧库隔离副本验收；PG/MySQL迁移/回滚；128KiB配套客户端升级及旧Private硬切联调；真实Provider/平台/物理Watch和Windows OS、QUIC/WSS；断电持久性。没有合并、push、部署、真实推送或访问用户数据库。没有重启性能探索，C13收据与失败不变。
