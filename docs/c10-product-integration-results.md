# C10 普通消息产品整合交付

结论：普通消息已从正常 Gateway 入口完成单账本整合，可进入代码审阅；尚不能发布到已有用户库。新库三后端的聚焦产品合同、Provider/Private/ACK/重启及故障检查已通过。旧库迁移、真实客户端及外部服务验收仍是上线前置，不用 C9 原型容量结果替代产品验收。本轮完成后停止，不合并、推送或部署。

## 基线、提交与依赖

隔离分支：`codex/gateway-c-product-ordinary-20261016`。起点为冻结 C9 `86e073dec487903cb27f2e67d6e5cbdcb06a6900`；Gateway main 保持 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。运行源码最终归档于 `5c7f638847c5a9fc391b3136cd5cc627e270447c`；随后两次提交只修故障测试器，完整实现/测试起点为 `ce6f7dd6c08504fc96f6bf1cf2440f20ba2a45a7`。本说明另作最终文档提交，最终完整 HEAD 见外部 Git 收据。

| 提交 | 内容 |
| --- | --- |
| `62afb90387208326b1fc48611e47ffc2b242ee98` | 产品内核、三个原生后端、正常控制权威接缝 |
| `8cd96d3ad50dcf872af7f7eea3c2b9cfc8cb156a` | HTTP/MCP/MQTT 统一服务及查询/ACK |
| `bfc5448c6b8b54f49f7a81575d308425cd7c4a7c` | 共享 Provider 预算、既有 Private 会话 |
| `1fb26e06e6d0eb79fa353e5c84613f0facf8bde0` | 正常启动关闭与失效处理，退出独立 prototype 服务 |
| `824936350b14ae604c9402dd251af8c75b9ee5e6` | 第一批正常产品合同、故障验证及边界说明 |
| `29b34bd38c463d77d144d03cc7a81ee52ee0c18c` | 可取消 session polling 不丢失已提交的 Private claim |
| `34063eae0278a192af91ab47d2dff59709b89d63` | 同账本 Private waiting、公平领取、Widget token 键和按频道可恢复合并 |
| `0a32355314e99a04f9b30fbf9138ea952bde01d7` | MySQL 固定 data session 显式事务收尾及取消 fencing |
| `5c7f638847c5a9fc391b3136cd5cc627e270447c` | MySQL 二进制规范身份的结果解码；不改变二进制比较 |
| `387613dddf09292d22cb63b77755b5dc6e980932` | MySQL 故障注入器用原生文本协议执行管理语句 |
| `ce6f7dd6c08504fc96f6bf1cf2440f20ba2a45a7` | `IS_USED_LOCK` 观察值使用原生 unsigned 类型 |

Gateway 锁定 Warp `fded360134f2144876bb11b95e7431cb1d72aef3`。配套 Android `07b634739ec10fb67720eaabaaec02d26b3932ea`、Windows `55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7` 保持不变，本轮未构建或重新验证它们。主树与冻结候选的已有无关修改及历史证据保留，具体见外部 `audit/final-preservation-preflight.json` 和最终复核收据。

## 真实产品路径与替换关系

正常 `src/main.rs → Args/RuntimeTuning → Storage/app/router` 启动。HTTP、MCP、MQTT 普通发送共同走 `submit_command → accept_ordinary_message → OrdinaryStore::accept_authorized`；既有纯校验、频道授权、目标选择与 Provider 投影继续使用。`thing_id + occurred_at`、FCM、APNs/iOS、APNs/WatchOS、WNS、Private 及普通附带 Widget 刷新均保留，不扩展这些业务。

设备/频道/订阅唯一来源为正常 `devices/channels/channel_subscriptions`。C routes/subscriptions 是读取它们的 view，正常控制事务与 C 接纳/发送前授权通过 Storage 的 durable gate 和原生事务衔接；Registry 是提交后投影。唯一普通正文/身份在 `ordinary_messages`，冻结投递及当前 Pull 能力在 `ordinary_targets`。frozen receipt owner 与可迁移 Pull owner 分开，路由代际/退休 epoch fence 旧能力。

普通旧 semantic reservation、sender status、dispatch submission/manifest、普通 Provider outbox 和旧 Private payload/outbox/Pull cache 的生产与消费子路径退出；没有失败后旧链路 fallback。共享 Storage、dispatch workers、PrivateHub 及旧表保留给未切换的其他业务。普通 Widget 派生刷新使用既有 APNs/outbox，不成为第二普通账本，也不计普通送达成功。42 个重复 prototype 运行/历史 fixture 测试源文件从本候选退出；必要运行模块迁入 `src/ordinary`，fixture 只 re-export/启动显式正常二进制，不再创建独立 HTTP 服务或数据库。详情见 [整合边界](c10-product-integration.md) 和 [迁入/退出清单](../prototype/docs/c10-product-source-cutover.md)。不以包含测试和报告的总行数宣称复杂度收益。

## 已确认的合同与最小新增成本

- 统一 TTL：0、负数及过去的合法绝对时间仍受理并保留身份，过期不生成目标；排队、重试、Pull、重连和 MQTT/Private 外发前共用到期判断。已交给网络的消息不承诺撤回。
- 冻结空集合：首次成功 COMMIT 后，空集合、ID、首次时间在 30 天窗口内固定。新增订阅者不改变原 op_id；新 op_id 才重新展开。事务失败不冻结，未知结果从持久账本恢复。
- Private 拥堵：没有新增状态枚举或第二队列；同账本未 ACK、未 claim 的目标就是 waiting。接纳原子保存完整责任，健康 Provider 先执行；只有系统待执行目标预算不足才整条拒绝且无部分身份/目标。已接纳 op_id 重放不重新判满。Private 执行窗口满不加载 waiting 正文、不占 Provider permit。恢复成本是一并读取同账本的有限 claim；每 session 用一位在 C/保留业务的新工作间交替，不引入调度控制器。
- Widget：仅普通派生任务键补齐 platform/token，保留频道/设备作用域；相同目标按既有顺序合并。`ordinary_widget_refresh` 同接纳事务按 `UNIQUE(channel_id)` UPSERT 最新无正文 marker，避免 Widget-only 空目标请求逐条堆积 marker。唯一投影者为既有 SubmissionRecoveryWorker，最多 8 频道、每页 128 目标；superseded 完成零行不删除新 marker。无 inline fanout/额外 worker。测试覆盖多 token、同目标重复、重启恢复和失效 token 的精确清理。

HTTP 整个 `/message` JSON 48 KiB，控制接口仍 32 KiB。Private 完整帧/WELCOME 128 KiB，包含 type/flags 两字节，不包含 TCP/QUIC 四字节长度前缀；不扩大 APNs/FCM/WNS 供应商限制。保留解析/分配硬上限和按需缓冲，无旧客户端协商或 WSS 旁路。旧客户端可能在 WELCOME 阶段拒绝连接，Gateway/Warp/JNI/Windows 必须配套升级；建议先准备并发布新版客户端再切换 Gateway，本任务不执行发布。

## 三库与资源所有者

| 项目 | SQLite | PostgreSQL | MySQL |
| --- | --- | --- | --- |
| C 数据事务 | 正常 core pool，BEGIN IMMEDIATE，局部有限 busy wait | 正常 pool，READ COMMITTED，transaction-local lock_timeout=3s、synchronous_commit=on | 正常 pool 中固定借出一条 data session，InnoDB 原生事务；局部 3s 锁超时/strict mode，不回流给其他业务 |
| 独占 | 规范路径文件锁，拒绝硬链接旁路 | 固定 advisory-lock 物理会话 + 数据集 UUID 同机文件屏障 | 固定 GET_LOCK 物理会话 + 数据集 UUID 同机文件屏障 |
| 失效/取消 | 异常事务连接不回池 | 未知提交/失锁 fence shared health | 已知失败显式 rollback 完成后释放 gate；未完成/取消/未知结果关闭固定连接并 fence health，不能重连冒充旧锁 |

三个后端仅成功 COMMIT 后响应持久接纳；数据库重试不重新执行已经发出的外部请求。失锁/致命 receipt 错误接 main 的失败处理，停止新接纳/领取，进程退出后持久工作可恢复。关闭按入口、会话/新领取、在途 receipt、data resources/pools、owner 排序。Unix 文件锁屏障有平台边界，不能据此宣称 Windows OS 所有者验收通过。

正常 Provider clients/Token Service/连接和 `ProviderBudgets` 只有一个所有者；普通 APNs、Live Activity、Widget 共用同一公平 semaphore。先取得 permit，再进入 gate/claim；等待 permit 不占数据库 gate，permit 保持到 receipt COMMIT。实际产品配置来自 RuntimeTuning，32 不是新批准的整产品最终上限。Private 仅由既有 PrivateHub/session owner 管理。

系统普通待执行目标预算 1,000,000，计 Private waiting/claimed-unacked 和 Provider pending/running/retry；Provider 已接受、仅等待 Pull/ACK 的正文不计该预算。Private 全局/每设备执行窗口合计旧非普通及 C 已发行 distinct claims，waiting 仅落盘。运行任务/页/在途缓冲按预算创建，非按积压数创建。30 天身份、Provider accepted 正文、频道 marker 和数据库文件没有新增字节/数量硬配额；有界执行和批次不等于固定磁盘上限。旧非普通 coalescible 重激活仍沿用原合同，不把整产品所有写入宣称为统一严格硬配额。

## 实际执行与证据

外部证据根为本 worktree 上一级目录。下表文件均在其 `audit/`；日志、原失败、源码 manifest、实际二进制 SHA 和环境输入文件 hash 保留，不提交二进制/日志/数据库。执行时 HEAD 为各收据原值，有些构建在提交前进行，不能把最终归档 HEAD 改写成当时执行身份。

| 范围 | 最后有效结果/收据前缀 |
| --- | --- |
| 聚焦产品单元 | 293 PASS、2 ignored（两个 native opt-in 随后分别实跑）；`unit-product.mysql-rollback-final` |
| MCP/Provider 单元 | 98 PASS；`unit-mcp-providers.mysql-rollback-final`；与其他组可能重叠，不相加宣称独立总数 |
| normal main 生命周期等 | 26 PASS；`unit-main.mysql-rollback-final` |
| PG/MySQL 原生产品合同 | 各 1 PASS；`native-pg.final` / `native-mysql.auth-final`，包含等待容量、原子失败/重放、身份合并及旧代际隔离、marker 合并；MySQL 另测事务取消和锁释放 |
| 三库正常 Provider | 各 1 PASS；`provider-{sqlite,pg}.final-coalesced`、`provider-mysql.final-observer-fixed` |
| 三库正常 Private | SQLite 2 PASS、PG/MySQL 各 1 PASS；`private-{sqlite,pg}.final-coalesced`、`private-mysql.auth-final` |
| receipt/ACK 原生 SQL 故障 | 各 1 PASS；`fault-{sqlite,pg}.final-coalesced`、`fault-mysql.injector-fixed` |
| 固定锁会话失效/活旧进程拒绝接管 | PG/MySQL 各 1 PASS；`owner-pg.final-coalesced`、`owner-mysql.unsigned-fixed`；SQLite 别名/同库第二实例在单元及正常启动冒烟覆盖 |
| 正常无 QA 产品 | `build-normal-noqa.receipt.json`、`normal-noqa-feature-isolation.json`、`normal-noqa-idle.receipt.json`，构建/参数隔离/启动关闭重启 PASS |
| fixture 退出接缝 | `cargo-check-fixture-product-final.receipt.json`：最终产品依赖图下 offline check PASS；只编译 re-export/launcher，没有运行第二服务 |

逐项日志与二进制绑定索引见外部 `audit/verification-catalog-c10-final.md`；完整 SHA 与全部早期失败保留在各原始 receipt，不在本说明重新拼接为一次统一二进制测试。

Provider 黑盒实际启动正常 Gateway 子进程，用受控 ProductMock 适配器：3 条普通消息、每条 4 个目标，覆盖 FCM/APNs iOS/APNs WatchOS/WNS，thing 关联、Direct/wakeup、base path、冲突/冻结、结果未知强杀重启、Pull/ACK 及正文/容量释放；旧普通权威写入计数为零。真实供应商网络没有运行。

Private 黑盒使用正常控制/接纳/Storage/session/ACK 的 loopback `ws://` 升级和 MQTT5 协议端，覆盖 48 KiB、进程重启回放、正文/metadata/稳定身份、ACK 收敛以及已到期、队列后到期、重连不复活。共享 restart contract 的末尾调用 MQTT expiry contract，因此三库均经过该 MQTT 到期 lane；旧阶段目录中“仅 SQLite MQTT”是当时的错误覆盖描述，本交付明确更正，保留原文件。此证据不是 TLS WSS、TCP/TLS/QUIC 客户端连接，也不是 Android repository/Room/Keystore、Apple 控制器/GRDB 或 Windows OS/GUI 本地存储闭环。

故障黑盒在实际 SQL 锁下观察 authenticated ACK 失败、正文保持、解锁重试/重复 ACK，receipt 失败后正常进程退出与重启恢复，PG/MySQL 终止实际固定锁会话并保留旧进程存活以检查同机接管屏障。不把普通 SQL 故障称为真实 COMMIT 回包丢失或断电持久性验证。

环境：Rust/Cargo 1.97.1，aarch64-apple-darwin，offline dev/test，CARGO_INCREMENTAL=0。PG16.14（READ COMMITTED，fsync/full_page_writes/synchronous_commit on；隔离 tmpfs 数据目录）；MySQL8.4.11（InnoDB，正常 REPEATABLE READ，flush_log_at_trx_commit=1、sync_binlog=1，Docker 磁盘卷）。仅全新 synthetic 库及真实 native dump/backup manifest，未访问用户库、生产凭据或系统信任。环境最终恢复 PG/MySQL paused，client/用户锁为零，leases 释放；`env/final-quiet-environment-restored.json`。

## 构建绑定与有限资源观察

最终 QA 二进制副本和 SHA 见 `audit/final-qa-binaries.json`。最终运行源码与 `ce6f7dd` source-equivalent；执行收据分别绑定原源码清单。SQLite/PG 最后网络收据使用 coalesced QA main `41c31a51…`，之后运行源码只改 MySQL；MySQL Provider 使用 rollback main `4756c3c9…`，之后仅增加 Private 身份查询结果解码；MySQL Private、fault、owner 使用最终运行 main `55cd2158…`。最后两次为测试器修改。未把未重跑的旧收据称为全部链接最终 binary，所有版本均保留副本/源码差异和报告。MySQL 受影响路径已按最终源码重测。

正常无 QA 二进制为 `binaries/normal-noqa/pushgo-gateway`，SHA256 `0b5ed7ae31ba775d63eb1179a318903c6cc282b762adfa9188b6cff960183d11`，在 `ce6f7dd` 清洁源码上构建。它没有 QA feature/注入参数，未加入测试 CA 或改变正式信任；受控供应商替身仅存在于独立 QA 构建。

无 QA 的 small profile、HTTP only、内嵌 SQLite、Private/MQTT 关闭、无消息/凭据的 30 秒生命周期冒烟：RSS 34,496→34,768 KiB，采样最大34,768 KiB，CPU 增量约0.38秒；同库第二进程退出1，SIGTERM及同库重启后关闭均退出0，普通 message/target/usage 为零。这是本机 unoptimized dev 二进制的最小配置观察，不是最小部署要求、默认全传输成本、长期空闲、堆分析、无泄漏或吞吐承诺；采样最大值不等于捕获所有瞬时峰值。

构建前预留增长余量，运行期间保持至少4 GiB可用，本轮没有删除历史证据或用户数据、绕过保护线。最终构建最低可用约8.4 GiB。没有重复 C9/C6 容量矩阵、没有新的 offer→逐目标 COMMIT p95/p99 或产品持续容量结论；256 targets/s 不是 SLA，历史 PG 约25秒差异及 C4早期写锁差异仍未由本轮归因。未恢复 C9 已撤回 SQL 试验，也未引入新控制器。

## 首错保留与尚未验收

实际产品缺陷已修并重测：可取消 Private polling 丢失 COMMIT 后 claim（PG auth_expired 首错）；MySQL 早返回依赖 SQLx 排队 rollback 导致固定连接仍持锁（1205 首错）；MySQL canonical binary key 结果不能直接解码 String（Private HELLO auth_failed 首错）。事务修复增加显式 rollback 和取消后 fence/关闭，不扩大外部请求重试。

测试系统首错也保留：早期容量断言与已确认产品决策冲突；去掉产品 inline Widget 投影后 Router-only helper 没有 worker；MySQL observer 的 VARBINARY→String/unsigned owner 类型；不支持的 prepared BEGIN；一次 URL 文件路径错误；最初误选全库测试触发既有 backend-init 环境流程后被中断。这些不抹成全通过、不等同当前 Gateway 缺陷。原始 log/receipt、阶段目录及最终验证目录分别保留；最终 PASS 仅指表中聚焦范围，不是全库/全平台测试。

发布前仍需：旧普通账本/身份历史显式迁移及回滚/恢复、旧 Widget key 与 marker 唯一约束迁移、真实 APNs及物理 Watch后台、断电/COMMIT网络故障、C10 对应的真实客户端存储闭环、Windows OS owner 与 Android/Windows QUIC/WSS，以及正常产品匹配输入下的有限性能验收。早期无频道唯一约束的 C10 测试库也必须显式迁移；启动 guard 拒绝它们及未迁移的旧普通状态，不自动双读或回退。

下一步建议先审阅本轮替换关系，再完成迁移和正常产品验收；当前没有必要在审阅前扩展 Event/Thing 等类型。本轮没有待决定的新业务取舍，也不自动开始下一阶段。
