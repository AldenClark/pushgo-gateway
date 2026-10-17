# C16：PostgreSQL / MySQL 窄范围历史身份切换

本轮将 C15 的 `legacy_unverifiable` 契约用于两个原生后端，未扩大旧数据支持范围。只转换固定旧 main 正常 API 实际产生、可验证已排空的零目标历史；不接管任何未完成、已发送或结果未知的旧投递。最终验收索引和未完成项见本文末尾；这不是上线批准。

## 起点、实现及证据身份

- 独立工作树：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c10-product-ordinary-20261016/workspace`，分支 `codex/gateway-c-product-ordinary-20261016`。起点 `195788925c75ea4b7e03b98b78fa3143a020cfab`，开始时干净，无其他任务修改；没有重置或修改主工作树。
- main 始终为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`，干净。C13 性能结果及 C14/C15 证据保留，没有重跑性能对照。
- 实现检查点：`43f74d5f69cb4cb90dc22c10fa6c522c078dc29b`（PG/共享接缝）；`22c997fdfa548d677b964698f427e83a3da57462`（MySQL）；`213a4f5c033c3f6867ac9b54a91f66726d79d1ac`（PG 所有者/ACL 恢复修复，最终运行源码）。最终工具/报告提交见证据根 `audit/final-state.json`。
- C16OUT：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c16-remote-history-20261017`。命令、退出码、原始日志、SQL、行/字段哈希、失败样本及测试工具封存均在此目录。数据库及二进制不提交 Git。

| 正常产品产物 | SHA256 / 对应源码 |
| --- | --- |
| `binaries/pushgo-gateway-final-native` | `8b523af0152c3d69d9a9a58474390b0ea163eff7b63844f58b9f40805c2566ee`；最终运行提交，360 路径清单逐项匹配 HEAD，见 `audit/final-runtime-binding.json` |
| MySQL 实际验收 `binaries/pushgo-gateway-mysql-native-locks` | `f23e6f4459ce615326f5211e0db7aaab76243e4939ea12ea999b40e837db5444`；与最终清单仅 `pg_cutover.rs` 的四个 PG dump/restore 参数删除不同；MySQL、共享入口及生命周期源码逐字节一致 |
| 固定旧 main `C12OUT/binaries/M-main` | `5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077`；本轮校验并实际执行，没有修改旧版 |

正常产品 `pushgo-gateway`，Rust 1.97.1、aarch64-apple-darwin、dev/default features、无 QA feature、离线构建、`CARGO_INCREMENTAL=0`。没有用 prototype/fixture 冒充产品验收。每次源码修复都另存二进制与前后源码清单，首错保留。

## 支持条件及历史映射

只接受固定 main 的 `2026-08-20-gateway-v12`，包括其 `20261013_001_watch_alert_window` 成功记录。逐项核对完整 migration ID/checksum/success 和原生 catalog；PG 白名单 289 项，MySQL 395 项，分别来自本轮固定旧二进制创建的新库，不从 SQLite 翻译。实际 catalog、迁移记录和源 API 请求见 `pg-source-02`、`mysql-source-02` 与 `mysql-source-catalog-01`。其他历史版本、旧 C schema、未知对象/触发器、checksum 或关系不匹配均拒绝。

源配置必须另有来源：显式 `--ordinary-source-profile small|public`；Small 为原 semantic `created_at + 7天`，Public 为 `created_at + 30天`。不按迁移时间重新计时，不把 semantic `expires_at=NULL` 当作永不清理，也不拿 sender status 到期时间补造消息 TTL。本轮两库正常旧 API 旅程实际使用 Small；没有另跑 Public 源的完整 API 旅程。Public 的规则源自固定生产代码和 C15 的配置边界证据，不能写成本轮 Public 全流程实测。

以下条件必须同时成立，且**覆盖所有模型**：

1. 停止并 join 旧服务/发送及所有使用该库的客户端，禁止自动重启。取得现有 ProductOwner 后再次核对原生会话和表锁；旧 main 不参与此协议，不能只凭新锁证明它已退出。
2. `dispatch_submission`、`provider_dispatch_outbox`、`private_payloads`、`private_outbox`、`provider_pull_queue` 全空，包含 terminal/ACK 行。普通 `dispatch_op_dedupe` 全无；其他模型 op 只允许 terminal `sent` 且 token/owner/lease 全 NULL。
3. 普通 semantic 与 sender status 精确 1:1，op/channel/message/scope/时间可证，严格为 `failed/not_attempted`、无 run token；拒绝 sent、partial、pending、lease、未知结果、孤立或歧义关系。不会清掉共享待投递记录来制造排空。
4. 独立 `delivery:<id>` 仅接受规范键、原 ID 和 `sent`，不猜测它属于某条消息。原样保留；新分配同时查询独立 PK 与 C delivery，最多四次，耗尽不留下部分接纳。

只把匹配的普通 semantic/status 替换为同一 `ordinary_messages` 的 `legacy_unverifiable` 行，保留原 message ID、原 op 字面值、channel/Thing、首次/更新时间和原生命周期。delivery、fingerprint、消息 TTL 为 NULL；正文、计数、目标均为空。CHECK 不允许把这些行伪装成 live。

历史同内容、异内容、大小写别名、换频道/Thing 重放均 HTTP409 `historical_identity_unverifiable`，不会生成正文/目标或返回虚构旧成功。状态明确为不可核验历史、`not_attempted`，NULL delivery/消息 TTL。新 live op 保持原有大小写、指纹、scope 和30天幂等语义。

两库历史索引有别：PG partial `lower(op_id)` 索引；MySQL binary generated alias 唯一索引，不依赖数据库默认大小写排序规则。历史清理按 op 分页≤256，260条同到期时间原生测试为256+4，无 NULL delivery 跳过。迁移临时关联索引落盘，每批读取≤256；没有把整个保留窗口放入内存，没有新增 history-full 拒收或磁盘硬配额。

## 原生事务、独占和备份恢复

| 范围 | PostgreSQL | MySQL |
| --- | --- | --- |
| 实际环境 | 16.14 / aarch64 Alpine；Read Committed 默认，fsync、synchronous_commit、full_page_writes 开 | 8.4.11 / InnoDB；Repeatable Read 默认，flush-log=1、sync-binlog=1、doublewrite 开，binlog 开 |
| 存储与隔离 | 本轮新建专用容器，loopback42772，1GiB tmpfs | 本轮新建专用容器，loopback42773，1.5GiB tmpfs；默认 utf8mb4/0900_ai_ci，业务身份使用原生二进制规则 |
| 离线持锁 | 现有 ProductOwner 固定原生会话；数据连接不池化/不重连；实际 advisory owner PID + pg_stat_activity | 现有 ProductOwner 固定 GET_LOCK 会话；数据连接不池化/不重连；实际 IS_USED_LOCK 连接 ID + processlist |
| 前置可见性 | 管理账号须能核对该库其他连接并完成原生备份恢复 | 离线工具要求可直接核实的全局 PROCESS grant 和必要元数据/备份权限；role-only grant 无法证明时拒绝。仅 SELECT processlist 不能看见其他用户，已有原生反例 |
| 备份 | 源 SHARE 锁、导出 snapshot、原生 custom pg_dump；保留 owner/ACL，排除候选 owner/marker | InnoDB 源 READ 表锁下原生 mysqldump consistent snapshot，包含 triggers/routines/events，排除候选 owner/marker |
| 转换提交 | prepared 先持久；SERIALIZABLE 中消息 DDL + 转换 DML + complete 原子提交 | marker CREATE 和消息 CREATE 均可能隐式提交；prepared/空合法 marker 持久围栏；autocommit=0 + WRITE 表锁后转换 DML/complete 一个 COMMIT，不在表锁内发 START TRANSACTION |
| 恢复 | 原生 pg_restore clean/single-transaction/exit-on-error，核对源 schema/身份后清 marker | restoring 先持久；原生 mysql 导入含逐条 DDL，**不宣称整体原子**；失败保留 restoring，完整原生重试及源核对后才清 marker |

所有本轮服务器和库均新建且为 `c16_synthetic_*`；既有 C7 容器保持退出，未读取/修改。tmpfs 是易失介质，本轮进程强杀/事务故障不构成断电持久性证据。host 磁盘全程高于4GiB+512MiB保护线，没有删除缓存、历史证据或用户数据。环境、镜像 digest、设置、最终归档见 `audit/*environment.json` 和 `audit/native-archive.json`。

原生客户端来自已安装容器镜像；测试 PATH 中的转发脚本只把 pg_dump/pg_restore/mysqldump/mysql 发到本轮对应容器，不进入产品构建、不改信任、不安装软件。产品需要匹配的原生客户端。PG 恢复依赖原集群角色仍存在及操作者的 ownership/GRANT 权限；不是全实例角色备份，迁移不修改集群角色。

MySQL 正常应用账号 `c16_app` 仅有本轮库权限，无全局 PROCESS/SUPER。binlog 开启时已有触发器初始化需要服务端 `log_bin_trust_function_creators=1` 或另行授权的管理安装步骤；本轮只在自建测试服务将该值0→1，记录在 `audit/mysql-trigger-setting.json`，没有给运行账号新增全局权限。

### 回滚的真实边界

prepared / restoring / 不完整 marker 拒绝正常接纳、发送及盲目续跑。complete 同备份/配置重复 run 为 no-op。启动正常 C 时，在 Storage、维护、ACK 和网络之前持久写 activated，**尝试正常启动本身**即保守越界，不能以“尚无 HTTP 请求”为由恢复旧快照。

- 越界前：验证 manifest/dataset/path/SHA，原生完整恢复，按 schema、逐表逐值、身份/交付责任对账，再由固定旧 main 实际读取原状态。
- 越界后：受支持 restore 工具拒绝，当前库不变。停止入口/领取/发送、收束在途、保全当前数据/归档/配置/新增事实，走另行评审的前向修复。不提供反向迁移或双写。
- **未解决**：两库 activated 副本上固定旧 main 实际仍能启动（仅状态查询、0条发送）。旧程序不认识 marker，管理员直接运行/自动拉起旧程序仍可绕过；新工具的拒绝不是普遍降级保护。下一轮应只处理这项发布门槛，不扩大本轮安全承诺。

## 实际验收与失败保留

| 项目 | PostgreSQL 证据（相对 C16OUT） | MySQL 证据（相对 C16OUT） |
| --- | --- | --- |
| 固定旧 main 正常 API 两条零目标历史 | `pg-source-02/source-history.json`，未注入业务行 | `mysql-source-02/source-history.json`；catalog单独成功捕获，原 source02 catalog 首错保留 |
| 逐身份/时间/保留期对账、NULL缺失值、无新增责任 | `pg-journey-combined-final/*/migrated-history.json` | `mysql-journey-06/*/migrated-history.json` |
| 5类历史409、真实MQTT接收/PUBACK、未ACK重启同ID、正文释放 | `pg-journey-combined-final/candidate-journey-result.json` | `mysql-journey-06/candidate-journey-result.json` |
| 正常HTTP V2 Pull、ACK1/重复0、Pull空及正文/目标0 | `pg-http-pull-ack-01/pg-normal-http/normal-http-v2-pull-ack.json` | `mysql-journey-06/normal-candidate/normal-http-v2-pull-ack.json` |
| 源版本/checksum、pending/lease/unknown/orphan/shared目标反例 | 23项原始用例 +4项空主键，`pg-faults-accepted-ledger-02.json`、`pg-empty-pre-fix-01/result.json` | 27项；最终逐项账本见 `mysql-faults-accepted-ledger-01.json` |
| Thing关联及 Event/Thing/LA/Widget 逐字段保留 | `pg-faults-01/positives/{before,after}-shared-field-hashes.json` 及总接受账本 | `mysql-faults-04/positives/result.json`；明确标注SQL构造的合成边界，不是完整业务平台验收 |
| 历史索引/清理260=256+4/独立collision四次/新live不变 | `audit/pg-runtime-first.log`，原生 composite 1 passed | `audit/mysql-runtime-second.log`，原生 composite 1 passed（含无网络模拟Provider receipt/Pull/ACK） |
| 真实最终COMMIT回包丢失 | `pg-final-commit-loss/result.json`：丢实际COMMIT完成帧，CLI EOF但独立核实已commit；重复不增、原生恢复一致 | `mysql-commit-loss-recovery-01/result.json`：丢实际COMMIT OK包，prepared语句绑定complete已观察；同库恢复，无重注入冒充成功 |
| 强杀、固定owner失锁、数据会话失效 | `pg-faults-accepted-ledger-02.json` 的原生PID/exit及514身份恢复 | `mysql-faults-accepted-ledger-01.json`；每项原始PID、时点和exit单列；最终data用例为 `mysql-data-session-02`，前一次窗口错过明确未注入 |
| 早期dump失败/不完整围栏/备份损坏 | `pg-final-backup-recovery/result.json` + 原PG故障收据 | `mysql-faults-03/{empty-marker,backup-failure,wrong-hash}/result.json` |
| MySQL实际DDL部分恢复失败→围栏→完整恢复重试 | 不套用MySQL DDL结论 | `mysql-faults-03/partial-restore/result.json`：原生首个DROP已执行后测试器退出97，restoring保留；完整重试逐值一致 |
| PG owner/ACL恢复 | `pg-acl-before-fix-01/result.json` 保留实际丢失反例；最终 `pg-acl-final-02/result.json` 精确一致 | 不以PG ACL测试替代MySQL验收 |
| 越界前旧main读取、越界后工具拒绝、直接旧main绕过 | 两库上述最终 product journey 及独立副本日志；不是只比总行数 | 同左 |
| SQLite回归/共用入口 | 本轮12条cutover、11条ordinary产品、26条main测试通过，见 `audit/{sqlite-cutover-regression,sqlite-product-regression,main-regression-pg}*`；SQLite迁移实现未修改 | MySQL新增后编译正常；后续仅MySQL模块/PG备份参数变动，不机械重跑SQLite矩阵 |

正常HTTP Pull使用合成FCM路由、本地不可用Token Service，不宣称真实Provider已接收；Provider结果结算在原生账本测试中受控注入。Private采用实际产品MQTT会话与QoS1 PUBACK，未声称Android/Apple/Windows客户端持久存储或全部运输路径验收。本轮没有真实外部通知。

首错均保留：PG fresh库旧main缺少外部备份证明、故障样本违反源UNIQUE、诊断文字匹配、错过注入窗口；MySQL源库错误默认collation、catalog查询字段错误、未签名元数据/owner类型、prepared锁命令；MySQL观察JSON的binary base64、binlog触发器环境前置、空op诊断归因、ACL观察器把候选元数据索引纳入源清单等工具/环境错误均与产品错误区分。没有把这些失败目录整体改写为通过。

首次PG源生成时未封存当时harness原始字节，限制在 `pg-source-02/harness-provenance-limit.json` 单列；实际旧二进制hash、命令、API与数据库事实仍有记录，没有补造旧工具hash。后续旅程与故障用例均保存各自工具身份。

产品必要修复包括 MySQL原生数值解码和LOCK/UNLOCK文本执行、PG恢复所有权/ACL。最后PG修复后只重跑受影响的ACL、备份失败恢复、真实丢COMMIT和正常产品旅程。MySQL数据路径源码与其最终验收二进制逐字节一致；没有为了换hash机械重跑无关大矩阵。

## 改动规模与结论

新增两份具体原生适配器及很小的分派/启动接缝，复用已有ProductOwner；没有SQL dialect框架、第二账本、双写、旧链回退或新调度系统。单账本增加明确历史状态及必要索引，迁移阶段表每库一份；正常运行只做一次临时启动检查连接并关闭，没有新增常驻任务、池、worker或Provider预算所有者。

单机Axum/Tokio、唯一控制权威和Private会话owner、领取前直到receipt COMMIT的共享Provider预算未改；48KiB整个消息JSON、128KiB完整帧/WELCOME及旧Private客户端硬切决定未改。本轮没有性能、客户端或上线验收。

物理差分统计（基线1957889，包含注释/空行）：运行Rust/SQL目录新增2136、删除15行，其中约42行为cfg(test)钩子，即生产部分约2094行新增；独立Rust测试710行，加上述钩子约752行；5个辅助测试脚本2289行，逐文件见 `audit/change-classification.json`。静态原生catalog JSON另3424行，不把它当运行逻辑或代码精简收益。迁移逻辑增加维护成本，本轮不声称全产品代码净减少、性能提升或新的吞吐能力。

结论：SQLite既有窄范围契约保留，PostgreSQL与MySQL原生验收完成，已具备三个后端同等的窄范围迁移能力。MySQL有限故障集共37个接受项（含27个拒绝项），不是把失败根目录整体算成通过。最终完整通过/无效/未运行账本与停止状态见 `audit/verification-catalog.json`、`audit/final-state.json`。

三库同等能力只指固定main、严格全库责任排空的窄范围历史身份；不支持带目标/未知结果历史、其他版本或旧C候选库。Public完整源旅程、真实用户旧库、任意手工降级保护、断电、客户端平台/真实Provider均未在本轮验收。下一轮建议只处理危险降级保护这一发布门槛；本轮到此停止，不自动执行后续工作。
