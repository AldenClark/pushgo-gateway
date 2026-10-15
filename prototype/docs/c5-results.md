# C5：MySQL 普通消息原生适配与三库客户端闭环

本轮在隔离分支实现和执行验证，未合并、推送或部署。最后索引修复已完成三库功能回归；最终 normal artifact 的 wire 四例、native attempt-03 六 loop 均已 PASS 且各自所属范围 QUIET；最终容量两条 raw 已完成且各自 QUIET：PG 全目标完成但相对 baseline 变慢原因未决，MySQL 190 秒 deadline FAIL；C5 owned 数据库环境已清理并 QUIET，详见末节独立收据。普通消息范围继承 C4 的 FCM/APNs；Private 数据面及 Event/Thing/Watch/WNS 未接入。完整合同、事务及计时差异见 [三后端合同](c5-mysql.md)，容量结果及未决诊断见 [容量核查](c5-capacity.md)。原始证据根为本机 `gateway/build/quality-results/c5-mysql-ordinary-20261015/`，源码验证材料在 [validation/c5](../validation/c5/README.md)。

## 基线、提交和产物

开始实际核验了八个独立 Git root。候选 `codex/gateway-c-ordinary-final-20261015` 干净，HEAD `3b19fd37602177761ffb69bf07274157a3e2b5e8`；PG 实现为 `f8ed62f94ce44e285414f1a0f6894878763f4dbe`。主仓库仍为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`，因此没有重复提交旧基线。Windows 原有修改及 warp-link 原有未跟踪收据不属本轮。

- `753a1836b134915b2c6af2ef9fa6d075f52125a3`：原生 MySQL ledger/control/schema、具体后端分派及合成 fixture 接线。没有新增依赖版本，SQLx MySQL 已存在于锁定依赖中；只是 prototype 启用该 feature。
- `e7b6d59ae8d615df86c23da2f3940eccb5a4fe2e`：三库共享合同、MySQL 原生事务/owner/预算/清理及准确元数据 oracle。此提交不改变普通二进制的产品源。
- `651bf7e7e4691bd5a78b36625ff34b693be83590`：最后的 MySQL 五列 targets_due 访问路径及精确旧 C5 四列修复，带未知签名拒绝、startup metadata-lock 1205 和恢复原生 oracle。CLAIM_ONE_SQL 不变；前三库功能结果绑定下表最终 test artifact。
- 后续文档及 source-only 验证材料提交不改变 651bf7 产品源；完整提交清单、最终 HEAD 和报告 hash 由 `final-delivery.json` 与 Git log 绑定。

| 产物 | 精确身份及用途 |
|---|---|
| 最终普通 fixture | `binaries/c5-final-ordinary-sqlite-pg-mysql`，SHA256 `3204f8ac126282e74980eaffec386ab9ffc67f028f8bbcd15f47c9eb284f8298`；对应 651bf7。最终 wire/process 四例及 native-03 六个 loop 已在该 artifact 独立通过，各自有所属范围 QUIET；旧 before-baseline 收据分别保留。 |
| 最终测试 | `binaries/c5-final-shared-native-tests`，SHA256 `173d98eab6eb7a9b4ba287471ef519219d5ee1fa2675d2e5693f09e527aae032`；默认/PG/MySQL 三项索引修复后功能收据共用它。 |
| 保存的 before-baseline | 753a 产品 / e7b6 oracle；`binaries/c5-ordinary-sqlite-pg-mysql` SHA256 `7324bc7ac546a2825c749b9f339c410dbeb6560129786b856a904873b39d0161`，`binaries/c5-shared-native-tests` SHA256 `055fde93d44abde498bd47248650433bb76eb1c84d1fac18e7583e82f9a0866d`。原三库、native attempt-02 和 wire 首轮结果全部保留。 |
| 容量 fixture | 另加有界 post-COMMIT observer，身份与原始输入单列于 c5-capacity.md；不能当作普通 fixture，最终容量两 raw 已完成且所属范围 QUIET：PG 完成、MySQL deadline FAIL，详见容量报告。 |
| 客户端 | Apple 使用未改变的缓存 native bundle；Android 安装原缓存 main APK/JNI 和本轮新 test APK，SHA256 `c95c2dda1bcdf16461636e9af8fc04613044fde9809a3ffee4f98febbccb31e2`。 |

Rust 使用明确的 `+1.97.1 --release --offline --locked`，复用唯一 `prototype/target`。`binaries/c5-ordinary-identity.json` 保留 before-baseline 产品/测试源 hash 与构建身份；最终冻结产物以上表独立身份为准。可变 target 最后可能是测量构建，不能代替冻结产物。Android test APK 在新 C5 APFS clone 中仅一次离线 Gradle 构建，实际 45 秒；新路径使生产 Kotlin 等依赖任务重编译，但安装的原 main APK/JNI 未变，没有 JNI 构建或下载。626 份原缓存与 191 份克隆生产源码前后核验不变。测试观察器下载了约 0.45 MB 的纯 Python 轮包，仅隔离 vendor，版本/源站/SHA 见 `native/observer-dependencies.json`；不是产品依赖或全局安装，不能宣称本轮完全无下载。

## 实现与功能证据

MySQL 已覆盖 accept、去重/冲突、冻结 fanout、容量、claim、发送前授权、receipt、Pull/ACK、状态、完整普通控制面、路由/退休代际及批次清理。与 SQLite/PG 共用 wire/normalizer/runtime/transport，不存在通用 SQL dialect 框架。成功接纳只在事务 COMMIT 返回后响应；数据库错误不自动重放事务，更不重发已执行的外部请求。

MySQL 使用 InnoDB、显式 READ COMMITTED、一条永不重连的 pinned session、ledger singleton 行锁和 mutation gate；没有产品 trigger，应用在同事务维护容量差额。保存 dataset UUID 的 GET_LOCK 与共享 Unix `/tmp` 文件锁共同防止活旧进程失去数据库锁后另一进程开始投递。连接别名和参数不会改变数据集 UUID。隔离容器锁目录或不同主机不在这一保证内。

所有身份文本保持 `utf8mb4_0900_bin` / NO PAD；长 token 的 256 字符前缀索引只过滤候选，完整 token 才决定相等。`get_unchecked` 只跳过 SQLx 对 BINARY_FLAG 的兼容判断，仍执行 UTF-8 Decode；scalar CAST 仅改变输出元数据，未改变 WHERE、ORDER、存储或索引相等关系。MySQL 8.4.11 已实际执行；未推论其他版本或 MariaDB 已验证。

默认 30 天身份保留不缩短、不提前淘汰、不增加 history-full 拒收。ACK 释放正文/队列而保留身份；frozen receipt owner 与可迁移 Pull owner 分离。清理和 recovery 的内存 keyset 每批至多 256，257 条同到期消息检查无跳过/漂移；工作量仍随数据增长，不能由批次上限推论固定总耗时或磁盘上限。

最后修复只调整 MySQL 领取访问路径：`targets_due(provider,state,next_attempt_at,delivery_id)` 增加 `device_key` 尾键，与未改变的生产 CLAIM_ONE_SQL 完整排序对应。新库直接五列；旧 C5 四列索引在两道 owner 后、running recovery 前经 metadata 精确签名校验，只接受四列旧定义或五列新定义（完整非 prefix、ASC、non-unique、BTREE、visible、非 expression）。旧四列通过一个原生原子 ALTER 同时 DROP/ADD；未知定义 fail closed，不猜测迁移。真实 metadata reader 阻塞该 DDL 时原生 1205，open 不 READY，accepted 身份与 running 义务未被 recovery 修改；释放后显式 reopen 保留身份/绝对 TTL/control epoch，旧 attempt 失效，新 attempt 递增。新增 oracle 在最终 MySQL aggregate 首次通过。这只修复已知旧 C5 访问路径，不是主线旧库或任意 schema 迁移/升级/回退验收。

容量 baseline 失败仍保留，最后功能回归不替代同负载性能验收；约 0.0647 ms 的单查询诊断不代表吞吐或整体 p95/p99 收益。最终容量结果如下，详细阶段及 raw 身份由容量报告单列。

| 最终执行 | 结果与真实范围 |
|---|---|
| 默认 Rust/SQLite | 86 passed、0 failed、4 ignored，8.62 秒，`tests-default-index-final.log`；含截断/超限 Provider 回复、SQLite 写入/COMMIT 故障、取消、健康栅栏和停机。4 ignored 中 PG/MySQL aggregate 已另选执行，余两项历史规模长测本轮未重复。 |
| PG 实库 aggregate | 1 passed，3.14 秒，`tests-pg-index-final.log`；共享合同、原生约束/回滚、连接失效及预算。 |
| MySQL 实库 aggregate | 1 passed，8.43 秒，`tests-mysql-index-repair-aggregate-first.log`；真实 1062/1213/1205、整事务回滚、取消、owner 丢失/显式释放、H32 receipt 背压、停机/恢复、实际生产 SQL 的 EXPLAIN 和 schema/index/collation 检查，新增旧 C5 索引修复/unknown signature/startup metadata-lock 1205/recovery oracle 首次通过。 |
| 最终静态检查 | `fmt-index-final.log` 与产品/测试源码 diff whitespace 通过；`clippy-index-final.log` all-targets/no-deps exit0。保留3个既有 WNS 依赖 dead-code、3个 test-only claim wrapper dead-code 警告，不声称 `-D warnings`。原样 .patch 数据的空 context 行不作普通源尾空白处理；旧静态收据保留。 |
| 独立审查 | `review/independent-source-review.md` 和 `capacity-source-review.md` 记录源码/测试/观测器的独立复核及实际 hash；最后索引小修独立 review 无阻塞，不代替执行收据。 |

保存的 before-baseline MySQL/PG 客户端 attempt-02 矩阵均通过，每库 Apple 8 个 native invocation、Android 3 个方法且 0 skip，加 Gateway 强杀重启；合计六条 loop。Apple 走真实生产控制器、NotificationIngress、GRDB 和持久 ACK，实际退避恢复分别 60.740/62.972 秒。Android 走真实 repository、Room、Keystore、入站处理和持久 ACK outbox，强制停止后换真实进程恢复：消息/outbox 为 5/1→6/0，新增 owner 合并再到 7/0。合并均以旧 owner 的已接受/在途消息为起点，当前 owner 持久化后真实 Pull/入库/ACK，旧能力被拒，冻结旧 receipt 迟到仍正确结算且没有复活授权。Gateway 另验证 coalescing、退休 epoch、ACK/receipt 交错及 SIGKILL 后有限未知重发。详见 `native/attempt-02-summary.json`、`attempt-02-matrix-result.json` 和闭库快照。

最终 native attempt-03 已独立完成相同六 loop，全部绑定 651bf7 / 3204，见 `native/attempt-03-summary.json`。PG/MySQL 各 Apple 8 invocation、Android 3 方法 zero skip、Gateway restart 全 PASS。Apple 实际退避恢复分别 62.515 / 62.235 秒；Android 两库均 Room/outbox 5/1→重启后 6/0→owner 合并后 7/0，旧 Pull denied、旧 ACK removed_count=0，current owner 入库/ACK、late receipt 200 及冻结能力边界通过。旧 attempt-02 仅为 before-baseline，不能与最终执行身份混用。

attempt-03 未新 build、download 或 retry 产品断言，复用原 cached Apple/main APK/JNI 与冻结 C5 test APK c95c2dda…31e2。`native/attempt-03-quiet.json` 记录 25 个 captured host PID 均退出、所属 5580 emulator 停止、lease 释放、六个 case 导出后 drop；626 份旧 cache、191 份 clone 生产源、216 份执行 adapter 文件及 test APK/最终 Gateway hash 不变。此 QUIET 不包含 root-owned PG/MySQL environment、容量 worker 或共享 adb server；Room 导出证明关闭后复制的 main 文件行，不是任意 live-WAL 完整性。Gateway-control restart 是合成 HTTP client；真实 owner 合并由另外的 Apple/Android controller/repository + 存储 + ACK 收据证明。

这些是 macOS host Apple native / API37 Android emulator / 合成 Provider 证据。没有验证 iOS/Watch 物理后台、APNs/FCM 生产网络、OS 后台/WorkManager 调度、UI、正式发布或部署。缓存 JNI 精确源码 revision 尚未追认，该私有通道旅程未使用。SQLite 客户端完整闭环沿用已冻结 C4 证据，本轮没有把 PG/MySQL 收据写成新的 SQLite native 运行。

## COMMIT、失锁、强杀和环境

保存的 before-baseline 四个外部 MySQL 故障 case 首轮均通过，全部使用 753a / 7324 普通冻结二进制；651bf7 / 3204 的最终四例也已分别在新的 fresh case PASS，最终收据独立列于下方。协议代理只在合成 loopback 禁用 TLS，实测握手无 CLIENT_SSL；识别 SQLx 真实 COM_QUERY COMMIT，没有伪造数据库错误/OK。

- 转发 COMMIT 前断开：HTTP503、整个 Gateway 退出70、入口关闭；session 关闭后无消息/目标和 Provider 请求。同 op 重启首次落库，然后一次请求、Pull/ACK 容量归零。
- 转发后收到真实服务器 OK 再丢失确认：HTTP503、退出70；身份已持久化、当时无外发。重启 same op 为 duplicate_completed，ID/首次时间/绝对 TTL/epoch/owner 不变，之后一次外发。
- Provider 请求已发但结果未知时 SIGKILL：同身份恢复，attempt1→2，实际请求共两次，属于允许的有限重复。
- 旧 PID SIGSTOP 仍活着，精确 KILL 其数据库 session 并确认 IS_USED_LOCK=NULL；别名/参数第二实例仍被 OS fence 拒绝。杀旧进程后新 owner 才 READY。

`fault/final-results.md`、四个 receipt 和 `quiet.json` 保存全过程。active session loss 的入口/新领取栅栏由 native aggregate 验证，SIGSTOP 的 OS fence 不能单独替代它。库层锁存 Health；fixture 监听失败后整个进程退出70。正常停机停止 HTTP、join pumps、关闭 session 后才释放 owner。现有部署方式没有安装/验证候选 supervisor，因此只证明 fail-stop 和受控手动重启，不能宣称部署自动拉起已验收。

最终 `fault/final-index-results.json` 明确绑定 651bf7 产品 commit 和 normal SHA256 3204f8ac…f8298，四例 `final-index-before / after / process / released` 均 PASS。before 返回 HTTP503、failstop70、端点关闭，同 op 重启为 new、Provider 请求一次；after 截住真实 server COMMIT OK `00000002000000`，HTTP503/failstop70，同 op 重启 duplicate_completed、请求一次；process 恢复 duplicate_completed、累计两次 Provider 请求；released 验证数据库锁释放后的 retained OS fence。新 receipt hash 与 harness hash 均冻结，343 份产品输入及 normal binary 前后不变，旧 before-baseline 收据保留。

`fault/final-index-quiet.json` 为最终四例所属范围的 QUIET：8 个 captured Gateway PID 全部退出，proxy/provider tasks join，四个 owned case DB drop，其他 case 未触碰。native-03 亦有独立 PASS/QUIET；两个 lane 的收据不代替容量 raw 或全局环境清理收据；容量所属 lane 已另行 QUIET，C5 owned 数据库环境也有最终 env 清理收据；均不表示整机外部项目停止。

实库为缓存固定镜像：PostgreSQL16.14 和 MySQL8.4.11，各 2CPU/1280MiB RAM/no extra swap、128PID、768MiB tmpfs datadir，loopback、只读 rootfs、无 host data mount 或持久卷。PG fsync/full_page_writes/synchronous_commit 开启；MySQL InnoDB、flush_log_at_trx_commit=1、sync_binlog=1、server RR，候选 session RC。测试为临时 fault trigger 开启 log_bin_trust_function_creators、给唯一合成角色 PROCESS 只读观察权，未授 SUPER，提交设置未放松。`env/environment-receipt.json` 和调整收据记实际配置。tmpfs 不能证明物理磁盘断电持久性；没有接触线上或既有用户数据库。

## 最终容量结果与未决原因

两条最终容量 raw 收据均已收到，所属 lane 均 QUIET；详细输入、观测器身份、阶段及 OS 采样见 [C5 容量报告](c5-capacity.md)。功能验证通过不代表容量目标满足：

| 后端 | 接纳与目标结果 | offer→post-COMMIT 延迟及边界 |
|---|---|---|
| PostgreSQL final | 2560 次 HTTP 全部持久 accepted，40960/40960 个 target 完成 COMMIT。 | 完整成功集合 p95 / p99 = 133143.957 / 137232.582 ms；全部 SQL 完成约在 offer 后 149.6 秒。baseline 为 124.446 秒，约 25 秒变慢原因未决。 |
| MySQL final | 190 秒 deadline FAIL。2560 次 HTTP 全部持久 accepted、HTTP error=0，但目标仅 7169/40960（17.5024%）完成；unfinished=33791，其中 pending=33736、running=55；late=0。 | 已成功子集的条件 p95 / p99 = 172601.739 / 184705.326 ms；不是全部 offered target 的总体百分位。没有全排空、ACK 或 post-ACK 回落阶段。 |

新增 sampler 提供有效 OS 观测，但尚不能把它认定为 PostgreSQL 相对 baseline 变慢的唯一原因；这个约 25 秒差异与 C4 旧约五秒高负载耗时差异分别未决。MySQL 五列索引目前只证明受控 fresh copy 上相同生产 SQL 可以去掉 sort，最终容量仍 FAIL，不能报告实际瓶颈已修复、吞吐收益或给两库严格性能比率。条件成功延迟不能掩盖 33791 个未完成 target，HTTP 接纳零错误也不等于投递全完成。

## 首次失败、未运行和下一步

没有删掉失败 lane。保留：初始 active-owner oracle 误计旧 coalesced token 行；新测试库1044、trigger1419、PROCESS1227前置权限；C候选文本 BINARY_FLAG/global unsigned 解码；两次测试编译问题；metadata signed INT/binary BLOB 观察解码；PG observer 默认 public 的42P01；一次 Android build wrapper cwd 核验错误及首次 PG 校准 CAST 类型错误。PG attempt01 在观察器失败前执行零个 native invocation；修复 schema 后才运行完整 attempt02。Android Gradle 自身一次成功，仅 wrapper 哈希观察修复后重核，没有重编译或重跑产品断言。

MySQL I_S 锁观察的 5ms 轮询会持续延后缓存刷新：官方8.4.11源码及同构负控保留，5ms/2s263次全空，而150ms约157ms观察到真实 LOCK WAIT。最终只改采样周期，总2s上限不变，精确绑定 pinned connection，事务提前结束会立即暴露结果。该解释只属于 C5 新观察器，**不追认 C4 原未标注阶段的 SQLite 写锁超时或约五秒高负载耗时差异**。旧 CURRENT HTTP500 仍仅有已复现连接池超时部分的证据，未将所有旧失败归为同一原因。

真实 Provider、物理手表后台、旧 PG/MySQL 库迁移/回滚、断电耐久性、候选部署监督及长期历史规模尚未验收；MySQL/PG 每条历史的真实空间成本不能套用 SQLite 旧数字。身份无硬配额，总磁盘无固定上限。没有新的产品行为决策项。

三库普通 FCM/APNs 已有最终 651bf7 的受限定功能、wire/process 和客户端执行证据，Private 普通数据面仍缺失，MySQL 最终容量仍 FAIL。下一步应先审查/补齐 ordinary Private 缺口与容量问题，不自动扩大其他消息类型。若目标是完整替换主线 Gateway，真实 Provider/物理后台、旧库迁移与兼容、断电耐久性、部署 supervisor 也仍阻塞；这些后续工作没有由本轮自动启动。wire/native/容量各自 QUIET 与最终 env QUIET 分别绑定各自资源；C5 owned 数据库环境已清理，其他项目未触碰。

## 最终 owned 环境清理

`env/final-cleanup.json`、`env/final-quiet.json` 确认 C5 synthetic database environment 已 QUIET：剩余六个 owned case 数据库全部 drop；按精确 container ID / UUID 匹配移除 PG/MySQL 两个 owned container；自有 runtime 资源归零、OrbStack 为 Stopped，loopback 32768 / 32769 均拒绝连接。合成 URL 文件全部删除，凭据随其库/容器删除失效。镜像保留，没有操作 volume 或其他项目/容器。

wire 的八个 PID / 四 case、native 的二十五个 PID / 六 case / emulator / lease、容量 lane 的 QUIET 各有自身收据；最终 env QUIET 补齐剩余 C5 数据库环境清理，不把其中任一收据冒充整机所有进程停止。清理前观察到另一项目 Aegir 的本机 cargo/rustc 构建，未触碰，且其不使用 Docker。没有证明测量全程不存在其他本机 build 或外部负载；该清理时点观测不能解释 PG final 约 25 秒差异或 C4 旧约五秒差异，二者原因仍未决。
