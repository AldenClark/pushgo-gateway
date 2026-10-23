# C6：MySQL 容量与普通 Private 候选

普通 Private 已实现三库账本、真实服务端入口及 Android 持久化恢复闭环；**尚不能认定全部合法普通输入已完整接入**。合法 32768 字节 HTTP 请求可封装成 33057 字节 Private 帧，超过既有客户端 32770 字节上限。用户随后明确未授权新增拒收，要求先评估保留合法范围的 Pull 与完整帧路线；[补充评估](c6-private-size-options.md)推荐首先实现授权的 exact Pull 和持久化后 stream ACK，当前仅完成评估，没有关闭交付缺口或扩大客户端协议。MySQL 容量结论、完整分母与保留失败见 [容量报告](c6-capacity.md)，Private 协议映射和预算见 [Private 合同](c6-private.md)。本候选未合并、推送或部署。

原始证据根是本机 `gateway/build/quality-results/c6-private-capacity-20261015/`。报告引用原位置执行收据；源码搬迁副本不是新增执行证据。

## 基线、实现和冻结产物

开始实际核验八个独立 Git root 和隔离 worktree：候选分支 `codex/gateway-c-ordinary-final-20261015` 干净，HEAD `f1d56670301669d9e69bb36ed366545ebad8fe61`，C5 实现 `651bf7e7e4691bd5a78b36625ff34b693be83590`。主仓库 main 仍为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。没有重复提交旧基线。原 C32、C4、C5 二进制、源码、报告及原失败保留；19 个冻结产物和 11 个 C32 文件的 SHA 记录于 `baseline.json`。Windows 原有 `src/release_smoke.rs` 修改及 Warp 原未跟踪收据不属本轮。

| 提交 | 本轮实际改动 |
| --- | --- |
| `3d10f1bffc77e548c6748e678d8e26fb69cd2fe8` | MySQL 原生领取固定从既有五列 due 索引按规定顺序读取；真实 SQLx/P_S 对照 oracle。 |
| `74bca9818ecd1138c9cecc9f9aaeccfc1f062fc7` | 三库具体 Private 能力、冻结 fanout、容量计数、路由/合并/退休迁移与共享合同；未引入 SQL dialect 框架。 |
| `e3de1ebe1caac618ecdcc293e040752e36752fe4` | 有界 Private owner、TCP/QUIC/WS edge/MQTT5、发现/认证、fixture 及真实协议测试；三库首轮客户端闭环源码。 |
| `0b7f0cbc32d87f0fd9de8c0a376052950540c76b` | 删除 receipt 同一事务内 9 条重复 SQL；新增 ACK-running/未 ACK 两种最后 reconcile 故障回滚与只重放数据库 receipt 的 oracle。 |
| `9fc812b40880e0ffd2375b4c83bb920292bdf880` | next_due 改成两种状态各取有序首条再 MIN；原生 SQLx 等价与实际计划/行数诊断。 |
| `e6a3aa5e30c7da4ae2bc1d0b48859dc5bddc646b` | 保存实际验证源码、静态映射与逐文件来源清单；173 个 Git blob 与工作文件逐字相同。归档位置未重跑，不改变运行代码。 |

当前运行源码为 9fc812b；后两项仅改变 MySQL，SQLite/PG 和 Private wire/runtime 源未改。后续文档和验证源码归档不改变运行代码。Rust 明确使用 `+1.97.1 --release --offline --locked`、fat LTO、codegen-units=1、唯一 `prototype/target`。启用现有缓存依赖/feature，没有新增注册表版本、checksum 或下载。测量版本在原代码上临时应用八个 observer 文件，构建后逐路径恢复；冻结 normal 与测试二进制均未改变。可变 target 不能代替下表身份。

| 冻结产物 | SHA256 / 对应范围 |
| --- | --- |
| normal `binaries/private-e3de1eb-normal` | `ef08db18881801b84d3fca496ae58d66b3e0eeb735f1d97e5cc665392bd0744c`；e3，三库首轮客户端 lane；后续 MySQL 相关项另重跑。 |
| tests `binaries/private-final-e3de1eb-tests` | `8e721dccd4bf8a481c0ce70cc319ca53c498786ffa4fa4628dfbf4084ed52204`；e3 完整源重新构建，首轮共享合同/原生故障集合。 |
| observer `capacity/final-e3de1eb/c5-observer` | `2616e3fd02244fcd0a4b10760803ae8e484422b1657115b0e9a8a7ff741d768b`；e3 + patch `a1e92a0116cfbcf57c87a0f264abcc3a73a94dc2deada5577e988b97357511d9`，仅容量测量。 |
| normal `binaries/private-sqlfix-9fc812b-normal` | `b7a0683dd46dd5d167c93b5e960adde4423323fd2bf96b81f89c9846b4572af3`；9fc，后续 MySQL 相关客户端与容量前的最终正常产物。 |
| tests `binaries/private-sqlfix-9fc812b-tests` | `5a610bd4bf301689abe46a7c2d49cdf2c06771305fdd09bb0e9a1a50a8805cb1`；9fc，全部三库合同及新晚期回滚/真实 SQLx oracle。 |
| observer `capacity/final-9fc812b/c5-observer` | `3dcceddb5c15fd35f1000f7b198519e9e49a87f29a3c84ae1aa8f3e1a5c01a69`；9fc + patch `fb29821fb462a2752672ad77cf28cd9743fcb2457dc8c45bb877a6e91a136cbe`，仅测量用途。 |
| 原 C5 observer | `52731d4a4599a379984e16734c9b9f304593aefe64b86563c6e7032e2a16e4af`；C5/651bf7，单独保持不变。 |

观察器的 Git baseline + 八个运行代码覆盖证明编译相关代码；构建时已有的文档修改独立保全，不声称整个 live 工作树与 Git baseline 逐字相同。`capacity/final-e3de1eb/{build-handoff-manifest,post-build-preservation}.json` 和 `tests/final-e3de1eb/identity.json` 给出完整对应关系。

## 三库合同及资源

accept、冻结收件人、身份/内容/首次时间/绝对 TTL、30 天身份历史、状态、claim/authorize、receipt、Pull/ACK、完整普通控制面及有界清理继续由各库原生事务实现。接纳成功仍在 COMMIT 成功后响应，数据库错误不自动重放外部请求。Provider H32/每次领取前 reservation/receipt COMMIT 前不释放预算均保持。

Private 只有一份正文和 delivery 身份；frozen receipt owner 与可迁移 Pull owner 分离，route generation、retirement epoch 和 Private claim/group capability 独立验证。Provider→Private、Private→Provider 和身份合并原子迁移保留内容与时间；旧已授权 Provider 回执可结算，但不能恢复旧投递能力。退订只改变未来 fanout；退休/到期清理不提前淘汰 30 天身份。ACK 释放正文和队列，进行中 Provider 工作持有到 receipt COMMIT。混合发送的 Provider 完成与 Private 入队不混为同一计数。

Private 使用现有 Small 的 96/device 待投/领取窗口基线、100000 全局持久待投、4096 全局 owned 工作、8192 连接/命令等明确预算，按连接创建状态，不按积压生成任务。工作先占 reservation，直到 ACK/release COMMIT 才归还；连接断开或调用者取消不能丢掉已排入 owner 的提交。控制变更唤醒 owner，空 owner 不周期扫描。连接、QUIC 缓冲/stream、MQTT parser/inflight 和 WSS upgrade/task 都另有预算，不把 Provider H32 直接套成 Private 连接上限。

SQLite 使用即时写事务及 trigger；PG 使用原生事务/行锁及按正确先后执行的 trigger；MySQL/InnoDB READ COMMITTED 使用显式计数增量和行锁，身份相等仍为 bin/NO PAD。三库具体分派，没有新增协调框架。PG/MySQL pinned 不重连会话锁 + 共享本机文件 fence、SQLite 规范化本机文件 owner 保持同数据集单实例；不同主机或隔离锁目录不属于此保证。连接错误/失锁会 fence 新接纳和领取，fixture 整进程退出并可受控显式重启；没有验收部署 supervisor 自动拉起。MySQL binlog 满盘使 COMMIT 永不返回时，本轮是在测试要求停机后才 quiescence 超时退出70，不能据此宣称生产会自动检测该停顿；新写入仍不能在未成功COMMIT时返回接纳成功。

C6 使用新 Private schema；旧 C5 schema 显式拒绝，未提供旧库升级/回滚迁移。30 天历史没有数量/字节硬配额，**磁盘不存在固定上限**。有界清理批次不意味着总工作量或总存储固定；同到期 260 条 Private 消息实际按 256+4 排空并通过重启/计数检查。

## e3 完整功能执行与后续相关重验

| 执行 | 结果与证据范围 |
| --- | --- |
| e3 默认 Rust/SQLite | 103 passed、0 failed、11 ignored；`tests/final-e3de1eb/default.log`。含 Provider 截断/超限、写入/COMMIT 故障、取消停机、路由/能力、真实 TCP plaintext、WS edge、MQTT5、ACK COMMIT 预算。 |
| e3 PG/MySQL Private 共享合同 | 各 1 个 aggregate PASS，真实 PG16.14/MySQL8.4.11 新隔离空库；能力、计数、容量迁移回滚、旧 receipt、合并 siblings、退订/退休和清理。 |
| e3 PG/MySQL ordinary 原生故障 aggregate | 各 1 个 aggregate PASS；共享合同及原生约束/事务回滚、1213/1205、锁会话失效/别名第二实例、H32 receipt 背压及取消/停机恢复。 |
| Apple Provider × 三库 | 每库 8 个真实生产控制器/GRDB/持久 ACK phase 全 PASS；真实新进程恢复、身份合并、退订/退出。冻结 Apple 源 `151d50cc…` 和缓存原生 bundle，合成 Provider。 |
| Android Provider × 三库 | 每库 3 个 repository/Room/Keystore/持久 HTTP ACK outbox 方法全 PASS；强制停止/新进程恢复、owner transfer、旧能力拒绝与迟到 receipt。 |
| Android Private × 三库 | 每库 3 个真实方法、19 checkpoints 全 PASS；JNI/TCP TLS→Room/Keystore/scoped ledger，ACK 存储故障 exit70、保留义务、同身份重放去重、断开/重连、退订、合并和路由退出。不是 HTTP ACK outbox。 |
| Android TLS 负控 | 错 CA/host/pin 各 PASS；实际 native 错误分别 UnknownIssuer、hostname mismatch、pin mismatch，服务端认证/Room/ledger 均 0。 |
| 9fc 最终共享合同重验 | 默认103 PASS、wiregap诊断1 PASS；Private PG/MySQL 与 ordinary PG/MySQL 4 aggregate 均 PASS。MySQL aggregate 12.30s，late1644两个分支均由独立完整快照验证，same-Ticket仅SQL重放两次仍只计1。实际SQLx prepared 的next_due相同值：旧examined256/new1（new有1内存tmp）；不是全负载收益或恒定O(1)证明。`tests/sqlfix-9fc812b/final-summary.json`，368项全树Rust/Cargo输入前后不变。 |
| 9fc Android Private / MySQL 重验 | `native/attempt-05-mysql-receipt-fix/`：b7 normal、原3708 APK/JNI，3方法、19 checkpoints、11.85s，0 skip/重试。真实ACK数据库故障退出70、同身份重启去重、TLS断开重连、退订、合并及路由退出均通过；Room/账本2→3→合并后1。源码最后修复后的相关路径实际重跑。 |
| 9fc Apple/Android Provider / MySQL 重验 | `provider-native-mysql-9fc812b/summary.json`：b7 normal，Apple原8个控制器/GRDB阶段73.25s、Android原3个方法7.07s均PASS；原3708 APK/main/JNI未改。两Gateway正常退出、joined=2/tasks=0；只卸载C6 QA包并停止captured模拟器，原lease释放为available。 |
| 9fc MySQL原容量输入两次 | 各2560消息/40960目标/H32/20ms Mock/原190秒，严格40960全COMMIT、无晚/未知。末回调189.592/179.239秒，完整分母p95为173.417/163.267秒、p99为178.360/168.011秒。首v4 identity核对跨截止仍FAIL；v6重复的身份/wire/ACK/postidle完整PASS；两次after-resource均STOP，分别保留，不写全面PASS或稳定SLA。 |
| 9fc PG原容量输入两次 | 两次完整PASS，40960全COMMIT、无晚/未知、身份/wire/ACK/postidle均通过。末回调96.994/116.144秒，p95为83.103/102.421秒、p99为86.133/105.419秒。当前慢段与嵌套maintenance SQL相关，没有计划/反事实因果，历史约25秒问题不追认为已解。 |
| 静态检查 | fmt/whitespace 与 Clippy exit0；保留风格和既有 dead-code 警告，不声称 `-D warnings`。独立源码与最终功能收据审查无新的重要产品缺陷。 |

默认11个ignored不能写成全部执行：四个数据库aggregate及wiregap已另显式运行；两个MySQL claim plan probe在早期对应源码的因果诊断中执行，9fc没有再次独立运行；两个百万历史/字段宽度测量保留C2历史收据、本轮未重跑；两个独立TCP TLS/QUIC unit本轮未运行（额外调用被自动审核拒绝）。它们与真实Android TLS客户端lane分别计证据。

测试均使用本轮捕获容器与全新synthetic case：e3功能与PG使用对应tmpfs环境；9fc MySQL共享合同和客户端相关重验使用fresh3专属磁盘卷。各收据记录实际介质与显式耐久设置，不是线上数据库、磁盘断电或迁移验收。native与Provider的各自`summary.json/quiet.json/executed-source-manifest.json`绑定相应版本和运行结果，不能跨版本互换。

Android main APK `779930c0750bfae52aab59472a1bca21104541335e536b6466cb9920417f50d2`；锁定 Warp `dbae3a80c8b796969cadc9045ee982a0a60c4d27` 的 JNI `802b41a519b3ce9deb214204869e0a899ed8965c76fa141d87b7bc3b2e4e883c`（ABI2、11 exports、3 LOAD 对齐0x4000）。功能/Provider 测试 APK `3708eacadbaf4da07e5a5fe38b2e40cfadb53545091e66f89ee36495dcbc1b75`；仅 TLS 瞬态状态观察器修复后的测试 APK `024a6945a14676159cdc62bcbc9ef034b77c2c70b9957ec127758fbdb45b0ab5`。原三个功能方法字节不变，main/JNI 不变，不能把两份测试产物混为一份。

JNI 测试构建只额外信任明确的 synthetic CA，PKIX/hostname/ALPN/leaf pin 保持；证书私钥只在内存及匿名管道中，不落盘。它不是未修改生产 trust 的验收。主 Apple/Android/Warp 仓库没有本轮必要产品修改；使用隔离 staging/test-only overlay，626 份旧缓存、191 份旧克隆产品源和 480 份原客户端/锁定依赖输入核验不变。

## 保留失败、未运行及仍受限

- 最初默认测试 95 PASS/5 FAIL：4 个 wire/status oracle 错误及真实 MQTT5 拒绝 CONNACK 缺 Property Length；后者已修，原日志保留。后续 103 PASS 不能覆盖原失败。
- Private native attempt01 错误要求 ACK 后目标行仍存在；attempt02 错误要求安全的固定故障诊断泄露 trigger 名。真实成功/回滚证据已保全，均仅修观察器。attempt03 wrong-CA 轮询错过瞬态 Fatal，原 FAILED 不追认；新测试通过生产状态流保全错误后另跑三负控。
- Provider attempt01 是 WSS 公开端口与 ACK 观察代理冲突的 fixture 启动错误、零 Swift phase；attempt02 仅选择独立 MQTT listener，原输入/时限/判据不变。
- 早期 claim-fix 与 e3 完整容量 lane 分别在 MySQL binlog 写满768MiB tmpfs后卡 COMMIT；e3 的 SQL见证32030成功/8930未完成、无最终telemetry，不得宣称容量通过。两轮各自有prepared COMMIT/精确errno28/满盘证据，逻辑导出与live不完整binlog保全、未知结果不追认；它们与 C5 原查询瓶颈是独立原因。后续充分存储环境已按旧/新同介质重建对照；9fc 的最终相关重验另记，旧失败不升级。
- 9fc首次最终容量：严格事件归约确认40960/40960目标在原190秒内COMMIT，0晚/未知，p95/p99为173.417/178.360秒，仅400.887ms截止余量；原runner因最后身份核对跨截止仍FAIL，退出后资源预算STOP。三种结论独立，不把原失败改写PASS；此lane没有post-ACK回落或全部prepared SQL统计。
- 合法大帧缺口仍未解决；不能声称 ordinary Private 全输入接入完整。纯网络丢 ACK 的真实客户端专项未跑，真实 ACK 数据库失败和普通 TCP 断开是不同证据。
- 独立 Rust TLS/QUIC unit 的额外执行被工具自动审核以凭据路径规则拒绝，记 NOT RUN，未委派或换壳执行。Android 实际 TCP TLS 是独立已授权路径；native QUIC/WSS/MQTT 未验证，WS edge/协议专项不冒充这些客户端组合。
- 额外创建容量配置/PG adapter/清单的一整条source-only准备动作被自动审核以`credential_store_path`拒绝，零执行、零产物；该动作没有重试或换壳。后续采用已经冻结、已有参数化接口的原v4 MySQL/v2 PG runner，不制作被拒绝的新adapter；各原有guard与独立预算/统计入口照常适用。
- C6 未重复 C5 四个外部 MySQL wire-COMMIT/进程故障脚本；旧脚本的 C5 硬编码/URL argv 限制见 `fault/c6-source-compatibility.md`。C6 三库原生故障及 Private 真实 ACK 失败/进程恢复已另执行，不把 C5 收据改记成 e3 PASS。fixture URL 输入渠道仍需在部署前安全化。
- 9fc Rust DB续跑的两条连接前环境布局失败均保留：fresh3父目录不在既有guard范围；alias后缺少同目录精确owned映射。没有修改产品/断言/路径guard或换库。环境所有者对同case建立0600、无凭据、不可lifecycle-adopt的guard-only派生映射，验证原helper仍因archive marker立即拒绝，canonical fresh3和两首错不变；完整guard与空库核查后continuation03另独立通过。已PASS的PG Private未重复，未运行项继续原oracles。
- 9fc MySQL Provider复验最初在4GiB空间预检停止，零Gateway/Swift/Android业务执行；wrapper缺少status产生KeyError只是二级分类错误。旧STOP、源码及失败完整保留。仅修严格STOP解析（34项纯解析检查），不降低预算；两个失败库逻辑导出、关闭binlog三方SHA/CRC核验后，仅精确回收已归档关闭日志，再另开预检与执行收据。该回收阶段未删除原数据库与当前binlog，未修改耐久或资源参数；最终测试资源移除另见末尾保全说明。
- 维护/观察脚本首错也保留：MySQL统计准备误给SHOW COLUMNS添加LIMIT、BusyBox不接受GNU timeout参数，均发生在唯一成功reset之前；PG1导出误假设public schema，零dump/DDL。分别只修SQL/CLI/quoted业务schema观察边界，没有改产品语义、延长观察上限或覆盖旧收据。17库最终保全实际全部通过。
- Apple 没有 Private 客户端；真实 APNs/FCM、物理手表后台、OS后台调度、旧库迁移/回滚、断电持久性、正式发布/部署均未运行。C4 旧写锁条件、旧高负载差异及 C5 PG约25秒问题没有新因果证据时保持未解释。

## 评审决策

用户后续明确不授权新增合法请求拒收，也不接受把大消息缺口算作完成。因此先完成[保留合法范围的补充评估](c6-private-size-options.md)，不再把拒收当默认下一步。推荐正向能力协商的 Private 小提示→授权 exact V2 Pull→生产 Store→原 stream ACK；完整 HTTP ACK outbox 另需扩展强能力，完整 DELIVER 则需按最坏序列化上界同步 Warp/客户端及字节预算。现 Private 客户端不具备透明 wakeup 分流，两路都不能自动解决未升级旧客户端；本次不决定退役范围，仍保持缺口为未完成。此补充仅源码评估，运行源码及既有收据不变。

实际实现和评审兼容范围后，优先补合法大输入与已有正文恢复、纯网络丢ACK及实际受支持传输组合专项。针对PG维护SQL只做有边界的计划诊断；不直接减频维护、拆事务或批量提交。未解决普通Private合同和恢复缺口前，不建议进入 Event/Thing/Watch/WNS。真实Provider/物理后台/旧库迁移和断电仍按用户要求留最终统一验收。

验证源码副本见`validation/c6/README.md`及逐文件manifest，原位置执行与搬迁位置NOT RUN严格区分。源包记录env专属role grant/alias/test-guard projection当时inline执行未保留独立源码的provenance gap，不制造“已执行”重建脚本。当前runtime仍9fc，normal/tests/observer SHA见前表；后续文档与验证源码归档提交不改变运行代码。

最终保全`env/final-owned-preservation/manifest.json`为17个活跃canonical/bootstrap测试库的稳定计数、逻辑dump/CRC/SHA和统计/配置/日志归档；它不把未知COMMIT追认为成功，也不冒充物理crash备份。仅移除本轮四个捕获容器及唯一专属卷，C6 URL/state/alias/projection退役；原C32/C5与全部失败、源码、冻结二进制、镜像、AVD/runtime和其他项目保持。`env/final-owned-cleanup.json`及`final-owned-remnant-check.json`记录实际无容器/卷/URL残留。OrbStack因保守进程守卫命中常驻MCP桥接进程而保留RUNNING，未停止这些进程，也不声称已恢复最初Stopped。

本轮停止等待评审，不自动启动其他消息类型、迁移或部署。
