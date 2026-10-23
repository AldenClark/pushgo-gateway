# C8 普通消息与 Private 候选验证

本报告为 C8 本地评审交付。运行源码、观察器覆盖和客户端产物分别绑定；后续归档与文档提交不改变这些已执行字节。原始失败、未运行项及环境限制均保留。

本轮在隔离候选实施消息提交整 JSON 48KiB、复用固定 128KiB Private 完整 DELIVER，补齐真实 Windows Private 注册，并完成三后端合同及配套客户端构建与 TCP 数据面验证。没有修改主线、推送、发布或部署，没有扩展 Event、Thing、Watch 或 WNS。

**源码和产物身份。** Gateway 实际运行源码为 `be3bc95c58500ee9913dbc2d9b442d5eb6a74227`，分支 `codex/gateway-c-ordinary-final-20261015`。本地正常 fixture SHA256 为 `b771b79a93b24025a037ca61c7056ea5a743ba52627a417dbee7f90d9d9efe44`，最终 test 二进制为 `8702e505b58db5cbdd787f0e1b07ec92951ee394f11750d4db9c6d0eb40da041`。受控测量二进制为 `a77c754c15f78fb725e4f22ae4b46981959744f0659b074c16d585372d8bf9eb`；它是在同一源码上应用八个已冻结观察覆盖、单次编译后恢复源码得到，不是正常产品产物。恢复验证包括 68 个编译和测试输入、六文件原字节与模式、两个新增文件移除，以及正常/test 冻结哈希不变。

| 仓库 | 本轮提交 / 最终依赖 | 含义 |
|---|---|---|
| Gateway | `1391b578`、`392c5166`、`1fa2f8cb`、`e2eac497`、`3774c0b1`、`be3bc95c` | 消息入口作用域、六类大消息合同、边界与 telemetry、隔离实库 guard、测试预期修正、Windows Private bootstrap |
| Warp | `fded360134f2144876bb11b95e7431cb1d72aef3` | C7 的正确 128KiB 实现保留，本轮未重复修改或提交 |
| Android | `9bfef733`、`893f5625`、`81691943`、`85bfe297`、`574a4ec8` | 48KiB fixture、QA JNI 隔离、TLS 负控观察器、ADB 大参数改为测试私有文件、最终证据文档 |
| Windows | `0caedc93`、`eaefbb0d`、`55c555e4` | 48KiB probe、独立 QA manifest、最终证据文档；正式四份 manifest/lock 保持 fded360 |

Android 正常 Rust/JNI 和 APK 编译来源 `893f5625`，后续只改测试；最终 QA 主 APK/JNI 来源 `81691943`、testAPK 来源 `85bfe297`。正常 JNI 编译 SO `c7617e4455fea01bd5e40ba268b646cfcb3a852d4bc978817397bf268d5ecb74` 经默认 strip 后为 `426cf4486a8aad2e1a3e02a94b978cc8be15cd482150b3f9d3392fed3d17d24d`；正常 APK `1cf69b33fb48640400d324e0fc7df3347fcd6ddb0432b8734bd7828a7c4ff1eb`。实际安装的隔离 QA 主 APK `f6a668f05e53a4267dac290f619136d9210260cec73d41192cc5b5e8c79ad372`、testAPK `c8fd7caa436f4908f7e22d81ba6723eeedaa4e1a7cb49ac12bc9634a13661a41`、JNI `542c0693401e8c9f206628a530becabd3d3e4ae59fdeb1aa55a3e4d35ca2b3e7`，ABI2、11 个导出、三个 LOAD 段均 16KiB 对齐。

Windows macOS host 正常/QA 可执行文件分别为 `f162c66c3d2152381b4a69d210aa227ebbc2129ff07daf4c4c954832851f02d9`、`e2724e3a1171d25afb657768b245c930e38c6c7e335cb0c3bd8b7763a524d1ee`。它们包含实际 Windows 产品 Rust 接收和 SQLite 路径；本轮没有 Windows OS、GUI 或 toast 验证，也没有 Windows GUI 正式目标构建收据。

**固定大小及作用域。** `MESSAGE_SUBMISSION_BODY_BYTES=49152` 只作用于 `POST /message`，计整个 UTF-8 JSON（包括密码、op_id、metadata 等），不是独立正文容量。其他控制接口仍取 `Config.max_body_bytes`，默认 32768；路径前缀和自定义控制上限的测试保持隔离。HTTP 49153 字节拒绝且不持久化。

Private 的 131072 字节包含 2 字节 type/flags 和编码 payload；TCP/TLS、QUIC 的 4 字节长度前缀不计入，因此最大带前缀记录为 131076 字节，TLS/QUIC 自身网络开销另计。WSS 对完整 binary message 和 frame 均设 131072，未添加 fallback。QUIC 的 64KiB 流控窗口控制可读进度，不是完整消息上限。MQTT 独立限制整个 MQTT 包为 131072，包括其自身头和属性；不把 Warp 帧长度等同 MQTT 包长。MQTT CONNECT 的 peer maximum packet size 未作为本轮新增协商能力实现；Android/Windows 没有实际 MQTT 消费端，不能据此承诺第三方客户端的大包兼容。

正式依赖及 WELCOME 宣告值均为 fded360 / 131072。旧客户端可能因为 WELCOME 中宣告值超出自身验证范围而拒连；不是 WELCOME 包本身过大。本轮接受这种硬切，不新增协商、分片、新 Pull 或额外 ACK。APNs/FCM 的原有精确序列化 4096 字节判断及超限 wakeup/Pull 路径保持；仅用了本地 Mock，没有真实供应商验收。仓库反代示例未另设 32KiB 限制，现网反代未观察。现有 Apple 生产 Swift 源码未找到 `/message` 提交器；其 UI 测试 32KiB markdown 安全阈值、Watch context 48KiB、quality descriptor 64KiB 不是 C 的提交限制，均未改动，也未新增 Apple Private。

**配套 QA 信任隔离。** 按本轮明确授权，只有独立 QA manifest 的 transport path overlay 通过编译时 `PUSHGO_C8_TEST_CA_DER` 加入本地合成 CA；证书链、主机名、ALPN 和 pin 校验保留。没有系统信任修改，没有生产凭证，私钥只经进程内存和匿名继承 pipe 传给自建服务端。正常 manifest/lock 没有 patch，正常 Android SO 与 Windows 二进制不含该 DER；Windows QA 二进制恰含一次。

Android QA SO 只放固定独立 `qa-jni-libs` 输入，`setSrcDirs` 排除正常 JNI 目录；必须显式 QA 开关及排除正常 JNI producer，解析后的 task graph 拒绝任何 Release（包括聚合任务间接触发）。正常生成 SO 在 QA 前后不变。正式构建不接收测试 CA。配套客户端发布前应核实正式依赖能在发布环境获取；本任务没有推送这些本地候选。

**最终执行覆盖。** 所有下列新结果绑定 be3 Gateway 正常或最终 test 字节，历史 C7/C6 结果单列。

| 验证 | 实际结果 | 证明范围 |
|---|---|---|
| Gateway release test | 115 passed / 0 failed / 10 ignored | SQLite、HTTP 48KiB/控制面 32KiB、128KiB 边界、Provider 回复/预算/停机、Private TCP/MQTT/WS 和恢复合同 |
| PG/MySQL ordinary + Private aggregates | 4 项，各一次 1 passed / exit0 | 实库共享合同及 native faults；Private 各有六类完整 HTTP 大消息、编码、迁移、reopen、ACK、30 天身份和 260 同时到期的 `[256,4]` 清理 |
| TCP TLS / QUIC 公开 Warp I/O | 各 1 passed | 实际本地 TLS/QUIC、PKIX/主机名/ALPN、DELIVER 与持久 ACK；不等于客户端 QUIC 大消息闭环 |
| Android API37 emulator | 7 lanes / 13 次真实方法全部通过 | 三库各三方法、独立数值大消息及三项 TLS 负控；生产入站、JNI、Room、Keystore、Private ACK、进程重启、身份合并、退出 |
| Windows macOS host | 两项组件及三项网络/故障场景首次通过 | 实际 HTTP Windows 注册、完整 49152 字节提交、生产 Rust+SQLite、ACK 前强杀、第二进程去重与 ACK、同 PID 重连及 ACK 数据库故障后 Gateway exit70/恢复 |
| Windows TLS 负控 | 三项 `BEHAVIOR_QUALIFIED` | wrong CA/host/pin 均无 WELCOME、无客户端数据、保留远端义务；具体错误被连接预算包装，精确失败阶段 UNKNOWN |
| Android `pr` / 正常 JNI | 295 JVM 测试及 localization、test compile、debug APK、三 ABI 构建通过 | arm64-v8a、armeabi-v7a、x86_64 正常 SO 均不含测试 CA；不代替设备测试 |
| Android `quality_changed` | 248 项中 1 FAIL / 0 ERROR | 绝对祖先路径含 build，源码索引为零，14 条 disposition 过期；测试系统失败保留，没有修改扫描规则 |
| QA 配置负控 | 两项 dry-run 拒绝正确 | 无 QA 开关拒绝、聚合 assemble 的 Release task graph 拒绝，未执行 Release 构建 |

三库六类样本包括文本、中文、转义、密集数值、负数与浮点；额外边界覆盖 supplementary Unicode。实际合法 49152 字节数值样本 DELIVER 为 111691、完整 MQTT 包 112053；原 32768/33057 回归也通过。没有找到新的合法 48KiB 超帧样本；没有截断、换身份或错误 ACK，也没有宣称对任意输入完成数学上界证明。

共享测试的 reopen 是同进程关闭并重开账本；Android/Windows 网络测试另有真实 OS 子进程重启证据。MQTT 大包是生产编码器与账本验证，真实 loopback MQTT 小消息/PUBACK 测试另在默认 suite；没有支持的 Android/Windows MQTT 接收器。Android/Windows 完整大消息实际传输只测 TCP TLS；客户端 QUIC/WSS、Windows OS/GUI、真实 APNs、物理 Watch、旧库迁移/回滚和断电持久性均 NOT RUN。Apple C3/C6 普通 Provider 控制器/GRDB 证据保留历史含义，本轮没有重跑或扩建 Apple Private。

Android 13 次调用中，每个后端 19 个实际 checkpoint，Room 记录由两条到三条、身份合并后新 owner 一条；原正文及消息身份保持。Private ACKED ledger/重放证明 Private 恢复，零 Provider HTTP ACK outbox 仅证明没有混入那条路径。数值独立样本 4445 项 metadata，每项语义值 `1e15`，metadata JSON 111203 UTF-8 字节；完整请求仍为 49152。Android TLS 负控实际捕获 UnknownIssuer、NotValidForName、certificate pin mismatch，Room/HELLO 均为零。

**失败保全。** 首个 Gateway 1fa suite 为 112 passed / 2 failed；两处新 oracle 错误为合法空 body 被规范化省略、默认 TTL 不补 wire 字段。只修测试，3774 114 passed，最终 be3 115 passed。Windows 3774 真注册 HTTP400 是实际遗漏，已修为 Windows Private-only；WNS/FCM/APNS 及 Private 非空 token 仍拒绝，禁用 Private 行为不放宽。

正常 Android APK 包装观察器首错把默认 strip SO 与未 strip 输入硬比；保留原 STOP，用 NDK strip 精确复现后认证既有产物，没有重建来掩盖。QA 第一构建因 `--no-deps` 未完成 local patch 锁文件规范化而 `--frozen` 拒绝；保留首错，完整离线解析并确认所有 registry 版本/checksum 不变后完成第二构建。素材准备显示层 `identities` KeyError 保留，内层准备成功，没有重生 CA。

Android attempt01 前两阶段成功，第三阶段 `am instrument` 参数的 Base64 达 65972 字节、返回 `error: closed`，没有确认 instrumentation 启动；56 字节导出内容为数据库不存在的 cat 诊断，不是 Room 损坏。85bfe 只把同一转移 JSON 通过 stdin 写入固定 app-private 测试文件，以长度和 SHA 校验后解析；只重建 testAPK。attempt02 七 lane/13 调用全部通过，原输入及时限不变。

Windows 正常信任负控首个严格诊断断言失败保留：原始状态是未认证、无落盘、远端未 ACK，错误仅为 connect budget exceeded；没有追认 UnknownIssuer。后三项不同负控按独立状态证据仅标记行为受限通过，保留具体失败阶段未观测的限制。

PG small 首个 lane 在预热 SQL 观察器失败，正式 offer 为零；重复 PGOPTIONS 覆盖 schema。修复只合并 schema 与既有 5 秒 statement timeout，未延业务截止；首源、首收据与失败库保留，修复后使用全新库。它不解释历史 PG 约 25 秒差异。

**性能结果。** 四条有限窗口结果如下，所有目标都在原观察截止前有精确 COMMIT 回调，failed / timeout / unfinished / late / unknown 均为零。

| 场景 | 消息 / 目标 | offer→目标 COMMIT p95 | p99 | 最后回调距首次 offer |
|---|---:|---:|---:|---:|
| MySQL 原小消息 | 2560 / 40960 | 159.791023s | 171.664790s | 182.850651s |
| PG 原小消息 v2 | 2560 / 40960 | 132.898174s | 136.948825s | 147.853199s |
| MySQL 大消息内容 cohort | 4 / 64 | 124.865625ms | 129.745750ms | 7.614083s |
| PG 大消息内容 cohort v2 | 4 / 64 | 71.355833ms | 72.919583ms | 7.580330s |

小消息基准严格为 256 消息/秒注入 10 秒、2560 消息×16 目标、Mock20ms、H32/Q32、8 个 HTTP caller、offer 起 190 秒窗口。大消息另为四个精确 49152 字节 JSON×16 目标，10 秒内容 cohort，不代表大消息持续容量。端到端是 offer Mach 时间到逐目标 receipt COMMIT 后回调，不是客户端落盘；Provider_accepted 是 Mock Provider 接纳后的账本状态。失败、超时、晚回调、未知与未完成按全部目标分母保留。

既有同域 Mach 收据还可计算“成功 HTTP 响应接收并解析完成→目标 COMMIT”：MySQL/PG small 的 p95/p99 分别为125.753347/134.849472秒、101.881575/104.759241秒；大消息分别为100.544625/104.254625毫秒、53.875292/56.066625毫秒。四条均覆盖全部目标，无 missing、负值或晚于原截止的样本需要排除。此观察点晚于接纳事务，不是数据库接纳 COMMIT；后者到目标 COMMIT 的精确间隔未测。主表仍坚持 offer 起点。计算定义、join、原始字段和限制见[独立离线补充](../../../../c8-private48-20261015/capacity/final-be3bc95/http-response-to-target-commit-supplement.md)，没有重跑负载或改动冻结容量主表。admission gate、checkout、BEGIN、SQL、COMMIT 的阶段累计在各 lane 的 `profile-interior-summary.json#/paths/accept/phases`，入口等待和 HTTP roundtrip 分列，不混称接纳吞吐。

已完成 MySQL small：40960/40960 窗口内精确回调，0 late/unknown/fail/unfinished；p95 159.791023s、p99 171.664790s，最后 182.850651s、余量约 7.15s。全部入口接纳完成 47.050664s，不是持续 256 消息/秒。生产者等待峰值 1808=`offered-started`，排除 8 个活跃 HTTP；持久化积压峰值 33436 是另一个计数。

MySQL 观测区间 CPU 17.5866 CPU-s /183.9093s，约单核 9.56%；冷/回落空闲约 0.075%/0.074%。Gateway RSS 冷 15695872、负载峰 20316160、ACK/回落 23855104 字节。post malloc in-use 1297120/reserved41943040，cold in-use1311824/reserved25165824，反映分配器保留与 live malloc 已回落；没有逐对象或完整 VM 归因，不能只凭 RSS 宣称泄漏或无泄漏。数据库服务整体 RSS 另计，不能从全进程 RSS 推每连接成本。

一个 181.001 秒阶段快照有 40486 次 receipt 样本：gate hold133.714s、并发累计 wait4499.924s，SQL40.619s、COMMIT await77.363s。claim select8.004s/60733、next_due1.104s/3873。计时包含并发/嵌套，不能相加作墙钟，COMMIT await 含服务端与网络等待，未进一步归因为硬件 fsync。证据将瓶颈定位在串行 receipt 写入路径；本轮没有改查询、连接池、H32 或恢复复杂控制器。单轮低余量排空不构成持续容量或产品 SLA。

PG16.14 为 768MiB 有界 tmpfs、fsync/full_page_writes/synchronous_commit on、read committed；MySQL8.4.11 InnoDB 为 disk-backed named volume（OrbStack VM btrfs）、flush_log_at_trx_commit=1、sync_binlog=1、64MiB buffer/redo。MySQL 全局 RR，候选会话显式 RC、3 秒锁等待、strict SQL mode。介质配置不同，不能据此跨库排名或作断电验收。历史 PG 约 25 秒变化、C4 早期写锁超时和未追认的旧 CURRENT 失败继续保留未决，不用本轮不同故障统一解释。 旧 CURRENT 只保留已复现连接池超时的归因，其他历史 HTTP500 不据此追认。C5 原 190 秒失败仍为 7169/40960 完成、33791 未完成；C6 两轮 MySQL 的 189.592/179.239 秒是各自冻结历史，C7 最终容量因磁盘保护未运行。C8 新跑结果独立保留，不拼接成新的 A/B/C 排名。

**资源和退出。** Private 沿用最多8192 I/O连接，认证连接是其中的子集，不能相加为16384；另有8秒握手、96每设备window、4096 owned slots、8192命令队列及每设备最多16个draining session的控制。工作直到 ACK/receipt COMMIT 才释放。空闲 TCP/QUIC 只读短前缀，不为每连接预分配 128KiB；WSS 初始 16KiB、MQTT 初始 2KiB，活动编码/解析有临时副本。有限数量乘帧长不是全部 RSS 上界。HTTP 128 连接、H2 每连接一 stream、请求总许可128/控制工作16和 Provider 回复16KiB 保持；全 raw HTTP body 同时达到48KiB只给约6MiB入口字节，不代表 canonical/native 复制的总内存。

保留 30 天身份历史，无数量/字节硬配额，不能声称固定磁盘上限；ACK 释放正文和投递目标，身份不提前删除。三后端成功接纳仍在 COMMIT 后响应；SQLite BEGIN IMMEDIATE、PG advisory lock、MySQL dataset GET_LOCK 及失锁 fail-stop 恢复保持。本轮只复用已获准隔离引擎和新测试库，不接触线上数据。

磁盘在授权精确缓存回收前由外部变化恢复约38GB，因此本轮实际删除清单文件为零。没有删除历史证据或用户数据、没有绕过4GiB保护；C7 RESOURCE_STOP 是测试器磁盘保护，非 Gateway 内存失败。最终 quiet、Git 状态、完整 SHA 与收据索引见交付 JSON。

Android 最终 HEAD 为 `574a4ec8fdb36ce282343c745b40ddfda5ad65ea`，Windows 为 `55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7`，两者最后一提交仅证据文档。Windows 实际编译源码为 `eaefbb0db73342648fc7257a6278cc9a5c7e664e`。Android `pr` 新编译三个正常 JNI ABI，arm64 字节与既有冻结输入相同；测试 CA 在三个 ABI 均不存在。实际闭环仍使用上述冻结 QA APK/JNI，没有冒用最后文档 HEAD 声称重新执行。

PG small 的全部 HTTP 接纳于 42.478149 秒完成；Gateway CPU 为 17.849378 CPU-s /148.497419 秒，单核平均约 12.02%。RSS 冷 14172160、总采样峰及回落 21905408 字节，post malloc in-use1141664/reserved37748736。PG 服务主进程 RSS 不是整个数据库物理内存；drain/postidle 的数据库聚合 CPU 因 PID churn 未能测得，不填零。大消息两库回落 Gateway RSS 分别 17481728/15941632 字节，CPU 分别 0.059063/0.049142 CPU-s。每次含 30 秒冷空闲与 30 秒 ACK 后空闲；连接采样为一个 pinned 业务连接和一个观察连接，不能据此推导每连接成本。

PG small 期间外部 `swift-frontend` 被采样 37 次、`swift-plugin-server` 15 次，另有 SWBBuildService/ibtoold 各一次。仅采样名称，没有读取其他工程参数或干预进程。起跑时安静不代表全程无环境干扰；这些观察也不足以归因历史约 25 秒差异。本轮没有匹配重建旧源码对照，不给新架构排名。

最终正常 JNI 构建后仍约15.33GB可用。两个原隔离数据库引擎在确认无其他客户端、事务和用户锁后恢复为原先的 Running/Paused 状态；保留的历史库没有停止、删除、清理或重置。剩余四项 ignored 为两项长期历史测量及两项 MySQL plan probe，本轮未运行；默认 suite 的另外六项 ignored 已按上表显式执行。没有 SQLite 40,960 目标容量新收据；既有长期历史空间/查询结果不改称本轮实跑。Android 路径扫描测试系统缺口也需要后续修复；Windows 精确 TLS 诊断阶段仍未观测。

本候选可供普通消息/Private 代码和 TCP 数据面评审；上线前仍应完成 Windows OS 正式构建/网络及所选客户端 QUIC/WSS 验证，并准备所有配套 128KiB 客户端。建议先准备并发布新版客户端，再切 Gateway；本任务不执行发布。建议先收口这些跨平台发布缺口，再进入 Event/Thing 等类型。本轮结束等待审查。


Source and evidence index:

- [Final delivery identity and receipt index](../../../../c8-private48-20261015/delivery/final-delivery.json)
- [Gateway native DB aggregates](../../../../c8-private48-20261015/tests/four-aggregate-summary.json)
- [Android runtime and build summary](../../../../c8-private48-20261015/native/summary.json)
- [Android final handoff and normal ABI hashes](../../../../c8-private48-20261015/native/final-handoff.json)
- [Windows final network matrix](../../../../c8-private48-20261015/windows/final-matrix.json)
- [Windows results and diagnostic limits](../../../../c8-private48-20261015/windows/final-results.md)
- [Four capacity lanes and raw receipt paths](../../../../c8-private48-20261015/capacity/final-be3bc95/combined-four-lane-results.json)
- [Original engines restored paused](../../../../c8-private48-20261015/env/final-paused-quiet-receipt.json)
- [Final original-root and frozen-artifact preservation](../../../../c8-private48-20261015/audit/final-baseline-preservation.json)
- [Full capacity interpretation](c8-capacity.md); [archived validation sources and reconstruction constraints](../validation/c8/README.md).

Full local commit list before this report commit (runtime identity remains be3bc95):

- Gateway:
  - `1391b578d8d689ac13b9a6d5a9b97f505850a64f` fix: scope 48KiB HTTP body limit to message submission
  - `392c5166bdf14b58bc478be9ef439a1ef5a18081` test: cover shared 48KiB private ledger migration and replay
  - `1fa2f8cb5bcaf088617d013d3de9c3695b458ae9` test: exercise 48KiB private boundaries and report scoped limits
  - `e2eac4976e7d5b0cb6a6497026b7b77c25e30de6` test: admit explicitly owned C8 database fixtures
  - `3774c0b1db6657a8418fac2ea808b2f98e0b6105` test: match ordinary empty body and implicit expiry wire semantics
  - `be3bc95c58500ee9913dbc2d9b442d5eb6a74227` fix: support ordinary Windows Private receiver bootstrap
  - `2664a6d4b49b7db7d9b93358379ea56c5be8f318` test: archive exact C8 validation sources and provenance
- Android:
  - `9bfef7335b103ec820ce2ea8d4507484c3998643` Prepare 48 KiB HTTP boundary client coverage
  - `893f5625aa0bf55a3e2c6be1604d99053b362bc7` Isolate QA trust JNI inputs from normal packaging
  - `81691943148a6afedcc34225928b60493d14419c` Observe real TLS rejection before reconnect transitions
  - `85bfe297684d5fddaf2ed42e26cf51bfa02164dd` Pass native owner-transfer test data through bounded private file
  - `574a4ec8fdb36ce282343c745b40ddfda5ad65ea` Record C8 Android executed Private and quality evidence
- Windows:
  - `0caedc9397222120b4a3784628a76d3bca623877` test(private): prepare Windows host checks for 48 KiB ingress
  - `eaefbb0db73342648fc7257a6278cc9a5c7e664e` test(private): isolate authorized Windows TLS QA configuration
  - `55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7` docs(private): record C8 Windows host network evidence and limits
- Warp unchanged: `fded360134f2144876bb11b95e7431cb1d72aef3`.
