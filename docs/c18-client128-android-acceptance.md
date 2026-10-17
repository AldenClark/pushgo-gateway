# C18：128 KiB 公共 Private 与 Android 配套验收

2026-10-18。结论：本轮公共传输边界和 Android TCP/TLS 的指定闭环已完成；不等于跨平台或发布验收完成。按用户最后指示采用官方 tungstenite 0.30.0，没有创建 vendor 或同版本私有补丁。Gateway 运行实现冻结，数据库、迁移、调度、预算和生命周期均未修改。

证据根目录 `R=/Users/ethan/Repo/PushGo/gateway/build/quality-results/c18-client128-20261018`。所有数据为本轮新建 SQLite 库、合成身份和消息；无真实 Provider、用户库或系统信任变更。工作在独立候选，未合并、推送或部署。

## 源码、依赖与产物

| 对象 | 实际身份 |
|---|---|
| Gateway 起点 | `bb2444b5e8db0a5e3b8ba542ac2ee24921cc62f1`，分支 `codex/gateway-c-product-ordinary-20261016` |
| Gateway 运行代码 | `334ce4e9c5bd48bc444e3c3f9b6551f364ca18d0`；C17 的正常产品二进制，无 QA/fixture，Rust 1.97.1、aarch64 Darwin、dev/default |
| Gateway SHA-256 | `619a9ecf1630c55c72226137f8899af4e6daeb2d544e8eb3fa78ab6507fbe9a2`，`R/binaries/pushgo-gateway-frozen` |
| Gateway QA 工具提交 | `c9228fa5fbcb989b6dcb6e26057966900193a6ed`，只含两个测试辅助程序 |
| 公共库起点 → 最终 | `fded360134f2144876bb11b95e7431cb1d72aef3` → `eeef2b4ded2773259dff26e4a588fcad421c110e`，`R/worktrees/warp-link` |
| Android 起点 | `07b634739ec10fb67720eaabaaec02d26b3932ea`，`R/worktrees/pushgo-android` |
| Android 依赖提交 | `a4f201cd5ccc74c81290afb074a806942055bded`，正常 manifest/lock 均固定公共库 `eeef2b4…`，非仅 QA manifest 引用 |
| Android 最终提交 | `b5bbf9ae94bbdf136c214ecea595e44b0c9e53ca`，新增严格的设备验收和 QA 构建目录白名单 |
| 最终 QA app APK | `7257e24f356b05a3ba1f43efc71859b2d00c1f7ca0910c175b3fc0c03b742270` |
| 最终 test APK | `9e7520816b0d3c13c2934266a3505f1d17f49c6f6a3c083e454c5ecf928bc912` |
| QA arm64 JNI | `48849f0efb2451f7698d0c72f57e3b582c0b4689806e2346dcb23a707bb83177` |
| 正常 arm64 / armv7 / x86_64 JNI | `0e08fbdddf34f8f265ff77e4b068320c7bd56ffdb48acf8f18604554d53f2502` / `6d7f2b6623002739188f2e34c4384964863e6813f747e765e9abea49f89eea3b` / `4609247622f5a2a82e274f4b64e0b920c1370c6704ca4f1609930c4612bbbccf` |

正式信任的三 ABI JNI 均以正常 Android manifest/lock 构建为 release SO；未包含合成 CA DER。设备验收使用独立 debug QA APK、arm64 release JNI 和仅加测试 CA 的 transport overlay，不能称作正式签名发布构建。安装后从模拟器读回主/测试 APK 和嵌入 SO 核对了哈希。`R/native/runtime-artifacts-final.json`、各 `normal-jni-*.receipt.json` 保存命令及环境。arm64 LOAD 对齐符合 16 KiB；armv7 是 ELF32，但未执行 32 位设备测试。

最终提交前后核对：Gateway C17 的 360 项运行源码/manifest 哈希全部相同；公共库 9 项已测文件、Android 两项已编译源码哈希相同。见 `R/audit/final-content-oracle.json`。Android APK 构建时 HEAD 是 a4f201c 加明确记录的测试/Gradle改动；后续 b5bbf9a 保存这些相同字节及文档，不把提交时间误写成构建时间。

## 官方依赖修复与大小口径

[官方 v0.30.0 parser](https://github.com/snapview/tungstenite-rs/blob/v0.30.0/src/protocol/frame/mod.rs) 在 u64 长度域中先比较上限，再转为 usize、预留内存；同时有 cfg(32-bit) 回归。这修正 0.29 在 32 位上先窄化、可能把 `2^32+2` 声明误当成 2 字节的问题。已核对实际下载 registry 文件和哈希，见 `R/codec/official030-registry-source.json`；非仅根据版本号判断。

公共库升级 `tokio-tungstenite`/`tungstenite` 为官方 0.30，关联 sha1 为 0.11；正常 Android lock 同步。其余 registry 依赖校验和保持一致，见两个 lock-delta 收据。未改系统工具或安装软件；为了引用未推送的公共库提交，仅向本机既有 Cargo Git cache 导入该精确提交，记录在 `R/native/local-source-seed.json`。

- HTTP `/message` 的 49,152 字节是整个 UTF-8 JSON 请求体，包括 JSON 字段名、转义与 metadata。控制接口仍为原限制。正常产品超限返回 **400 / invalid_request_body / length limit exceeded**，不是独立 fixture 的 413。
- 完整 Private 应用帧上限为 **131,072 字节**，包括 1 字节 type、1 字节 flags 和编码内容。TCP/TLS、QUIC 的 4 字节大端长度前缀不计入；最大有前缀字节数为 131,076。WSS 外层协议头不计入，但单帧和重组后的消息都设 131,072 上限。QUIC 流控窗口不是消息上限。
- 复用已有共享常量和正确的 128 KiB 实现；只把相同 WSS 配置提取成小纯函数供真实路径和测试共用，未改配置值。流读取器先检查长度再分配当前帧；空闲连接不预分配 128 KiB。WSS 读写缓冲仍为 16 KiB，写缓冲最大 256 KiB；既有超时和连接生命周期保留。没有新增生产任务、队列、调度器或预算所有者。
- MQTT 是 Gateway 独立协议，不是 Warp/Android Private 的运输；不能把上述 TCP/TLS 通过外推为 MQTT 客户端验收。APNs/FCM 限制和语义未调整。

## 已执行证据

| 检查 | 结果与直接收据 |
|---|---|
| 公共 transport | 17 PASS，`R/codec/transport-final-02.log`：恰好 128 KiB、连续帧、超限、零/u32 最大长度、截断、取消后恢复、WSS 原始巨大 u64 长度、重组总大小和背压 |
| profile codec | 9 PASS，`R/codec/profile-final.log`。包含合法 DELIVER 信封恰好 131,072 / 131,073 拒绝；payload 是 codec 级不透明字节，**不是 128 KiB 合法业务 JSON 的端到端交付证明** |
| WELCOME / 旧客户端负例 | 1 PASS，`R/codec/welcome-final.log`。新验证器接受 131,072；固定旧 dbae3a8 验证函数报 `server selected invalid max frame bytes 131072`；旧 32,770 正例仍过。是原函数负例，不是旧 APK 网络运行 |
| JNI host 解码 | 各 1 PASS，`jni-full-deliver-host.log`、`jni-numeric-metadata-host.log`；仅组件，不冒充设备证据 |
| 正常 JNI 构建 | arm64、armv7、x86_64 exit 0，`R/native/normal-ABI-build-summary.json`；未执行 armv7/WSS |
| Android 质量选择 | plan-only 250 selector tests、READY；没有放宽门禁；release 建议仍属发布范围，未执行 |
| Android PR | 最终 attempt04：295 JVM，0 fail/error/skip，localization、androidTest 编译和组装通过；真实 adb 显式 emulator-5580。PR 本身不运行设备测试。`R/native/quality-pr/final-pr-complete.json` |
| Android 实际设备方法 | **2 执行、0 skipped、PASS**，`R/runtime/attempt05/result.json`；命令/退出码/清理见 `R/native/device-owner-05`，设备 API 37 arm64，只读自有模拟器 |

Android 使用已有生产 `PrivateChannelClient`、运输切换/频道同步、真实 JNI、入站处理、`MessageRepository`、Room、Keystore 和持久 ACK outbox；不是协议 stub。测试自行启动这条真实客户端链，不宣称 UI、前台 Service、系统后台或物理 OEM 生命周期验收。

正常 Gateway 控制/API → 唯一账本 → Private DELIVER → Android 解码/Room → 显式 ACK → 同账本事务完成。为观测长度并注入 ACK 丢失，客户端经过一个**测试专用 TLS 终止并重新加密的 relay**连接最终 Gateway；relay 不产生业务消息或伪造 ACK，不替代存储/会话。两段均保留证书链、127.0.0.1 主机名、pushgo-tcp ALPN、leaf pin 校验，3 次会话均实际核对。与纯端到端不终止 TLS 的部署连接应区分。

| 输入/阶段 | 实际结果 |
|---|---|
| 中文、emoji、引号、反斜杠小消息 | 请求 238 字节，DELIVER 517 字节；Room 标题、正文、ID 与原请求一致 |
| 密集数值 metadata | 整请求 **49,152** 字节，4,443 个 `1e15` 值；DELIVER **111,637** 字节，带 TCP 前缀 111,641；Room/Wire 每个值语义相等，无截断 |
| 持久化后 ACK 丢失 | relay 丢弃实际 type=9 ACK；服务端仍有 1 个未 ACK 目标和正文，未误报完成 |
| Android 进程重启 | PID 3630 → 3952，原 Keystore/Settings 和 Room 保留；同 message/delivery ID 在第二连接重投 111,637 字节，Room 仍只有一份该消息；新 ACK 后目标删除、正文释放 |
| 断线重连 | 第三连接完成第三条消息，DELIVER 485 字节；没有换协议兜底 |
| 49,153 字节合法 JSON | 400 / invalid_request_body，明确长度超限；没有新身份、目标或额外 DELIVER |
| 最终对账 | 3 个服务端身份、0 个目标、0 正文，Room 3 条 canonical 消息、3 个 acked ledger、ACK outbox 0；SQLite integrity_check=ok |

原始 HTTP/帧/逐 checkpoint/两阶段一致 Room 快照/最终账本位于 `R/runtime/attempt05`。独立逐条比较原请求、实际 DELIVER、Room 的内容及身份见 `R/audit/final-content-oracle.json`。ACK 状态不能只凭客户端 acked 推断：这里还要求真实正 ACK、到期前服务端已提交的目标移除和正文释放；正常实现不会保留已完成目标行。

## QA 信任隔离与资源

本轮重新获得了 QA CA 授权。overlay、QA manifest、合成 CA 和证书仅在忽略的 R 目录；normal manifest 无 patch 指向它们。QA 两个 RootCertStore 只增加本地合成 CA，不关闭原有验证。固定公知合成私钥由公开测试材料在内存生成，经匿名 pipe 交给进程，未写 key 文件；不创建正式凭据。正常三 ABI SO 均检查 CA DER 不存在，QA SO 则存在，完整 source/trust diff 在 `R/native/qa-source-isolation.json` 和 `qa-trust-only.diff`。

Gradle QA 必须显式开关、精确允许目录、独立 `.c7evidence` applicationId、排除正常 JNI builder，Release task graph 明确拒绝 QA 输入。正常信任及系统信任未修改。PR 和联调只选 emulator-5580，附着的物理设备未被使用。自有模拟器、Gateway、relay、reverse 均结束并释放；最终清理无错误。

relay 测试预算为最多 4 次连接、256 条帧元数据、4 MiB 原始帧、有限 WELCOME/DELIVER/ACK 捕获；没有按最大帧给空闲连接预分配。它的额外 TLS/线程开销是测试器开销，不能当作产品资源或性能数据。本轮最低记录可用空间约 36.5 GiB，高于 4 GiB+512 MiB 保护线；未删除历史证据或缓存。

## 保留的失败及未运行

没有把失败改名为通过。以下工具错误保留原始日志，均未修改 Gateway 运行代码：

| 记录 | 原因与处理 |
|---|---|
| codec bootstrap / 首次 transport compile | 解释器缺 tomllib；测试 helper Read trait 歧义。分别换已装 Python3.13、限定测试方法名；原日志保留 |
| native attempt01 | 错把 prototype delivery_id 当成正常 HTTP 响应字段；在解释响应前落收据，从真实已提交账本核对 message_id 并取得 delivery_id |
| native attempt02 | 错等 ACK 目标保留行；正常事务删除目标，已实际收到小消息和 ACK。改为严格检查真实正 ACK + 未过期身份 + 已提交正文/目标释放 |
| native attempt03 | 第 13 个 checkpoint 错期待 413；前 12 项成功单独保留，整次不算 PASS。用全新库校准正常 400/error_code 后修正两端测试断言 |
| native attempt04 | 最终 APK 收集器 JSON 形状缺 driver 键；安装/Gateway 启动前失败。原收集器 JSON 保留，补入有实物哈希支持的既有键后前置校验。模拟器已正常 boot，随后清理，不能称为模拟器故障 |
| PR earlier attempts | init 配置失败、一次 adb shim 空清单的环境样本均保留且不作最终证据；正式最终 PR 使用真实 adb 和指定模拟器 |

各 native attempt 的 failure-classification.json 与 launcher 日志保留；唯一完整最终闭环是 attempt05。校准的额外新库仅验证请求提取边界，不替代授权成功接纳。

未运行：Android QUIC/WSS 真网络、32 位 WSS parser 执行、物理 Android/后台 Service/Doze、正式签名发布构建、Windows OS、真实 Provider、性能和三库迁移复跑。也未在本轮注入 Room ACK 写入失败；已验证的是**实际 ACK 线上丢失后的持久化、重投和去重**。进程重启不等于设备重启或断电。

## 代码增量与发布清单

`R/audit/change-classification.json` 区分 cfg(test)。公共库生产 Rust 仅等价配置提取，净 +4 行；内嵌测试及固定旧函数样本净 +221 行。Cargo manifest/lock 单列，不把依赖树去重当生产精简。Android native manifest 2 行替换及 lock 更新，生产 Kotlin/JNI 不变；Gradle QA 白名单 +5/-1 行，设备测试 +149 行，文档 +6。Gateway 生产增量 0，测试器 +811 行。vendor 源码 **0 行**；无新长期生产对象、权威、协调或调度机制。

其他客户端只盘点，见 `R/audit/consumers-final.md`：Apple 未发现 Warp Private 接收器，Provider route sync 不是 Private stream；不扩建 Apple 能力。Windows main 仍固定旧 dbae3a8，C7 隔离版本固定 fded360，均不是本轮 eeef2b4；Windows 需要单独更新依赖并在 Windows OS 验收，macOS host 结果不可替代。Android/Warp main 也未合并此隔离候选。公共库提交未推送；本机正常构建使用精确本地 Git cache，其他环境须在审查并正式提供该公共库 revision 后才能复建，不把当前本地可构建当作已发布依赖。

发布前按顺序：审查并整合公共库与 Android 依赖/锁及正常构建；单独完成 Windows 配套和 Android/Windows QUIC/WSS、Windows OS 验收；完成既有真实 Provider/平台和断电等发布门槛；准备并先发布新版客户端，再切换 Gateway。**128 KiB 客户端必须配套升级，旧 Private 客户端可能在 WELCOME 阶段拒绝，新 WSS 不提供兼容旁路。** 本任务不执行上述发布步骤，也不重开尺寸/协商设计。本轮完成后停止。
