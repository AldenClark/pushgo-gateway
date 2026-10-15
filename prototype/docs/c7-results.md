# C7：普通 Private 大消息配套升级

服务端完整 DELIVER 的大消息边界已修复，Warp 与两个客户端的配套实现及可行构建已完成，三库合同通过；**尚未完成新版 Android/Windows 的真实 Private TLS 收发/持久化/ACK/进程重启闭环，也没有本轮最终容量实跑结果**。前者受测试信任准备被自动审批拒绝限制；后者按剩余磁盘保护停止，不能用旧 C6 结果替代。没有新增合法 HTTP 请求拒收、能力协商、交付协议、Pull 接口或 ACK 路径。没有合并、推送或部署。

证据根：`gateway/build/quality-results/c7-private-frame64-20261015/`。目录和客户端分支名保留第一轮 64KiB 实验名称，最终固定值为 **128KiB**。[限制与升级要求](c7-private-frames.md)给出每层长度含义。

## 基线与源码

开始核实八个主工作树及隔离候选：候选分支 `codex/gateway-c-ordinary-final-20261015`，干净 HEAD `3113c97eb208d054d881677116b4ae81912a100c`，当时运行源码 `9fc812b40880e0ffd2375b4c83bb920292bdf880`；主 Gateway 的 main 保持 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。没有重复提交基线。主 Windows 原有 `src/release_smoke.rs` 修改及主 Warp 未跟踪证据不归本轮，均保留。`baseline.json` 记录各根状态和原冻结产物。

| 仓库 / 提交 | 含义 |
| --- | --- |
| Gateway `6d461fe8302ce0aace672217c9aca84ddbf4ba6e` | 本轮运行实现；共享帧上限、候选 WSS 16KiB 初始缓冲、完整帧/合法 HTTP/恢复测试及精确 Warp pins。 |
| Gateway `8b3656ed20d3d1305f9d56081c53680363d73184` | 测试专用 C7 隔离库 guard、生产 MQTT 编码器边界 oracle。正常运行逻辑不变；normal 产物仍绑定 6d，最终测试与 observer 绑定 8b。 |
| Gateway `c671d59cedba4caece384c3fdf9c3ef9e3da4ebc` | 保存32份精确验证源及来源清单；只归档，不改变运行代码、不新增执行结果。 |
| Warp `0f02fa76e37168627b83cb3d7e8714a7e86fecb4` | 首次 64KiB 配套实现；真实合法输入失败保留，不作为最终依赖。 |
| Warp `fded360134f2144876bb11b95e7431cb1d72aef3` | 最终 128KiB；统一 core、profile、transport、engine 与 WELCOME 校验。 |
| Android `df364e028cb939b278fc3787513f7e2f136bf53d` | final Warp pins、两项 host JNI 组件测试、显式 QA 配置及四个真实客户端测试方法源码；执行范围另列。 |
| Android `9deaa11a9bc9e9824c798deddf7db976b45a1e75` | 最终 Android HEAD；仅修正显式 C7 QA 包名不匹配 Firebase 配置的构建开关并补文档，正常产品构建不变。JNI 源未变，重跑受影响的 APK 构建。 |
| Windows `5ff667391637b7329b398f34fdbb7aba21ce9b74` | 精确依赖 final Warp；feature 隔离的生产回调/SQLite headless 验证工具，normal GUI 保持原本地化入口。 |

Warp、Android、Windows 使用各自隔离 `codex/private-frame64-20261015` 分支。依赖均为本地未推送 Git revision；远端尚不能取得新 revision，评审/复现须保留本机 worktree 或显式引入该 Git 对象，不能把本地构建成功解释为远端可下载。Cargo 注册表版本/checksum 没有升级。

## 冻结产物

| 产物（证据根下） | SHA256 / 对应源码 |
| --- | --- |
| `binaries/gateway-6d461fe-normal` | `5a61d4ec778583875fd02c1fef83d8a6fde738ed09f0c55d13a159ad2205ae71`；6d 正常候选。 |
| `binaries/gateway-6d461fe-tests` | `2a010b0eb416d90d9af0010a9c07f2c662e2ca61f2e8e0668b065acb06b9a816`；6d，109 默认测试。 |
| `binaries/gateway-8b3656e-tests` | `46a43262c038e34587537eb561da00f6b84a5e386de0fdc95253eaa42c409f36`；8b 最终测试、109 PASS / 0 FAIL / 10 ignored；`tests/default-8b-first.*`。 |
| `capacity/final-8b3656e/c5-observer` | `0c5d121c25440abdf2e1d878d1a6d5ae3e966d955f56d8d47777fc76418f2911`；8b + 原冻结八文件 observer patch `fb29821fb462a2752672ad77cf28cd9743fcb2457dc8c45bb877a6e91a136cbe`，仅用于测量。 |
| `native/normal-jni-build-attempt01/libpushgo_quinn_jni.so` | `c7617e4455fea01bd5e40ba268b646cfcb3a852d4bc978817397bf268d5ecb74`；df364e + final Warp，真实 Android arm64 原 manifest normal-trust release 构建；ABI2、11 exports、3 个 LOAD 0x4000。 |
| Android main APK（`native/normal-apk-build-attempt02/`） | `ccdb40edbe849c1f7c47729a5e1e0cb9b7570d5340dd3f8ce7e6e7d62696abbd`；9deaa11，隔离 debug QA 包；并非签名发布验收。 |
| Android test APK（同目录） | `160f5ad2d1595e4c3ac56db8f1e4a11123205c61f649b886fa8a52a16e6d6fb9`；包内 SO 与 c761 冻结值相同。 |
| `windows/binaries/private-host-fded360-normal-trust` | `7573de8d9c7df1d53fc6ffafbbeceb97b816d5e28c8e35b6217060ebea2486ff`；Windows 最终源码、本机 headless normal-trust 构建。 |

Gateway 使用 Rust `+1.97.1 --release --offline --locked`，fat LTO、codegen-units=1、panic=abort（测试按 Cargo 测试语义使用 unwind）。Observer 只执行一次构建，55.966 秒；临时小 patch 完成后八路径恢复，468 个源码/测试/文档/验证文件和 Git 状态、normal/test SHA 全部不变，详见 `capacity/final-8b3656e/build-handoff.json`。没有以可变 target 替代冻结产物。

## 大消息证据与保留失败

首次 64KiB 真实失败：原始 HTTP 恰为 32768 字节、input BLAKE3 `88c19505167de2476eaec88721f2604a9248c8dde9177934366e1400871172e2`，metadata 短指数数字经既有 Rust JSON 规范化生成 80901 字节 canonical、74901 字节 DELIVER。`tests/numeric-first.{json,log}` 保留 exit101 和源生成器身份；不改合法输入、不截断、不伪 ACK。128KiB 默认回归随后通过。没有建立逐字段膨胀公式或新交付协议。

6d 默认测试 109 PASS / 0 FAIL / 10 ignored，`tests/default-128k-first.*`。已执行文本/中文 33057 字节、转义 17185 字节、numeric 74901 字节完整 DELIVER；exact MAX/one-over 也检查 profile 与分配边界。真实明文 TCP 候选链路覆盖原 33057 案例的 ACK、持久化后断线重连、同一测试进程中关闭并重开账本、同身份正文/时间/TTL 与 Provider route 切换后的 Pull/ACK；这是服务器/协议端恢复证据，并非 OS 进程重启或 Android/Windows 客户端 E2E。

8b 最终默认重跑 109 PASS / 0 FAIL / 10 ignored，180.848秒含重编译、实际测试4.01秒；所有输入SHA保持不变，采样最低可用空间5171810304字节，高于4GiB保护线。MQTT补测实际完整包：text/chinese/escape各33421字节，numeric metadata75267字节，均≤131072；原HTTP仍恰为32768字节。

Warp 首64与最终128各 39 PASS，原日志均保留。额外显式运行最终 6d 的 TCP TLS / QUIC ignored 专项各 FAIL，原因均为缺少 `explicit synthetic leaf` 环境夹具，尚未进入握手。其前置零发现 selection 收据也保留，不计 PASS。没有用这些失败声称传输实现错误或握手成功。

Windows：最终 headless 构建通过，两个本地组件用例通过。真实 production WarpLoopApp callback → NotificationPipeline → SQLite Store → AckOk decision，验证 duplicate 只有一行、关闭 Store 后重开并再回放、正文和全部 metadata 相同。numeric 合法32768 HTTP形状产生组件帧74687字节（少于服务端74901，因为这里未补全部 Gateway canonical 字段）；全部2988项 metadata 保留。文本输入32768、正文32619、组件帧32857。没有 socket、TLS、远端 ACK、ACK 数据库故障或 kill-process 恢复证据；不是 Windows OS/GUI 验收。原锁规范化失败、拒绝 cache-latest 注册表升级并恢复、SHA 格式编译失败均保留于 `windows/`；最终锁仅含原冻结注册表集合。

Android：两项 host JNI exact tests 各1 PASS（26.112/1.007秒），涵盖大于旧上限的完整 decoder/截尾拒绝、>64KiB metadata 经生产 decoder 和事件 JSON 后逐项一致；不是 jstring、Room 或网络证明。独立 Android arm64 JNI 构建通过（约6秒），确实重编译 final Warp 四个包，没有以旧C6 SO代替。APK与设备执行按最终收据单列。

Android APK 第二次构建 PASS（53.351秒），静态 JNI 合同脚本 PASS；API37 只读模拟器实际运行既有 `realJni_abiStartPollAndStop_areConsistent` 一项 PASS（1.673秒）。安装 APK 与抽取 SO 哈希匹配，走真实 JNI ABI/start/session profile JSON/stop，所有网络 transport 均关闭。没有运行 Private 收发、Room、Keystore 或 ACK 故障链。仅卸载本轮独立 QA 包、停止捕获的只读模拟器并释放 lease；旧状态不清理。首 APK 的 QA/Firebase 配置失败保留，未读取或复制 Firebase 配置；更正仅作用显式 QA 开关。

HTTP 负例额外由正常 6d 二进制执行：完全无凭据的32769字节及1MiB JSON均413，消息身份记录0、进程干净退出0，见 `tests/http-oversize-second/receipt.json`。最初含合成密码字面量的脚本被审批拦截、未执行；安全替代完全移除认证字段。安全替代的首执行又因误启未提供TLS证书的TCP fixture配置失败，零请求；日志保留。改为现有明文 WSS edge fixture后只验证HTTP限额，不据此声称TLS成功。

## 三库最终回归

以最终8b测试二进制直接运行四个 opt-in aggregate，每项使用本轮创建的独立空库；各实际执行1项，不以退出0/零发现计成功。SQLite ordinary/Private 共享合同已在109默认测试内通过。

| 最终原生实库 aggregate | 结果 / 秒 |
| --- | --- |
| PostgreSQL Private | 1 PASS，1.649 |
| MySQL Private | 1 PASS，2.454 |
| PostgreSQL ordinary + native failures | 1 PASS，2.242 |
| MySQL ordinary + native failures | 1 PASS，12.488 |

收据在 `tests/aggregate-runs/{private-pg,private-mysql,ordinary-pg,ordinary-mysql}/receipt.json`。每项后冻结 binary/source身份不变。Private 两库实际记录相同TTL的260身份按[256,4]清理，无遗留目标、重开账本后稳定；原生 ordinary aggregate含既有事务回滚、owner失效、迟到结果、容量/H32背压、MySQL两种末段1644回滚与next_due原生SQLx等价/计划 oracle。不能把这些同进程/数据库故障测试写成新增客户端TLS或OS强杀恢复证据。

新实例为PG16.14（有界tmpfs）和MySQL8.4.11（专属具owner标签磁盘卷、实际btrfs、InnoDB、RR，flush/sync/binlog等由新identity实际记录）。app角色只获精确case权限；factory角色另行限制。`env/environment-identity.json` SHA `2999dfe10f539a05eed6cf9764c6c6fbadaa90f60b7b4aec3d37d84fe0c542f6`；不接触线上或既有用户库，不把此结果写成迁移/回滚或断电验证。

## 失败与未运行

质量入口 PLAN_ONLY 首次241个测试出现1 FAIL +3 ERROR（其余237通过），原结果保留，不称全套通过。3 ERROR来自shell Python3.9而脚本需要新Python行为；使用已安装Python3.13.14对受影响的精确用例/模块共10项重跑PASS，未升级依赖。1 FAIL已定位为基线已有扫描器按绝对路径祖先`build`排除所有文件：本worktree恰在`gateway/build/...`，导致0源文件和14过期审计项；相同源码的只读relative-root诊断扫描179文件、无未审计项。未修改扫描器或审计规则、未把原FAIL改成PASS。实际PR、完整quality_changed产品lane、Android全ABI/release发布验收未运行。

Gateway根crate相关TCP/WSS运行源码随普通依赖编译；新增单元测试本身未单独编译或执行。候选协议与Warp测试的通过不替代该项。所有10个默认ignored仅四个原生aggregate另显式通过；两个历史测量、两个计划探针未独立运行（ordinary aggregate内部的SQLx计划/等价子oracle已执行）；TLS/QUIC两项显式运行因夹具缺失失败，如前述。

## 验证限制与下一步

旧 Private 客户端可能在 WELCOME 阶段拒连，即使消息很小；必须按最终 Warp revision 配套升级 Gateway 与客户端。本轮不兼容混用，也不新增协商。MQTT 四类编码尺寸与服务器协议证据不等于第三方客户端支持；当前还未按 CONNECT Maximum Packet Size 收紧出站，不扩大 MQTT 消费者范围。

Android 的整仓源码快照、独立测试 CA/transport 源准备先后被自动审批以 `credential_store_path` 拒绝；未执行被拒动作，也没有更换路径或委派重试。改走原生产 trust 的直接隔离 worktree 构建。真实本地 TLS 需要合法测试信任链，因此本轮相关真实网络/Room/Keystore/ACK/强杀重启链不能以旧 C6 收据替代。准备好的测试源不是执行通过。

真实 APNs、物理 Watch 后台、旧库迁移/回滚、断电持久性，以及 Windows OS/GUI、全部客户端传输组合仍未验证。Apple 没有现有 Private 数据面，不新增该范围。

原始 C5 7169/40960 at190s 失败、C6 修复后两个 MySQL 40960/40960（最终提交179.239/189.592s）、PG96.994/116.144s 及约25s历史差异均保留在原报告。189.592秒lane的业务COMMIT窗口完整，但原身份见证超时失败保留；179.239秒lane业务/验证/ACK/回落通过，两轮后续资源观察均STOP，不写成全项无条件PASS。PG历史差异未归因，C4早期写锁超时的历史未决项未改名成已解决。本轮不做完整A/B/C排名，不承诺256消息/s持续容量或190s产品SLA。

本轮最终 MySQL 容量回归 **NOT RUN / ENV_RESOURCE_STOP**：observer已编译冻结，原输入256消息/s×10秒×16目标=40960、20ms Mock、H32、固定190秒均保留；capacity新库尚未分配，未发出任何该lane请求。四个功能aggregate完成后OS-only证据 `env/os-budget-stop-after-aggregates.json` 测得host4644540416字节、MySQL guest4268326912字节，后者比4GiB少26640384字节，combined guard=false。平台可用空间还出现波动，没有证据将变化全部归于某个组件；不靠RSS/du猜泄漏。按用户要求停止，不再为了补统计删除证据、清理用户数据、降低线或延长窗口。没有本轮offer→COMMIT p95/p99、CPU/RSS/积压/排空结果可报告；旧C6数值不得重贴为C7。observer构建成功也不是容量通过。

四项结束后仅pause两个精确C7自建容器，状态为Paused=true，保留PG tmpfs、MySQL磁盘卷、4个0600引用与owned状态；未stop/rm、未删除数据或触碰其他容器。`env/paused-environment-receipt.json` SHA `a130b90a1e76ecffe1140e2f142608bf203848a6c3e8e82f69fe2f25924821fe`。没有Gateway、编译、客户端测试或本轮模拟器进程继续运行。后续需在评审后明确恢复并重新检查空间，暂停环境不是可用负载许可。

磁盘预检保护线保持4GiB。回收仅为精确 SHA 清单内、无打开文件的隔离 Cargo `.rlib/.rmeta` 可再生编译缓存；冻结 executable、源码、失败日志、报告、数据库、旧证据与用户数据均未删。缓存清单和独立审计保留在 `tests/*compiler-cache*.json`、`review/`。RESOURCE STOP 代表测试器剩余磁盘保护，不能写成 Gateway 内存失败。30天身份历史仍无固定总磁盘配额。

建议先完成可用测试信任链下的最终Android/Windows真实Private持久化、ACK故障、重连和OS进程恢复，以及磁盘条件满足时的一轮原容量输入回归，再进入Event/Thing等类型。本轮实现可供配套升级评审，但尚无完整客户端上线条件证据。没有启动下一类型或数据库迁移阶段。

验证源归档位于 `validation/c7/`，32个文件与执行原位置SHA逐字对应，只包含环境/容量/HTTP验证代码；不是搬迁后重新执行的证据，不含URL、owned状态、凭据/证书、数据库、二进制或日志。原生客户端生产及测试源分别在最终Android/Windows提交中。精确C7路径guard和owner前提仍有效，不能在归档目录原地创建另一环境绕开原guard。归档差异检查有3处原样空白提示（两份patch context及原helper空行），为保持原执行字节未格式化；不把它写成全差异检查无警告。
