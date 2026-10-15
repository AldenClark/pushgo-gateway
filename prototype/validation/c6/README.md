# C6 源码回放材料

本目录保存测试系统的实际源码、稳定历史副本和来源清单，**迁移到本目录后全部未执行（NOT RUN）**。它不是独立的一键回放工具，也不是新的功能或容量验收收据。每份源码的外部来源、SHA-256、字节数与执行绑定见 `manifest.json`；绝对路径和布局假设保持原字节，未为迁移位置改写。

当前共 165 份源码、4 份静态 SQL hash→label 映射和 1 份派生补丁，加上 README/manifest 共 173 个文件（含局部 `.gitattributes` 元数据）。其中 133 份 Python 仅作 AST 解析，其余仅作 UTF-8/NUL 文本检查；全部复制字节与清单中的稳定外部来源一致。没有 import 或执行 harness，没有构建、DB、ADB/native 操作。包内不含 URL 值、凭据、owner state、证书材料、二进制、APK/JNI、数据库、binlog、原始日志或运行结果 JSON；外部收据仅引用路径与摘要。

## 当前 9fc 身份

以下身份来自原执行收据；打包没有重新读取或重算二进制。9fc 产品保持原源码，observer 是单独带观察补丁的产物。

| 对象 | 身份 |
| --- | --- |
| source commit | `9fc812b40880e0ffd2375b4c83bb920292bdf880` |
| source tree | `304a7787f98714a5fe340421edd3d0fe96b24129` |
| normal server | `b7a0683dd46dd5d167c93b5e960adde4423323fd2bf96b81f89c9846b4572af3` |
| test binary | `5a610bd4bf301689abe46a7c2d49cdf2c06771305fdd09bb0e9a1a50a8805cb1` |
| observer binary | `3dcceddb5c15fd35f1000f7b198519e9e49a87f29a3c84ae1aa8f3e1a5c01a69` |

`tests/sqlfix-9fc812b/` 保留最终验证脚本及 continuation02/03。默认 103 项、wiregap、Private 两库与 ordinary 两库合同的实际结果以外部 final-summary 为准；MySQL ordinary 包含 late1644 A/B 与原生 SQLx next_due 观察。两次 MySQL Private 布局失败都发生在连接前，原日志保留；安全 alias/projection 后 continuation03 是独立执行结果，不追认旧失败。

## 收录范围与来源

- `env/` 保留 base、fresh2 依赖、fresh3 disk3 helper、预算快照、PG 准备与重置源码，以及 sqlfix 空间归档 phase1、清理 phase2。fresh3 为磁盘 named volume；具体环境、owner 与 URL 仅由外部收据绑定，不把旧 state 当作回放输入。
- `preserve_reset_sqlfix_final_arm.py` 与两份 `first-failed-source.py`、`second-failed-source.py` 分别保留最终实际源码和两次失败的原字节。首错为 SHOW COLUMNS 误加 LIMIT，次错为 BusyBox timeout 不支持 GNU 长参数；均发生在 snapshot/TRUNCATE 前。修复仅调整语法，5 秒边界不变，成功 reset 一次。corrections 与两次首错、成功 reset 的收据仅作外部元数据引用。
- `capacity/` 保留实际 PG 使用的原 v2 全套 helper、历史 v3、MySQL 首轮 v4 和重复 v6 源码，以及 timing_unknown/observation-boundary 补丁与静态 oracle。PG 两个 lane 均直接使用原 v2 CLI，没有新造 adapter。v4/v6/PG1/PG2 的 `executed-source*` 副本与相应冻结源码逐项相等，执行 manifest 仅外部引用。各原布局的 `prepared-query-hash-map.json` 是静态代码数据，不是 post-completion 结果；也按原字节收录。
- e3/9fc observer patch 与实际 builder 单独保留；9fc builder 位于 prepared-9fc812b，由最终 build-handoff attestation 绑定。env 下还保留 PG1/PG2 的先 guards 后原 main、SQL 单次 5 秒限制 wrapper，以及 PG1 首个 archive、修正 archive 与精确 drop 源码。早期失败和 preparation patch 保留原含义，准备收据不追认为实际执行。
- `native/attempt-05-mysql-receipt-fix/executed-source/` 七份源码逐项绑定实际执行 manifest。历史 `native/source/` 保留 native04 输入；其中 driver 原路径已更新为 native05，旧项改指 SHA 相同的 attempt04 稳定历史副本，并另记原执行路径。
- `native/attempt-03/historical-source-preservation/` 保留历史功能 driver，以及从 attempt02 源码重建的 coordinator 与 diff。重建只修正故障诊断 oracle，保留触发器名与原 15 秒期限；所得字节与 attempt03 执行 manifest 一致，但重建本身不是一次重新执行。
- `provider-native/` 保留 e3 历史执行源码；`provider-native-mysql-9fc812b/` 的 11 份源码和 `finalize-quiet.py` 已逐项绑定最终 manifest `883779b83d47a27e878016414f559ef929266479b0ca512c93724e4b341e0fb4`。原 OUT 的 Apple/MySQL、Android/MySQL 两 lane PASS 与 quiet 由该外部 manifest 证明；原 preparation provenance 不改，仓库副本仍 NOT RUN。
- STOP budget adapter 与 34 项 pure-check 源码独立保留。首个 raw STOP stdout 未持久化，check 按原 helper schema 与真实 STOP receipt 重建其 shape，明确来源；pure checks 不表示新的 DB、预算或 native 观测。

功能测试使用 3708 test APK 对应的旧 Kotlin，单独保留在 `native/functional-artifacts-3708/`；024a Kotlin 是 TLS-observer 输入，不能混用。Apple provider app、Xcode 工程及完整 Swift 测试源码依赖外部缓存，未复制整套产品源码。

## 历史 e3 与客户端身份

e3 表只说明保留来源的历史身份，不代表当前 9fc 产品。

| 对象 | 历史身份 |
| --- | --- |
| e3 commit | `e3de1ebe1caac618ecdcc293e040752e36752fe4` |
| e3 tree | `d631191587514d1286044ec6c8eb674d947c7087` |
| e3 normal | `ef08db18881801b84d3fca496ae58d66b3e0eeb735f1d97e5cc665392bd0744c` |
| e3 tests | `8e721dccd4bf8a481c0ce70cc319ca53c498786ffa4fa4628dfbf4084ed52204` |
| e3 observer | `2616e3fd02244fcd0a4b10760803ae8e484422b1657115b0e9a8a7ff741d768b` |
| e3 observer patch | `a1e92a0116cfbcf57c87a0f264abcc3a73a94dc2deada5577e988b97357511d9` |
| main APK | `779930c0750bfae52aab59472a1bca21104541335e536b6466cb9920417f50d2` |
| functional test APK | `3708eacadbaf4da07e5a5fe38b2e40cfadb53545091e66f89ee36495dcbc1b75` |
| TLS-observer test APK | `024a6945a14676159cdc62bcbc9ef034b77c2c70b9957ec127758fbdb45b0ab5` |
| JNI | `802b41a519b3ce9deb214204869e0a899ed8965c76fa141d87b7bc3b2e4e883c` |

历次 README/manifest 原字节归档在 C6OUT `bundle-history/`，每次目录和旧摘要见清单。源文件既不因摘要刷新而覆盖历史，也不以当前可变路径冒充旧来源。

## 回放前提与未完成边界

原执行依赖 macOS、原 checkout、Rust **+1.97.1**、精确 Cargo.lock 与离线 registry/git 缓存（含 locked Warp dbae），以及原 Python 运行时和 DB observer 依赖。Android 依赖离线 Gradle/SDK/NDK、arm64 JNI 工具链、API 37 emulator、ADB 与协作租约；Apple provider 依赖外部缓存 Xcode 项目、app/UI-test runner 与模拟器。这些缓存、工具链、设备镜像与运行环境均未打包。

数据库依赖 OrbStack `orbstack` context 与原缓存镜像：

- PostgreSQL：`postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`
- MySQL：`mysql@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb`

helper 含资源创建、重置和删除能力。源码复制没有授予执行或清理权限；回放须重新绑定独占窗口、全新自有合成 case、具体路径及 owner guards。PG stats 保留/重置还需相应 QUIET 和归属证据。不能直接复用旧 state、旧 URL 或其他 lane。

测试 CA 仅用于合成 overlay，仍保留 PKIX、hostname、ALPN 和 leaf-pin；不表示生产 Android 默认信任测试 CA。Apple 不支持 Private。合法 HTTP 超帧 gap 仍待产品决策，不能据此包宣称完整 Private 验收。纯 lost-ACK 场景及未实际覆盖的 native 其他 transport 仍为 NOT RUN；独立 TLS/QUIC unit 工具因 DLP 拒绝也保持 NOT RUN，本次没有补跑。

**来源缺口：** envowner 确认 sqlfix 专属 role grant provision、alias copy、test-guard projection 当时以 inline Python 执行，没有保存独立实际源码。通用 create helper 不包含这三段修改，结果 receipt 不能冒充 source；清单明确记为 provenance gap，不制作虚构的已执行重建脚本。

## 最终执行边界与清理

9fc 的四个最终容量 lane 均已结束，源码绑定已收齐。MySQL 两次都在原 190 秒窗口内完成 exact 40,960/40,960 COMMIT；首轮 v4 的 identity witness 越过截止，因此原 runner FAIL 保留，未执行 post-ACK，after-resource STOP 也保留。v6 只将聚合已全完成后的独立限时 identity 验证与业务截止分开，不延长原 190 秒或事后赋时；重复 lane 的业务、identity/wire、ACK/post-idle 通过，但 after-resource 仍 STOP。两次 COMMIT 窗口通过不等于首轮 runner 或资源检查通过。

PG1/PG2 使用相同 9fc 产品与原 v2 runner，两次均完成原窗口内的完整分母与 identity/wire/ACK/post-idle。外部 comparison 记录当前两次维护 SQL 与串行 gate 时间的关联差异，不证明 planner、统计、checkpoint、存储或 host 因果；历史 C5 PG 约 25 秒及更早约 5 秒差异仍未解释。post-ACK RSS 保持稳定的观察也没有 allocator/leak 因果归因，PG master RSS 不等于整个集群物理内存。包内只引用这些收据摘要，不复制其观测数据。

`final_owned_preserve.py` 已在原 OUT 实际执行，17 个 canonical case/bootstrap 的保全 manifest 身份为 `3179f0620fa9ee31d26fd349c98d49da2c7e72a4097fa33ff660ba97a860fc98`。最终 `final_owned_remove.py`（SHA `abe2a5c45345a647507670c895a3b142faa06adcd6e9bbd94f23c1a8a178a6ea`）随后经 root 授权执行，4 个精确容器及唯一 fresh3 volume 已删除，URL/canonical state 清零、projection 退役；原保全 manifest 保持。镜像、AVD、源码、产物、原始证据和 memory 未动。OrbStack 因保守进程名 guard 命中常驻 MCP bridges 而保持 Running，root 接受该边界，不能宣称恢复到初始 Stopped。

旧 `final_owned_remove.before-lsof-and.prepared-only.py`（0d335…）只是未执行的 prepared 历史；包内单 flag diff 是从两份精确源码派生的补丁说明，唯一变化为 lsof 添加 `-a`，不能将旧 prepared 源追认为实际执行。保全、删除及 remnant 收据均只引用元数据。

最终来源收集无待追加项。不可独立复现的 inline provision/alias/projection 来源缺口、未覆盖用例与迁移位置 NOT RUN 仍是明确边界，不因本次打包而消失。

## 历史原字节与局部 whitespace 属性

为保持实际执行源码与历史 patch 的 SHA，原空白行和 patch 上下文字节不作格式化。此目录的 `.gitattributes` 仅对 `*.patch` 及 `env/isolated_db.py`、`env/fresh2/isolated_db.py`、`env/fresh3/isolated_db.py` 关闭 Git whitespace 检查；只影响本回放目录，不修改产品、全局 Git 配置或其他文件检查。README 自有多余 EOF 空行已修整。首次 cached diff 检查 exit 2 的 root 报告与后续只读复现分别归档，复现不冒称首调用。
