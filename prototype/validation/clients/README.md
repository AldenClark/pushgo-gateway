# C2 原生验证执行源归档

这里只有显式白名单内的新增 Swift/Kotlin 测试、Swift 包清单和执行脚本。它不是独立的客户端工程，也不是测试结果。没有归档生产源码副本、GRDB/Gradle 依赖、APK、可执行文件、数据库或日志；不要在本归档目录内编译或产生运行输出。

原执行目录：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015`（下称 `ORIGINAL`）。逐文件原始路径及 SHA-256、未改动生产源码的引用清单都在 `source-hashes.json`。八份执行源均为原文件的逐字节副本，未改原始执行文件。

原 Apple 实测输出为 `ORIGINAL/client-evidence/apple-first`，绑定 core binary SHA-256 `7969c61d1e9fcb7587e884c69792076a77ad56077ead50d759d12bd1b3f4515f`；两个独立原生测试进程各执行一次，实际 provider wakeup → 应用 NotificationIngressController → GRDB → 持久 ACK → 新进程恢复。代理在失败 ACK503 与成功 ACK200 请求时只读核验客户端规范数据和 leased ACK 行；另以真实 Pull 响应核对完整正文和标识。它不证明 APNs/OS delegate 分发、已安装应用重启、物理后台行为。SwiftPM 仅在隔离 Package.swift 加入未改动的 controller 源码及与主 Xcode approachable concurrency 对齐的功能开关；最初配置编译失败保留在原目录，发生在首个产品断言执行之前。

原 Android 实测输出为 `ORIGINAL/client-evidence/android`：三项原生仪器测试首次通过，实际 InboundMessageProcessor.process/default hooks → HTTP → 磁盘 Room → ACK outbox。恢复是数据库/仓储关闭重开，**没有证明进程重启或 WorkManager 调度**。HTTP 服务是测试内 loopback stub，不是 candidate gateway；因此 Android 证据不绑定 core binary 行为。生产 Android 源码和测试源未变时可复用这份结果，不能将其扩大为最终 gateway 联调通过。隔离 `.c2evidence` applicationId 避免触及主应用数据。

最终 Apple 复验也首次通过：`ORIGINAL/client-evidence/apple-final-f573` 绑定实现 `f57357c42900dbf06c4b27271b6962ad4c47a1c5` 与最终 fixture SHA-256 `2611b966f30837854a08c3a36ee5982a1e0c258c78b615270d067cd8ea32fc10`。ingest/recover 退出码 0/0、原生 PID 72145→72291，1 次实际 wakeup 捕获、1 次 Pull、ACK503→200；完整 8,214 字节正文和 leased ACK 在两次请求前核对，服务端 ACK 后正文/待执行目标/目标行均为 0。manifest 记录八份执行源仍与本归档逐字节相同；进程退出记录确认 runner、fixture、mock、两原生进程均已结束。这里的重启仍是 SwiftPM 原生测试进程；不扩大为已安装应用 OS 分发或物理后台证据。Android 未重复运行。

## 复现入口

先将本归档的 `client-evidence/` 和 `harness/` 复制到一个新的、归档外的工作目录 `RUNROOT`，保持两者为兄弟目录。检查 source-hashes.json，再从原执行包（或哈希完全一致的主客户端）补齐 `RUNROOT/client-evidence/apple-package/Shared`、`Tests/Fixtures`、`Package.resolved`；从原离线缓存复制 `apple-build` 到 `RUNROOT/client-evidence/apple-build`。这些生产文件和依赖仅用于工作目录，不属于本归档。当前 Swift Package.swift 所列全部源文件都需要存在；缺缓存应报告 NOT RUN，不能静默下载或换依赖版本。

最终 binary 由根任务在冻结后显式给出；不得把原 core SHA 说成最终 binary SHA。针对 store 变更，仅重跑受影响 Apple 链路，使用新的输出目录：

```sh
python3 "$RUNROOT/harness/run_apple_wakeup.py" --binary "$FINAL_BINARY" --out "$RUNROOT/client-evidence/apple-final"
python3 "$RUNROOT/harness/verify_apple_receipt.py" --run "$RUNROOT/client-evidence/apple-final"
```

`FINAL_BINARY` 必须是最终冻结可执行文件的绝对路径，执行计划自动记录该文件 SHA-256。`--out` 必须不存在，脚本拒绝覆盖首次回执。脚本自动建立候选服务及 provider capture/proxy；用普通长正文触发生产 oversized wakeup 投影，不补造标记；两阶段之间尊重生产 ACK 退避约60秒。输出包括两阶段退出码、各自 PID、原始 provider JSON、HTTP 次序和只读 SQL 请求时观察。两个阶段都会单独发现并执行一个测试。复现后 `verify_apple_receipt.py` 只读核对标识、完整内容和服务端 ACK 后释放状态。

如确实需要重做 Android（本轮最终 gateway store 变更本身不要求重跑），在新的归档外 `RUNROOT` 中先提供 Android Studio JBR、已缓存依赖/JNI，以及一个已授权、明确选择的运行中 emulator：

```sh
export JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home'
"$RUNROOT/client-evidence/android/stage-native.sh" /Users/ethan/Repo/PushGo/pushgo-android
ANDROID_SERIAL="$OWNED_EMULATOR_SERIAL" "$RUNROOT/client-evidence/android/run-native.sh"
```

stage 使用源文件副本并校验真实边界哈希，复用缓存 JNI；run 限两名 Gradle workers，禁用该副本的 Rust JNI 构建，只执行指定三项原生测试。脚本不会启动模拟器。不要复用已有 stage 或输出目录覆盖首次结果；保留第一个失败并先分类，不靠重试产品断言变绿。
