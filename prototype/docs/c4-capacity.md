# C4 SQLite 有限性能复核

下面先保留旧冻结源码 `10e59ec97230550216bc00aa3fe8c924b02510e1` 与 `19cc5c686419255739776611d1fae25b8ed7b6fa` 的复核：相同附加测量代码，按 **10e r1 → 19cc r1 → 19cc r2 → 10e r2** 执行，四例全部通过，原四例结束时 QUIET，全部自有 Gateway、Mock、采样、日志和观察器线程退出。后来独立授权追加 2 个最终 facade/Health 源码的 C4 lane，单列在文末，不能将旧 19cc 当成最终 C4 的性能。本地旧四例原始证据位于 `gateway/build/quality-results/c4-sqlite-postgres-20261015/capacity/`，入口为 `final-handoff-manifest.json`、`abba4-comparison.json` 和 `stage-diagnostics.json`，原收据未覆盖。

这四例中，19cc 的 offer→提交完成回调尾延迟和整段完成时间均高于同编号的 10e，但两种版本的重复区间重叠，不能据两次重复建立普遍性能结论。所有例子的后半段数据库积压及 producer 等待均增长，不能承诺持续 256 消息/s。此次没有 CURRENT/C32 排名、H64 实验、真实 Provider 或生产容量验收。

## 固定输入、源码与测量边界

每例输入 **256 消息/s × 10s = 2560 消息**，每条 16 个目标，共 **40960 targets**。两 Provider 各 8 个订阅者、每 Provider H32/Q32、8 个 HTTP callers、1024B 正文、20ms loopback Provider 适配延迟、Remote 合成 Token Service，TTL 使用原有绝对 24 小时含义。每例独立新库、相同公共 API 设置订阅、原有 180s settle deadline；没有扩大超时、重试失败 lane 或绕过 SQL 接纳。

使用 Rust/Cargo **1.97.1**、Release opt3/fat LTO/cgu1/panic abort、Tokio 4 workers。两个源自完整 tracked Git archive 的测量源码只在本机 OUT 内修改；根候选产品源码未加入观察器。原始版本差异是 `store.rs` 的 BEGIN IMMEDIATE 修改，以及 `tests.rs` 新增的两个 native 测试；这些测试不进入本次 release fixture。观察器补丁的新增、删除及上下文内容相同，仅统一 diff 的 hunk 行号不同，归一化 payload SHA256 为 `7088fb73f2da181bc98b2d1603c03f023e5d420d2b5a346955c1dac93d353d70`。

| 测量二进制 | SHA256 |
|---|---|
| 10e + observer | `6ea8c1f17b5b4a044000d42760c0152433684e4a66b98943faed5227f62e578c` |
| 19cc + observer | `4f9d95113e1276461c3c639fe91c9468807672e428cb6fcba4a09e7b43873ddf` |

offer 时间是在实际向 executor 提交业务消息时记录，区别于预定发送时间。每个目标在 receipt 事务 `tx.commit().await?` 成功返回、`changed > 0` 时，使用事务内最终有效 state，立即调用观察器，再归还连接。fixture 回调与 Python producer 均使用 `mach_absolute_time`，保留相同 timebase，无墙钟换算。这里的 **post-COMMIT callback 是提交 await 返回后的观测完成边界，不是 SQLite 内部 fsync 的精确瞬间**；未使用提交前写入的 `receipt_at` 意图时间冒充它。

观察器以固定 96B 事件记录目标身份、attempt、state、sequence 和单调时钟。Gateway 只增加固定 4096 槽 `sync_channel`、64KiB BufWriter 和一个 writer OS 线程，回调使用非阻塞 try_lock/try_send；没有全窗口目标缓存。channel payload 为 393216B，另有固定槽开销和线程/栈。任何 dropped、invalid identity、write error 或未 join 都使 lane 不合格；HTTP 与 runtime shutdown 后关闭发送端、排空并 join。默认关闭 feature，不增加外部依赖；库保持 `forbid(unsafe_code)`，系统时钟 FFI 仅在测量 fixture 中。两版本均包含相同测量成本。有限 Python driver 保留原来的输入/wire 数组，其 RAM 不计入 Gateway RSS。

## 全分母与精确尾延迟

每例保留每个已 offer 目标的结果，包括接纳失败时没有 delivery_id 的目标。下表以全部 40960 offered targets 为分母；本轮全部成功，因此 observed-success 分位数也覆盖全部 offered targets。若有失败、超时或未完成，不能删去这些目标后仍声称全 offered 分位数，也不能补造完成时间。

| lane | 消息 | offered targets | 成功 | 接纳失败 | Provider失败 | timeout | unfinished | dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 10e r1 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| 19cc r1 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| 19cc r2 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| 10e r2 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| 合计 | 10240 | 163840 | 163840 | 0 | 0 | 0 | 0 | 0 |

invalid identity、write error 均为 0，所有 writer 均已 join。每例另有 16 个 warmup 目标，其身份由独立 SQL 与实际 Pull/ACK 确认后明确排除，不能用固定行数截断。四例均通过完整 wire 身份/正文、全目标持久 receipt、Pull/ACK 和正常退出检查。

精确分位按每目标的 `(commit_mach_ticks − offer_mach_ticks) × timebase` 计算并排序，使用 nearest-rank `ceil(p × N)`；N=40960，p95/p99 分别取第 38912/40551 个样本。这是完整事件样本分位，区别于旧固定 log2 直方图的分位上界，也不能把各阶段 p95 相加。

| lane | offer→post-COMMIT p95 s | p99 s | 首次 SQL 全 receipt 可见 s | target/s 含 drain | producer waiting peak | active HTTP peak | Gateway peak RSS MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| 10e r1 | 17.156325 | 17.521473 | 27.810 | 1472.9 | 576 | 8 | 23.34 |
| 19cc r1 | 18.984735 | 19.292922 | 29.475 | 1389.6 | 1023 | 8 | 23.45 |
| 19cc r2 | 21.528604 | 21.978516 | 32.372 | 1265.3 | 1002 | 8 | 23.47 |
| 10e r2 | 20.484979 | 20.831281 | 30.982 | 1322.1 | 1008 | 8 | 23.45 |

`producer waiting = submitted − HTTP-started`，只表示已提交但 HTTP 尚未开始；**不包含同时活跃的 8 个 HTTP**。`active HTTP = started − finished`。target/s 是 40960 targets 除以从 load 起至首次 SQL 全 receipt 可见的时间，包含输入及排空，不能当持续吞吐。SQL 可见时间受既有采样边界影响；每目标 COMMIT 分位来自独立回调流，不从 SQL 轮询时间反推。

## 前端、gate 与数据库阶段

| lane | offer→HTTP start p95 ms | HTTP start→response p95 ms | offer→response p95 ms | 输入结束 DB 积压 targets | 后半 DB 增长 targets |
|---|---:|---:|---:|---:|---:|
| 10e r1 | 3899.48 | 77.39 | 4004.40 | 22754 | 6098 |
| 19cc r1 | 8558.81 | 98.01 | 8648.25 | 15002 | 3647 |
| 19cc r2 | 8763.31 | 98.31 | 8851.07 | 14347 | 4608 |
| 10e r2 | 9348.30 | 99.48 | 9428.82 | 15464 | 3996 |

前端三列均来自该轮实际 offer/request Mach 时钟，2560 条消息逐条关联。不同列分位不可相加。旧 accepted_at→receipt histogram 不含这些接纳前等待，即使其均值下降也不能替代完整 offer 延迟。输入结束 DB 积压较少也可能是更多输入还滞留前端，不能单独视为性能改善。

load→全 receipt SQL marker 窗口内，独占 gate hold 占 **83.2–88.8%**。各 lane 的调用均值范围如下，完整样本数、直方图与各路径总量保留在 JSON 中：

| 阶段 | accept | receipt |
|---|---:|---:|
| gate wait mean | 11.81–15.36ms | 6.23–7.18ms |
| pool acquire mean | 0.122–0.175ms | 0.046–0.065ms |
| COMMIT mean | 1.160–1.318ms | 0.071–0.089ms |
| 10e BEGIN mean | 17.71–19.43µs | 13.21–13.78µs |
| 19cc BEGIN mean | 47.55–54.38µs | 25.72–31.12µs |

claim 路径的 gate wait mean 为 2.78–4.22ms、pool acquire 0.330–0.471ms、COMMIT 0.063–0.102ms；BEGIN mean 在 10e 为 13.27–13.73µs，在 19cc 为 23.19–31.29µs。claim 的 pool 统计还包含逐目标授权调用，不能把它的调用次数与单个 claim 事务数视为相同。

这些观测支持存在明显的串行 gate 等待，不能将较小的 pool 均值描述成已证明的 pool 瓶颈。gate hold 包含 BEGIN、SQL、COMMIT 及观察器，SQL inclusive 包含 trigger、SQLx dispatch/result，pool 包含 checkout/ping，BEGIN/COMMIT 包含 worker 排队和调用方调度；不得把嵌套总量相加，也不能把跨任务累计 wait 当墙钟。COMMIT 数字不是 engine-only/fsync 时间。

BEGIN IMMEDIATE 有可见成本，但没有单独隔离所有变化。旧的单次 19cc 28.726s 与较早 10e 23.863/23.363s 相差约 4.86–5.36s，版本和执行时序同时改变，不能把这约 5s 全归 BEGIN。此次 10e 自身重复差约 3.17s，19cc 自身差约 2.90s；按同编号比较的 first-SQL 差约 1.66/1.39s，两个版本区间也重叠。native network mean 为 26.01–30.15ms，完整 Mock 的实测 p95 为 27–29ms，虽配置固定 sleep20ms，仍有本机调度及适配开销。没有证据把其余变化全归数据库、写锁或 Provider，也没有因此测试 H64 或建议简单提高并发。

## 旧派生指标修正与 CURRENT 500 边界

旧 `analyse_c1_base.py` 从 register label 重建 token 时使用 `i + 20261014`，实际 C3 runner 注册 route 使用 `i + 20261015`。按 `(provider, op_id, delivery_id, token)` 关联时会偏移到同消息的其他目标，并遗漏边界目标。本轮旧 reducer 的以下四项只有每 Provider 17920 样本，总计 35840/40960，即 14/16 子集，不能当完整或精确目标关联的分布：

- `queue_to_first_network_ms`
- `caller_to_first_network_ms`
- `mock_http_duration_ms`
- `response_to_completion_intent_ms`

最后一项还会错误配对其他目标的 completion intent，不能仅理解为少了一些样本。旧 reducer 和已生成的 `profile-summary.json` 原封保留，不覆盖首次收据；C4 汇总明确排除这四个派生字段，Provider duration 改从原始 `mock.jsonl` 中实际 op_id 的 finished 记录计算，完整 **20480/Provider、40960 总样本**。功能 wire oracle 使用实际 `device_tokens`，新 COMMIT reducer 使用真实 `(delivery_id, device_key)`，native phase/network histogram 独立采集；它们不依赖这个错误映射，四例有效性及新精确 COMMIT 分位未受影响。

CURRENT 旧五条 lane 的 40 次 HTTP500 仍保留原失败事实；旧日志观察器全局 veto 导致不能逐条追认原因。后来在精确 CURRENT 源码的独立诊断中复现了 14 次 HTTP500，实际错误为 `pool timed out while waiting for an open connection`，支持该次复现的接纳前 pool timeout；没有证明 SQLITE_BUSY，也没有证明具体 pool、连接占用者或旧 40 次请求的逐条根因。此次未运行新的 CURRENT lane，不能借 C4 gate/BEGIN 数据给全部旧 500 追认原因。

## 最小 source-only 复现材料建议

最终 portable package 由 root 整合；本文件只建议清单，不复制大型数据、源码 snapshot、target 或 binary。精确重建这组 A/B 还需要能读取上述两个 commit 的 Git 对象；单独提供新的最终候选源码，不能假装已包含旧冻结源。建议打包这些小型源码与清单：

1. 一个 `README.md` 和参数化 manifest：固定两个 commit/tree、Rust/profile、ABBA 顺序、输入、180s deadline、指标语义、四个旧派生字段禁用说明；说明需要本地 Git objects、两个 commit 原始根目录与 prototype 的 Cargo.toml/Cargo.lock，外部 OUT、唯一 CARGO_TARGET_DIR 和独占资源窗口。保留原运行 manifest 的结果身份摘要即可，不打包原始负载数据。
2. `prepare_sources.py`、`observer_library.rs`、`observer_fixture.rs`，以及两个小 observer patch 或其归一化 payload 摘要。准备器从本地 Git archive 重建目标源，校验原始文件 hash，再施加相同 observer；默认 feature 关闭。当前本机准备器路径需要 root 在 portable 版参数化，不能把绝对本机路径当通用命令。
3. `build_and_run.py` 和 `run_profile_capacity.py`：参数化 source repo、OUT、target、Python 和 helper 路径，明确启用 `cargo +1.97.1 ... --locked --features commit-observer`；保留原输入/退出 oracle、first-failure STOP，不附带自动重新执行或延长 deadline。
4. Mock/采样依赖源码：`c3_mock.py`、`resource_monitor.py`、`common.py`、小型 `resource-monitor-source-provenance.json`，以及原 `c3_pid_rusage.c`，由复现者本地编译 helper，不分发已编译 helper。
5. 只读 reducer：`reduce_commits.py`、`summarize_abba.py`、`reduce_profile_capacity.py`、`analyse_c2.py`、`analyse_c1_base.py`。若保留最后一份原执行版本，必须保留上述四项禁用及完整 Mock 重算逻辑，不能静默沿用错误 token map；修正版另记 hash，不覆盖原收据。
6. 一个很小的 calibration 输入/生成脚本：两个成功、一个失败、一个未完成，验证分母及 nearest-rank；dropped 负控制必须拒绝精确结果。本机该校准已通过，位于 OUT 的 `reducer-calibration/result.json`，可打包生成逻辑和结果摘要，不需携带真实负载流。

不需要分发本机 `sources/`、tracked tar、`binaries/`、Cargo target、四例 SQLite/WAL、完整 peer/mock/offer 流或大型 snapshots。它们保留在本机证据目录，由小 manifest 的 SHA 指向；复现时新建自己的输出，不覆盖现有收据。

## 最终 C4 源码两例补充：d925b97

根候选完成 facade、Health 和 PostgreSQL feature 集成后，另行批准并只运行 **2 个最终 C4 SQLite lane**。精确 source commit 为 `d925b97fe30068b66aefb66e33284831df6d8e4f`，tree 为 `e8c016252f7101433c8a4ffdf21d51425b67cf04`；产品实现 commit 为 `f8ed62f94ce44e285414f1a0f6894878763f4dbe`，d925b97 仅补充 writer-probe 测试协调。测量从 d925b97 完整 tracked archive 重建，只在 OUT 的新目录加入相同 observer，没有修改根产品。新增/删除的 observer 代码与旧 19cc 组一致；Health 的提交前检查保留，错误不会产生成功 COMMIT 回调。

| artifact | SHA256 / 身份 |
|---|---|
| 最终 C4 测量 fixture，启用 observer | `83ab543e6e14760c20b2911e624fb33f80355afb6d466f1d753a589773d9c753` |
| 根任务已冻结的 normal fixture，未用于这两例测量 | `8d458bbf23e0306f4a78ee26a1735fa2795bee02f39a30a52acb11634559f80e` |
| 测量源码/补丁/构建身份 | `capacity/final-c4/source-identity.json`、`observer.patch`、`build.json` |
| 两例原始证据与 SHA 清单 | `capacity/final-c4/final-handoff-manifest.json` |
| 完整离线阶段与资源数据 | `capacity/final-c4/final-c4-summary.json` |

两例均沿用上述 Rust1.97.1、Release、Tokio4、H32/Q32、20ms、16 targets/message、8 HTTP callers、1024B、Remote 合成凭据及 180s deadline，均为 256 消息/s × 10s、独立新 SQLite。观察器、输入、wire/SQL/Pull/ACK/退出 oracle 与原 driver 相同；没有 PostgreSQL 性能测试、额外 rate、H64、失败重跑或延长期限。normal/test 产物已由根任务在测量构建前另行冻结；本次覆盖的只有唯一既有 Cargo target 中的构建输出。

| 最终 lane | 消息 | offered targets | 成功 | 接纳失败 | Provider失败 | timeout | unfinished | dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| C4 r1 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| C4 r2 | 2560 | 40960 | 40960 | 0 | 0 | 0 | 0 | 0 |
| 合计 | 5120 | 81920 | 81920 | 0 | 0 | 0 | 0 | 0 |

invalid identity、write error 均为 0；每例 16 个独立 ACK 确认的 warmup 目标明确排除。两个测量进程及全部 Mock/资源采样/日志/observer 线程均已退出，结束后 QUIET，未追加运行。

下表 offer→post-COMMIT 仍使用实际 offer 与成功提交 await 后立即执行的 Mach 回调，nearest-rank、N=40960；是完整样本分位，不是 fsync 内部瞬间，也不是旧 log2 桶上界。所有成功均覆盖全 offered 分母。target/s 仍包含 drain；producer waiting 仍不含 active HTTP。

| 最终 lane | offer→post-COMMIT p95 s | p99 s | firstSQL 全 receipt 可见 s | target/s 含 drain | producer waiting peak | active HTTP peak |
|---|---:|---:|---:|---:|---:|---:|
| C4 r1 | 13.266980 | 13.576580 | 23.867 | 1716.2 | 302 | 8 |
| C4 r2 | 14.465226 | 14.763025 | 25.189 | 1626.1 | 525 | 8 |

| 最终 lane | 输入结束 DB backlog targets | 后半 DB 增长 targets | 后半 producer waiting 增长消息 | CPU user/system s | peak RSS MiB | 最后有效 RSS MiB / phase |
|---|---:|---:|---:|---|---:|---|
| C4 r1 | 23740 | 7475 | 302 | 9.216766/14.977781 | 24.516 | 24.516 / ack-start |
| C4 r2 | 20340 | 5761 | 423 | 9.208011/15.024918 | 24.922 | 24.922 / ack-start |

CPU 是 load→first-all-targets-SQL marker 的进程 user/system 增量，合计 24.195/24.233 CPU 秒，不是全机 CPU 或墙钟。peak RSS 来自整个 fixture 的 `time -l`，包含启动、warmup、排空、ACK 与观察器成本。最后有效 RSS 采样分别在进程启动后约 37.831/39.264s，phase 都是 `ack-start`；**本次没有固定的负载后或 ACK 后空闲回落窗口，不能把尾部采样称为回落 RSS，也不能据此宣称恢复 idle 内存**。原 C3 falloff 数据不能替代最终 C4 的回落验证。

最终 C4 的独占 gate hold 占 load→SQL marker 窗口 85.46%/81.65%。下面是 caller-wall mean，单位 µs；SQL 是 statement inclusive，完整调用数、桶及分位上界保留在 JSON：

| lane/path | gate wait | gate hold | pool acquire | BEGIN | SQL inclusive | COMMIT |
|---|---:|---:|---:|---:|---:|---:|
| C4 r1 / accept | 8806.512 | 2624.400 | 99.408 | 22.094 | 11.294 | 1263.921 |
| C4 r1 / claim | 2158.251 | 443.297 | 192.257 | 19.602 | 14.295 | 57.705 |
| C4 r1 / receipt | 4202.982 | 190.607 | 35.411 | 19.402 | 10.926 | 63.630 |
| C4 r2 / accept | 8108.516 | 2615.385 | 72.089 | 22.539 | 11.425 | 1212.614 |
| C4 r2 / claim | 2128.781 | 457.623 | 205.384 | 19.734 | 14.252 | 61.495 |
| C4 r2 / receipt | 3983.148 | 193.164 | 33.833 | 19.557 | 11.157 | 66.262 |

gate 的等待仍明显，不能把 pool/BEGIN/COMMIT 的较小调用均值扩展为全链路归因；嵌套 gate hold/SQL/COMMIT 不可相加。两例输入结束均有明显积压、后半段继续增长，完成率不是持续 256 消息/s 的承诺。最终样本比旧 ABBA 更快，但源码同时新增 facade、Health、PG feature，主机执行时序也不同；不能将变化归于任一单项，更不能据这两例复原或解释旧约 5s 的差异。

旧 reducer 的四个 token 关联字段仍原封保留并从新结论排除；最终 C4 的完整 Provider duration 另从每例 20480/Provider 的原始 finished 记录重算。新 COMMIT 精确分位、全分母和功能 oracle 不使用该错误映射。

根任务复制 source-only bundle 时，可附带小型 `final-c4/execute_final.py`、`summarize_final.py`、`observer.patch`、`source-identity.json`、`two-lane-plan-executed.json`、`build.json`、`final-handoff-manifest.json` 及前述 observer/driver/Mock/reducer/helper C 源码。执行脚本为本机精确路径版本，**未 portable**，需要本地包含 d925b97 的 Git 对象及显式唯一 target/OUT；清单用于说明已执行来源，不应把它包装成无需路径配置的通用命令。不要复制 `final-c4/source/`、tar、测量 binary、数据库、完整流或 Cargo target；这些大型原始证据继续留在本机 OUT。
