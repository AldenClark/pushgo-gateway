# Gateway C3：普通客户端闭环与 mutation gate 定位

本轮以 `447f93443e254a9d62ad696696abbc82e1ce3820` 的干净隔离候选继续。主线保持 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。没有合并、推送、部署、生产凭据或真实用户数据。本报告的普通消息范围是既定的 FCM/APNs；Private 数据面、Event、Thing、Watch、WNS 仍未接入。

## 交付身份

| 提交 | 用途及证据 |
|---|---|
| `447f9344` | 本轮起点；原型源码归档及八个独立仓库状态保存在 `baseline.json`、`baseline-447-prototype.tar` |
| `13c2e74` | 控制面、现有凭据 owner 接线、固定大小分路径 profile；阶段 A 为 77 PASS、2 个历史测量待显式运行 |
| `9b6186c` | 仅 retirement 查询改为 marker 外层的 CROSS JOIN；阶段 78 PASS |
| `10e59ec97230550216bc00aa3fe8c924b02510e1` | 修复 coalescing 后旧 frozen job 新发送/ACK capability 错位；客户端闭环冻结实现，80 PASS，两个历史测量另列 |
| `19cc5c686419255739776611d1fae25b8ed7b6fa` | 写事务显式 BEGIN IMMEDIATE，保留 3 秒预算与 fail-closed/restart；82 PASS，完成本轮实现 |
| `cb0da19cfc1ca542e14a19e506a086a830103bcd` | 单独诊断分支 `codex/gateway-c-client-loop-scan-control-20261015`，完整合同与最终实现一致，仅一行 retirement SQL 保留旧 JOIN，供配对性能控制；不用于交付 |

最终实现仍位于 `codex/gateway-c-ordinary-final-20261015`。运行实现固定 `19cc5c6`；本报告与验证源码的最终 HEAD/清洁状态另由本轮 `final-delivery.json` 收据绑定，文档提交不改变运行实现。`build-final.json` 绑定客户端/配对性能冻结 executable SHA256 `c22a71df7fc12d8b30a63bfbb24d7f3d8d895f62c35dcab58d2f3d894f1d1e9a`，`build-final-tests.json` 绑定 native test SHA256 `52e1102109523365d006dbb94c885afdbfca0341b166a78579931858ad454202`。最终写锁修复由 `build-writer-final.json` 绑定 `19cc5c6`，executable SHA256 `6a6e760f51db767ef7a7a69287a63b4cbb252d5812a701caa59dce63eac046f1`、test SHA256 `d75b836eb3651607b1aeff9e0557c80830e1991d8f9f6650f1ba6ec43f769694`；对应的产品源码无未提交差异，打包源码只包含验证输入和文档。

## 控制面合同与差异

| 路径/状态 | 最终行为及验证 |
|---|---|
| register、channel/device | 复用同平台 device key；返回当前 channel_type、provider_token、issued_new_key 与独立持久 route_revision；相同 route upsert 递增 revision，但不吊销已接纳工作所用 generation。原生 Apple/Android bootstrap 与 Rust revision/overflow 回归 |
| channel/exists、rename | 返回现有客户端所需字段；rename 需频道密码，仅更名，不改已接纳正文。实际 router 与两平台生产 repository/controller |
| channel/sync | 最多 2000 项，逐项错误；部分成功保留成功项、保留遗漏订阅；全部成功才移除遗漏项；空成功集合清空订阅。Rust partial/full-sync 与真实客户端 sync |
| channel/unsubscribe | 只取消订阅；不删除已接纳 frozen target、Pull、正文或幂等身份。Rust 与真实客户端 unsubscribe |
| provider route delete / logout | 清当前 provider token、更新 revision/必要 generation，保留订阅和已接纳 Pull；未授权旧路由不再发送，已接管的外部请求可完成。两平台 held-provider/logout 交错 |
| provider-token/retire | 仅匹配规范化 platform/token；内部 control_epoch 立即屏蔽旧目标，最多 256 个一批物理释放；同 token 重绑后的新 epoch 消息不受旧 marker 影响。Rust、真实 Gateway SIGKILL 重启 |
| 同 token 多 owner coalescing | 请求 key 胜出；订阅 union、retained Pull capability 转给 winner，旧 key 失效。原 delivery/device/attempt 仍负责 frozen receipt；转来的旧 job 永久禁止新授权，以 superseded_route 收敛；已授权请求不取消 |
| coalescing 的 ACK | 同 delivery 多存活 target 在 Pull/ACK 计一次；已 ACK 删除的 A target 不重建，B 尚未 ACK 的义务可转给 A。主线 coalesce 不查询 A 的 ACK tombstone，故没有新增更强的跨 owner 抑制规则 |
| 时间、TTL、幂等 | message/delivery/op 身份、首次时间、绝对 TTL、重复语义保持；完整 30 天身份保留，ACK 释放正文和队列；没有历史满额拒收或提前淘汰 |

单频道既有上限为 32 个订阅者。原计划的 256 recipients 静态检查后撤回且未运行；实际 fanout lane 使用合法公共 API 的最大 32，2 条消息合计 64 个目标。128/256 指业务消息每秒，常规每消息 16 个投递目标。

本轮没有改客户端显示、ACK 身份或展示去重策略。独立审查发现的 ABA 复活和 direct ACK 旧 capability 问题均已修复。主线实际 worker 在 coalescing 删除旧设备后将旧 frozen job supersede；没有采用“把旧 job 重新绑定 winner 发送”的新语义。资格授权成功是接管边界，之后的凭据获取/网络请求不因路由变化强制取消。

## 凭据及资源预算

候选依赖同仓库 Gateway library 的真实 FCM/APNs traits 与 Remote owner，并通过极小 factory 导出复用现有 Token Service client、缓存、single-flight、刷新和失败退避。没有复制 signer、认证体系或 token 生命周期。Token Service 回复沿用现有 64 KiB 上限及原有超时/同源重定向策略。生产 FCM/APNs Service 原先的无界 Provider 回复读取未被重新引入；候选继续使用自己的 16 KiB 有界 Provider transport。

提供显式配置的 HTTPS Provider origin 构造接口；构造期间无 I/O。fixture 仍只能连接显式 loopback Mock，并可用 `--mock-token-service-endpoint` 经过真实 Remote owner。HTTPS origin 校验和无凭据调用构造已测；真实 Token Service、FCM/APNs 账号与 TLS 联调未运行。

H32/Q32 是每 Provider 的实验安全上限/领取批次，不是批准的产品最大值；两个 Provider 合计最多 64 个已领取/接管位置，结果待提交继续占用位置，数据库阻塞不会无限堆积结果。退避不占网络执行位置，停机保留可恢复工作。HTTP 沿用 32 KiB 请求体、128 个总接纳许可、16 个控制响应工作许可、128 连接、每 HTTP/2 连接 stream 1 及有界窗口；许可跟随响应 Body 到 EOF/drop。

新 profile 为固定约 87 KiB，8 条路径、8 类阶段、33 类 SQL，不存用户/SQL 参数或无限样本。gate wait/hold、pool checkout、BEGIN、SQL、COMMIT、auth/compute 分开。SQL 是 SQLx 派发/返回与 trigger 的包含时间；COMMIT 包含 worker queue/WAL 持久化，不能冒称纯 fsync；无安全 trace API，未虚构 trigger-exclusive 时间。不同维度峰值不相加，嵌套 maintenance/fanout 不再加到 parent gate hold 上。

## 真实客户端与恢复证据

| 验证 | 最终结果与真实边界 |
|---|---|
| Rust native | 最终 `19cc5c6` 为 82 PASS、0 FAIL；覆盖完整字段、权限、幂等、容量、ACK/receipt、route ABA/coalescing、bounded Provider replies、写失败、取消/停机及领取/接管窗口。两个 ignored 历史实验显式另跑，不将 ignored 当 PASS |
| Apple | 最终 7 个独立 native process、20 次实际候选 HTTP，全部 `/gateway` 前缀。未修改生产 controllers/111 份 Shared 源；实际 GRDB 两条精确正文、direct legacy ACK、oversized filtered V2、durable ACK503、新 PID 按真实 62.660 秒退避恢复、unsubscribe、held logout/晚 receipt 均通过 |
| Android | 最终 2 个 instrumentation 方法、0 skipped，PID 3992→4093；未修改 191 份生产文件。真实 SettingsRepository、AndroidKeystore、Room、repository 与 ingress/ACK coordinator 直连候选；精确 Room 5→6、未知结果 outbox 1→0；SQL 失败不 ACK、同步/退出与投递交错、ACK 先于 held Provider receipt、完整 force-stop/reopen 均通过 |
| Gateway OS 重启 | PID 12790 SIGKILL→12791，同 DB；已 ACK 与已退休各仅一次 Provider 调用，新 epoch 一次 unknown 后仅一次重发；身份/业务内容/首次时间/绝对 TTL/30 天保留稳定，最终 target/body 均释放 |

Apple 是 host native controllers/GRDB 测试，不是 iOS/Watch OS 后台交付或 Settings UI。Android 使用实际生产入口内部路径，WorkManager/FCM OS 调度未运行；缓存 JNI 已绑定 SHA，但精确源 revision 未核实，不声称新构建的全栈 release。Android 导出的 closed-main SQLite 副本逐条核对了所需最新数据，但未导出任意 live WAL；新 PID 重开原 Room 才是主要恢复证据。两平台没有普通 sender API，发送由显式 HTTP fixture 发起，没有把它称为客户端原生发送 UI。

真实 APNs、物理 Watch 后台、真实 FCM/Token Service、PG/MySQL 实库迁移、真实 OS ENOSPC/断电均未运行。SQLite FULL 和 deferred COMMIT 失败为实际 SQLite 错误注入，不能冒充文件系统断电试验。

## gate 定位与配对容量

原 matched 16 例计划中，主 8 例全部通过；第 9 例 DB-block 真实失败后停止，余 7 例最初 NOT RUN，修复后另立 follow-up，不把它们伪装为原配对完成。旧 A128 仅用于定位，不计入最终比较。最终配对 source 为 `cb0da19` / `10e59ec`，完整 tracked tree、实际执行脚本、helper、binary、compiler、lock 与 profile 均冻结；两 source 唯一区别是一行 retirement SQL。Rust 1.97.1，Release opt3/fat LTO/cgu1/panic abort，Tokio4，loopback Provider 20ms、body1024B、8 HTTP callers、H32/Q32，相同逻辑输入/24 小时绝对 TTL 含义，各自独立生成服务器身份。

首个旧查询诊断 A128 的 gate hold 合计 31.425 秒；嵌套维护 SQL 23.705 秒，约占 75.43%；两条 retirement 维护 SQL 合组 23.297 秒，不能全部精确归给 SELECT。独立原生 SQLite 3.54.0 将该 SELECT 单独隔离：空 marker 时 10k/20k target 的 fullscan=9,999/19,999、VM=60,014/120,014；marker 外层 CROSS JOIN 用既有索引则 VM=13、fullscan=0。11 组相同结果对照覆盖 future epoch、多 marker、LIMIT256、owner 引用等。

因此只修改此 JOIN，不扩池、不批量 receipt、不拆接纳事务。两个 devices 索引建议未混入：实际 load cleanup 仅 49.5ms，coalesce 在该窗口没有调用。非空退休集合的匹配/排序，以及大 coalescing SQL 仍是随数据量变化的工作量；有界返回/内存不是恒定数据库工作量。

以下 old JOIN/new JOIN 均含完整 C3 控制/凭据/客户端合同，**只是 C 内部热点的因果对照，不是主线/C32/C 新排名**。各次输入 10 秒，128/256 消息每秒分别是 1280/2560 条业务消息、20,480/40,960 个实际目标。全部成功接纳、最终全部目标 receipt 持久化，wire 身份/Pull/ACK/停机检查均通过。producer peak 为尚未 HTTP 完成的输入数；DB at input end 为持久目标积压。完整表见本机 `capacity-matched-primary8-table.md/json`。

| source/rate | firstSQL r1/r2 s | target/s incl drain r1/r2 | producer peak r1/r2 | DB at inputend r1/r2 |
|---|---:|---:|---:|---:|
| baseline128 | 29.818/30.794 | 686.829/665.055 | 222/240 | 8648/8498 |
| baseline256 | 140.602/161.403 | 291.318/253.775 | 1464/1430 | 11531/14009 |
| candidate128 | 10.376/10.38 | 1973.875/1972.947 | 1/1 | 426/312 |
| candidate256 | 23.863/23.363 | 1716.462/1753.205 | 562/480 | 17180/18754 |

这些 target/s 是整段输入加排空的平均完成率，不是可持续吞吐。128 优化版仍在输入结束留有 312/426 个目标，10 秒测试不能证明长期 128 消息/秒；256 优化版在输入结束仍积压 17,180/18,754 个目标，完成需要 23.863/23.363 秒，明显不能承诺持续 256。

| 版本/rate | E2E 均值 r1/r2 ms | E2E p95/p99 bucket 上界 ms | queue 均值 ms | network 均值 ms | receipt 均值 ms | COMMIT 均值 ms | CPU 秒 r1/r2 | peak RSS MiB r1/r2 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| old JOIN/128 | 8079.88/8470.75 | 16777.215/16777.215 | 8033.11/8422.75 | 24.15/24.22 | 22.62/23.78 | .052/.053 | 30.925/31.701 | 22.219/22.125 |
| new JOIN/128 | 58.01/46.82 | 262.143/262.143 | 31.65/20.54 | 23.76/23.79 | 2.60/2.50 | .058/.058 | 10.910/10.950 | 22.125/22.063 |
| old JOIN/256 | 60080.22/74934.17 | 134217.727/134217.727 | 60000.86/74846.99 | 26.50/25.65 | 52.86/61.52 | .058/.062 | 141.705/162.028 | 22.734/22.406 |
| new JOIN/256 | 6821.46/6964.44 | 16777.215/16777.215 | 6790.22/6933.96 | 28.07/27.12 | 3.17/3.37 | .057/.056 | 21.396/21.691 | 22.781/22.734 |

p95/p99 在这些粗 log2 buckets 恰好相同，不是精确分位数；表中该列两数指 p95/p99，各重复的上界相同。CPU 是目标进程 user+system，从 load 到近邻 SQL 可见采样；并非墙钟或全机 CPU。Provider Mock 设定 sleep20ms，实际完整 capture 的 256 优化版均值 23.704/23.638ms、p95 27ms；native network 还包含凭据/HTTP 部分。

优化后 256 两次的独占 gate hold 为 17.811/18.273 秒，占 load→SQL marker 窗口 73.83%/77.35%。receipt gate wait 为跨 40,960 次累计 122.763/130.560 秒，不能当墙钟；receipt hold 7.169/7.302 秒，其中 COMMIT 2.326/2.301 秒。claim pool checkout 累计 11.015/10.703 秒，claim SQL 2.667/2.729 秒。正常持久化过程没有显示单次 fsync 激增：结果前排队和重复事务/调度工作仍显著，不能仅归因 Provider 延迟。

完整 network duration 积分平均占 47.66/47.02 个位置，合计上限64；1Hz 左采样均值53.76/50.20是另一个近似，不混用。owned/network/receipt 各自峰值均受界，不能把不同时刻峰值相加。因此没有证据支持 H64 能解决该瓶颈；保留 H32 作为当前对照，不恢复复杂控制器，也不声称 H32 已是最优产品上限。

### 写锁故障及有界恢复

原第 9 例 `matched-observerfix-baseline-db-block-r1` 持外部 `BEGIN IMMEDIATE` 锁 2.021 秒。8 个真正产品 JSON503 在约32–35ms 返回，随后 owner driver 日志 `SQLite code5 database is locked`，进程 fatal；其余请求及第二波是进程退出后的 connection-refused/local proxy HTML，不能全计作产品503。原观察器自然退出的 `exit_codes=[]` 不证明正常0，实际 fatal 日志与 PID 消失证明失败。没有具体失败 SQL/stack，不能断言正是某条 DELETE；静态维护路径存在 deferred 先读后写升级窗口，实际时序与此机制吻合。

只将预期写事务统一为 SQLx `begin_with("BEGIN IMMEDIATE")`，读取前保留 writer；所有语句、事务边界、COMMIT 后成功和原子 fanout 保持。现有3秒 busy timeout 不扩大；纯读、runtime、并发池均未改。新 native short-lock（显式100ms停留）继续 alive/提交；>3秒错误 fail-closed 后同库新 owner 可恢复原 identity/firsttime/absolute TTL。长锁政策依然可能 fatal，需要外层重启；没有新增吞错、自动重放未知 COMMIT 或无限 retry queue。首次 long-test 的 target_status/status oracle 混用失败保留，修正取值后全82通过。

写锁修复后的独立九例 **9 PASS、0 FAIL、0 NOT RUN**，全部经过 SQL全目标receipt、完整wire/Pull/ACK、joined停机检查并最终 QUIET：

| 最终补测 | 消息/目标 | 全部receipt落盘完成秒 |
|---|---:|---:|
| 19cc 同2秒 DB-block |16/256|2.487|
| cb0d / 19cc fanout32 |各2/64|0.276 / 0.289|
| cb0d / 19cc cleanup |各16/256|0.340 / 0.336|
| 19cc idle60 |0/0|60.024秒观察窗|
| 19cc burst+稀疏/falloff |67/1072|3.716，后另≥10秒空闲|
| 19cc 128/s×10s |1280/20480|10.614|
| 19cc 256/s×10s |2560/40960|28.726|

旧8例性能严格绑定10e/cb0d；新实现19cc正常回归各单次，不把新旧样本拼成同源 A/B。最终128/256含排空完成率1929.59/1425.87 targets/s，输入结束DB积压1280/10267，producer peak2/1128；256时后半producer仍增加634条，积压部分移到接纳前，不能只看DB目标数少了就说改善。最终E2E accepted_at→COMMIT均值193.04/6626.00ms，p95/p99 bucket上界1048.575/16777.215ms；queue166.03/6589.28ms，network23.80/32.05ms，receipt3.20/4.67ms。CPU到近邻SQL marker11.283/22.109秒，peakRSS22.250/23.156MiB；全阶段分位和SQL数见 [容量报告](c3-capacity.md)。

最终256单次28.726秒比旧23.863/23.363慢。BEGIN累计0.554/0.590→1.209秒，多0.62–0.66秒，不能解释全部4.86–5.36秒墙钟差；claim pool累计11.015/10.703→14.838秒，gate hold17.811/18.273→19.765秒。完整Mock mean23.704/23.638→24.021ms（p9527→28ms），native network还包括凭据/HTTP。安全修复有可见BEGIN开销，其余差异未隔离，未为单样本继续扩大改动或提出新的架构排名。

前端完整op关联显示，256的producer offer→HTTPstart mean1133/772→4251ms、p954007/3028→9500ms；HTTPadmission mean40.94/34.68→62.35ms、p9576.28/70.16→91.49ms。因此最终accepted→COMMIT均值更低并不代表总耗时更低。**精确offer→逐target最终COMMIT p95/p99未采得**；producer是1ms事件分辨率，不能相加分位数，也不能用receipt_at代替COMMIT。该测量缺口单列，不隐瞒。

### 回落内存与空闲

最终idle60.024秒CPU0.061773秒，interrupt/package wakes135/50，RSS中位/最大12.047MiB；malloc live1,188,400→1,188,784B，reserved20→24MiB。67条burst+稀疏消息排空/ACK后，10.428秒窗口CPU0.018518秒、wakes24/4，RSS18.50–18.95MiB；malloc live2,580,496→2,561,632B、blocks5751→5744，reserved36MiB不变。两者providerClient owners均false/false，owned/network/receipt/provider targets归零。

falloff末vmmap malloc resident9888K、allocated2242K、free/fragmented7646K（78%），physical footprint11.4M（与RSS口径不同）。支持分配器空闲驻留/碎片是该probe回落RSS的重要来源，不能泛化无泄漏，也未量化SQLite缓存贡献。这个falloff probe是67条消息，不冒充256/s持续运行后的长时heap审计。fixture有每秒完整profile心跳，observer每250ms取ps/阶段取stats/Mach及vmmap；不是未instrument的生产空闲成本。


端到端 timing 指接纳至 Provider 结果 COMMIT；不代表手机收到或展示。profile p95/p99 是 log2 微秒 bucket 上界；receipt_at 是意图时间，不能当精确持久化时间。完整落盘使用只读 SQL 可见性与 native COMMIT 完成指标交叉，采样偏移另记。

## CURRENT 原五条 HTTP500 lane

旧五 lane 合计 40 次 HTTP500（3+3+17+5+12）。原 QueryCounts `Layer::enabled` 全局 veto 屏蔽了 Gateway 的错误日志，原日志无法逐条追认内部原因，未删除任何失败 lane。

另建精确主线 `dfb6b7c2` 的诊断 fixture，仅修观察层；同 Rust 1.97.1/Release，依赖版本不升级、发送函数 AST 相同。1280 次输入复现 14 次 HTTP500，14 条路由错误均为 `pool timed out while waiting for an open connection`；未证明 SQLITE_BUSY。14 个失败均无持久 manifest/op dedupe/target，支持接纳前 pool 获取失败；具体 pool、调用点及连接占用者未被直接观测证明。不能把新复现强行当成旧 40 个请求逐条根因。主线未修改，本轮没有新 CURRENT/C32/C 架构排名。

## 历史与磁盘

两个 ignored native 历史实验在冻结 `10e59ec`/tests-final 各首跑 PASS（6.68s、23.87s）；补充物理 probe 首跑 PASS（0.63s）。最终19cc只改事务起始意图，不改 schema/行布局，故复用该量化并明确没有重跑。native SQLx SQLite3.46.0，Python补充3.54.0，不能混为同引擎。

默认生成 op46 的 compact identity 含表/索引实际426.435–429.425B/message；op16约363.643–366.510B，op128约610.099–611.656B。每条业务消息一条身份，fanout不倍增历史。正文共享一次，每目标另存。以下是30天算术外推，**不是30天实跑或生产接纳承诺**；GB=10^9B：

| 消息/秒 | 30天身份数 | 默认op46身份 GB |
|---:|---:|---:|
|1|2,592,000|1.105–1.113|
|64|165,888,000|70.740–71.236|
|128|331,776,000|141.481–142.473|
|256|663,552,000|282.962–284.946|

未ACK target 含全部索引实际884.3264B/target；合法fanout1/16/32补充probe分别864/903/897B，受engine/键宽/行数/page fill影响。Native10k target直接SQLseed只量物理行布局，超过单message公共API的32上限，绝非合法大单条发送吞吐。未完成正文另计一次（probe448B/1KiB/4KiB）；WAL、碎片、文件系统和运行余量另计。未ACK积压可能先触发既有pending容量拒绝，不能据表假设无限接纳。合法fanout各rate/7d、30d的target及body拆项外推见 `history/active-fanout-projections.csv`。

10k/100k/1m seeded history 的50次实际顺序查询/重复/新接纳+ACK：status p95为41/44/43µs，duplicate162/142/149µs，accept358/257/447µs；全部真实nativeACK后target/body=0，仍保留10,050/100,100/1,000,150身份。seed使用500条批次，不是1m生产HTTP接纳。对应checkpoint DB4,096,000/39,997,440/400,183,296B（seedop布局非默认op46）；这是本机短热测试，不等同历史深度下的持续网络吞吐。

维护40次COMMIT、每批最多256，删10k过期身份；p50/p95/max 908/2457/2942µs，累计40.132ms。物理DB仍400,183,296B，产生960freepages；TRUNCATE checkpoint令WAL0，不缩DB。六种op/顺序原位重插10k实际消费594–1451空闲页；顺序case文件零增长，randomcase仅8–40KiB页分布增长，证明复用而非宣称立即归还操作系统。没有VACUUM。详细表/原始收据在 `history/analysis.md`、`execution.json`、CSV；供审查的精简版本归档进 validation/c3，并见 [历史报告](c3-history.md)。
**本轮没有历史数量/字节硬配额，不提前淘汰 30 天身份，因此磁盘使用没有固定上限。** 不新增历史满额拒收策略；可选配额只作为后续明确取舍建议。

## 失败、保留与未运行

所有原 C32/C2 源码、二进制、失败 lane 和产物均保留。初次 Rust 编译的 DTO `Sync` 名称冲突、Apple A01 defaults 隔离/A02 BLOB recorder、Android APK collector/空 adb extra/readonly snapshot 后处理、Gateway restart 的 urllib logger、matched observer 缺 common.py 均保留首回执并区分为测试系统或构建问题；修复后的最终原生测试不覆盖这些历史。observer 启动失败没有启动 daemon/没有任何容量 lane；修复后全部配对使用同一新 prefix 和脚本。新增写锁测试首次long oracle误读target_status字段的失败也保留；更正status/absolute-expiry取值后82项通过。旧DB-block产品故障保留，修复后的9例另立身份，不替换旧记录。

独立审查曾误向C2 review原文件追加本轮后缀，随后仅移走自己的新增后缀，保留原19014字节前缀（现SHA5797f0b88c85ed7f4fb100783a60b3d9bdab1f322b1322eadb858ee3ca46f4ac）；没有独立的写前hash，不把恢复的前缀hash冒称预先冻结证明。本轮审查存入新OUT，并复核原CURRENT/C32/C2共4个冻结二进制hash均不变。

候选旧实验库不原地迁移，缺新 ownership/revision 列会显式拒绝；本轮全用独立合成库。SQLite 本身仍是唯一实现后端，编译依赖含 PG/MySQL 不等于新 C 已适配它们。

## 完成与剩余边界

普通FCM/APNs消息已具备 **本地SQLite隔离候选的现有客户端接入条件**：普通控制面、原凭据owner、本地实际候选、两平台生产存储与持久ACK/新进程恢复均闭环；无须为本轮另改客户端生产源码。原子接纳、稳定身份/时间/绝对TTL、30天历史及ACK释放保持。独立审查两轮未留下确定性缺陷。

仍不是完整主线替换/生产验收：Private数据面及其他类型、PG/MySQL适配和实迁移、真实Provider/Token Service、OS后台与物理Watch均未运行；生产Gateway app整体入口切换/发布也未做。最终负载是短Mock、128/256单次新版本回归，不能承诺可持续128/256；19cc相对10e的部分耗时差异及精确offer→COMMIT分位仍未隔离。超过3秒写锁仍可能fail-stop，需要外层重启恢复。portable复现适配只做语法/hash审核，没有借原执行结果声称已运行。

本轮没有新的待批准产品行为变化。未来若增加可选身份配额，应在新消息接纳事务中预留完整30天身份预算，满时显式拒绝；ACK不释放该历史预算，不能提前驱逐旧身份。取舍是降低合法新接纳率，且逻辑预算不能直接保证物理DB/WAL文件上限；需明确额外正文/目标/WAL余量。这里只建议，**本轮不实现新拒收策略**。

## 下一阶段

待本轮审查后，优先将已稳定的普通消息合同映射为 PG/MySQL 的事务、唯一键、索引、单进程误开保护和共同 oracle；包括 frozen receipt owner 与 Pull owner 分离、route_revision/generation、retirement epoch、ACK 释放和 30 天无配额历史。先验证新建库功能，再单列旧库迁移/回退，不能把空库通过当成升级通过。SQLite 的 CROSS JOIN 优化不能直接当作其他后端的计划证据。

其他消息类型随后按输入/指纹、不可变投影、目标展开 seam 逐项接入，不复制队列或恢复旧控制器。真实 Provider、物理后台、各库实迁移集中验证仍需独立验收。本轮不自动开始下一阶段。

## 本机证据根

`gateway/build/quality-results/c-client-loop-gate-20261015/`。重点收据：`baseline.json`、`build-final*.json`、`artifacts-profile-matched.json`、`independent-review.md`、`control-contract-evidence.md`、`apple/verified-final-receipt.json`、`android/c3-android-result.json`、`control-restart-final-01/result.json`、`current500/diagnosis-result.json`、`native-diag/actual-A128-conclusion.md`。完整容量为 `capacity-results-final.md`/`capacity-final-state.json`，历史为 `history/execution.json`/`analysis.md`；最终八仓/冻结二进制复核为 `primary-roots-and-frozen-binaries-final.json`，最终候选HEAD/工作区与停机身份为 `final-delivery.json`。主线始终dfb6b7c2；Apple/Android等八主仓HEAD和逐文件状态与起点一致，Windows既有修改未动。版本化source-only验证包不含日志/DB/bin/APK/生产源体，portable适配均标NOT RUN。
