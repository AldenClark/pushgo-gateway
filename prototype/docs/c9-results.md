# C9：空闲、单机升降负载与已撤回的最小 SQL 试验

本轮已完成测量、最小实验、按预设门槛撤回和最终受影响合同复验。保留既有按需执行与有界并发，不新增伸缩控制器。C9 不发布、推送、部署或扩展消息类型。外部证据根为 `/Users/ethan/Repo/PushGo/gateway/build/quality-results/c9-idle-scaling-20261016`（下文C9OUT）；普通编译源码在隔离 `workspace-final`，归档的observer源码不参与产品编译。

起点为 Gateway 隔离分支 `codex/gateway-c-ordinary-final-20261015` 的 `a17f605323ed1195439508df4146ab54e6aea4f0`，实际运行源码 `be3bc95c58500ee9913dbc2d9b442d5eb6a74227`。四个隔离起点为 Gateway a17、Warp `fded360134f2144876bb11b95e7431cb1d72aef3`、Android `574a4ec8fdb36ce282343c745b40ddfda5ad65ea`、Windows `55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7`。12仓库与59项冻结证据保全见 `audit/baseline.json`、`audit/frozen-preservation.json`；主线 dfb6b7c2 和 Windows 原有修改保留。

消息提交整个 JSON 保持49152字节，控制接口默认32768；Private帧与WELCOME保持131072，帧包括2字节type/flags、不包括TCP/QUIC4字节前缀。旧客户端硬切决定不变。本轮没有新的大小方案。

## Android 扫描修复

提交 `07b634739ec10fb67720eaabaaec02d26b3932ea`，独立工作树干净。`source_files()` 从检查绝对 `candidate.parts` 改成只检查 `candidate.relative_to(root).parts[:-1]`，从而不排除仓库祖先的 build/target 等目录。根以内生成目录仍排除。

断言、门禁、dispositions未放宽。修复前3方法/7失败（包括6祖先subtest和原current-repo gate）保留；修复后11 focused、250 selector通过，实际扫描恢复60 product/62 testreference IDs，没有新增未审差异。250是plan-only选择器测试，推荐pr产品lane、APK/JNI/设备没有运行，不能写成平台覆盖。AIhistory十任务校验READY。独立审查见 `review/c9-android-scanner-review.md`，运行汇总 `native/summary.json`。

## 测量配置与限制

Mac17,4/Apple M5、10核、32GiB、macOS27.0.1；Rust1.97.1，release opt3/fatLTO/cgu1/panicabort，locked/offline。MySQL8.4.11/InnoDB，现有获准隔离disk-backed volume、2CPU/1280MiB，buffer/redo64MiB，flush_log_at_trx_commit=1/sync_binlog=1，候选RC、3秒lock timeout。PG保持暂停，本轮不追历史25秒差异。设置不代替断电验收。

基线直接使用C8冻结正常fixture b771b79a… 和观察器 a77c754c…，不重建或替换冻结产物。be3到A的实际main/prototype源码及manifest/lock差异只有mysql_store和三个cfg(test)模块，见`audit/baseline-A-direct-source-delta.json`，没有把旧主工作树实现套进候选。观察器是be3加八个已证明、已恢复的观察覆盖。MySQL基线输出 `capacity/baseline-mysql-v2`，一进程两cycle，H32每Provider/Q32/8HTTP callers，正常Mock20ms、慢Provider500ms。每slow阶段只在发输入的8秒切500ms，随后恢复20ms排空；实际基线命中500ms为1421次、20ms为35299次（含16warmup）。同一时间切换下after命中数会随吞吐变化，是反馈混杂，不能把差异全归为SQL单因果。

每cycle依次：0.25msg/s×20s、4/s×5s、16/s×30s、256/s×2s，排空屏障，然后慢Provider16/s×8s、恢复20ms并排空/ACK/120s回落。同进程两次各1145消息×16=18320目标，另四条精确49152字节请求×16=64目标；共2294消息/36704正式目标，另16个warmup事件单独排除。每cycle从首次实际offer起190秒，屏障和输入阶段不重置截止。

旧v1的16/s阶段仅5秒，执行前改为30秒以看积压斜率；v1从未MySQL执行且原计划/收据保留。新v2输入SHA74a6d630…、最终driver9f9dd7c…；input5、业务归约6、实际sampler虚拟时钟1检查通过。sampler旧版host24次/harness0次的失败保留，修复为独立host+5s/harness+1s，不改变业务输入。

Gateway与数据库分别采OS指标。后核天然STATS发现SQLite idle尾约159秒与MySQL baseline进程重叠，包含MySQL coldidle及首cycle约35秒；各PID计量独立，但不是全host完全排他对照（`audit/measurement-coactivity-note.json`）。after没有该同测负担，且engine缓存/前置合同测试历史并未清空；这些和实际500ms命中反馈都限制SQL单因果归因，不额外清缓存、删证据或刷跑。HTTP callers、producer、Mock/TokenService仍同一Python PID：其RSS/OS CPU为合并值，不假拆分；method thread_time为局部CPU下界。Mock方法CPU5.284秒已包含在harness总CPU内，不能相加。采样子进程CPU未完整测得。记录offer lag、入口等待和8caller在途，排队不直接叫CPU饱和。1Hz fixture STATS及观察负担均包括在测量内。观察构建另有固定4096×96字节回调queue与64KiB单writer；这些是测量开销，不是正常产品新增的结果缓存。root另在非业务idle核验exact PID/binary后采少量vmmap-summary，非payload/对象内存dump；不会把全虚拟或共享映射总量叫Gateway物理内存。

## SQLite 最小被测配置

空SQLite、Private关闭、无HTTP业务、嵌入式数据库；不是完整主线或全功能绝对最小值。1260秒观察，采样跨度1258.993324秒，Gateway CPU2.452345708秒，平均约单核0.194786%。RSS首12795904、末13385728字节；malloc live1157840→673776，reserved20971520→29360128，tasks始终5；owned/network/receipts/http均零。空数据库155648字节，日志、采样器、二进制另计。

Provider即时quiesce，没有池idle计时器；MySQL/PG固定数据库连接直到关闭。SQLite SQLx idle600/maxlife1800/reaper600、min=max1。1260覆盖两次reaper边界；600附近无SQL计数变化，1200.002仅自然PRAGMA+1，其余sql_operations17/claim2不变。0HTTP和0SQL观察查询不意味着自然SQL为零，不从RSS或PRAGMA推断连接close/reopen；1800寿命轮换未覆盖。没有空队列周期SQL清理器，维护在打开/接纳/claim等路径触发，不能把物理过期清理描述成固定时刻已执行。

SQLite空闲尾段存在上文coactivity，0HTTP/SQL观察不代表整机无其他进程负载。

harness自身CPU6.627960292秒、约单核0.526449%，采样子进程CPU未测。原始数据/分窗口/VM口径详见 `capacity/baseline-sqlite-cold-idle/sqlite-idle-resource-summary.{json,md}`；流式归约源码与9输入哈希已核。不从21分钟推出任意长期无泄漏。

## MySQL 基线

整体writer join后36720原事件减16warmup=36704正式目标，全部accepted；late/unknown/unfinished=0，wire/Pull/ACK验证通过，exit0/quiet。主延迟从offer到目标COMMIT返回后的精确Mach回调，不是客户端持久化；不按已完成样本缩小分母。

| 场景 | 正式目标 | p95 | p99 |
|---|---:|---:|---:|
| cycle0 | 18320 | 29.9793s | 31.9584s |
| cycle1 | 18320 | 35.0788s | 37.0931s |
| 48KiB内容cohort | 64 | 119.283ms | 124.705ms |

30秒16msg/s阶段内只提交5674/6065目标（189.13/202.17 targets/s），末offered-minus-COMMIT积压2006/1615，不能称持续256targets/s。突发末offer后排空32.526/37.574秒。这里输入offer速率不是Gateway接纳速率：burst两秒内512个offer只有147/138个HTTP成功响应，ramp16的480个offer有411/479个响应；其余继续在后续完成。压测端8caller上限形成外部队列，峰queued414（不含8在途）、最老排队6.106秒。端到端延迟包含该等待，不能全归为服务端排队，也未测128入口的最大接纳能力。offered-minus-COMMIT不等于SQL durable backlog；稀疏样本实际只采到durable1950、最老6.474秒，下界不是连续精确峰。两周期已有明显自然波动；未完成任意长稳态容量证明。其余实际速率、阶段/滚动窗口与延迟定义在 `baseline-offline-summary.json`、`rates-1s-rolling5.jsonl`。

receipt interior samples18205/18214（非整窗18320），gatehold51.876/55.442秒、COMMIT30.021/33.114秒、SQL-inclusive15.900/16.051秒；Usage四SQL bundle6.382/6.477秒，约40% SQL/12% gatehold。pool acquire2.900/3.216秒、BEGIN1.384/1.391秒。其gatehold大于accept10.717/8.640秒和claim14.632/14.603秒；claim的pool acquire41.667/33.601秒属于重要caller等待，不能加成gatehold。gatewait1500.883/1520.043是并发累计，不是墙钟；相互嵌套时长不能相加。COMMIT等待包含网络/数据库服务，不独断为物理fsync。

Gateway全观察CPU21.086秒、峰RSS25018368字节，postcycle0/1 RSS23871488/23986176，malloc live均1297088、reserved均33554432。root vmmap两次回落zoneSIZE均33.2M/live约1073K，resident12.0→12.1M、fragment9599→9711K，物理footprint12.3→11.9M（工具rounded单位，不能与RSS相加）。支持allocator保留而非两周期live对象不断累积的解释，非长期或逐对象证明。

实际1Hz任务峰77，全局峰值owned64/network64/receipts62、per-provider reservation各32、HTTP8；1Hz样本峰不是连续精确峰。数据库连接只在边界采到case2（Gateway1+observer1）、server3，连续峰未测。逐阶段计数/offerlag/oldest/backlog详见`stage-gauges-and-activity.{json,md}`；provider_targets不是实际worker数。

同Python harness全观察CPU40.623秒、峰RSS329203712字节，含Mock、HTTP callers及保留结果。数据库cgroup边界CPU63.625秒还含exec观察；mysqld、cgroup匿名/文件cache分别记录，不冒充每连接成本。详见 `component-metadata-summary.json`。

## 唯一最小试验：未达到保留门槛，已撤回

基线主限制仍是串行receipt/COMMIT。仅试MySQL reconcile两个读合成一个相关scalar SELECT，四SQL到三SQL；不改锁、事务/两UPDATE顺序、COMMIT次数、H32、ACK或身份。不跳DELETE：ACK可能先标记running，必须由receipt补删除。真正批receipt没有现成ready seam，会侵入attempt/取消/预算，故本轮不实施。

前置保留条件已经在看到新结果前确定：正确性/预算不退化、两个周期同方向，目标提交/排空/尾延迟收益须超过baseline周期自然差异且CPU/idle无代价；只有少一个SQL不算成功。最多一个baseline和一个同输入after，不因不显著重试刷分。若无可区分收益，撤回A。

测试guard独立提交 `cfd66fdf4f6cb1323e912c9132981cccd749896a`；A独立提交`1b9836a3a1c98d0c6a8e7a7559ea9676c0027c9a`。普通及Private新C9库/role严格独立，C7/C8 registry不改。A正常fixture SHA9b2fdc888800d8584f2d96664efe7dc2e202c43f80405a0b33a789ab6577a86a，test SHA9cdff4e83b02d5f52e573c6606f9a0df7cedf949843ada19ce1375f371381d25。115默认、1普通MySQL原生/故障聚合、1Private聚合通过；第一次原生过滤器少父模块选0项，保留为未执行并用正确全名运行，不冒充通过。A观察二进制SHA07da4d7f419d1620ddcba001be90db9865607dfb7f23815f5e19106f919ff94c；exact1b加8sparse覆盖构建，82源码/测试输入及6原文件bytes/modes恢复、2新增删除，normal/test哈希不变，proof见`capacity/final-1b9836a-observer`。

相同v2的A同样36704/36704正式目标在窗口内COMMIT，HTTP2294/2294、late/unknown/unfinished均0，wire/Pull/ACK/quiet通过。

| 指标 | 保留的基线cycle0/1 | 已撤回A cycle0/1 |
|---|---:|---:|
| offer→COMMIT p95 | 29.9793/35.0788s | 26.5979/34.4405s |
| offer→COMMIT p99 | 31.9584/37.0931s | 36.7225/36.4409s |
| 首offer→末COMMIT | 104.7915/107.7830s | 109.2654/107.1444s |
| burst末offer→排空 | 32.5263/37.5739s | 37.2106/36.9072s |

A的48KiB cohort p95/p99=115.585/122.421ms（64目标）。Gateway CPU21.086→19.683秒、峰RSS25.018→24.871MB，仅为观察值；降低CPU不弥补cycle0尾延迟退化，也不是因果证明。A实际500ms命中1971次、基线1421次；慢输入切换相同不代表每个目标的下游延迟完全相同。after Performance_schema_digest_lost边界增加93306（baseline0），不能用缺失digest或SQLx bundle次数冒充engine真实SQL总量。Usage bundle按源码分别4/3SQL，samples本身仍为调用次数。详细原样指标与边界在`capacity/c9-before-after-comparison.{json,md}`。

A未通过预承诺门槛，已用`07634d20357f506f167ca4026ce0cd9337dfaa9e`单独revert，实验提交和全部产物保留，未跑第三轮。最终normal重新构建的SHA **b771b79a93b24025a037ca61c7056ea5a743ba52627a417dbee7f90d9d9efe44** 与C8冻结be3 normal逐字节相同；正常编译源码与be3只差两个cfg(test) guard模块，见`audit/final-normal-source-equivalence.json`和`tests/final-07634d2-normal-build.json`。因此最终运行时继续采用本轮baseline测量，不能把A数据包装成最终候选收益。

本轮保留Android scanner最小修复和测试授权guard/重现资料，没有保留新Gateway运行时优化、控制器、批队列或缓存。保留既有按需future与有界并发：实际网络/owned随流量0→64→0，回落task5，不预建32worker。串行receipt/COMMIT仍是下一次有明确更高容量需求时需评审的主要路径；本轮不以牺牲事务边界换分。撤回后的最终test binary SHA **b1e0acd651ddc99c6d30884705dc6593a6c5a5843172a93725e1cd3f13936882**；在该二进制上重跑115默认、1 MySQL普通/原生故障聚合、1 Private聚合均通过（8.83/11.85/2.60秒）。新Private使用独立新库/role，前次非空证据不重置；native factory仍为空，每次创建新UUID子库并仅自行清理本次子库。见`tests/final-07634d2-correctness.json`。

内存由入口和在途预算约束，积压主要落SQL：默认128 HTTP连接/任务、128请求、每H2连接1stream；control16工作permit满时在总请求预算内等待，连接满暂停accept、总request满503。Provider每类H32，FCM/APNs两pump，先reserve再claim，receipt COMMIT返回前不释放；backoff落DB而不占实际执行位置。Private本轮关闭，其8192连接/session嵌套门、8192命令queue、4096共享work slots、每device96窗口均为源码边界而非本轮压满实测。Provider owner在empty claim且实际工作清空时quiesce；停机取消未完成attempt并以durable running供恢复，不能描述成每条都已成功COMMIT。完整文件行号/拒绝与等待区别见`audit/c9-final-resource-boundaries.md`。持续过载时10,000未完成消息/1,000,000 pending目标（含Private）等既有接纳容量原子拒绝，实际拒绝边界以现有合同测试和配置为准，本轮输入未打满该容量。30天身份是保留期限，没有数量/字节硬配额；正文一份、目标随fanout和ACK/TTL增长，ACK逻辑删除后可复用页、物理文件、WAL/binlog/undo要分开。历史计量证据不改称C9长时间实跑。

发布前保留Windows OS、客户端QUIC/WSS、真实APNs、物理Watch、旧库迁移和断电待办。本轮不新做跨平台全面验证，不进入新消息类型。

## 通过、失败与未运行范围

保留sampler首次deadline饥饿失败、SQLite离线归约首次UTF-8错误、native首个精确过滤0项记录；这些不是Gateway产品失败，也未静默删lane。v1计划从未执行。C9未新跑PG、Android APK/JNI、Windows host/OS或真实客户端网络闭环；扫描门禁修复不能代替这些结论。C8客户端与三库证据只按原产物/范围引用。历史C4早期写锁超时、旧CURRENT HTTP500未逐项追认和PG约25秒差异保留原未决含义，不因本轮无新错误归为已解决。

整个过程先守4GiB加增长预算，未删除历史证据或用户数据；MySQL沿用精确获准隔离disk-backed volume与新库/角色，PG始终暂停。最终环境quiet，MySQL已恢复PAUSED、PG始终PAUSED；暂停前client/transaction/userlock/native子库均0，历史数据与权限不变，host余17.75GB、guest最后暂停前16.78GB，见`env/final-quiet-environment-restored.json`。12仓库、59冻结证据复核收据列入外部 `delivery/final-delivery.json`；完整提交及最终状态也由该收据绑定，避免文档自引用自己的未来commit。

A两smallcycle回落live均1,297,056B、reserved41,943,040B，RSS23,658,496/23,838,720B；大消息后live1,444,512B，比smallcycle增加147,456B，不能把这部分当作纯虚拟reserve。它与连接/编码缓冲保留相容但未逐对象归因；不称完全释放或泄漏已证明。基线vmmap明确显示大部分RSS残留是低live和高zone碎片/驻留，结论只覆盖有限两cycle。

## 交付与判断

| 仓库/阶段 | 准确提交 | 结果 |
|---|---|---|
| Gateway C8起点 | a17f605323ed1195439508df4146ab54e6aea4f0 | 不重复提交 |
| C9隔离测试guard | cfd66fdf4f6cb1323e912c9132981cccd749896a | 保留，cfg(test) |
| A试验 | 1b9836a3a1c98d0c6a8e7a7559ea9676c0027c9a | 正确性通过，收益门槛未通过 |
| A撤回/最终构建源码 | 07634d20357f506f167ca4026ce0cd9337dfaa9e | normal与be3逐字节相同 |
| C9重现资料归档 | 0b251858d7ee9cbfed9eaf626c3b6f5264b1f7c5 | 58原字节源码＋README/清单，60文件 |
| Android scanner | 07b634739ec10fb67720eaabaaec02d26b3932ea | 仅scanner/对应测试与说明 |
| Warp | fded360134f2144876bb11b95e7431cb1d72aef3 | C9未改，依赖锁定不变 |
| Windows | 55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7 | C9未改/未新构建 |

Gateway仍在`codex/gateway-c-ordinary-final-20261015`；归档/说明提交另见最终交付索引。源码归档以`prototype/validation/c9/README.md`及manifest为入口，保留实际v2、未执行v1、失败前源码、归约与observer构建/恢复材料；不提交原始日志、数据库、二进制、URL文件、凭据、授权state或lease token。外部二进制/报告/收据保留准确SHA，不拿可变target当测试产物。

普通SQLite/Private协议回归在115默认中通过；MySQL实际新库普通/故障与Private聚合最终通过。容量两arm各2294消息/36704正式目标全部完成，未以失败或未完成删分母。本轮的wire/Pull/ACK来自harness与Rust合同路径，**不是**本轮Android Room/Keystore、Apple GRDB或Windows真实系统客户端闭环；C8这些结果只保留原版本与实际范围。

最小被测配置是Private关闭的空SQLite候选，RSS约12.8–13.4MB、平均约单核0.195%、常驻5个Tokio task、空DB155648B，另计二进制/日志/观察器；不是全功能或Private连接上限下的容量承诺。MySQL需要另计现有engine约0.47–0.49GB进程RSS及文件缓存，不能把它摊成Gateway常驻开销或每连接成本。

本环境已见256目标/秒的30秒阶段积压，实际窗口提交189–202目标/秒；更低流量和有限突发能排空，不等于标定了长期稳态容量。offer端8caller队列、数据库durable队列和结果提交等待均分列。当前主要串行成本是receipt/COMMIT，H32加大或恢复复杂controller没有本轮证据支持。过载内存由入口、工作和提交预算约束，业务积压落盘并受现有接纳容量拒绝；本轮未压满10k/1M，也未用有限8秒下游慢测试冒充无限期过载实跑。磁盘仍无history数量/字节硬quota；计划容量须计30天身份、正文与fanout target/index、WAL/binlog/undo和页复用/文件保留、增长余量。

两smallcycle后已释放实际工作、网络、receipt和Provider client owner，任务回落；保留的有allocator驻留/碎片、固定运行时/SQL连接和DB缓存。malloc live两cycle稳定不等于完全无活对象，large后147456B额外live未逐对象归因。内存结论限定于这两个周期和21分钟idle，1800秒连接寿命轮换、长时间history增长/清理及任意长期泄漏未在本轮重做。

A不值得在当前证据下保留；本轮改进在于修复真实扫描问题并形成可复核的资源/容量边界，运行时保持简单。后续若需求明确超过本次有限容量，再单独评审receipt提交减少往返/批处理的原子性、尾延迟与预算代价。本轮到此停止等待审阅，不自动开始新消息类型或下一轮。
