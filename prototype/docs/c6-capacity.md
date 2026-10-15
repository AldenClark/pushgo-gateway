# C6 有限容量：固定原190秒窗口，完整40960目标分母

这是本地20ms Mock 的10秒突发与排空测试，不是持续生产容量、客户端持久化延迟或新的190秒产品SLA。Provider入站接纳和逐目标结果 COMMIT 是不同事件。Private 默认关闭的原 C5 输入用于定位普通 Provider 瓶颈；不能从本页推论 Private 高负载吞吐。

证据根：`gateway/build/quality-results/c6-private-capacity-20261015/`。所有原失败保留，未拼接旧 B、CURRENT/C32 或不同编译配置形成新排名。

## 瓶颈的可证伪诊断

C5 原始失败不变：2560消息×16目标=40960；190秒只完成7169，33791未完成，HTTP2560 accepted不等于完成。C5五列 due 索引存在仍不能强迫优化器使用它。真实 SQLx owner 会话的最小增长/新建大表对照均复现 devices→targets_device 或 messages-first 的扫描、临时表与排序；同连接 literal 也慢，不能归因给 SQLx binding 或仅归因 prepare 时表为空。

`mysql-diagnosis/causal-handoff.md`、`sqlx-contrast-final.json` 将精确 THREAD_ID/EVENT_ID 与每条实际 prepared 执行关联。两条 pending Provider 原查询分别 examined60385/60393、33.613/43.273ms；固定访问路径后各examined3、0.055/0.059ms，无temp/sort，返回tuple相同。到期、退休owner、退休token、empty-pending等累积反例同样核验（fixed最多19 examined）。它只证明该访问路径原因，不是完整吞吐结论。

第一项性能产品修复是原生 `SELECT STRAIGHT_JOIN ... targets FORCE INDEX(targets_due)`，沿既有 `(provider,state,next_attempt_at,delivery_id,device_key)` 顺序读取；资格过滤、退休epoch、排序、LIMIT、绑定及事务边界不变。没有提高H32/连接池、拆接纳事务、提前释放receipt预算、批量确认或动态控制器。

早期完整 pair 的新候选在原 MySQL tmpfs 用尽时失败：native COMMIT长时间PREPARED、同thread94在精确时刻报binlog errno28，datadir768MiB Avail0；row locks均granted、无wait edge、redo已flush，排除当时的row-lock阻塞及仅Rust调度自等待。claim_select此前1870完成调用总0.230s，说明那个平台停顿有独立的存储原因。该lane仍是FAILED，只有666个非warmup回调下界，无最终observer flush，不能出版总体p95/p99。原未知COMMIT/DROP在容器停止后未追认为成功；逻辑导出不等于物理crash备份。

## 可比条件、时间和计数

- 固定256消息/s×10s、2560消息、8 FCM+8 APNs设备、fanout16、body1024字节、8 HTTP callers、单Provider20ms Mock、每Provider H32/Q32。HTTP输入/超时/190秒绝对截止未降低或延长。
- Rust1.97.1 release/fatLTO/codegen1/offline/locked；旧observer `52731d4a…`，e3+同callback observer `2616e3fd…`，后续9fc观察器 `3dcceddb…`。后两者另有Private实现，但本负载默认关闭，不能宣传完整替换收益或Private容量。
- MySQL8.4.11/InnoDB、READ COMMITTED、单pinned连接；PG16.14、READ COMMITTED。隔离容器各2CPU/1280MiB；功能/早期容量用768MiB tmpfs，后续MySQL容量另在专属磁盘卷重建同介质对照。MySQL buffer pool64MiB/redo64MiB/maxconn60，binlog与flush/sync均1，trigger测试trust1。PG shared_buffers32MiB/maxconn60/maxWAL128MiB，fsync/full_page_writes/synchronous_commit均on。不是物理磁盘/断电环境。
- C6 P_S与pg_stat_statements/IO timing开启，和旧C5原环境不同；新两MySQL arms使用同一设置。服务器已有合成历史/cache，不是冷数据库。每arm外先保全旧统计再重置instrumentation，原业务/失败不动；无业务连接后做精确测试库归档/回收，closed binlog完整复制0600并SHA后才PURGE，耐久/资源不变。不会为了放下两lane累计存储而扩大tmpfs。
- 每条expected target保留实际offer的Mach时间；receipt事务成功返回后同步callback，减去该offer时间计算端到端。完整分母包含HTTP未开始/失败/超时、未持久化、非成功与未完成，不只筛成功样本。消息ID/目标/Provider/body独立SQL与捕获见证，丢事件/写错误/晚于cutoff单列。
- `submitted-started`/producer queue是尚未开始HTTP的消息，不含活跃HTTP（另有≤8）。网络时间包含凭据owner、HTTP及回复解析，不等于纯20ms RTT；receipt时间包含gate/连接/SQL/COMMIT。各并发wait总秒不能相加成wall；log2 histogram只给桶界，不是精确分位数。claim路径pool_acquire还含发送前授权检查，不能直接同PG mutex数字等同。
- 30秒pre-offer idle位于setup及ACK过warmup后；成功后ACK并再30秒idle。此间无Gateway HTTP/SQL观察调用，但fixture原1Hz heartbeat计入CPU/wake。目标全COMMIT后、ACK前可作一次有界prepared-instance后置计数，独立标记其时间/覆盖，不能算作目标完成时间。

## 正式原C5对照：仍失败

`capacity/matched-final-pair/run-mysql-old/` 一次、无重试。与C5原7169分开保留，不能升级原失败。

| 指标 | 同环境旧527对照 |
| --- | ---: |
| offered / HTTP accepted消息 | 2560 / 2560 |
| offered targets / cutoff内COMMIT成功 | 40960 / 7745 |
| 未完成 | 33215（33164 pending+51 running，全部durable） |
| HTTP错误 / 未开始HTTP | 0 / 0 |
| exact events（含warmup16）/drop/write-error/late-censored | 7761 / 0 / 0 / 0 |
| 总体p95/p99 | 不可识别；81.09%未完成，不能只挑成功样本 |
| 仅18.91%成功目标的条件p95/p99 | 171692.178 / 184792.292 ms |
| 入HTTP前排队p95/p99 | 130988.460 / 141547.222 ms |
| 全部HTTP接纳最后响应 / 最后窗口内目标callback | 首实际offer后156.088 / 189.513 s（后者非排空） |
| Gateway pre-idle最后 / burst峰值RSS | 14794752 / 18644992 bytes |
| Gateway pre-idle CPU（一核均值） | 0.153% / 30.019 s |
| Gateway独立CPU窗口 | offer→全部HTTP完成156.097s，5.076CPU秒（3.252%一核）；不冒充全190s |
| DB主进程RSS峰值 | 495652864 bytes，含既有case/cache/P_S；不是逐连接成本 |
| post-ACK回落 | 无，该lane未排空/未ACK |

保守189.002s STATS内窗只含7669个receipt delta，不能冒充7745 exact全run：claim_select155.680s、claim gate_hold160.848s；receipt hold18.490s、wait3043.635s（并发累计）。接纳自身持锁9.168s，fanout count/insert标签总约1.420s，receipt COMMIT约1.221s。第一瓶颈是claim选取持锁的数据库工作，而不是20ms Provider RTT、原子fanout或提高H32即可解决的问题。

schema-scoped P_S digest没有生产prepared claim/receipt DML，即使lost累计0也不能猜出它们的扫描/返回/影响/表锁。其中1409088 examined来自47次observer target-state查询，**不是claim**。whole-server row-lock time/waits差分均0只覆盖这些计数，不能证明不存在任何类型等待。完整SQLx gate/hold/connection/begin/SQL-inclusive/COMMIT及fixed标签样本见`profile-interior-summary.json`；少数标签覆盖SQL bundle，不冒充引擎单语句总数。

## e3 的768MiB tmpfs完整输入：存储耗尽失败，不能宣称容量通过

`capacity/matched-final-pair/run-mysql-final/` 保留原190秒FAIL。HTTP2560全部接纳，首offer后约30秒已完成入口；SQL状态停在32030 accepted+8895 pending+35 running=40960 durable。`10:05:12.575 UTC`首次plateau后没有进展；receipt BEGIN/全部SQL计时比COMMIT多1。fixture只在测试要求停机后quiescence超时退出70，不证明生产运行会自动检测永不返回的COMMIT。

独立 `env/fresh2/formal-final-first-failure/` 将线程536/P_S664、COMMIT1090322、`10:05:12.328 UTC`的binlog errno28、datadir805306368/805306368 bytes满盘绑定。binlog003为502509568 bytes；redo已flush，无行锁wait edge、OOM=0。该失败与前次独立证明相同存储机制，但没有根据前次直接归因；两次各有原生证据。

最终observer未正常flush/telemetry缺失，原始记录仅能给出31356个非warmup成功下界，不能发布精确总体分位数或用退出后RSS0冒充回落。Gateway峰值RSS19562496 bytes，无post-ACK窗口；old/final累计digest lost均0仍不能补上缺失prepared执行指标。全量完成后的prepared计数hook未触发，记UNAVAILABLE。

`env/fresh2/formal-final-retained/` 保留11表逻辑导出（counts前后稳定、gzip CRC/SHA通过）及live/incomplete binlog原始副本。它不是closed log、crash-consistent备份或未知COMMIT的最终判定。固定768MiB tmpfs连同数据库文件无法容纳此次完整binlog；放大tmpfs又会逼近既有1280MiB内存上限。因此后续使用专属空磁盘卷为旧/新两侧重新建立相同介质的对照，保留CPU/RAM/池/H32/耐久和190秒输入；不将本节与磁盘新结果直接计算架构收益。

充分存储环境后续已执行，结果如下；不能由最小SQL诊断外推。C4旧写锁/高负载差异与C5 PG约25秒差异分别保留未决，没有新的因果对照就不解释成已解决。

## 专属磁盘卷：旧 C5 与 e3 都保留为 FAIL

`capacity/matched-disk3-pair/` 两侧使用同一新 MySQL8.4.11 容器、独占有标签的 named volume `/dev/vdb1` btrfs；不是 tmpfs。CPU/RAM/池/P_S/buffer/redo/flush1/sync_binlog1/binlog1、Rust编译与原40960目标/190秒输入保持不变。host/VM均用OS优先的实际字节预算核验；Btrfs inode计数0/0记UNAVAILABLE，不假装为耗尽或编造可用数量。精确UUID/镜像/挂载/命令见`env/fresh3/environment-receipt.json`。两侧依次执行、有共享server/cache历史，不是两个完全冷实例；不与前文tmpfs数字计算介质无关的架构收益。

| 指标 | frozen C5 old527 | e3 final2616 |
| --- | ---: | ---: |
| offered消息 / 目标 | 2560 / 40960 | 2560 / 40960 |
| HTTP accepted / timeout / 未开始 | 2184 / 8 / 368 | 2560 / 0 / 0 |
| 有成功callback时点的窗口内目标 | 5826 | 31603 |
| 完整分母内未确认完成 | 35134 | 9357（含1个timing_unknown） |
| 事后SQL目标：accepted / pending / running | 5827 / 29183 / 62 | 31604 / 9302 / 54 |
| 无durable目标行 | 5888 | 0 |
| 总体p95/p99 | 不可识别 | 不可识别 |
| 仅已观察成功条件p95/p99 ms | 169470.964 / 185938.603 | 175307.560 / 180957.750 |
| 退出 / clean shutdown | 0 / true | 0 / true |
| 运行后有效空闲字节 | 5553090560 | 4792684544 |

旧侧8个HTTPtimeout的op逐一与独立SQL identity见证对应：每个均有完整16目标，共128 durable targets；HTTP超时不能推断回滚，事后见证也不能定位接纳COMMIT在cutoff哪侧。1个已知晚callback被明确censor。e3侧writer joined、drop0/writeerror0，但有1个SQL accepted目标没有成功await callback tick；原strict reducer拒绝收据完整保留。另存派生结果仅把该目标标`timing_unknown`并纳未完成，既不造时间也不称已知late。派生完整分母审计通过不等于容量通过。两侧均未排空，因此没有post-ACK回落或可持续吞吐结论。

e3的187.998s保守STATS内窗只含31199 receipt delta：接纳gate持有18.199s、claim38.718s、receipt130.909s，合187.827s，支持共享gate被持续占用。receipt SQL-inclusive53.192s、COMMIT66.848s（31199个，均值2142.6µs）、BEGIN2.485s、acquire5.327s；Usage helper 93596次/32.373s是三次四SQL bundle的累计墙时，不能当成单语句时间。claim next_due15.205s/2927，select5.669s/46846。receipt gatewait4737.856s与claim337.292s为并发累计，不能相加成wall。owner/acquire含mutex与必要IS_USED_LOCK检查，不直接等价连接池等待。Gateway近190s窗口17.11CPU秒/189.859s≈9.012%一核；DB排空内段47粗CPU秒/129.058s≈36.42%，端点量化误差±2秒，非整个190s CPU。

这次未发现盘满，下一项热点是已经测到的receipt重复SQL和next_due积压扫描。源审计证明同Tx receipt body18条SQL中9条重复，删除后仍由原最后reconcile/refresh及COMMIT维护结果；无batch、提前释放预算或扩大H32。独立只读next_due诊断在4662个FCM pending上，原MIN examined4662、新two-range examined1，值相同；SQL PREPARE服务端3.166→0.154ms。最初小写`fcm`导致空集的探针保留并排除，SQL PREPARE不代替SQLx binary protocol。`9fc812b`另加原生SQLx oracle，最终执行和全输入收益必须另给实证。

最终修复重跑前保全两个失败库的全表计数/逻辑导出与关闭binlog000001/000002（源、压缩流、解压后尺寸/SHA/CRC均核验），只执行一次`PURGE ... TO 'binlog.000003'`；当前000003及失败库原表完整保留，未RESET、DROP或改耐久参数。Provider首个4GiB空间预检STOP仍是原失败，之后客户端复验通过且captured模拟器退出。最终容量preflight有效空闲5088731136 bytes，636条P_S数字统计先保全再唯一digest reset，原业务数据未动。该准备的两次reset前观察器错误（SHOW COLUMNS误加LIMIT、BusyBox timeout不接受GNU参数）保留，修正语法不延长5秒观察期限。

VM文件系统报告总容量曾由9395240960变为8589934592 bytes，记录了实际快照，没有执行文件系统/cgroup扩容，也没有证据归因该平台变化。主机与VM可用空间相关、同server/cache历史及宿主其他活动均限制精确架构归因；统计开启和不同介质结果不混算。

## 9fc首次最终源码输入：目标窗口全部完成，整条runner仍FAIL

`capacity/final-9fc812b/run-mysql-final/`直接使用未改的冻结v4入口，observer `3dcceddb…`、正常源码9fc；没有新adapter、扩大预算或改负载。原严格二进制事件归约通过：40976事件含16 warmup，40960个目标全部有原cutoff内的成功COMMIT回调，drop/write-error/late/timing_unknown均0、writer已join。完整分母的p95=173417.486ms、p99=178360.159ms；最后callback距首实际offer189592.254ms，按原计划Mach cutoff计算仅余400.887ms。HTTP2560全accepted、0错误，最后接纳距首实际offer51724.303ms；不能据此称持续256消息/s。

原runner在最后全量identity witness跨越截止时FAIL，原首错没有覆盖。退出后独立SQL见证40960 provider_accepted/0 nonterminal不反向赋予完成时间；时间结论来自原回调。三个独立结果是：**目标COMMIT窗口PASS；identity-witness deadline FAIL；退出后resource STOP/no-next**。只有约0.4秒余量的一次结果不证明稳定容量或新的SLA。

188.001s STATS保守内窗含40577个receipt：receipt gatehold141.623s，其中COMMIT87.899s、SQL-inclusive39.019s、acquire7.608s、BEGIN3.240s，唯一保留Usage bundle14.954s；claim gatehold28.617s、SQL18.090s、COMMIT7.001s、next_due1.011s/3807次、claim_select7.358s/60821次；accept hold17.575s，三类hold合187.815s。该样本不是40960全run账本；相比e3的不同数量内窗须先按样本数归一，不直接把累计秒作优化百分比。重复SQL和next_due扫描成本下降后，单次持久receipt COMMIT是最大已观察成本，共享gate仍持续占用。

Gateway冷idle30.019s CPU约0.138%单核，68 interrupt/32 package wakes；近完整189.667s窗口CPU16.42s，约8.657%单核，live RSS峰20398080 bytes。没有进入ACK/post-ACK阶段，因此没有本lane的回落RSS、空闲连接或堆存活归因；退出RSS0不算回落。post-completion prepared hook未触发，after statement capture因资源守卫停止，不用缺失digest假造生产SQL扫描量。

退出后预算guest4299182080/host3979898880 bytes，有效值低于4GiB而STOP，SQL inventory未尝试。没有满盘/errno28证据，不把它归为ENOSPC。后续仅清理隔离target中8个无open handle/无编译者的可重建rlib中间文件，646649408逻辑字节；所有冻结产物/报告/原失败保持，实际可用空间另由新OS预算确认。这不改变本lane的resource STOP。

## 同源码重复：目标、身份、ACK与空闲阶段通过，退出后资源守卫仍STOP

`capacity/final-9fc812b/run-mysql-repeat-v6/`使用同9fc/3dcc、同输入和新空case。v6只修正验证边界：原190秒前聚合必须已全accepted，才记录`SQLaggregate_complete_before_cutoff`并进入独立总计最多10秒身份观察；暖机、输入、SQL单次上界、资格、wire/身份/attempts断言及ACK均不变。完整callback仍按原Mach cutoff严格归约，晚/未知/缺失会使结果失败。20个纯AST/假clock边界oracle及独立源码审查通过，原v4和它的FAIL不改。这不是延长投递窗口。

| 指标 | 9fc同源码repeat / v6观察器 |
| --- | ---: |
| offered / HTTP accepted消息 | 2560 / 2560 |
| offered / cutoff内COMMIT目标 | 40960 / 40960 |
| 剩余/晚/未知/丢事件/写错误 | 0 / 0 / 0 / 0 / 0 |
| 完整分母p95 / p99 | 163267.066 / 168011.156 ms |
| 首实际offer→最后目标callback | 179239.220 ms |
| 计划10秒输入结束→最后callback | 169239.220 ms |
| 原runner / clean shutdown | exit0、failure=None / true |
| 身份、wire、Pull/ACK、postACK30秒 | 均通过 |
| 冷idle RSS / 业务峰 / ACK峰 | 15646720 / 20299776 / 23314432 bytes |
| postACK30.049s RSS | 恒23314432 bytes，没有回冷启动水平 |
| 冷idle / postACK CPU（单核） | 0.164634% / 0.129719% |
| 冷 / postACK interrupt、package wakes | 66、30 / 69、28 |
| 内核CPU窗口 | 16.400782 CPU秒 / 179.974128s，约9.113%单核；包含身份验证，并非exact最后callback终点 |
| DB连接边界 | case2含observer1，即Gateway pinned1；全server3。是边界值，不是峰值。 |

Provider reservation峰每Provider32，总owned/receipt峰64，实际Provider网络wrapper峰55；producer到Gateway的活跃HTTP和Gateway HTTP连接峰均8。最后owned/receipt/network/targets/reservation及HTTP连接均0。fixture仍有5个后台任务、num_alive=2，不能写成所有对象都已释放。没有heap/分配器或堆对象因果测量，因此RSS残留的具体来源仍**未归因**；连接边界和预算归零只是资源证据，不足以证明分配器保留或泄漏。

MySQL PID1采样RSS峰496664576、postACK idle493707264 bytes，含此前测试历史、buffer/cache/P_S，不能除以连接数当常驻连接成本。排空内段约134.413s记录38个粗CPU秒，约28.27%单核，端点量化误差±2秒；该值不是整个run或整个VM的CPU，postidle粗CPU计数未增加也不等于精确零CPU。

本轮post-completion prepared hook可用：60条会话缓存实例属于cache-lifetime下界，可能含setup/warmup或漏掉已逐出项，不能当全run SQL总数。原map中`CLAIM_ONE_SQL`执行61694、examined122928、sent40976；未知hash保留原numeric，不作0、也不假装9fc新next_due已在旧map分类。after statement capture仍因退出后4GiB守卫STOP未执行。

原始map为1项已分类、59项未知；另存纯源码字节SHA对照才把其中一个原UNMAPPED hash精确识别为9fc `NEXT_DUE_SQL`：3949执行、examined3835、sent3949、affected0、累计0.724669s，仍只代表缓存lifetime下界，不猜绑定/窗口。repeat的178.0s保守profile内窗含40684 receipt：receipt hold135.702s/COMMIT82.168s/SQL39.137s，平均每receipt分别3335.50/2019.65/962.00µs；claim hold29.603s、next_due0.989s。入口未开始HTTP队列峰1802消息、活跃HTTP峰8、数据库非终态积压峰33387目标是三个不同计数；HTTP最后成功距首实际offer44.750s，不能把队列和活跃HTTP或消息和目标相加。

| 分段 | repeat测量及口径 |
| --- | --- |
| offer→开始HTTP | 2560条精确样本，p95=33247.655ms、p99=34452.032ms；是测试producer的未开始队列。 |
| 单条HTTP请求 | 2560条精确样本，p95=209.812ms、p99=472.438ms；包括Gateway接纳等待和响应。 |
| Gateway内排队 | 40658个内窗首attempt样本，从持久身份的首次`accepted_at`到凭据/网络执行前；log2桶p95/p99上界均134217.727ms，均值75954.439ms。不含producer的HTTP前排队。 |
| 凭据及Provider网络 | 40658个内窗样本，均值24.198ms；p95/p99桶上界均32.767ms，不能等同固定20ms Mock延迟。 |
| Provider结果→receipt返回 | 40684内窗样本，均值110.418ms；p95/p99桶上界262.143/1048.575ms，包含gate与事务等待。 |
| receipt COMMIT await | 同40684样本，均值约2.021ms；p95/p99桶上界2.047/8.191ms，只是事务提交子阶段。 |

这些profile分位是桶上界、覆盖保守内窗，并非全部40960的精确分位。库内名为`end_to_end`的histogram也从首次`accepted_at`开始，不能代替本报告从offer开始的Mach精确端到端数据；不同阶段分位和并发累计时长不可相加。锁内SQL-inclusive含驱动往返、扫描和约束处理；没有把MySQL每种内部引擎等待、锁与fsync分别完全隔离，缺失项记覆盖限制。

after预算guest4125339648/host4371812352 bytes、effective4125339648低于4GiB，SQL inventory未尝试。**business与完整验证PASS、资源STOP/no-next分别成立**；runner内部next_lane_allowed不能代替root授权。归档并回收本隔离环境已校验关闭日志后才允许下一lane，不降低4GiB守卫、不删除原失败。两次目标完成时长约179.24–189.59秒，余量差约10秒；尚不足以承诺稳定生产容量，更不是持续256消息/s。用户要求的历史PG约25秒差异和C4条件未由此解释。

## 同最终源码的PG有限复核

PG1 `capacity/final-9fc812b/run-pg-final-1/`使用未改的冻结v2入口（无新增PG adapter）、同9fc/3dcc/工具链/原40960输入和190秒截止。完整runner、身份/wire/Pull/ACK/postidle通过；严格40960/40960 callbacks，0晚/未知/drop/writeerror/invalid，writer40976含16 warmup且已join。最后callback距首offer96994.389ms，输入10秒后排空86994.389ms；完整分母p95/p99为83102.702/86133.026ms，HTTP全部成功距首offer23257.897ms。

冷idle30.021s CPU0.170552%单核、68 interrupt/33 package wakes；postACK30.046s CPU0.103095%、69/20。Gateway冷RSS约14.090MB→业务峰18.235MB→ACK/post恒21086208 bytes，具体残留来源未归因。96.001s保守内窗40544 receipt：claim hold47.873s、SQL42.071s；receipt hold38.726s、SQL26.621s、COMMIT3.041s。这是各后端原生SQL与trigger实现的实际路径，不把PG/MySQL累计秒硬当同一条引擎SQL比较。PG统计116项/dealloc0/reset时间不变；track=all父语句与trigger嵌套耗时不可加和为wall，原capture未采plans/plan_time，不冒称已完成计划归因。

PG1 ACK后逻辑messages2561、targets0，实际`pg_database_size`仍339893271 bytes；逻辑dump671773 bytes不是物理记录成本。未测其中可复用页比例，不能用膨胀后的数据库直接外推30天身份空间或宣称ACK立即缩文件。归档经CRC/SHA/稳定全表counts后，仅删除此全新一次性PG1 case，其他库不动；实际tmpfs空闲从230360增至562296KiB。原导出脚本仅枚举public而失败、零dump/DDL；首源和错误保留，第二次修正为所有非system业务schema包含pushgo_c后独立通过。未执行VACUUM FULL/显式CHECKPOINT、扩大tmpfs或更改耐久参数。PG2准备依据PG1实测398856192字节增长加64MiB余量重新核预算。

历史差异另作限定10文件只读审计，见外部`review/pg-historical-variance-audit.md`。C5原/最终SQL全完成见证124.446→149.717秒（+25.271），精确callback123.939933→148.130939秒也增加24.191006秒，所以不能全部归为SQL轮询。输入/fanout/锚点/Rust工具链/profile一致，runner及二进制身份不同，数据库OS sampler从失败的pcpu路径变成有效的/proc+top；多阶段均更慢，但没有sampler开关或其他隔离反事实，不能认定它、planner、cache、外部编译或主机负载是原因。C6启用pg_stat_statements与新source/hostobserver，当前重复范围不反解历史。C4约5秒、写锁条件及原CURRENT失败仍按旧报告的未知范围保留，不借此重归因或宣称修复。

PG2 `run-pg-final-2/`同样完整PASS，40960/40960、0晚/未知/drop/writeerror/invalid；身份/wire/ACK/postidle和退出均通过。两次原始数据与归一化比较在`capacity/final-9fc812b/pg-current-finite-repeat-comparison.{json,md}`。

| 同源码PG原输入 | PG1 | PG2 |
| --- | ---: | ---: |
| 消息 / 实际目标 | 2560 / 40960 | 2560 / 40960 |
| 最后目标COMMIT距首offer | 96.994389s | 116.144173s |
| 完整分母p95 / p99 | 83.102702 / 86.133026s | 102.420998 / 105.419307s |
| postACK30秒Gateway RSS | 21086208 bytes | 20774912 bytes |
| PGstat条数 / dealloc | 116 / 0 | 116 / 0 |

PG2最后callback慢19.149784s，仍未触及原190秒截止。原始STATS已有的8种path定位显示：96.001s/40544与115.000s/40448 receipt保守内窗，maintenance SQL均值155.36→365.69µs，总11.829→27.717s；它嵌在accept/claim的gate内，不与gate再相加。accept hold均值3.631→9.611ms，claim12.585→13.432ms，receipt0.955→0.979ms；claim_select313.76→308.44µs、网络23.718→23.616ms没有一起增长。因此当前较慢主要与维护相关SQL阶段相联；没有实际计划或受控反事实，仍不能断言planner/checkpoint/cache/存储/宿主原因，更不能直接解释C5历史差异。没有为此继续优化PG或追加第三轮。

只对92对唯一、完整、短于256bytes的normalized statement作离线配对；歧义/截断项不配、不作0，原queryid和numeric保留。原capture有shared/temp数值，但没有plan/WAL/IO-time字段；总PG engine CPU因进程集合变化UNAVAILABLE。PG主PID约10.2/10.34MB RSS只是master，不是集群物理内存；也不能拿PG tmpfs和MySQL磁盘卷结果生成后端性能排名。两个postidle的RSS均未回冷水平，未作分配器/泄漏因果归因。

## 退出与可复现边界

全部最终运行源码保持9fc，正常/测试/观察器使用各自冻结SHA，validation源码包是实际脚本的搬迁副本，搬迁位置NOT RUN。17个活跃canonical/bootstrap测试库已作逻辑导出、稳定计数、CRC/SHA保全；旧失败导出/closed日志/live不完整日志和原始收据保留。只删除本轮四个捕获容器及一个专属卷，C6 URL/state退役；镜像、AVD/runtime、源码、冻结二进制和原失败不动。OrbStack因保守守卫命中常驻MCP bridge而保持RUNNING，未停止这些其他任务进程，未宣称恢复到最初Stopped。

当前证据支持修复MySQL病态claim访问路径、receipt重复工作和next_due扫描，并在两次原输入中完成40960目标。当前主要成本仍为串行持久receipt COMMIT；H32保留，没有恢复复杂控制器。它不证明持续128/256消息/s、真实Provider/公网/物理设备/断电容量，也未新增Private大连接/高负载矩阵。history无硬配额，WAL/binlog、历史和数据库可复用页均需独立预算，不能声称磁盘固定有界。
