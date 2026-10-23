# 本地容量实测

默认保留每个 provider 的 H32/Q32：最终实现的 64 条消息/秒输入在 30 秒窗口内队列接近平坦；32 条/秒的 60 秒窗口完成全部目标，但后半 SQL backlog 有小幅正斜率和尖峰。128/256 条/秒不能据短时最终收敛宣称可持续。H64 没有稳定的吞吐收益，增加约 4–5 MiB RSS 和网络/receipt 占位。

核心矩阵绑定 `ff314261eab7dd5409b5f113ff1fa08f9cf17d19`、binary `7969c61d…4515f`：67 例加相邻 H32/H64 两例，共 69 例，64 PASS、5 个 CURRENT 容量输入失败。最终复验绑定 `f57357c42900dbf06c4b27271b6962ad4c47a1c5`、binary `2611b966…fc10`：原 8 例和等消息总量补充 2 例全部 PASS。CURRENT/C32 有效原始对照复用，未重跑；两份 C2 源身份不混用，C32 的旧协议实现不据此视为与最终普通消息合同等价。

环境为 Apple M5 /10 CPU/32 GiB、macOS 27.0.1；Release opt3、fat LTO、codegen-units1、panic abort、Tokio4。使用独立 SQLite、合成凭据、loopback provider；普通延迟20ms，故障/slow lane单列。常规每消息16个真实目标、body1024字节；fanout为32目标，very-low为2目标。CURRENT/C2输入与wire TTL为绝对毫秒，C32输入为相对秒、wire为绝对秒，显式映射同一24小时含义。没有真实APNs/FCM或PG/MySQL容量结论。

60秒冷空闲对照如下；cold是READY后2秒RSS，不是冷启动耗时。CPU为Mach ticks经numer/denom转换后的user+system；interrupt_wakes为`ri_interrupt_wkups`，不是all wakes。

|源|cold/idle RSS MiB|60s CPU秒|interrupt wakes / package-idle wakes|SQL QueryCounts事件|
|---|---:|---:|---:|---:|
|CURRENT|15.69 /16.81|0.40250|721 /342|1662|
|C32|9.78 /10.33|0.00609|135 /58|0|
|C2 core|10.22 /10.66|0.02984|135 /54|0|

最终短idle8秒：CPU0.002492秒、interrupt wakes17、SQL0、RSS峰10.81MiB，provider owner/owned/network/receipt均为0。QueryCounts是sqlx完成/drop的语句事件，按verb计数（CURRENT包括OTHER60），不是成功事务数、query-plan工作量或磁盘IO。

核心矩阵 first-all-target SQL visibility，单位秒：

|源|128/s×10s，两次|256/s×10s，两次|64/s×30s|
|---|---|---|---|
|CURRENT|各3/1280次HTTP500|17/2560与5/2560次HTTP500|12/1920次HTTP500|
|C32|10.372 /10.897|28.564 /27.593|30.097|
|C2 core H32|10.930 /11.535|36.177 /27.888|35.723|

5个CURRENT失败均保留首次错误、所有响应和错误码。失败操作的dispatch/Pull目标均为0，daemon退出干净；因没有因果SQL错误日志，HTTP500的底层原因未确。失败lane未完成全目标收敛，不计算settled throughput。计划中的第二次是独立重复输入，不覆盖首失败。

core长64/s的producer峰332条、后半已接受DB backlog增长1259目标。其0–10/10–20/20–30秒完成窗口network均值23.08/23.34/23.60ms，mock约23ms；receipt为0.85/4.28/50.74ms，gate等待0.61/2.89/47.24ms，直接COMMIT为0.060/0.125/0.876ms。后段主要观察到commit之前的共享gate等待；不能据这些聚合计数定量拆成maintenance/trigger/claim/SQLite调度，也不能把这一旧源结论冒充最终源的长64测试。ff314与f573的源码和host时序同时变化，未做同源A/B，不能由这两次差异断言某个索引的因果收益。

最终原8例全部PASS。所有128/s为1280消息/20480目标，256/s为2560消息/40960目标；下表producer是未开始HTTP的消息峰，DB增量是后半已接受但未receipt的目标增量，二者不相加。

|最终case|first SQL秒|producer峰 / DB增量|RSS峰MiB|network /receipt /gate /COMMIT均值ms|
|---|---:|---:|---:|---|
|短idle8s|—|0 /—|10.81|—|
|falloff 64+3消息=1072目标|6.486|16 /—|18.20|见完整收据|
|H32 128 r1|10.076|2 /+13|21.28|23.33 /1.69 /1.29 /.052|
|H32 128 r2|13.019|34 /+2886|22.03|31.05 /3.15 /2.71 /.053|
|H32 256 r1|29.884|1374 /+1262|22.25|32.47 /5.27 /4.67 /.077|
|H32 256 r2|24.992|1136 /+2186|22.03|30.82 /2.88 /2.49 /.052|
|H64 128 r1|10.385|2 /+9|25.83|26.38 /4.77 /3.98 /.061|
|H64 256 r1|28.557|1406 /−69|27.08|44.85 /9.20 /8.77 /.058|

falloff包含3次间隔1秒的稀疏输入，不能把6.486秒用作突发吞吐；producer峰仅覆盖初始64消息线程池，追加3次顺序HTTP均在请求/SQL/wire收据内。H64-256虽DB末段平，但producer仍积压1406条；单看DB会误判可持续。

最终补充2例，各仅一次、同1920消息/30720目标，不称重复或soak：

|输入窗口|first SQL秒|后半producer min/median/max、斜率 条/s|后半DB backlog min/median/max、斜率 target/s|queue前半→后半均值ms|最后HTTP start/response→全SQL可见ms|
|---|---:|---|---|---|---|
|32/s×60s|60.130|0/0/1，+0.000625|16/16/97，+0.394|4.715→9.431|144 /126|
|64/s×30s|30.107|0/0/1，+0.001236|20/30/32，−0.022|2.903→2.919|100 /90|

两例后半owned/network中位分别16/16与32/32，receipt中位0，RSS峰21.30/21.38MiB。64/s的30秒窗口接近平坦；32/s的60秒有小幅SQL正斜率/尖峰，不包装成严格平稳。尾差含SQL观察采样延迟，不是精确的最后COMMIT时间；以上仅说明这些有限窗口的实际跟随/收敛情况，未建立长期生产容量承诺。

core H8/32/64/128首轮first SQL为33.73/10.56/11.48/14.63秒；H32/H64第二轮12.45/11.47秒。H32实际global owned/network峰64/64，H64为128/128；H128为228/178（H是每provider上限）。不同axis的峰发生在不同时刻，不能相加声称超H。H8同时用Q8，其他用Q32。core较大H下mock均值仍约24–25ms而network均值升至39–45ms；socket/TCP、客户端调度及Python服务器/GIL的各自贡献不可定量拆分，不能全归因DB。

内存回落有直接分配器证据。core两次falloff的5秒idle，malloc live约1.66MB、reserved约41.94/37.75MB，pool owners均false、owned/network/receipt均0，RSS约17.5–18.14MiB。core r1 vmmap的malloc resident9168K、allocated1564K、fragment/free7604K（83%），physical footprint10.6M。最终falloff对应resident9424K、allocated1663K、fragment/free7761K（83%）、physical footprint10.9M。确认了malloc区域内驻留空闲/碎片和这些provider所有者已释放；RSS含共享页，不等于活跃对象。SQLite cache配置约2MB只是上限，实际贡献未定量；这些证据不证明进程完全无泄漏。

每个PASS都独立核对预期op/device/provider目标集、wire身份/内容、Pull在ACK前保留与ACK后移除，并要求exit0、daemon消失、reader/sampler join及SHUTDOWN显式joined且无panic/abort/HTTP timeout。性能以第一次SQL全目标可见为准，早于wire核验；stored receipt_at是commit前intent，不能当真实COMMIT。direct timing用固定32个log2微秒桶，只报告p50/p95/p99桶上界，非精确分位数。

完整数据与源证据：

- [core69状态](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/core69-status.json)、[core69全表](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/core69-full-summary.json)、[最终8例](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/final8-comparison.json)、[追加2例](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/final-boundary2-comparison.json)、[最终10例全表](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/final10-full-summary.json)。
- [CURRENT首次失败与收件人诊断](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/current-capacity-failures-complete-diagnostics.json)、[完成窗口趋势/CPU/QueryCounts](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/core-c2-completion-window-trends.json)、[vmmap证据](/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/malloc-vmmap-falloff-observations.json)。
- [执行源码收据manifest](../validation/capacity/source-receipt-manifest.json)指向OUT和精确归档字节。原3个smoke执行源码未保留，仅SHA和原收据可用；未重建冒充历史版本。C2首smoke因warmup已ACK目标被正确物理回收而触发旧observer计数假设，首失败保留后改为精确ACK-ID排除；69主例与修复后smoke有真实源码归档。追加2例前的README身份guard在daemon启动前拒绝文档差异，不计容量PASS/FAIL；随后仅允许root授权的这个精确README路径，记录build/current SHA与dirtydiff，全部编译输入仍逐字节匹配f573。

最终H32关键成本（只抽取现有final10收据，未增加测量）：

|输入重复|accepted_at→receipt COMMIT均值 /p95桶上界 ms|first-attempt queue p95桶上界 ms|CPU 输入10s /load→可见marker，u+s秒|首SQL同刻语句计数；近邻总数[读/写]、延后|目标/firstSQL平均完成率 target/s|
|---|---:|---:|---:|---|---:|
|128 r1|29.443 /65.535|16.383|10.397 /10.404|精确同刻不可得；340548[112652/227896]，+232ms|2032.65|
|128 r2|1965.251 /4194.303|4194.303|6.475 /9.381|精确同刻不可得；280608[81965/198643]，+245ms|1573.12|
|256 r1|4783.734 /8388.607|8388.607|7.064 /23.379|精确同刻不可得；537376[155196/382180]，+422ms|1370.64|
|256 r2|4400.341 /8388.607|8388.607|6.573 /18.347|精确同刻不可得；564988[165238/399750]，+427ms|1638.92|

p95均为已有log2桶上界，不是精确分位数。accepted_at是持久化接收时间字段，未包含producer待发HTTP时间；queue结束于第一次provider执行前。CPU的第二个窗口结束于首SQL之后的观测marker。精确首SQL同刻SQLx计数不可得，近邻计数延后232–427ms，不能冒充原子同刻计数；写为INSERT+UPDATE+DELETE，其他verb在这四个差分中为0。最后一列含全部排空时间及SQL观察延迟，是目标数/首次全receipt可见时间的平均值，绝非可持续吞吐。
