# C5 PG / MySQL 有限容量：原基线与最终复测

最新 `651bf7e7e4691bd5a78b36625ff34b693be83590` 的各一次同输入有限复测中，PG全量完成，
**MySQL仍为容量失败：7169/40960目标完成，33791未完成**。2560条HTTP全部accepted并不
等于40960目标已提交。最终结果和限制见文末“651bf7最终同输入复测”；不声称索引已解决
动态瓶颈，不声称持续生产容量或架构排名。

下方原e7基线正文完整保留。其不可变副本为
`capacity/final-e7b6d59/c5-capacity-baseline.md`，旧manifest、失败及执行副本均未覆盖。
原基线中的“暂留case”描述是当时状态；最终DB清理已交环境owner统一处理，本agent不再查询。

# C5 PG / MySQL 有限容量基线

最终源码 `e7b6d59ae8d615df86c23da2f3940eccb5a4fe2e`（产品实现
`753a1836b134915b2c6af2ef9fa6d075f52125a3`）上，PG 完成此次有限突发；
**MySQL 未在固定窗口内完成，是本输入的容量失败**。没有重跑、降低输入、提高 H/pool
或延长 deadline。MySQL 没有全目标完成、ACK drain 或 post-ACK falloff 证据。
这不是持续 256 消息/s 的证明，也不是三种数据库的架构排名。

原始收据位于 `gateway/build/quality-results/c5-mysql-ordinary-20261015/capacity/`，
最终输入和执行在其 `final-e7b6d59/`：`build.json`、`source-identity.json`、
`authorized-plan.json`、`run-pg-02/`、`run-mysql-01/`。
`exact-commit-summary.json`、`result.json`、`profile-window-summary.json` 和
`resource-summary.json` 分别保留精确目标完成、完整失败分母、阶段桶差分及 OS 观测。

## 固定输入与身份

两例均为 256 消息/s × 10s = 2560 消息，每条 16 targets，共 40960 offered targets；
8 FCM + 8 APNs 订阅者，每 Provider H32/Q32，8 HTTP callers，1024B 正文，
20ms 合成 Provider 回复延迟、真实候选 Provider/Remote Token owner。TTL 仍为绝对
24 小时。PG16.14 / MySQL8.4.11 使用隔离的新 case DB；容器的缓存和后台进程已经过
先前功能测试，**新 DB 不等于冷数据库服务器**。有界 tmpfs 也不是持久磁盘/断电验收。

Rust/Cargo 1.97.1，Release opt3/fat LTO/cgu1/panic abort、4 Tokio workers。
只复用候选 `prototype/target`；测量源码以稀疏覆盖文件和其余源码链接构成，没有第二份
大源码或 target。构建前后 tracked 产品源码 hash 和冻结 normal/test binary 均复验。

| 二进制 | SHA256 |
|---|---|
| normal fixture | `7324bc7ac546a2825c749b9f339c410dbeb6560129786b856a904873b39d0161` |
| shared native tests | `055fde93d44abde498bd47248650433bb76eb1c84d1fac18e7583e82f9a0866d` |
| 此次 observer fixture | `1a996105f673140e65217a20a6f782ded6bb0f60e9c24795aa3acd2bca4c8b4a` |

receipt COMMIT await 成功返回且 `changed > 0` 后立即回调；SQLite、PG、MySQL 的 seam
一致。事件使用共享 Mach 时钟，不用提交前的 `receipt_at` 充当提交完成。96B 固定事件、
4096 槽 channel、64KiB writer buffer、一个 OS writer；无全窗口 Gateway cache 或按积压
分配的 task。库 `forbid(unsafe_code)` 保持，时钟 FFI 只在 fixture。两有效 lane 均
dropped/invalid/write_error=0、writer joined。Python 有限 driver 的数组不计入 Gateway RSS。

## 全分母、截止与完成

完成截止固定为计划输入结束后 180s，即 offer 开始后约 190s；HTTP 等待、SQL poll 或
identity witness 不重置截止。SQL 子进程有 remaining-time budget，成功判定后复验时间。
首次失败与 deadline 取较早者作 Mach cutoff；之后的 COMMIT 仍保留原始流，但不计入
窗口成功。每个实际 offer 都展开到 16 个 intended targets，即使没有 HTTP 开始或 DB row。

| 项目 | PG02 | MySQL01 |
|---|---:|---:|
| offered messages / targets | 2560 / 40960 | 2560 / 40960 |
| HTTP started / accepted | 2560 / 2560 | 2397 / 2389 |
| HTTP timeout / 未开始 HTTP | 0 / 0 | 8 / 163 |
| cutoff 内目标 COMMIT 成功 | 40960 | 6528 |
| offered targets 中 unfinished | 0 | 34432 |
| 成功覆盖率 | 100% | 15.9375% |
| 截止后成功、保留但 censored | 0 | 1 |
| 全目标完成、身份/wire/ACK 核验 | PASS | 未达到 |
| post-ACK 30s idle | 完成 | 不存在 |

MySQL 首错为 `/message` 的 `c5:capacity:2394` 在绝对截止附近 socket timeout；
`first-failure.json` 原样保留。Gateway 随后正常 shutdown、exit0，不会把有界退出误写为
容量成功。8 个 HTTP timeout 的消息最终均已持久化，故目标分母按实际 DB 状态列为
unfinished，HTTP timeout 另列，不能重复相加。

停止后的稳定 SQL 见证为 **38352 targets / 2397 messages**：6529 provider_accepted
（含那 1 个 late COMMIT）、31760 pending、63 running。未开始 HTTP 的 163 消息对应
2608 非持久 targets。因此 34432 unfinished = 31823 durable nonterminal + 2608
未持久 targets + 1 late accepted；这里没有把外部 caller queue 混入 DB backlog。
两个本轮 case 暂留供单独授权的只读归因，未自动删除或重放。

| 精确 Mach nearest-rank，毫秒 | PG02 | MySQL01 |
|---|---:|---:|
| offer→目标 COMMIT p95 / p99 | 110412.172 / 113262.810 | 165219.005 / 182529.301，**仅条件成功样本** |
| caller offer→HTTP-start wait p95 / p99 | 35440.689 / 36512.313 | 159267.726 / 176331.156，仅 2397 started |
| HTTP response p95 / p99 | 262.882 / 275.717 | 1725.019 / 2088.653，仅 started |

MySQL 不能从 6528 成功目标的条件 p95/p99 推导全部 40960 offered targets 的总体
p95/p99，亦不能删去未开始 HTTP 的目标。`all_offered_success_quantiles_identified=false`。

PG 计划输入只有 10s，全部 HTTP accepted 的最后响应在首个实际 offer 后 **46.891s**；
最后一个精确目标 callback 在 **123.940s**，相对 10s 计划输入结束为 **113.940s**。
独立 SQL 全目标见证 marker 在 offer-start 后 **124.446s**，其 poll/身份读取形成上界，
不能冒充精确 callback；相对实际 offer-end marker 的 SQL 见证排空时间为 **114.393s**。
ACK 校验另耗时，不混入目标 COMMIT 延迟。

MySQL 未完成全部 HTTP 接纳；最后一个成功 HTTP response 为首个实际 offer 后
188.451s，窗口内最后成功 callback 为 188.519s；这两个数都不是全量完成/排空时间。
最终截止约 190s，之后的 shutdown/稳定 SQL 取证没有扩展性能窗口。

## 阶段定位：内窗 histogram 差分

`profile-window-summary.json` 使用真实 measured Provider 首次 receive 之后的 first STATS
与最后 finish/cutoff 之前的 last STATS，取 offer→COMMIT 的保守内窗，排除 setup、cold、
post-ACK。PG 内窗 123.000s，receipt counter 从 80 到 40589（差 40509）；MySQL 内窗
188.003s，从 69 到 6505（差 6436）。因此这些并非完整 40960 目标的阶段分位数。
STATS 毫秒墙钟窗口选择使用保存的 host Mach/wall bridge，假设期间无墙钟跳变；
**精确目标延迟仍直接用 Mach ticks，与该墙钟选择无关**。

下表为内窗累计 bucket 相减，均值来自 total_us/sample；p95 是 log2 微秒桶上界，
不是 exact p95。重叠/nested 阶段和并发 waiter 的时间不可相加为运行时间。

| 内窗阶段 | PG mean ms / p95≤ms | MySQL mean ms / p95≤ms |
|---|---:|---:|
| accept gate_wait | 127.253 / 262.143 | 615.777 / 2097.151 |
| accept gate_hold | 11.360 / 32.767 | 3.852 / 16.383 |
| accept begin | 0.113 / 0.255 | 0.096 / 0.255 |
| accept COMMIT | 0.134 / 0.255 | 0.213 / 0.255 |
| accept pool_acquire | 0.840 / 8.191 | 0.684 / 8.191 |
| accept statement_inclusive | 0.147 / 0.511 | 0.210 / 1.023 |
| fanout_insert | 0.703 / 1.023 | 0.366 / 0.511 |
| claim gate_wait | 50.120 / 262.143 | 347.744 / 2097.151 |
| claim gate_hold | 14.620 / 32.767 | 268.832 / 2097.151 |
| claim begin | 0.077 / 0.255 | 0.095 / 0.255 |
| claim statement_inclusive | 0.253 / 0.511 | 6.714 / 65.535 |
| claim COMMIT | 0.092 / 0.255 | 0.196 / 0.255 |
| claim pool_acquire | 1.617 / 8.191 | 3.471 / 8.191 |
| claim_select | 0.272 / 0.511 | 16.521 / 65.535 |
| receipt gate_wait | 56.884 / 262.143 | 339.497 / 2097.151 |
| receipt gate_hold | 0.951 / 2.047 | 2.301 / 4.095 |
| receipt begin | 0.070 / 0.127 | 0.085 / 0.255 |
| receipt COMMIT | 0.076 / 0.127 | 0.144 / 0.255 |
| receipt pool_acquire | 0.056 / 0 | 0.160 / 0.255 |
| receipt statement_inclusive | 0.111 / 0.255 | 0.201 / 0.511 |
| transport network | 23.631 / 32.767 | 24.509 / 32.767 |
| receipt 全 settle | 57.835 / 262.143 | 341.761 / 2097.151 |

MySQL claim_select 的 9694 个 profile 样本合计 160.152s，而 claim gate_hold 的 603 个
完成样本合计 162.106s。receipt gate_hold 6436 样本合计 14.810s，receipt COMMIT 合计
0.929s；receipt Usage 标签合计 7.472s。该观测支持继续检查 claim 查询为何长时间持有
共享 gate、使 accept/receipt 等待；尚不能单凭 bucket 差分确定具体执行计划原因。
receipt gate_wait 合计 2184.661s 是并发 caller-wall 累加，不是 2184s wall duration。

`Counters.sql` 是名义 charge，不是引擎 SQL、触发器、RPC 的真实总数；Usage 包括
四条 SQL 的 reconciliation bundle，profile 标签样本也不能当一条引擎语句计数。
MySQL acquire 包含 owner 检查，PG acquire 主要为其 mutex，不能把 pool phase 当等价工作。
完整 begin/statement/commit/pool、按语句的均值与 bucket 分布在原始差分 JSON 中。

`timings.network` 从 authorize_ticket 后包住整个 `transport.send`，包括 Token owner/
credential、HTTP、bounded reply 解析；不是单 20ms Mock RTT，network_inflight 也不是
实际 Provider HTTP 请求数。实际 Provider 请求由完整 peer 流核验。`queue` 从 durable
accepted_at 到 transport 前，不包含 caller 未开始 HTTP 的等待。`receipt` 覆盖 settle 的
gate/连接/SQL/COMMIT；offer→COMMIT 才覆盖这些部分及外部 caller 队列的全程。

## Gateway idle、峰值、falloff 与独立数据库成本

设置订阅并 ACK-验证 warmup 后，offer 前固定 30s；全部 ACK 后再固定 30s。idle 只做
OS 采样，无 Gateway HTTP/SQL 观察调用；fixture 原有 1Hz STATS heartbeat 成本仍在。
以下 RSS 为进程驻留 bytes，不包含 Python、数据库容器或 Mock。

| Gateway OS 指标 | PG02 | MySQL01 |
|---|---:|---:|
| pre-offer idle 最后 RSS bytes | 13598720 | 15056896 |
| burst/drain 观测 RSS 峰值 bytes | 18350080 | 18989056 |
| ACK 后 30s idle 最后 RSS bytes | 21348352 | 无 post-ACK window |
| pre-offer idle CPU，一核百分比 | 0.163% / 30.017s | 0.157% / 30.017s |
| pre-offer interrupt / package-idle wakes 增量 | 67 / 23 | 68 / 31 |
| post-ACK idle CPU，一核百分比 | 0.098% / 30.040s | 不可用 |
| post-ACK interrupt / package-idle wakes 增量 | 71 / 16 | 不可用 |
| offered burst 后的 Gateway CPU | offer-start→SQL全完成marker，kernel均值9.625%一核 | ps TIME内窗189.585s累计4.74s CPU，约2.500%一核；无kernel全窗口结束marker，不硬比相同精度 |
| 外部 producer queue 采样峰值（消息） | 1664 | 2071 |
| HTTP inflight 采样峰值 | 8 | 8 |
| durable nonterminal 采样峰值（targets） | 34081 | 31823（停止后见证） |

PG ACK 校验阶段的 RSS 增至 21348352 bytes，随后 30s 没有回落到 pre-offer 水平。
该短窗不足以认定泄漏或长期稳定；MySQL 未 ACK，不能用退出后的服务器 idle 伪造
Gateway post-burst falloff。CPU 窗口使用 owned-PID kernel 差分；ps percent CPU 是
进程寿命估计，不能冒充窗口平均。两种 wake 是特定内核 counter，不是所有 wakeups。
MySQL 的 CPU 补充只用 `ps TIME` 累计值作上述内窗差分，保存于
`gateway-ps-cpu-interior.json`，有百分之一秒读数粒度及未采样首尾限制；并未使用
ps percent CPU 求窗口均值。

**原业务 lane 的数据库进程 RSS/CPU trace 均 UNAVAILABLE。** `docker top` 的原字段
`pcpu` 不被 OrbStack ps 支持；returncode1/stderr 全部留在 `db-process.jsonl`，未吞掉、
也未回填成有效数值。此观察器缺陷不改变真实 COMMIT、完整分母、Gateway OS 数据或
MySQL 容量失败，但限制了完整数据库成本的结论。

随后独立授权仅用支持的 `pid,ppid,comm,rss,time` 作 1Hz OS-only 补采：

| 独立 DB 观察 | 实际范围与限制 |
|---|---|
| MySQL late supplement | 108 样本 / 约107.018s，始于原 lane offer-end 期间；原始 RSS `309m`→`310m`，累计 CPU `1:29`→`3:10`（约101s CPU / 107s observed，秒级读数），不覆盖前段或原峰值 |
| MySQL /proc 单点校准 | namespace PID1 comm=mysqld，VmRSS=312056 kB，即319545344 bytes；Linux /proc kB按1024换算，仅这个时刻，不把 top 的 `m` 无依据转成MB/MiB |
| PG post-run cached server idle | 独立30s/31样本；master raw RSS `9428`，后台进程含raw `39m`、`37m` 等；各进程显示累计CPU未在秒级读数中增长，不能证明零CPU |
| MySQL post-run cached server idle | 独立30s/31样本；raw RSS `310m`→`307m`，累计CPU `3:11`不变；不是原冷基线或 Gateway falloff |

补采的 ownership guard 每样本验证 captured container full ID、label、name；无数据库
SQL、Gateway HTTP、额外业务流量。数据库进程保留在原隔离服务器中，RSS 与 Gateway
分开。PG 共享映射会重复计入多个进程 RSS，禁止简单求和声称物理 RAM。

业务边界 connection snapshots 含一条显式 observer 连接：PG case count=2（1 pinned
Gateway + 1 observer），server count=7；MySQL case count=2。它们不是峰值连接采样。
没有证明逐连接堆内存与缓存的分摊，也没有证明冷服务器基础成本。

## 原失败与范围

第一次 PG `run-pg/` 在 warmup 观察 SQL 时使用新 psql session 的默认 `public`，报
`targets does not exist`；正式 offered=0。该观察器失败、reducer 拒绝性能结论和原
runner hash 完整保留。只在单个 psql 进程注入 PGOPTIONS search_path=pushgo_c，
qualified/unqualified OID同18774、count同16后，才在全新 case 执行 PG02。
原16个 warmup rows 实际为13 accepted+3 running；首错即停，不要求它们全完成。
校准脚本曾额外误加“全 accepted”断言，其静态源码/首失败亦单独保留，未算产品失败。
修复通过12项纯 oracle 和独立 delta review；没有重建或改变业务判据。

本轮没有真实 Provider、持续容量、物理磁盘、生产连接数、长期内存、完整 DB 成本验收。
不解释旧 C4 writer 条件、旧高负载5秒差异，不建立 CURRENT/C32 或 SQLite/PG/MySQL
架构排名。退出证据为 owner shutdown report 和 OS 中无自有进程；`tasks` 是当时全局
wrapper 观测，不能把某个非零读数描述为所有对象/任务均为零。


## 651bf7最终同输入复测（一次/后端，未追加）

最终入口为 `capacity/final-651bf7/`，small handoff manifest、
`finite-comparison-summary.json`、各lane raw/result/exact/profile/resource收据均独立保存。
源码树/逐文件hash、完整observer patch、Rust 1.97.1 release locked offline命令和构建日志
保存在 `source-identity.json`、`observer.patch`、`build.json`；仅原target构建，产品源码未改。

| 最终冻结二进制 | SHA256 |
|---|---|
| normal fixture | `3204f8ac126282e74980eaffec386ab9ffc67f028f8bbcd15f47c9eb284f8298` |
| shared native tests | `173d98eab6eb7a9b4ba287471ef519219d5ee1fa2675d2e5693f09e527aae032` |
| observer fixture | `52731d4a4599a379984e16734c9b9f304593aefe64b86563c6e7032e2a16e4af` |

业务输入/toolchain/COMMIT observer不变：256消息/s×10s、2560消息/40960targets、fanout16、
每Provider H32/Q32、8 callers、20ms Mock、30s前置idle、成功ACK后30s idle、190s绝对截止。
原DB OS sampler的pcpu失败则明确修复：最终增加了有效`/proc`和Docker OS观测，其开销与
原基线**并不完全相同**；新观测不能回填旧缺项，单次before/after比值不能作严格唯一因果。

| 有限收据 | 原PG02 | 最终PG01 | 原MySQL01 | 最终MySQL01 |
|---|---:|---:|---:|---:|
| offered targets | 40960 | 40960 | 40960 | 40960 |
| cutoff内目标COMMIT成功 | 40960 | 40960 | 6528 | 7169 |
| unfinished | 0 | 0 | 34432 | 33791 |
| 成功覆盖率 | 100% | 100% | 15.9375% | 17.502441% |
| HTTP accepted / started | 2560/2560 | 2560/2560 | 2389/2397 | 2560/2560 |
| HTTP errors / 未开始HTTP | 0/0 | 0/0 | 8/163 | 0/0 |
| 目标p95 / p99 ms | 110412.172 / 113262.810 | 133143.957 / 137232.582 | 165219.005 / 182529.301 条件值 | 172601.739 / 184705.326 条件值 |
| post-ACK 30s idle | 有 | 有 | 无 | 无 |

最终MySQL首错为固定drain deadline exceeded，未重置/延长截止、降输入、提高H或追加lane。
全部40960 targets已持久化；截止/停止后稳定见证为7169 accepted、33736 pending、55 running。
**33791 unfinished全部仍在durable DB；未开始HTTP或未持久目标均0**。0 late-censored，
0 dropped/invalid/write errors，writer joined；exit0/正常shutdown只证明有界退出，不是容量PASS。
目标条件p95/p99仅覆盖17.50%，不能称总体p95/p99。没有ACK后falloff，退出后ps的RSS0
是进程不存在/退出哨兵，不是RSS释放曲线。原始resource-summary的该min/last值保留但不可用。

| 最终精确Mach/独立见证边界 | PG01 | MySQL01 |
|---|---:|---:|
| 全部HTTP accepted最后响应，首实际offer后 | 53.455s | 176.790s |
| 最后窗口内成功目标callback，首实际offer后 | 148.131s（全量） | 189.416s（部分） |
| callback相对计划10s输入结束 | 138.131s（全量排空） | 179.416s（不能称排空） |
| offer-start→全目标SQL见证marker | 149.717s | 未达到 |
| 实际offer-end→SQL全量见证 | 139.654s | 未达到 |

PG业务路径未变，但最终SQL见证149.717s比原124.446s更晚约25.27s；精确目标尾延迟也更高。
这是必须保留的环境/观测/单次波动未决信号，**未证明sampler是唯一原因**，未追加重跑调查。
该差异与旧C4的5s问题分别未决，不能混为一个已解释问题。

### 最终残余阶段观测，不推断动态执行计划

相同保守内窗bucket差分：PG147.000s、40495 receipt增量；MySQL189.003s、7081增量。
不是全run累计，也不是exact阶段分位数；完整begin/statement/commit/pool/fanout等见
`profile-window-summary.json`。以下为最终MySQL内窗：

| label | samples | caller-wall总秒 | mean ms | p95桶上界ms |
|---|---:|---:|---:|---:|
| claim_select | 10656 | 155.345 | 14.578 | 65.535 |
| claim gate_hold | 664 | 161.033 | 242.520 | 1048.575 |
| claim gate_wait | 665 | 216.894 | 326.156 | 2097.151 |
| accept gate_wait | 2541 | 1382.210 | 543.963 | 2097.151 |
| receipt gate_wait | 7080 | 3777.001 | 533.475 | 2097.151 |
| receipt gate_hold | 7081 | 17.620 | 2.488 | 4.095 |
| receipt COMMIT | 7081 | 1.241 | 0.175 | 0.511 |
| receipt Usage标签 | 21243 | 8.742 | 0.412 | 1.023 |

最终claim_select标签仍主导claim持有时间，未证明五列索引已解决动态负载实际瓶颈。
先前same SQL/真实基数对照证明小query的扫描/排序计划差异，**不等于本次动态负载实际
选择了该计划**，也不等于完整容量修复。没有再EXPLAIN、诊断其他热点或新增第三lane。
Usage标签含四SQL reconciliation bundle，以上样本不是引擎SQL总数；waiter总秒并发重叠，
不可相加为wall duration。network仍含credential owner/HTTP/解析，queue不含caller队列。

### 最终Gateway与DB OS指标分列

| Gateway进程指标 | 最终PG | 最终MySQL |
|---|---:|---:|
| pre-offer idle最后RSS bytes | 13533184 | 14893056 |
| burst/drain采样RSS峰值 bytes | 17678336 | 18808832 |
| post-ACK idle最后RSS bytes | 20447232 | 不存在 |
| pre-offer 30s CPU一核均值 | 0.0995% | 0.0715% |
| pre-offer interrupt/package-idle wakes | 68/18 | 63/6 |
| post-ACK 30s CPU一核均值、wakes | 0.0903%，66/22 | 不可用 |
| producer queue采样峰值（消息） | 1719 | 2134 |
| durable nonterminal采样峰值（targets） | 34103 | 34109 |

PG ACK阶段RSS高于burst/drain，随后的30s idle未回到pre-offer基线；不能据短窗认定泄漏或
长期稳定。fixture原有1Hz heartbeat计入idle成本；idle没有Gateway HTTP/SQL观测调用。
Gateway kernel CPU、ps CPU/退出哨兵的精度和可用边界分开，MySQL无完整kernel结束marker。

最终DB每样本验证owned容器ID/label/name，native PID1 comm+VmRSS kB×1024，1Hz读取
supported top累计CPU TIME，原始记录全保留。未知格式、PID churn、owner/start/init PID
变化或missing sample均不回填为CPU0。该修复及24+5纯oracle/独立review已在执行前完成。

| 独立数据库进程观测 | 最终PG | 最终MySQL |
|---|---:|---:|
| pre-offer native PID1 RSS bytes | 9818112 | 347471872 |
| burst/drain native PID1采样峰值 bytes | 9818112 | 348749824 |
| post-ACK native PID1 RSS bytes | 9949184 | 无post-ACK window |
| pre-offer累计CPU粗差分 | 0秒/约29s，7进程，端点量化界14s | 0秒/约29s，1进程，量化界2s |
| loaded CPU范围 | offer-end/drain因PID churn总量UNAVAILABLE | offer-end观测166.007s中累计149 CPU秒，约89.755%一核，端点量化界2s |

PG这里仅master/PID1 RSS，遗漏其他backend的私有/共享映射；禁止sum共享RSS当物理RAM，
不能与MySQL单进程作整库RAM排名。MySQL约348MB是当前隔离服务器及既有case/cache的驻留，
不是一个pinned connection的内存成本；没有逐连接分摊证明。CPU0粗差分不代表实际零CPU。
DB phase的实际首尾时刻/量化界见JSON，不把退出后取证片段冒充截止内精确CPU窗口。
新DB仍不等于冷server；已修的OS trace不能回填原基线缺失，更不能构造内存/CPU改善比值。

两lane边界case connections仍为2（1 Gateway pinned +1 observer），非峰值采样。
环境owner已确认最终cleanup/quiet：剩余6case和2个精确容器已删除、OrbStack恢复Stopped、
URL文件为0，详见env收据。本agent未再查询retained DB。环境清理时另见Aegir本机cargo/rustc，
未触碰他项目；本轮不能声称整机全程无外部负载。启动前无外部compile只限于当时快照，
不能据后来观测因果解释PG约25s或C4差异，未额外调查/重跑。只做最终源/binary hash与
自有OS PID退出复验，不称全局对象/tasks为0。
本轮到此结束：保留原失败与最终失败，无持续容量、真实Provider、长跑或生产接受承诺。
