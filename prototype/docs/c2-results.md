# Gateway C2 普通消息候选：本轮交付

实现仍在隔离分支，未合并、推送或部署。它是单机 SQLite 的普通 FCM/APNs 消息候选，当前可执行入口只允许 loopback Mock；不是已经适配三种数据库、接通生产凭据和全部消息类型的 Gateway 替代品。

## 源码、二进制与回退

主仓库是 `/Users/ethan/Repo/PushGo/gateway`，基线 `main@dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。PushGo 父目录不是 Git 根。8 个独立仓库的开始状态和原 C32/C1 源码、二进制哈希在原始输出目录的 `baseline-before-commit.json`；其他仓库的既有修改不属于本轮。

| 提交 | 内容与对应证据 |
|---|---|
| `283acf583a61035d3a600700c931f607ba22642f` | 将原 detached C1 prototype 的 13 个源码、测试和必要文档文件保存为可回退基线；不提交数据库、二进制、日志 |
| `ff314261eab7dd5409b5f113ff1fa08f9cf17d19` | 普通消息合同、30 天紧凑身份、计数/清理、背压、Provider 有界回复、协议预算、凭据接口、指标；51 个原生测试通过。`c2-core-build.json` 绑定 core 二进制 `7969c61d…4515f`；首轮 69 项容量与首轮客户端证据属于此提交 |
| `f57357c42900dbf06c4b27271b6962ad4c47a1c5` | 客户端设备身份复用、跨平台有界退休、索引和恢复、COMMIT 失败与空间测量 oracle、响应 Body 持有预算、128 总请求/16 控制工作有界等待、30 天配置下限；最终 64 个原生测试通过。`c2-final-build.json` 绑定最终 fixture `2611b966…2fc10` |

最终实现分支为 `codex/gateway-c-ordinary-final-20261015`，checkout 为原始输出目录下 `workspace-final`。原首轮分支 `codex/gateway-c-ordinary-contract-20261015` 保留在 C1 输出目录的 `workspace`，冻结于 `ff314261`，避免比较过程中改变源码。原 C32 checkout、原始二进制、数据库和已有失败记录均保留。结束核对确认 5 个原始二进制、11 个 C32 源文件哈希不变，13 个原候选文件的 `283acf5` Git blob 与开始哈希相同；8 个主仓库 HEAD/分支/状态在相同 `-uall` 观察方式下全部保持。Windows 的既有修改和 warp-link 的既有未跟踪证据均保留。`preservation-verified.json` 保存这些逐项结果。

原始输出目录：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/`，下文简称 OUT。最终文档/验证源码提交的 HEAD 及工作区状态见 OUT 的结束状态记录和本轮最终回复；编译输入仍对应上面的最终实现提交。

## 已实现与合同差异

完整逐项表及命名测试见 [ordinary-contract.md](ordinary-contract.md)。覆盖完整 Sender 输入、可选 op_id、稳定消息/投递身份、首次时间、绝对 TTL、状态查询、权限/密码/Bearer、路由版本、Direct、V2 Pull、显式批量 ACK 和当前客户端直接 ACK，配置 base_url 含路径前缀。

正文只保存一次，全部有效收件人同一事务接纳。未完成 manifest 和 pending Provider job 使用现行 10,000/1,000,000 预算，终态释放这两个预算；ACK 释放保留正文/队列，保留完整身份、指纹和状态。进行中的 ACK 不丢 receipt，也不因重启或同 op_id 重发而复活。没有为了拆事务而部分接纳 fanout。

本轮明确选择完整 **30 天身份历史**，不新增历史数量/字节硬配额、不提前淘汰。源码核对发现主线 Small 维护去重期为 7 天，Public/default 为 30 天，不能笼统称所有现行配置都是 30 天；C2 按本轮明确选择保证至少 30 天。省略 TTL 的正文/投递默认 7 天与身份期是两项独立合同。显式绝对 TTL 最多到首次接纳后 30 天，省略 TTL 不向 wire 补一个新的 TTL。

未引入分布式调度、选主、多节点租约或跨 Provider exactly-once。结果未知允许有限重复请求，但重试内容、身份、首次时间和绝对到期时间不变；客户端展示策略未改。没有扩展 Event/Thing/Watch/WNS，thing_id 明确拒绝；没有扩大对退役客户端/旧 Gateway 的承诺。

## 测试事实

| 层次 | 结果与实际覆盖 |
|---|---|
| 最终原生 Rust | **64 通过、0 失败、2 ignored**；`final-native-first.log`。2 个测量不是跳过交付：随后显式以 Release native test binary 分别运行，均首次通过 |
| 静态与构建 | 严格 Clippy all-targets `-D warnings` 通过；Release fixture 与 Release 原生测试构建通过，verbose flags、二进制及源码哈希保留。`final-verification.json` 汇总并核对 reviewer 所审源码与执行输入相同 |
| SQLite 故障 | 原生 `SQLITE_FULL=13` 与延迟外键 `COMMIT=787` 通过；后者先证明 INSERT 成功/COMMIT 失败，实际 HTTP 返回 503/success=false；未提交操作无身份、无成功计数，既有消息/ACK/首次状态重开保持，恢复写入可用。没有填满宿主盘，也未运行真实文件系统 ENOSPC、I/O 错误或断电测试 |
| 所有权/崩溃 | 原生 barrier 覆盖 claim COMMIT 后未接管、caller abort、外部结果未知、receipt 等待提交、ACK 两种顺序、owner 排他与重开、阻塞 claim/receipt 停机无等待环；三方独立进程故障用真实网络在途 kill，保留被杀退出和新进程恢复的不同记录 |
| 首轮容量 | **69 项中 64 通过、5 个主线对照容量失败保留**，即 67 个原计划案例及 2 次 H32/H64 相邻复验；`core69-status.json`。失败为主线 128/s 两次、256/s 两次、64/s 持续一次 HTTP 500；失败请求没有投递/Pull 目标，清理退出通过，具体 HTTP 500 根因未确认，因此这些行无有效可持续吞吐/完整排空排名 |
| 最终容量 | 受源改动影响的 8 个 C2 案例全部通过；另补 32/s×60s 与 64/s×30s、相同 1,920 消息/30,720 目标的 2 项边界观察，均通过，共 **最终 10 项通过**。有限窗口的积压与尾部分析见 [capacity-results.md](capacity-results.md)。有效 CURRENT/C32 对照复用，不重跑整个首轮矩阵，不把 core 结果冒充最终源码结果 |
| Apple 首轮与最终复验 | 两个源码阶段分别首次通过。最终 f573/2611b966 的 ingest/recover 退出码 0/0、原生 PID 72145→72291；真实捕获的过大消息 wakeup → 未改的应用 `NotificationIngressController` → 磁盘 GRDB → ACK 503/持久 leased outbox → 全新原生进程 → 原 60 秒退避后 ACK 200。仅一次过滤 Pull；两次发 ACK 前独立核验完整正文、身份与 leased ACK。8,214 字节正文完全一致，最后服务器 payload/pending/targets 均为 0；没有私有构造器伪造通知。OUT/client-evidence/apple-final-f573 含 reconciliation、源码/实际 xctest/最终 binary manifest 与全部进程退出证明。没有经过 OS APNs 派发或物理后台 |
| Android | 原生 **3 通过、0 失败/跳过**。未改 `InboundMessageProcessor.process` 默认 hooks、过滤 Pull、磁盘 Room、存储失败不 ACK、ACK 503 outbox、数据库/仓库重开后按原 Gateway/device/contract 排空。使用本地协议 stub，服务端另由 Rust 验证；不是完整进程重启、WorkManager/FCM Service 调度或物理后台证明 |

首次失败全部保留：初期原生测试的旧 wire TTL/重复内层 ID/ACK 物理删除假设、观测初始化竞态和一次整合编译竞态已分类修正；首个 C2 smoke 的观察器把已确认 ACK 的 warmup 目标计入期望，原日志/DB保留，修复后逐一绑定真实 ACK ID，其他有效证据复用。没有通过延长等待或吞掉失败制造通过。原 3 个 smoke 执行时 runner 源码未逐字节归档，保留实际 SHA 与日志并明确缺失，不重建冒充；主矩阵及其后续运行均有真实 runner 版本归档。最后 2 项边界观察启动前，源码 guard 拦住已经说明的 README 文档变更；尚未创建 daemon/mock，不计容量失败。仅该精确文档路径获得显式例外，前后 SHA 保留，全部 Rust/Cargo/lock 编译输入仍与构建记录逐字节相同。

## 资源与容量结论

详表、端到端/队列/网络/receipt/实际 COMMIT 分布、CPU、空闲 kernel interrupt wakes、SQL 语句计数、积压、峰值与回落内存见 [capacity-results.md](capacity-results.md)。C2 端到端直方图从接纳时间计到 receipt COMMIT，不包含生产者尚未开始 HTTP 的等待；offer/caller 的时间和服务器排队另列，不能相加不同分布的 p95。分布是固定 log2 微秒桶的上界，不是精确 p95；receipt_at 不是 COMMIT 完成时刻。SQLx 语句事件不是成功事务、trigger 内部语句或磁盘 I/O。

资源随负载实际增长并回落：按需 Futures、领取 reservation、网络请求、待提交结果分别有所有者和指标；工作到 receipt COMMIT 才释放位置，慢 DB 不产生无界结果缓存。退避在 SQL、空闲不预建 worker，Provider pool 在真正清空后释放。保持可配置安全上限与懒执行，推荐当前本机实验仍用 H32/Q32；H64/128 未证明稳定吞吐收益，资源成本增加。32 仍不是已批准产品上限。没有恢复复杂控制器，也不以 target 数字变化宣称伸缩成功。

在首轮较长 64/s、16 个目标/消息的负载中，后段 Mock/网络约 23ms，receipt 阶段约 51ms，其中共享 mutation gate 等待约 47ms。可见首要拥塞在提交前共享串行边界；现有证据不能精确拆出领取/维护/trigger/SQLite 调度分别占比。更高 H 时还存在超出 Mock handler 时间的网络/客户端等待，不能全部归于数据库。128/s、256/s 的生产者等待与已接纳数据库积压分开记录；最终排空不等于可持续吞吐。

最终 f573 的补充边界观察中，64/s×30s 的后半生产者等待最多 1 条、DB backlog 20/30/32 个目标（min/median/max），斜率约 −0.022 目标/s、queue 均值 2.903→2.919ms；这一有限窗口能跟随约 1,024 目标/s。32/s×60s 的 DB backlog 16/16/97、斜率约 +0.394 目标/s，queue 4.715→9.431ms，有小幅正斜率及尾段波动。两项均为 1,920 消息/30,720 个目标，最后 HTTP 响应到首次观察全部 receipt 可见约 126/90ms，包含 SQL 观察采样延迟；不是精确最后 COMMIT 延迟。首轮 core 较长 64/s 的劣化与最终此项是不同源码/时序，不能宣称某个索引修复产生了已证明的性能收益。这些 30/60 秒观察不等于生产 soak，也没有证明长期部署容量或无条件持续 128/256。

RSS 未回冷启动有具体分配器证据：空闲后 owned/network/receipt 为零、Provider pool owners 释放、malloc 活跃字节稳定；vmmap 同时显示驻留区中大量未分配/碎片页。SQLite cache 配置只说明预算，尚不能定量归因其实际占用。可以排除仍持有已完成工作的解释，不能据短 Mock、RSS 或有限快照证明一般意义无泄漏。

请求体沿用 32 KiB；HTTP 128 总接纳许可、16 个控制响应工作许可有界等待、连接 128、HTTP/2 stream 1/连接，响应 Body 持有许可到 EOF/drop；Provider 回复累计上限 16 KiB。密码窗口缓存有界，历史与注册别名落盘逐点查询；fanout、计数、索引与每批 256 清理的具体边界和数据相关工作量见合同文档。不存在固定磁盘总上限。

## 历史量化与后续

[history-results.md](history-results.md) 给出实际表/索引/目标成本、op_id 宽度/插入顺序、1m 历史查询/接纳、过期清理、空闲页回填及 30 天规模表。默认 46 字节 op_id 的 ACK 后身份约 426–429 B；64/s 约 70.74–71.24 GB/30 天，128/s 约 141.48–142.47 GB，256/s 约 282.96–284.95 GB，不含未 ACK 正文/目标。ACK 后身份不乘收件人数；未 ACK 的每目标成本、共享正文、7 天/30 天分别估算。

实际删除 10k 身份后文件不缩，free pages 增加；再插回 10k 确实消耗空闲页，随机索引仅有少量额外增长。checkpoint 清 WAL 与数据库缩文件不同，本轮不运行 VACUUM。没有历史 hard quota，所以高持续量仍可能耗尽磁盘；本轮不实现新的拒收策略。后续可评估默认关闭的可选历史预算，触顶只拒新 op、允许重放、完整保留 30 天，代价是 ACK 后也可能拒收新消息；不得用提前删身份代替这一产品决定。

[next-adapters.md](next-adapters.md) 列出下一阶段 PG/MySQL 的事务/索引/锁、迁移/回退及三库共同 oracle。普通消息语义稳定后再按接纳、投影、执行三个 seam 接其他类型。真实 Token Service 接线、真实 APNs、物理 Apple/手表后台以及 PG/MySQL 实库迁移尚未完成；本轮未使用生产凭据或真实用户数据。

当前 fixture 实现的是文中列出的普通消息发送/投递合同入口及必要的 register/route/subscribe。完整设备/频道管理控制面（包括主线 `/channel/sync`、`/channel/unsubscribe` 等）尚未接入新 C；因此本轮也不能表述为现行客户端全部功能已经可以切到 C。正式替换前，应另列完整控制面与旧库迁移差异，并保持主线既有行为。

没有需要现在再决定的新用户可见行为；完整 30 天、无历史硬配额已按明确选择实施。可选配额及最终产品安全上限仍需将来基于目标机器/真实 Provider 的证据决定，本轮到此停止，不自动进入下一阶段。

新增可复现源码在 `validation/clients/` 与 `validation/capacity/`，不提交二进制、原始日志、数据库、依赖缓存或完整客户端副本。原始证据、失败、源/二进制哈希仍在 OUT，并与原 C32/C1 目录并存。
