# 后续：普通消息收口与数据库迁移（附 C3 原计划）

C4/C5 已完成 PG/MySQL 普通消息原生实现与全新隔离实库验证；C6 接入三库普通 Private 并修正 MySQL 领取扫描。C5 原190秒容量失败保留，C6结果独立记录。Private 合法大请求超帧仍待行为决定，四传输证据也必须逐项核对；当前不自动进入其他消息类型。旧库迁移、回滚、真实 APNs、物理手表后台、断电持久性和部署仍留最终验收。以下保留 C3 原计划，不是当前实现缺失清单或已验证结论。

**C3历史上下文：** 本文件当时是下一阶段执行计划，不是实现或验收结果。当前隔离 crate 的 `store.rs` 使用 `SqlitePool`、SQLite DDL、触发器及本机文件 owner；原型自己的 SQLx storage 仍只有 SQLite；主仓库凭据 owner 的 path dependency 会编译其他依赖，不等于已有 PG / MySQL storage 适配。主线 Gateway 支持三库不能证明这个 crate 已具备三库事务、迁移或故障恢复能力。本轮没有新增数据库适配器或启动实库服务，不连接真实 Provider。

容量证据提示共享 mutation gate/结果提交前排队先于提高 H 获益。C3 已对现有 SQLite 各路径分开 profile，并以同工具链/完整合同的一行 SQL 对照证明空 retirement marker 下的 target 扫描热点；仅固定 join 顺序，未扩池、批量提交或拆接纳事务。SQLx SQL 时间包含 trigger；未证明 trigger 独占时间。优化后高负载 gate 仍占明显比例，继续适配不应预设批量提交为答案。不因 H 数值可变而恢复旧控制器，也不把本轮短 Mock 完成量当部署容量。

## 1. 先固定事务合同，再替换 SQL

保留单机、单进程 owner 和现有写入 gate。PG / MySQL 使用明确的 authority 配置标识取得本机排他锁，禁止通过不同配置重复启动同一 authority；数据库连接池不能绕过 owner。连接失效应停止接纳，完成恢复后再继续。这里不扩展跨主机协调或分布式租约。`attempt_id`、冻结 route_generation/device_key 仍是旧回执的条件更新凭据。C3 新增 pull_owner 与 frozen owner 分离、独立 route_revision/actual-change generation、token retirement control_epoch；coalescing 只转 retained Pull，旧未授权工作永久 fenced，已授权回执仍归原 frozen key。三库共同 oracle 必须含这些条件。

先将现有 store 方法及测试 oracle 固定，抽取一个后端事务边界；不把整套数据库驱动暴露给 runtime。三库必须满足以下相同结果：

| 操作 | 必须在同一事务内完成的内容 |
| --- | --- |
| accept | 授权后检查 op_id、范围及完整指纹；重复复用首次结果；新操作同时写不可变正文、身份、冻结收件人及路由 generation、首次时间、绝对 TTL 和容量增量。容量拒绝或 COMMIT 失败不能留下已接纳身份或成功响应。 |
| claim | 先取得现有运行时预算，再选到期目标，条件更新为 running、递增 attempt_id，提交后才交给网络。只读取已预留数量的正文；数据库事务期间不得等待 Provider。 |
| settle | 按目标、running 状态及 attempt_id 更新一次；同事务更新结果计数、Sender 状态及冷却时间。invalid_token 仅在当前设备仍匹配冻结路由 generation 时删除受影响频道订阅。旧代回执不能修改新任务。 |
| ACK | 设备与 delivery_id 精确匹配，首次确认更新一次；移除可释放目标，最后消费者确认后释放正文。运行中的目标保留到回执结算；重复 ACK 返回零。身份历史保留，重复提交和恢复不能重建已确认目标。 |
| GC / 退役 | 正文到期与 30 天身份到期分开；保持现有每批 256 的清理边界。退役立即取消旧身份的可见性，分批清理订阅及目标；不把它们迁给新身份。运行中回执和其他收件人不受误删影响。 |

PG / MySQL 的写事务先锁 `ledger_usage` 单行，再按固定顺序锁设备、消息及目标；所有写入口使用同一顺序。单进程下仍保留此锁，保证容量判断与增量修改不可分离。第一版 claim 无需 `SKIP LOCKED` 或新租约框架。死锁、超时、连接中断均返回原始失败；提交结果不明时按同一 op_id 查询恢复，不能换身份重投。

SQLite 当前用触发器维护计数。适配时可采用显式事务增量，但每库只能有一个计数维护者，避免触发器与应用各加一次。复用等式：`messages = pending_targets > 0 的消息数`，`targets = 未 ACK 的 pending/running/retry_wait 目标数`，`bytes = 保留正文的 payload_bytes 总和`。终态 Provider 回执释放未完成任务容量，正文按 Pull / ACK 生命周期释放；不增加历史数量或字节硬配额。静态计数重算用于停写核验，发现差异应保留首个错误并停止迁移，不能自动修平后当作通过。

## 2. 类型、索引与迁移回滚

身份键保持精确、区分大小写的比较；MySQL 可使用明确编码的二进制键，避免默认排序规则改变去重。时间一律有符号 64 位毫秒数，不经时区转换；正文为原始字节，PG 用 BYTEA、MySQL 用二进制大字段，不通过数据库 JSON 重编码。所有唯一键冲突必须区分“已有相同操作”和“指纹 / 范围冲突”，不能用忽略插入错误代替授权和合同判断。

保留索引目标：op_id 唯一、delivery_id 唯一、目标 `(delivery_id, device_key)` 主键；`(provider,state,next_attempt_at,delivery_id)` 支持两个 Provider 的启动恢复；设备 Pull 按冻结的 `(accepted_at,delivery_id)` 顺序读 201 条，指定 delivery_id 单独走主键。PG 可保留未 ACK / 有正文的部分索引；MySQL 用 `(device_key,acked_at,accepted_at,delivery_id)`，正文到期可用生成的 has_payload 列加 `(has_payload,expires_at,delivery_id)`。这些只是待验证 DDL 方案：三库实际 EXPLAIN 必须证明目标查找与清理选择使用索引，Pull 不对整设备积压排序。身份到期、退役设备、订阅设备和注册别名到期也应有对应有界查找索引。

迁移按“停写、排空已拥有任务、快照、导入、核对、切换”执行，不引入双写。旧库主存储和 delivery sidecar 必须在同一停写边界采样。逐项映射消息 / 投递 / 操作 ID、首次 accepted/occurred/sent 时间、绝对 expires_at、指纹、冻结目标、路由 generation、Sender 状态和 30 天历史。显式迁入 ACK / consumed 事实；Provider 已接受不能当作客户端 ACK，缺失旧字段也不能猜成未确认。无法无损映射的旧记录先形成具体迁移阻塞清单。

回滚保留原库快照及迁移清单。目标库尚未接纳新写入时，可验证后切回原库；接纳新写入后，旧快照已经过时，必须停写并反向迁入新增身份、终态及 ACK 事实，或继续使用目标库，不能直接恢复旧快照制造重投。迁移及回滚均须验证同一 op_id 保持原 ID、首次时间和 TTL，ACK 后不复活。当前注册重试别名落 SQL、重启后仍可在十分钟内解析，是比主线内存别名更强的恢复行为；迁移说明须显式保留或另作已确认决定。

## 3. 三库同一 oracle，逐层取得证据

依次推进，前一层未通过不扩大测试：

1. 把现有普通 Sender / store 测试变成后端参数化套件，注入相同时间、身份和合成路由；比较规范化响应、正文哈希及逻辑表投影，忽略物理行序。覆盖完整字段、绝对 TTL、重复 / 冲突、容量边界、ACK 隔离、回执乱序、路由 ABA、无效令牌清理、身份退役、注册复用及有界 GC。
2. 在受控真实 PG / MySQL 上跑同一套 oracle、事务并发及 EXPLAIN；验证实际驱动的二进制键、affected rows、锁等待和回滚行为。SQLite 通过不能替代这一步。
3. 用受控旧版本三库样本逐库迁移，再做切换前及接纳新写入后的回滚演练；保留源身份、快照、迁移差异和首次失败记录。
4. 在 accept / claim / settle / ACK / GC 的提交前后注入断连、写入失败、空间或配额不足、进程终止；重启后验证旧数据完好、没有未持久化成功、旧回执不越代、ACK 不复活。明确区分提交未知与确认失败。
5. 最后复用相同合成负载、收件人数、历史深度和配置测压力；记录事务提交及 gate 等待、数据库错误、索引计划、当前容量、正文 / 历史实际空间与可复用空间。此时才能讨论实测结果，本计划不提供吞吐承诺。

真实凭据、真实 Provider 和物理设备后台统一留到设计收敛后的验证阶段；上述适配先使用合成数据及受控故障，避免把外部投递差异当成存储合同差异。

## 4. 普通消息稳定后再接其他类型

下一种类型只接三个 seam：输入规范化及指纹、不可变领域投影、目标展开策略。它们复用 accept/claim/settle/ACK/GC 和统一计数，不复制队列或另建状态机。Event/Thing 的生命周期、版本及合并键先形成独立合同 oracle，再逐种接入；Watch/WNS、private transport 和其他通道另行确认范围。本轮不实施这些能力，也不把普通消息测试通过解释为其他类型或平台已验收。
