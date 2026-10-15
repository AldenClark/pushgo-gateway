# C：普通消息合同候选

独立单机普通消息 crate，已实现 SQLite 与 PostgreSQL 原生存储；可执行 fixture 只连接本地 Provider Mock。PG 在真实 PostgreSQL16.14 的全新隔离测试库验证，使用 tmpfs，不代表旧库迁移或断电验收。保留 MySQL 产品范围，但尚未实现新 C 的 MySQL 适配。复用既有 Remote 凭据 owner/Token Service；真实 APNs 未验证。Event、Thing、Watch、WNS 不在本轮范围。带 thing_id 的输入明确拒绝。

## 已实现的普通消息边界

`POST /message` 接受可选 op_id、body、severity、绝对 TTL、occurred_at、URL、images、ciphertext、tags、metadata，按主线规则规范化；拒绝由 Sender 指定 message_id。省略 op_id 每次生成新操作，显式 op_id 的相同输入保持同一消息、投递身份、正文和首次时间，冲突不修改已接纳结果。省略 TTL 不向客户端补写 TTL；账本默认采用现行 Small 配置的 7 天正文/投递期限，显式绝对 TTL 最多到首次接纳后 30 天。

正文 TTL 与身份历史是两个维度。本轮用户明确选择完整 30 天身份/指纹/状态历史，C2 的 30 天来自这一选择；不是所有主线 profile 都有 30 天去重窗口。主线 Small 的队列默认 TTL 和维护去重保留期分别均为 7 天，Public 分别均为 30 天（`src/runtime_config.rs:191,213,283,305`）；`MaintenanceCleanupConfig::default()` 的 30 天不覆盖正数的 profile 配置。

正文保存一次，全部有效收件人用一笔 INSERT SELECT 事务冻结。Direct、V2 Pull、直接单条 ACK、V2 批量 ACK 共用稳定身份和可信配置 base_url，支持路径前缀；V2 外层 delivery_id 为准。`GET /send_status/{op_id}` 与 fixture 目标诊断分离。普通客户端所用 ACK 路径不意味着对退役客户端新增兼容承诺。

频道密码保存为主线格式的加盐哈希，兼容旧 Argon2 验证，旧算法执行位置有界。共享 Bearer 认证先于 JSON 解析；关闭共享认证时沿用现行密码接口每 IP 每分钟 60、全局每分钟 1200 次限制。错误不返回数据库错误、凭据或请求正文。路由版本随实际变更递增，旧 A→B→A 回执不能删除新订阅；失效令牌只清理匹配原版本的受影响频道订阅。

凭据复用主仓库真实 FCM/APNs Remote owner、Token Service client、缓存、single-flight 和强制刷新；Provider 保留候选有界读取。合成凭据经本地 Token Service/Provider Mock 实测；真实服务未验证。设备/频道完整普通控制面、订阅变化、coalescing、logout 已接入，具体合同见 [C3 报告](docs/c3-results.md)。

## 所有权和资源

库与 fixture 都以 Config 为默认来源。当前 H32/Q32 是实验默认，可配置安全上限；不是已批准的产品最大值。两个 Provider 驱动按需持有 FuturesUnordered 工作，不预建全部 worker。领取 reservation 在加载正文前占预算；工作持续拥有执行位置直到结果事务提交。退避留在 SQL，不占网络位置；没有动态目标控制器和周期空队列扫描。关闭时先释放 attempt/receipt，再等待已保留的 claim，避免持锁等待环。

输入沿用 32 KiB；128 个连接在创建连接任务前受限，HTTP/2 每连接默认通告 1 个并发 stream，使合规客户端在协议层排队。保留原 128 个请求总接纳许可；控制响应另用 16 个工作许可有界等待，等待时已持总许可且尚未解析 JSON，没有新增 16/112 并发拒收。许可随响应 Body 到 EOF、错误或 drop 释放。Provider 回复最多累计 16 KiB，保留状态与 Retry-After，2xx 的诊断正文失败不触发重发。Provider 连接池按安全上限配置，连续积压保留，真正空闲后释放，无额外清理定时器。

未完成冻结消息 10,000、待执行 Provider 目标 1,000,000 沿用主线边界；事务计数避免每次接纳全表 COUNT/SUM。实验聚合正文限额默认关闭。ACK 释放正文和投递队列，进行中工作保留到结果提交；身份、指纹和状态完整保留 30 天。过期正文和身份清理各采用有界 256 条批次，索引不把整段历史加载到内存。

**本轮没有历史数量或字节硬配额。磁盘随 30 天接纳量增长，不能声称存在固定磁盘上限。** 逻辑删除、可复用空闲页、WAL checkpoint 和文件实际大小分别测量。SQLite WAL+FULL、单连接和短时进程内 mutation 锁保留；规范化路径 OS 文件锁阻止多进程误开。没有分布式调度、选主或租约。

## 验证与复现

在 prototype 目录可用缓存依赖运行 `cargo test --release --locked --offline --lib`。C3 最终写事务修复的原生 82 项通过；两个 ignored 历史测量在同一 schema 的冻结 `10e59ec` 显式各跑一次通过，不计为新二进制的执行结果。C2 的 Clippy 收据保留；C3 不冒用它声称新依赖接线已完成 strict Clippy。

C3 的 Apple 未改生产 controllers/GRDB 和 Android 未改生产 repository/Room/AndroidKeystore 均直接连接本地候选，包含独立进程恢复；wakeup 由捕获的真实候选 payload 进入生产处理路径。真实系统 APNs/FCM 调度、物理 Watch 后台、PG/MySQL 实库仍未运行。

C3 证据在主仓库 `build/quality-results/c-client-loop-gate-20261015/`，源/二进制/工具链对应关系和首个失败均保留；旧 C32/C2 对照产物不替换。最终交付见 [c3-results.md](docs/c3-results.md)，先前报告 [c2-results.md](docs/c2-results.md) 保留历史含义。验证源码在 `validation/c3/`，不含二进制、数据库、日志或凭据。

SQLite 写事务显式 `BEGIN IMMEDIATE`，沿用 3 秒 busy timeout。预算内写锁释放可继续；超时仍失败关闭并依赖持久化身份和独占 owner 重启恢复，不承诺任意长阻塞在线重试。没有增加重试队列或放宽接纳成功条件。

C4最终实现、客户端闭环、数据库与资源边界、保留失败及产物身份见 [C4结果](docs/c4-results.md)、[PG实现](docs/c4-postgres.md)、[有限容量复核](docs/c4-capacity.md)。普通fixture为冻结8d458bbf；复用target当前可能是83ab543e测量构建，不要混用。后续MySQL须等待本轮审查；没有自动合并、推送或部署。
