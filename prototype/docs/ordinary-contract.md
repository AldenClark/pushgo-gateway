# 普通消息合同与验证边界

比较基线为 Gateway `dfb6b7c2`，原 C 切片已保存为 `283acf5`。这里描述本候选的普通 FCM/APNs 消息；不是主线替换或发布承诺。最终测试结果、二进制身份和容量数据见 `c2-results.md`。PostgreSQL/MySQL 仍在产品范围，C 当前仅实现 SQLite。

正文 TTL 与身份历史保留期分别规定。本轮用户明确选择完整 30 天身份/指纹/状态历史；C2 采用这一合同，同时省略 TTL 时沿用 Small 的 7 天正文/投递期限。不能把它表述为“主线全部 profile 的现行去重窗口都是 30 天”：`src/runtime_config.rs:191,213` 的 Small 分别为 TTL 7 天、维护去重 7 天，`:283,305` 的 Public 分别为 30 天、30 天。`app.rs:481,491,506-507` 将 profile 值传给配置和维护；正数 7 天不会被默认值归一成 30 天。无 private runtime 时 Sender 状态期限另回退到默认 30 天（`submit_runtime.rs:29-34`），也不改变维护去重窗口。

| 合同 | 原 C 切片的差异 | 当前实现及对应原生 oracle |
|---|---|---|
| 发送输入 | op_id 必填，遗漏 severity、URL、images、ciphertext、tags、metadata、occurred_at；TTL 是相对秒数 | `sender.rs` 复用主线规范化规则；可选 op_id；拒绝 Sender 提供 message_id。`ordinary_full_fields_absolute_ttl_identity_and_auth_preserve_first_acceptance`、`sender_router_preserves_full_fields_and_generates_distinct_omitted_op_ids` |
| 输入校验 | 不能证明完整合法输入被保留 | 32 KiB 请求体沿用主线；字符串 trim、images/tags 去重及既有数量/长度，metadata 标量及键约束；不新增 URL scheme、图片格式或密文格式校验。`sender::tests`、`http_timestamp_validation_and_fields_match_ordinary_boundary` |
| 操作与消息身份 | 只验证简化字段 | 显式 op_id 相同规范化输入复用 message_id/delivery_id；跨频道冲突和正文冲突分别返回既有错误；未提供 op_id 每次新建。认证先于去重；重复/失败不改首次时间及绝对到期时间。`complete_fanout_fixed_identity_conflict_and_ack_never_replays`、完整字段 oracle |
| 绝对 TTL | 默认 35 天、相对秒数 | 秒/毫秒/数字字符串归一到绝对毫秒；省略时 wire 仍省略，账本采用现行 Small 配置 7 天；显式 TTL 上限为首次接纳后 30 天，过去时间不变成未来。`past_absolute_ttl_is_failed_without_jobs_and_replays_first_identity`、`pending_expiry_fails_but_preserves_sent_status_and_stable_identity` |
| 状态 | 只有 fixture 目标诊断 | `GET /send_status/{op_id}` 返回现行公开字段；Provider receipt 与客户端 ACK 分开计数；superseded_route 沿用主线非失败终态，不伪造 Provider accepted。`mixed_expiry_waits_for_owned_receipt_then_reports_partial_failure`、`runtime_superseded_route_is_nonfailure_terminal_like_mainline`、`pending_client_ack_closes_queue_without_fabricating_provider_acceptance` |
| Direct / Pull / ACK | V2 内外重复 delivery_id；ACK 不释放容量 | 同一规范正文投影 Direct 和 V2；外层 delivery_id 为准；V2 非破坏性 Pull、显式批量 ACK；保留当前客户端直接单条 ACK 路径。配置 base_url 含路径前缀，拒绝 Sender 覆盖。`ordinary_router_supports_prefixed_legacy_and_v2_clients`、`provider_receipt_and_client_ack_are_independent_in_both_orders` |
| 设备登记 | 每次 register 都新建身份 | 当前客户端所用已有 key 同平台登记复用身份与路由；跨平台替换创建默认 private 身份并退休旧身份，不迁移旧订阅或消息；旧身份立即失去访问权限，物理清理按批进行。10 分钟 SQL 别名逐点查询并验证目标仍有效，重启保留别名比主线内存别名更强。`repeated_register_reuses_current_ordinary_identity_and_route`、`replacement_retires_in_batches_preserves_other_recipient_and_owned_result`、`retirement_queued_targets_are_immediately_hidden_and_physically_drained_in_batches` |
| 完整设备/频道控制面 | 原切片仅有 register/route/subscribe | 本轮仍只接入所列普通消息合同所需入口；主线 channel/sync、channel/unsubscribe、设备删除等完整控制面未接入，NOT RUN，不能声称现行客户端全部功能可以切换到 C。正式替换前需补独立差异与验证，不影响本轮已验证发送/投递路径的范围说明 |
| 密码与访问保护 | 频道密码明文 | 当前加盐 BLAKE3 格式，兼容旧 Argon2 验证且 blocking 执行有界；共享 Bearer 先于 JSON；公开密码入口沿用每 IP 60/min、全局 1200/min。数据库/凭据/正文不进入公开错误。`security_tests`；旧明文实验数据库拒绝打开 |
| 路由与失效令牌 | 旧回执可能作用于新路由 | 冻结 route_generation；旧 A→B→A 版本不能删除新订阅；失效 token 只清理原频道、原版本。`current_invalid_token_unsubscribes_only_affected_channel_and_keeps_history`、`token_aba_generation_rejects_old_attempt_and_blocks_stale_invalid_cleanup` |
| 凭据 | 只有固定 Mock token | 注入获取与强制刷新接口，无新增缓存；获取失败不发 HTTP，刷新只供下次持久化尝试，不内联重发。`credentials_tests`；真实 Token Service/Provider 接线未实现，当前构造入口仅允许 loopback Mock |
| 保留与容量 | 35 天全部保留，ACK 不释放容量 | 按本轮用户明确选择保留完整 30 天身份/指纹/状态；Provider 终态释放未完成 manifest/Provider job 预算，ACK 释放保留正文和队列；running ACK 保留到 receipt。没有历史数量/字节硬配额，不提前淘汰身份。`provider_receipt_releases_pending_capacity_and_ack_releases_bytes_preserving_history`、`bounded_expiry_skips_compact_history_and_maintenance_keeps_unexpired_identity` |
| 原子接纳与写失败 | 只有部分事务行为证据 | 单笔事务冻结正文与全部有效收件人；容量拒绝不创建身份/部分目标；只有 COMMIT 成功才返回成功和计数。真实 SQLite FULL、延迟外键 COMMIT 失败、重开保留既有消息分别验证。`atomic_target_cap_and_payload_cap_survive_concurrent_admission`、`sqlite_full_admission_never_reports_success_or_loses_prior_accepted_work`、`deferred_sqlite_commit_failure_never_reports_success_and_preserves_prior_work` |

`legacy` 是已有代码/测试的命名。这里保留受支持客户端实际使用的直接 ACK 和协议路径，不向已退役客户端或旧 Gateway 扩大兼容承诺。Private 注册的完整私有发送/迁移链路、Event、Thing、Watch、WNS 不在本候选的发送范围；带 thing_id 明确拒绝，不能悄悄按普通消息成功。

## 资源所有权

Config 是库和 fixture 默认值的唯一来源。H 是每 Provider 的可配置安全上限；Q 是单次领取数量。当前 H32/Q32 只是实验默认。目标并发沿用 H，没有动态控制器。可观测项分别为安全上限、领取 reservation、已接管 attempt、实际网络在途、结果待提交、连接及 Provider pool owner。

领取先预留位置，再加载正文；attempt 从接管一直持有位置到 receipt COMMIT。数据库阻塞时结果最多占已有 H，阻止继续无界领取。retry_wait 存在数据库，不用睡眠 worker 占网络位置；真实需求回落后 Futures 和空闲 Provider Client owner 释放。退出先丢弃 receipt/attempt，再等已保留 claim，避免互等。

Provider 回复最多累计 16 KiB，按块读取；溢出/截断保留 HTTP 状态及 Retry-After；已收到 2xx 不因诊断正文坏掉而重发。请求体 32 KiB、连接 128、每连接通告 HTTP/2 stream 1 和窗口 65,535。HTTP 保留原 128 个总接纳许可；控制响应另用 16 个工作许可有界等待，等待时已持有总许可且尚未解析正文。许可一直跟随响应 Body 到 EOF/drop，不能因 handler 返回而提前释放。没有新增 16/112 并发拒收。合法尺寸不因 HTTP/2 设置变小，合规连接按协议排队。这些连接/执行数仍是实验运行配置，不是新批准的产品最大值。

单频道既有最多 32 个订阅者；fanout 在 SQL INSERT SELECT 中一次冻结，不在内存展开整个历史。未完成 manifest 10,000 与 pending Provider jobs 1,000,000 沿用主线所有者，已完成但尚未 ACK 的 Pull 正文不属于这两个计数。事务 trigger 维护计数，不为接纳执行全表 COUNT/SUM。索引覆盖领取、设备有序 Pull、到期正文、身份期限、退休设备与其订阅；精确 Pull 走主键，不排序整个设备积压。

正文清理每批最多 256 个消息，身份每批最多 256；退休设备每批最多 256 个目标、256 个订阅。查询返回和内存批次有界不意味着总数据库工作恒定：例如大量过期候选过滤、现有历史与 B-tree 高度仍会影响工作量，必须结合测量说明。维护不拆分已接纳 fanout，也不提前删除有效幂等身份。

**无固定磁盘上限。** 完整 30 天历史、TTL 内尚未 ACK 的正文/目标及 SQLite 页/WAL 都落盘；没有新的历史满额拒收策略。历史量化单独给出 op_id 宽度、插入顺序、表/索引、fanout、逻辑删除、free pages、checkpoint 后文件大小与重新使用空闲页。FULL oracle 限制 SQLite max_page_count，并没有填满宿主磁盘；COMMIT oracle 使用原生延迟外键失败，并不等同真实 I/O、断电或文件系统故障。

## 客户端恢复证据的层次

协议级 Rust 测试证明 Direct/V2/ACK、存储与重开；不能替代应用入口。Apple 单独运行真实捕获的过大消息 wakeup，经未改的 `NotificationIngressController` 应用控制器、磁盘 GRDB、持久 ACK 503、全新进程和原退避后 ACK 200；在发出 ACK 前独立检查已持久化正文及 leased ACK。它没有经过系统 APNs 派发或物理设备后台。

Android 原生测试经过未改的 `InboundMessageProcessor.process` 默认 hooks、磁盘 Room、过滤 Pull、事务失败不 ACK、503 后 ACK outbox、数据库/仓库重开与按原 Gateway/device/contract 排空。它没有重启整个应用进程，也没有证明 FCM Service、WorkManager 调度或物理后台。Android 使用本地协议 stub；C2 服务端协议由 Rust 测试独立绑定。原生附加测试源码和 runner 应与最终报告的源哈希一起保存。

下一阶段先将这些普通消息不变量映射为 PostgreSQL/MySQL 的事务、计数、索引、锁与升级/回退测试；三库相同 oracle 通过后再接其他消息类型。真实 Token Service、APNs 和物理后台集中验证另列，不能由短 Mock 容量结果推定。
