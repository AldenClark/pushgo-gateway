# C7：Private 固定帧上限与配套升级

本轮沿用完整 DELIVER 和持久化后 stream ACK。没有增加能力协商、提示/Pull 协议、分片或 ACK 路径，没有缩小合法 HTTP 输入。Gateway、Warp、Android JNI 与 Windows/Rust 必须配套升级。旧 Warp `dbae3a80c8b796969cadc9045ee982a0a60c4d27` 的客户端仅接受 WELCOME 公告字段 `max_frame_bytes≤32770`；新版公告为131072，因此会在 WELCOME 校验阶段拒连，即使没有大消息。这是公告值校验，并非 WELCOME 帧自身长达128KiB。本轮不承担新旧 Private 混用兼容性。

## 固定限制的含义

| 层 | 本轮限制及含义 |
| --- | --- |
| HTTP 发送请求 | 保持 32768 字节；包含整个输入 JSON，不是 body 字符数或业务消息序列化后的大小。 |
| canonical 业务消息 | 持久化身份、时间、TTL、路由等元数据及规范化 JSON 会改变大小；不按 HTTP 字节数截断。 |
| Warp 完整帧 | 共享 `MAX_FRAME_BYTES=131072`（128KiB），包括 type/flags 的 2 字节，不包括 TCP/QUIC u32 长度前缀的 4 字节。不是 128KiB 正文限额。 |
| TCP / QUIC | 声明长度先校验再分配；writer 在写长度前拒绝超限帧。QUIC 的 64KiB flow-control window 是分段流控，不是完整帧上限。 |
| WSS | 同时限定单个 WebSocket frame 与重组后的 message；候选 upgrade 的 read buffer 固定 16KiB，不随最大帧预分配。TLS 与 WS 外层开销不计入 Warp 帧限额。 |
| MQTT5 | 独立限定完整 MQTT packet（含 fixed header、remaining-length、topic/properties、JSON wrapper），同为 131072 字节。CONNACK 声明的是服务端接收上限；当前未按 CONNECT 的 Maximum Packet Size 限制出站，不能据此保证第三方接收端支持。MQTT 不是 Postcard DELIVER 的另一个长度前缀。 |

64KiB 是实际执行的第一候选，失败后保留原收据，没有按单个 33057 字节样本增加 287 字节。真实合法 32768 字节 HTTP 请求中，短指数 metadata 经现有 Rust JSON 规范化生成 80901 字节 canonical 内容、74901 字节完整 DELIVER，超过 65536；128KiB 是针对该实际失败的最小简单固定余量调整。该样本及普通文本、中文、多字节、转义测试通过，不把几个样本写成任意配置/任意第三方 MQTT 客户端的数学保证。没有新增合法发送拒收策略。

## 所有权和内存

保留现有连接上限、认证时限和账本预算。TCP/QUIC 空闲 reader 等待 4 字节前缀，不为每个连接预分配 128KiB；仅验证长度后为活动帧分配。WSS 原默认 read buffer 会预分配 128KiB，候选因此显式使用 16KiB，这是本轮发现并修复的实际资源缺口。MQTT 保留现有渐增读取、完整包硬上限和有界命令队列。

活动连接组装的最大帧内存会随上限增加；不能声称连接数量有界就等于内存不变。现有 slot/连接数仍约束同时持有对象的数量；本轮未引入新的预算或调度框架。Provider H32、领取前 reservation、等待 receipt COMMIT 仍占同一预算均未改变。Android/Windows 生产流式 ACK 的合同是在客户端持久化完成后返回，服务端提交 ACK/release 后归还 slot；解析失败或重连不虚假确认正文。第三方 MQTT 的 PUBACK 仅为协议确认，不能据此证明其应用已持久化。

消息/投递身份、首次时间、绝对 TTL、冻结收件人、当前 Pull owner 与 frozen receipt owner、路由代际/退休 epoch 保持原合同。30 天身份历史没有数量/字节硬配额，不提前淘汰；磁盘没有固定总量上限。

## 支持范围

Android 生产 Private 客户端使用 Warp/JNI TCP TLS；Windows/Rust 使用其生产 Warp transport 路径。Apple 当前没有 Private 数据面，本轮没有扩展。候选服务端含 TCP、WSS、QUIC、MQTT5 入口，测试须按入口单独报告；服务器协议测试不能替代 Android/Windows 的生产客户端持久化、ACK 与进程恢复证据。仓库内没有已核实的 Android/Windows MQTT 消费者，不新增第三方 MQTT 产品承诺。

本轮构建与执行的准确版本、首次失败、最终覆盖和环境限制见 [C7 结果](c7-results.md)。C6 报告是冻结历史记录，其中推荐 Pull/协商的方案已被本轮用户明确选择的固定帧配套升级取代，不据旧建议新增协议。
