# C6 Private 大消息：保留合法输入范围的方案评估

本次按用户后续要求先评估，不实施新拒收、不截断、不扩大帧上限，不改变旧客户端支持范围。评估基线为文档 HEAD `2581edbff10286a6e8dc82c1d8f4d47185de623c`，运行源码仍为 `9fc812b40880e0ffd2375b4c83bb920292bdf880`。下述是源码推导及建议，**没有新实现或新端到端通过收据，大消息交付缺口仍未关闭**。

先前提出的“超帧新发送/路由迁移原子拒绝”没有获准，不再把它列作默认下一步。原 canonical 正文、message/delivery/op 身份、first/accepted 时间、绝对 TTL、当前 owner 未确认义务继续保留；不把收到提示、Pull 成功或旧模式 ACK 当成完整正文已持久化。现有 Provider Pull 能力不收紧。当前 Private 模式本身尚无 HTTP Pull；Provider→Private 不能靠沿用旧 Provider HTTP ACK 能力解决，必须补受 Private 授权的正文读取，不能掩盖这一缺口。

## 现有客户端是否已支持

核对 Android `b831a5eadbe8f67b64535868af91aa74dbe1ba3f`、Windows/Rust `f39598ed7b1854584320f63f005f837c18e8a650`、Apple Swift `151d50cc859c969385d8ef93762ab98e362dd5aa`。Android/Windows 与候选均锁定 Warp `dbae3a80c8b796969cadc9045ee982a0a60c4d27`，不是 Warp 工作目录的另一个 HEAD。Windows 本次仅源码审计。

| 消费者 | 已有入口与确认语义 | 对 Private wakeup 的实际支持 |
| --- | --- | --- |
| Android Private | `notifications/PrivateChannelClient.kt:1516–1584`：DELIVER→`handlePulledMessage`→Room/scoped ledger→stream AckOk；新进程依靠同 delivery 重放去重。 | 不走 Provider wakeup 分流。`:386–408` 的 HTTP ACK drain 为 IDLE，所谓 wakeup recovery 只重连 stream。 |
| Android FCM | `InboundIngressRouteResolver.kt:15–32`、`ProviderIngressCoordinator.kt:99–134`：wakeup→V2 Pull→Store→持久 HTTP ACK outbox。 | 存储、HTTP 和去重代码可复用；不能直接把整条 Provider coordinator 当 Private 实现，否则有 mode/路由与确认差异。 |
| Windows/Rust Private（包括同源码平台入口） | `src/core/private_channel.rs:579–605,1072–1137`：直接 decode payload1→pipeline→stream ACK。 | 无 Private wakeup dispatch；`:273` 的 HTTP wakeup 受 WNS mode gate 限制。`:881–935` 的 HTTP Pull/SQLite ACK outbox 是可复用基础，不是当前 Private 行为。 |
| Apple Swift | Provider V2 Pull/持久 journal/Store/ACK worker。`ChannelSyncController.swift:436` 的同名 Private-state 同步实际是 Provider route。 | 没有查到 Private 数据面，不据此新增 Apple Private 承诺。 |
| MQTT 外部接收端 | MQTT5 JSON 下行与 PUBACK；候选 [映射及确认](../src/private_mqtt.rs:161)。 | 没有仓库内已核实的 wakeup 消费者。成功 PUBACK 是传输确认，不能直接证明第三方应用持久化。 |

Textual 是 SwiftUI 富文本库，不是消息接收端。现有 wire2/payload1 没有 wakeup 帧类型；HELLO 仅传版本列表，没有 peer frame/wakeup capability。虽然 core `HelloCtx.metadata` 存在，锁定 profile 并未将它编码上 wire。Android JNI 和 Windows 当前只 advertise payload `[1]`。

因此不能向旧 Private 客户端直接发送带 fallback title/body 的 Provider wakeup map：它可能将提示当正文保存并 AckOk，过早清除真正正文。两条候选路线都必须显式协商，保留旧小帧原行为；没有一条能透明修复未升级旧客户端的大消息交付。本次不决定退役版本，也不把“保留 pending 等升级”算作完成。

## 路线 A：有界提示、授权的 exact Pull、持久化后确认

**推荐先做 A1，保留 Private 现有的持久化后 stream ACK。** 复用 V2 非破坏读取的 JSON 形状、HTTP 基础设施及生产 Store/去重入口，但新增 Private 的明确授权分支；它不是零修改开关，也不声称复用了持久 HTTP ACK outbox。

1. 新能力客户端接收固定小型 Private 提示，仅引用原 delivery 与当前 capability；在持久化前分流，不进入普通正文 parser。服务端只做发送时投影，不改 canonical row、指纹、时间或 TTL。
2. V2 URL 可继续使用，但缺 Private capability 的请求仍保持原 Provider 语义。新增 exact-delivery 只读分支，核对 current Pull owner、route generation、delivery epoch、claim token/group、退休/合并和 TTL。不能直接把三库查询的 `delivery_mode='provider'` 改为 `OR private`，更不能拿 device key+ID 映射为任意当前 grant。
3. 完整正文进入原生产 Store/scoped ledger，落盘成功后再发原 stream AckOk。数据库仍用原 `private_ack` 强能力，slot 持有到 ACK/release COMMIT；收到提示或 HTTP 读取完成都不归还预算。
4. 网络/存储失败、断线或客户端进程退出不能成功确认正文。服务端保留原义务，重连重新授予能力并重放同一身份；客户端已持久化则去重后确认。旧 epoch/grant 不能消费新路由。

现行 [V2 Pull](../src/store.rs:1638) 一次 batch 可读取 201 条并返回 200 条，没有响应字节预算；32KiB 只约束 HTTP 请求。Android `ChannelSubscriptionService.kt:725–726`/Private helper `:2441` 使用 `readText()`，Windows `gateway_client.rs:320–321` 使用 `response.bytes()`，Apple 用 `URLSession.data`，均不能作为已有的有界大响应保证。A1 先只取 exact 一条，必须按序列化上界限定服务端构造和客户端累计读取，并保留 handler permit 到响应 EOF/drop；不能把整个积压改为 HTTP batch。

另外 Android JNI 的 ACK decision 默认 10 秒，既有 HTTP read 15 秒、Private helper read 20 秒且最多 3 次尝试。不能原样同步套入 stream callback，更不能靠延长 ACK deadline 掩盖。一次有界 fetch、持久化和 resolve 的总和必须受剩余 ACK 决策预算约束；失败使用不消费正文的 Ignore/Error 路径保留并重放，不能误用可终结目标的 InvalidPayload。超时后已完成本地持久化、但未成功发出 ACK 的记录继续通过同 ID 去重恢复。必须用实际 native 路径验证，不能只用 HTTP stub。

**A2 是完整的 V2 HTTP ACK 路线。** 如果还要求断开 Private stream 后由持久 HTTP ACK outbox 独立完成确认，则需新增 Private HTTP ACK 能力及持久 destination：outbox 保存 mode/owner/epoch/grant，能力失效后为同 delivery 刷新当前 grant，而不是重建消息或把旧 ACK 返回 0 当成功。服务端需让 HTTP ACK 与 stream ACK 共用同一有界 owner/COMMIT 释放点。现有 Provider outbox 仅 device key+IDs，不可原样承担这些语义。A2 的改动和交错验证范围大于 A1；本次没有替用户选定 HTTP ACK 必须覆盖 Private。

## 路线 B：完整 DELIVER 的保守帧上界

不能用单个 33057B 样本证明上限。这里给出当前普通 HTTP 路径的**保守足够上界，不是 tight 最大值，也不是已批准的产品默认**：

- `B` 为原 HTTP 请求字节上限，当前默认 32768；`U` 为规范化 `public_base_url` 的 UTF-8 字节数。配置目前没有独立 U 长度上限，所以没有配置无关的固定帧常数。
- canonical 顶层字段最多 `N=21`，key 总字节 `K=173`。普通输入还会补 ID、op_id、时间、版本、severity、base URL 等。
- 锁定 serde_json `1.0.151` 使用 zmij `1.0.23`，finite formatter 的 buffer 上限为 24 字节。metadata 短指数数字可能规范成长小数；负零单独也会规范化。按最短合法 entry 成本及 24B 输出保守记 4 倍用户输入，而非假设规范化永不增长。其余列表/字符串的输入 JSON 已支付一次转义成本。
- 令 canonical map 中 key+value 的原始字符串字节和为 `X`，有 `X ≤ 4B + U + 520`。postcard version/map/字符串长度 varint 保守增加 422B；DELIVER 的 seq/ID/payload 长度及 type/flags 增加 55B。因此 **`F_binary ≤ 4B + U + 997`**。F 包括 type/flags 2B，不包括 TCP/QUIC 的 u32 长度前缀 4B。
- canonical JSON 再序列化按每字节最多 6B 转义及字段结构预算，`C ≤ 6X + 7N + 2 = 24B + 6U + 3269`。MQTT whole packet 另保守增加 topic、QoS packet ID、wrapper、properties、remaining-length 等 512B，得 **`F_MQTT ≤ 24B + 6U + 3781`**；MQTT 不能直接沿用二进制 DELIVER 上限。

例如只作部署包络示例 `B=32768,U≤4096`，可证明 binary≤136165B、MQTT≤814789B，分别向上取 256KiB、1MiB 是足够的候选值。**U≤4096 尚不是新增配置限制，这两个值也没有实施或通过边界验收。** 这份保守证明不能据此声称 64/128KiB 一定足够；采用前应进一步收紧推导并用锁定 Rust 序列化器做浮点、转义、metadata、images/tags、最长 ID/时间/base URL 的边界生成验证。直接调用库 accept 绕过 HTTP 的任意大对象不在 B 的证明范围内；既有行也必须按实际持久内容核验，不能被新估算截断。

完整帧同步修改至少包括：锁定 Warp transport reader/writer/WSS 配置及 client Welcome 校验/server clamp；候选 runtime Welcome、WS upgrade、MQTT parser/writer/CONNACK；Android JNI 所锁 Warp、Windows/Rust 所锁 Warp；新能力协商、客户端内存及 ACK 队列的字节预算。生产旧 Gateway 还有独立 TCP/WS 常数，不能因候选改动就声称它已兼容。通用 MQTT 客户端另需 peer Maximum Packet Size 与 payload schema 支持证据；CONNACK 的服务端接收上限不等于对端接收上限。

QUIC 的 64KiB flow-control window 不是 frame cap，需与较大 frame 的分段传输、停机和连接级总缓冲一起验证。不能把 8192 连接的单帧上限从约32KiB直接提高到256KiB/1MiB而保持“内存基本不变”的说法；增加累计字节 reservation、限制同时组装帧数量及 ACK 队列预算是路线 B 的组成部分。

## 比较、推荐和下一步验证

| 项目 | A1：提示+exact Pull+原 stream ACK | A2：再接 Private HTTP ACK | B：完整有界 DELIVER |
| --- | --- | --- | --- |
| 复用程度 | 复用 V2 只读 JSON/HTTP、现生产 Store、Private ledger/stream ACK；增加授权读取及 wakeup dispatch。 | 再增加 Private ACK capability 和持久 HTTP outbox。 | 保留现 stream 语义；同步修改 Warp/transport/客户端大小与协商。 |
| 资源 | 提示固定小；正文只在有界 exact HTTP fetch 中传输。若 claim 仍加载 canonical payload，原 owned 内存并不会自动消失，后续可做 metadata-only projection，但需单独验证。 | 另有有界持久 ACK 义务、失效能力刷新和 COMMIT 结果背压。 | 不多一次 HTTP，但单连接解析/编码、重传、跨 JNI JSON 和待确认字节增加；数量上限不能代替字节预算。 |
| 故障/语义改动 | 保留持久化后 stream ACK 和重连重放；新增 fetch 失败/10s 决策边界。 | 跨 stream 生命周期确认，迁移/合并/重启交错范围最大。 | 正文/ACK 模型变化最少；较大帧的慢连接/资源耗尽必须重验。 |
| 兼容 | 当前 Private 客户端未支持，必须正向协商；旧客户端不能自动收到 hint。 | 同左，且 outbox 协议也要升级。 | 当前旧 reader/Welcome 硬32KiB，扩大服务端上限不能透明兼容。MQTT 外部消费者另核。 |

推荐 **A1 作为首先实现和验证的路线**，保持合法发送范围且避免把大正文全面搬入长连接帧；是否进一步做 A2 取决于是否要求 Private 独立 HTTP ACK outbox。B 是完整帧备选，不能仅按样本加常数。两路都需要明确支持的客户端版本/能力协商，不擅自宣布旧版退役；当前没有一种已验证的零客户端修改方案。

实现前应将新能力的兼容策略具体化；实现后至少重跑三库合法32KiB/转义及数字边界、已有超帧记录恢复、actual Android Room/Keystore、Windows源码合同、断线四窗口、Pull超限/超时、持久化失败、ACK未知/失败/重启、迁移/退休/合并、旧Provider ACK不能消费Private、global byte/slot上限和空闲唤醒。MQTT 的新提示/确认模型不能在第三方消费者未确认前默认为支持；本次不改变它。真实 APNs、物理 Watch、迁移/回滚及断电仍留统一验收。

本次仅源码审计和保守推导，没有启动数据库/设备/新容量 lane，没有覆盖或升级原失败收据。普通 Private 大消息仍是阻塞项，不进入其他消息类型。
