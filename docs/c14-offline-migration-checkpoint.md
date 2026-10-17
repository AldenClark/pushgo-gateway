# C14 离线迁移：停在旧数据语义检查点

**尚不能验收迁移或进入下一项客户端联调。** 固定 main 的合法零收件人成功请求会立即删除原请求指纹、正文及 op 到 delivery 的关联；仅凭旧数据库无法无损填入 C 的冻结身份合同。本轮按“遇到无法恢复的旧数据语义即停止”收口，没有用时间猜配、当前订阅重算、伪造指纹、丢弃历史或新身份绕过。

## 基线与本轮改动

工作树 `/Users/ethan/Repo/PushGo/gateway/build/quality-results/c10-product-ordinary-20261016/workspace`，分支 `codex/gateway-c-product-ordinary-20261016`。起点 `7542a6bf50fff69417820b4c0e5ef0ba96b0190b` 干净；main 主树仍为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6` 且干净。349 个运行文件逐项匹配 `0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886` 的 C12/C13 清单。本轮只增加两个测试辅助文件及本文；没有修改普通运行链、依赖、SQL、配置、预算或启动护栏，没有实现部分转换后宣称可交付。

证据根 C14OUT：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c14-offline-migration-20261017`。最终提交/工作区、源码/命令/产物 hash 见 `audit/final-state.json`、`artifact-manifest.json`、`verification-catalog.json`。C13 三组 P/C、六次有效运行和旧 main in-flight 失败保持原收据；本轮没有重启性能比较或修旧 main。

| 正常无 QA 产品 | 对应提交 | SHA256 |
| --- | --- | --- |
| M-main | `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6` | `5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077` |
| C-final | 运行源码 `0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886` | `643bdd9789d02c97adf2af0a493b70f230927d0b35e8a98bcada369becf3a4fe` |

复用 C12 封存的正常产品二进制并重新校验，没有本轮构建。原构建为 Rust1.97.1/aarch64-apple-darwin、dev/default features/noQA、`CARGO_INCREMENTAL=0`。本轮 macOS27.0.1/arm64、Python3.13.14；Python 观察器 SQLite3.53.1 不冒充 Gateway 内嵌 SQLite 版本。没有启动外部 PG/MySQL；磁盘始终高于 4GiB+512MiB 保护线，未清理缓存或历史证据。

## 最小源契约与阻塞

源范围只审查固定 main、schema `2026-08-20-gateway-v12` 及其实际 migration 清单。其他历史版本未验证。**当前没有任何形态获得“迁移已支持”的结论**；下表是必须满足的映射条件，不是已实现转换器。

| 事实 | 旧来源 | C 要求及限制 |
| --- | --- | --- |
| 消息身份、scope、首次时间 | `semantic_id_registry`、`sender_submit_status` | 保留原 message/op/channel/thing scope；状态行尚在时 accepted_at 可恢复，不能改为迁移时间 |
| 投递身份、指纹、完整输入、冻结目标 | `dispatch_op_dedupe`、`dispatch_submission.payload_blob` | 原有 op/delivery 关联和指纹必须可核验；manifest 携带 request/dispatch_targets。源旧指纹算法与 C 不同，不能直接当作新指纹；未实施版本适配 |
| 正文与绝对 TTL | manifest、Private payload、Provider/Pull payload（视阶段） | 必须保留真实业务 expiry；sender status 的 expires_at 是状态保留期限，不能代替消息 TTL。正文已释放不应重建正文 |
| 待交付及已完成目标 | manifest、Provider outbox、Private outbox、Pull 队列 | 逐目标对账，已 ACK 不复活；表中没有一行不能自行推导为已 ACK 或零目标 |
| 发送中、租约、重试、外部结果未知 | Provider job/lease generation、run token、Private claim/attempt 等 | 停进程不能证明外部未生效；不能一律重置 pending。本轮尚未转换/故障验收 |
| 30天身份保留 | 旧 semantic/dedupe 的原创建时间及既有清理配置 | 不以迁移时刻重启窗口，不提前清除；状态行的7天期限与身份历史期限不能混淆 |
| 共享业务 | semantic/status/manifest、Provider outbox、Private/Pull、Live Activity/Widget 等共享表 | Event/Thing/Live Activity/Widget 仍需保留。此次没有删除或改写任何共享记录；没有用仅普通样本声称共存已验证 |

最小复现全部来自旧 main 正常 API，无业务 SQL 注入：注册 `mqtt` 设备 → Private 路由 → 创建频道/订阅 → 取消订阅 → 两个不同 op 各发送一次。两次 `/message` 均 HTTP200/success，返回不同 message_id；状态为 `failed/not_attempted`，表示受理成功但没有目标，不能称送达。

`repro-c/missing-source-facts.json` 逐消息保存 op、message、accepted_at、状态及期限，并逐表核对：两条 semantic identity 保留，所有普通 manifest/op/Provider/Private/Pull 责任表均空；另有两条 `delivery:<id>` 防碰撞记录，但没有 op/message 外键。该防碰撞表只有 ID、状态和时间，不能用相近时间作为身份关联。**这次实际两条请求不是同毫秒；同毫秒身份歧义是源码支持的推论，不是实测案例。** 指纹和原输入已完全缺失，无须依赖同毫秒推论即可确定不能恢复原内容冲突判定。已保留的 accepted_at 本身没有丢失。

固定 main 的精确来源（全文 hash 和行摘录在 `audit/mapping-source-excerpts.json`）：

- `src/delivery_core/response.rs:167-178`：`NotAttempted | PrivateQueueTooBusy => ClearPending`。
- `src/storage/database/sqlite/access/maintenance.rs:1166-1194`：同事务先删关联 `dispatch_submission`，再删 pending `dispatch_op_dedupe`；PG `maintenance.rs:1024-1049`、MySQL `maintenance.rs:1074` 起也有相同删除。
- `src/api/handlers/message/dispatch/mod.rs:273-303`：被删除的 manifest 原本保存 delivery_id、op_id、request 和冻结 dispatch_targets。
- `src/storage/database/sqlite/bootstrap.rs:11-17`：剩余 delivery 防碰撞、semantic、sender status 均无请求指纹和完整关联。
- C `src/ordinary/store.rs:712-715`：重放检查原 scope 和 fingerprint；不能填入任意占位 hash 后宣称幂等兼容。

先前确认的“新 C 空目标也冻结身份”并不补回旧库已经删除的事实。本轮没有把该决定解释为授权制造旧 fingerprint 或拒绝所有合法历史重放。

## 实际执行与失败保留

| 检查 | 结果与边界 |
| --- | --- |
| 固定 main 真实入口生成两个零目标请求 | 通过复现；2成功接纳、2原消息身份、0待交付责任；不是手写新表数据 |
| C 在源库独立副本启动 | 正确拒启，退出1，日志明确 `legacy ordinary ... explicit cutover migration`；HTTP未开放、ordinary_messages 表尚未创建；保留旧身份/状态/责任不变 |
| 停止并 join 旧进程后完整 SQLite family backup | 三个实际数据库逐文件 SQLite backup API，非仅复制 core；逐表/逐行hash及 schema hash一致、integrity_check均ok；没有并发写入，未用新锁假定已锁住旧进程 |
| 备份恢复至另一独立目录，再启动旧 main | 通过；启动前完整 logical snapshot 一致，正常 send_status 返回原身份、首次时间、状态及期限。原源库不变 |
| helper 单元检查 | 最终4通过：四文件含未checkpoint但已提交 WAL 的备份、拒绝覆盖已有备份、失败收据不可覆盖、已有运行目录拒绝且不追加文件。WAL测试由静止的测试连接持有，不是产品断电/迁移测试 |
| 三库转换、转换重复执行/中断、迁移后产品交付/Pull/ACK | **未运行/未实现**：命中信息不足停止条件，没有提前转换完整记录子集 |
| 迁移后 A 回滚、B 越界标记/危险降级拒绝 | **未运行/未实现**；上述旧库备份恢复不是迁移后回滚A验收 |
| PG/MySQL 实库全部迁移矩阵、不同目标/thing关联/共享业务共存、损坏源拒绝 | **未运行**；后端源码相同删除只作为定位证据，不当作实库通过 |

全部首错保留：`audit/bootstrap-first-failure.json` 为证据根路径选择错误（进程启动前）；`source-zero-first` 为 readiness 非JSON解析错误（工具，旧进程已正常退出）；`source-zero-second` 成功初探；`repro-a` 在候选正确拒启后，工具错误假定 ordinary_messages 表已经存在而失败。修正为“表不存在，或存在但零行”，不是放过迁移或改产品。`repro-b` 初次全链断言通过；保留其工具版本。最后统一目标计数命名并补目录所有权负例后，`repro-c` 在最终工具源码上全部断言通过、脚本退出0，结果明确 `BLOCKER_REPRODUCED_NOT_MIGRATED`；无产品迁移通过收据。首错库、日志及工具版本保留，未覆盖补写成功。

## 回滚边界与既有机制缺口

本轮没有建立可上线的 C 离线迁移命令。现有 managed upgrade 不能直接当作本次迁移/回滚保障：

1. SQLite `bootstrap.rs:1623-1629` 只 checkpoint/copy core；`restore_upgrade_backup:1683-1688` 只恢复 core、清除其 WAL/SHM，没有完整 family 的一致恢复。本轮测试辅助用 backup API 保存全部文件，**没有修改产品备份机制**。
2. `upgrade/state.rs:36-40` 把 `failed`、`rollback_failed` 算作 finished；不能把现有 upgrade-run 状态直接复用为可靠的“部分迁移未恢复、禁止启用”标记。PG/MySQL 外部 artifact 的hash/URL校验也不证明可恢复，现有 restore 仍要求人工原生恢复。
3. MySQL bootstrap 按语句执行 DDL，隐式提交可能保留部分schema；未增加 C 迁移阶段标记，也未做中断恢复验证。
4. 旧 main 不持有 C 新 ProductOwner 的运行锁；停机和确认旧进程退出仍是必要前置，不能只取得新 advisory/file lock 就宣称已挡住旧写者。
5. 尚无本次 C 切换的持久化“新写入/外发已越界”标记与旧 main 拒启契约。正常 C 的 ACK、维护、receipt、退休/过期清理都属于写入，不能只以无HTTP新请求判断仍可恢复旧快照。

因此：A 只允许在确认未发生新版本任何写入/外发且有完整一致备份时考虑，**本轮未验收迁移后的这个边界**；B 默认禁止恢复旧快照/直接降级。若未来进入B，应先停入口/领取/发送并收束在途，保全当前完整库、WAL及新增事实和二进制/配置证据，使用理解该库的版本前向修复；新增数据导出、与旧快照合并及反向迁移需要另行设计批准。本轮没有执行这些操作，没有承诺外部恰好一次。

## 最小决策与下一步

推荐继续保持严格拒绝：是否接受**含此类信息不全、仍在保留期的旧普通记录的数据库不属于可直接迁移范围**？可以等待既有保留期自然结束、由旧版正常清理后再做停机迁移，或提供可校验的原始请求与投递关联材料。不能提前删除身份来制造可迁移库。严格拒绝不丢现有数据，但延后切换；也不能保证等待后所有其他形态都可迁移，仍须对账。

若必须立即迁入这类历史，则需要单独决定旧历史 tombstone 的重放/冲突语义和无法恢复的内部投递关联，例如保留 op/message/首次时间但对所有历史重放返回专用冲突；这会改变合法重放行为，**未获批准、未实现**。也不建议恢复旧普通链路作为旁路。

决定之前停止在此可回退检查点。迁移实现、三库逐目标对账、阶段中断恢复、A完整恢复及B拒绝危险降级仍阻止发布；暂不推进客户端联调。之后仍保留128KiB配套客户端/旧版硬切、真实Provider/平台与物理Watch、断电持久性门槛，本轮均未展开。没有合并、push、部署、使用生产凭据或读取真实用户库。
