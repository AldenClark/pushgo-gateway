# C17：固定旧 main 的普通账本降级保护

本轮只补数据库所有权切换的版本围栏。没有改普通消息调度、SQL 热路径、预算、客户端协议或旧数据支持条件。保护对象是未修改的固定 main `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6` 的**正常产品启动入口**，不外推到所有历史版本、定制库调用或管理员主动改库。

## 基线、实现和产物

- 独立工作树：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c10-product-ordinary-20261016/workspace`；分支 `codex/gateway-c-product-ordinary-20261016`。起点 `31618a4a80a1cbe48ddc075ec7a12c8b43ae3845`，开始时干净；main 原提交和主工作树未变。
- 运行实现：`334ce4e9c5bd48bc444e3c3f9b6551f364ca18d0`。只改三个具体 cutover 模块和共享 schema 常量/catalog 目标，不新增通用迁移引擎。最终交付 HEAD、完整状态与分类清单见证据根 `audit/final-state.json`。
- C17OUT：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c17-downgrade-guard-20261017`。这是沿用的证据目录标签，不代表所有测试均在17日执行。日志、命令、退出码、SQL、逐表/逐值快照、失败样本及工具字节均保留；数据库和二进制不提交 Git。

| 正常产品二进制 | SHA256 / 作用 |
| --- | --- |
| 固定 `C12OUT/binaries/M-main` | `5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077`；未修改，真实生成 v12 源并验收拒启/恢复 |
| `C16OUT/binaries/pushgo-gateway-final-native` | `8b523af0152c3d69d9a9a58474390b0ea163eff7b63844f58b9f40805c2566ee`；仅用于生成真实 C15/C16 v1 complete/activated 标记，不冒充旧 main |
| `C17OUT/binaries/pushgo-gateway-first` | `f683269a5d4d25b4cd868426c96c7c602b2d7862d46665de88cd93480705b510`；三库主体有限验收 |
| `C17OUT/binaries/pushgo-gateway-final` | `619a9ecf1630c55c72226137f8899af4e6daeb2d544e8eb3fa78ab6507fbe9a2`；最终实现；SQLite 恢复补丁、MySQL v1 元数据表示修复后的受影响复验 |

Rust 1.97.1、aarch64-apple-darwin、dev/default features、无 QA、离线构建、`CARGO_INCREMENTAL=0`。正常 `pushgo-gateway`，没有以 fixture 验收。`audit/{second,final}-source-{before,after}.json` 记录源码，构建前后各自一致；first→final 仅 SQLite cutover 与 MySQL cutover 两个文件改变，PG、共享启动及所有普通运行模块逐字节相同。PG first 的有效证据因此保留，不为换二进制 hash 机械重跑未变路径。

## 旧 main 为什么能安全拒绝

先在三个旧 main 正常 API 生成的隔离 v12 库副本中**只更新真实 schema 版本值**验证可行性，未改 DDL/checksum 或制造损坏。三库均 exit1，结构化原因 `schema_version_mismatch`；display 为 expected v12 / got v13。完整 schema、所有表行和 migration/version 前后一致。预检见 `native-preflight-result.json`，原 v12 源仍可由旧 main 使用。

实际调用顺序（固定 main 源码）：

1. `main.rs::initialize_runtime_then_bind` 先等待 `build_app`，成功后才 bind HTTP。
2. `app.rs` 使用 `Storage::new_with_config(managed_upgrade: true)`；恢复、维护、Private/MQTT 启动和 worker 在其后。
3. `storage/storage.rs` 先执行 `UpgradeManager::execute`，成功后才调用正常 `DatabaseDriver::new_with_config`。
4. `storage/database/upgrade/manager.rs` 通过 upgrade-only driver、临时锁，读取 migration ID/checksum、版本和 runtime presence，调用 `SchemaMigrationPlan::for_state`。未知非空版本直接拒绝；写升级状态、备份、bootstrap、DDL 和版本回写均在成功规划之后。

所以本轮采用真实 `2026-10-17-gateway-v13` 表示普通账本已取得唯一所有权。既有六条共享 DDL migration 的 ID/checksum 不变，原来 v12 的两个 catalog target 固定为显式 v12，不能随 current 常量漂移。v13 是数据集所有权版本，不是伪造一条共享 DDL 迁移；新版本的普通启动也不自动把未切换 v12 升为 v13。

“拒绝前没有修改”指没有业务行、schema、持久 migration/version/阶段改写。旧版仍会建立数据库连接、取得释放临时 advisory/named lock；SQLite 可能创建、写 PID 并删除 upgrade lock 文件，连接选项含 DELETE journal/EXTRA synchronous。验收库原本使用 DELETE，未观察到数据库内容变化；不声称零磁盘 I/O、零数据库服务内部统计或全物理介质字节不变。无成功 TCP 接入是1ms采样证据，与上述启动顺序、退出日志和完整快照共同使用，不把轮询当严格时间证明。自定义 `managed_upgrade: false` 库调用不在这个正常二进制保证内。

## 阶段与后端原生边界

| 阶段 | 固定旧 main | 当前正常产品 | 受支持工具行为 |
| --- | --- | --- | --- |
| 未切换完整 v12 | 可正常运行 | 拒绝，必须显式离线切换 | 严格来源/全模型排空检查后 plan/run |
| `preparing`，尚未发布 v13 | 数据仍完整原 v12，旧版可识别 | 拒绝 | 仅意图/协调元数据，无业务转换；严格源验证后恢复/中止 |
| 已发布 v13 的 `preparing` / `prepared` | 明确拒绝 | 拒绝不完整切换 | 完整恢复，不带半转换状态启用服务 |
| `complete`，未激活 | 明确拒绝 | 先保全 v13、持久 activated，再初始化正常 Storage | 可恢复完整源；重复 run 不重复转换 |
| `activated` | 明确拒绝 | v13 重复启动，版本不回写 v12 | 拒绝旧快照 restore，不以“没有 HTTP”放宽 |
| `restoring`，尚未发布完整原库 | 明确拒绝，header 持续 v13 | 拒绝 | 完整恢复/验证后，最后才允许发布 v12 |
| 恢复完整原库并发布 v12 | 可正常运行，实测读取原状态 | 拒绝再次普通启动，须重新显式切换 | 完成 marker 清理；崩溃于末尾时仅严格验证原库后收尾 |
| 全新空库由当前产品创建 | v13，明确拒绝 | 正常启动/重启，保持 v13 | 不伪称它是旧库迁移 |

`preparing` 不等于 `prepared`：前者只能代表尚未改业务数据的意图。旧 main 不参与 C ProductOwner 协议，离线前置条件仍要求停止/join 旧服务、发送和使用库的客户端，禁止自动重启，并核对句柄/数据库会话。新锁本身不证明旧进程已退出。

- **SQLite**：完整 family 备份后记录 preparing；在所有成员 EXCLUSIVE 锁下，core 单独提交 v13 并重新取得锁，才发布 prepared/转换。跨文件提交不冒充原子。恢复时先围住原 core（包括 C15/C16 complete-v12），再关闭 handles；原生验证完整 staged family，先发布 guarded v13 core，再发布 siblings；全部校验后最后原子替换未改写的原备份 core-v12。不是只复制 core，不让部分 family 暴露 v12。
- **PostgreSQL**：原生事务把 v13 与 prepared 一起提交，之后导出真实 fenced 快照并 `pg_dump`。v2 custom archive 本身包含真实 v13，不文本改包；完整 native `pg_restore --single-transaction` 后仍是 v13，验证完成后以一笔事务发布 v12/移除 marker。早期备份失败仅在证明完整 pristine 源后原子中止。owner/ACL 保留。
- **MySQL**：preparing 先持久，验证后以原生元数据写提交 v13，prepared 才可见；DDL 隐式提交明确存在。v2 主 dump 排除 `schema_meta`，另一个原生 data-only REPLACE metadata 文件保留真实 v13；双文件 hash、metadata 行摘要、源版本和 format 绑定。恢复期间不 DROP 版本表；其他 DDL 可部分提交，但 v13 始终存在。完整校验后最后发布 v12，崩溃后的源验证/marker 清理无需在 v12 下再执行业务 DDL。

固定锁会话及原有失锁退出约束未换成重连池。没有新增锁服务或第二账本。

### C15/C16 预发布标记的限制

真实 v1 **complete/activated** 标记可在正常启动时验证来源/备份绑定和实际 identity schema 后提升为 v13；不是看到 marker 名称就改版本。SQLite 另核对 canonical identity DDL、迁移收据和原生 integrity。MySQL 原生 VARBINARY 默认值可呈现 `0x6C697665`，只接受与 `live` 相同的精确表示，未移除其他元数据约束。

SQLite v1 未激活完整备份仍可由当前恢复入口使用。**PG/MySQL 的 v1 原生归档包含 v12，当前 fenced restore 明确拒绝该格式且不作恢复写入**；这些预发布归档需要保留 C16 工具与旧进程停机的恢复流程，不能冒称已自动升级为 v2。旧 v1 不完整/损坏/来源不明中间态不新增支持，也不声称历史上已经处于 v12 的未处理候选库会自动受到 v13 保护。受支持的本轮新切换、全新库，以及经过当前入口验证提升的完成库，才适用上表保护。管理员手改版本、删 marker 或主动绕过不在防护目标。

## 验收和首错

详细项目与最终增量见 `audit/verification-catalog.json`。三库 first 主体证据为 `native-acceptance-first/acceptance-summary.json`；每项保留具体 argv、exit、日志及前后快照。最终受影响路径使用 final hash，索引记录明确绑定，不将失败目录整体改写为通过。

| 项目 | 实际覆盖 |
| --- | --- |
| 固定旧 API 源 + 仅版本预检 | 三库均通过；原 v12 可用，v13 明确 exit1，无业务/schema/version 变化 |
| 新切换 complete/activated、重复 run、pre-activation restore | 三库正常二进制；恢复后旧 main 读取原身份/状态/时间 |
| 新产品历史重放、新消息、ACK 和恢复 | 三库五类历史409、真实产品 MQTT QoS1/PUBACK、重复显式 ACK、正文清空、断线及重启；不是平台客户端本地存储验收 |
| prepared 故障/拒启/恢复 | SQLite 实际 SIGKILL，512条显式 SQL 注入历史+2条旧 API 历史；PG/MySQL native dump child exit97；旧/新均拒启，恢复可重跑 |
| restoring 故障/拒启/恢复 | PG/MySQL 真实 native 恢复执行后 child exit97，保持 v13；最终 SQLite 一次真实 SIGKILL 命中 restoring，恢复514条源身份；MySQL 首个真实 DROP `channel_subscriptions` 后 exit97，版本表未删除，旧/新拒启且恢复一致 |
| 新空库创建/重复启动 | 三库 first 正常产品均保持 v13，旧 main 拒绝 |
| C15/C16 完成标记 | 真实 C16 二进制生成各库 complete/activated-v12，再运行当前正常产品验证 v13 提升和旧 main 拒启；不是手写标记冒充旧产物 |
| 聚焦 Rust 回归 | SQLite cutover最终16；migration plan11；MySQL backup2；SQLite ordinary产品11；main启动26。共66个不同测试通过，不把 filtered 算通过 |

保留的产品失败：MySQL v1 默认值表示校验过窄，修复后重跑 MySQL 两例；SQLite legacy restore staging 前仍暴露 v12，精确回归先失败再修复并重跑受影响路径。保留的工具失败：首次 SQLite 新测试路径未 canonicalize；第一次 restore 回归钩子插错位置；MySQL binary phase 观察器按已知 ASCII 解码修正；首次快照把合法新建运行表当作既有共享数据改动。各首错、原因及修正日志均列入 catalog，没有隐藏或当作 Gateway 吞吐问题。

## 范围、成本与结论

PG16.14 / MySQL8.4.11 的本轮独立容器，loopback42772/42773，tmpfs1GiB/1.5GiB，原生持久化参数开启；实际引擎/版本/镜像/命令见 audit。tmpfs + 进程中断不等于断电持久化。只创建 `c17_synthetic_*` 合成库；没有使用旧服务器已有数据、生产凭据或真实 Provider。测试归档后停止本轮服务器，保留原始归档。磁盘全程高于4GiB保护线，本轮无删除缓存或历史证据。

相对起点，五个 Rust 文件物理 +895/−105，其中生产逻辑/注释/空行估算 +663/−100，内嵌 cfg(test)/钩子 +232/−5；格式变化也在物理行统计内，不声称新增可执行逻辑恰好等于663行。三个辅助 Python 脚本新增489行，最终文档单列于 `audit/change-classification.json`。新增长期任务、池、预算所有者、权威账本和协调服务均为零；增加的是离线阶段/备份验证及启动一次性版本检查维护成本，不宣称代码净减少或性能收益。

结论：**固定旧 main、受支持的本轮切换/恢复入口范围内，危险降级门槛已闭合。** 三个后端均有真实正常产品拒启、快照不变、恢复旧版可用和激活后拒绝恢复的证据；没有剩余已复现产品失败。两处产品失败已最小修复，全部首错保留。最终状态见 `audit/final-state.json`。19个本轮合成库（PG9、MySQL10）已作原生归档并校验，再停止两台自建服务器，未删除容器或历史证据。

本轮不扩大 C15/C16 的严格排空/历史身份支持范围。48KiB整个消息请求、128KiB完整帧/WELCOME、旧 Private 客户端硬切、30天新身份窗口和 receipt COMMIT 前预算持有均未改。其他旧二进制、PG/MySQL预发布v1由新工具直接恢复、旧v1不完整候选的自动接管、真实 Provider、物理 Watch、客户端平台、旧库更广形态和断电验收均不在本轮通过范围。

评审本轮后，若接受上述窄范围/预发布格式边界，下一项才是128KiB配套客户端联调；本轮不执行、不发布、不合并或推送。
