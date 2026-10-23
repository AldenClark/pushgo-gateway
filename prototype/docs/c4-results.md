# C4：SQLite 收口与 PostgreSQL 普通消息适配

范围继承C3的普通FCM/APNs，Private数据面仍未接入。继续使用隔离候选及 axum/Tokio；没有合并、推送、部署、主线修补或扩展其他消息类型。代码不是仅设计稿：HTTP、runtime、控制面和普通投递已选择原生 SQLite / PostgreSQL backend。最终证据身份在下文及本机 `c4-sqlite-postgres-20261015/binaries/c4-identity.json`；原始日志、数据库、二进制留在 build 证据目录，不提交 Git。小型验证源码与精确来源放在 [C4验证材料](../validation/c4/README.md)，迁移后的脚本仅做语法/hash检查，没有执行，不能冒充原始运行。

## 基线及变更

开始时重新核实八个 Git root。候选分支 `codex/gateway-c-ordinary-final-20261015` 干净，HEAD `90a2881d70c7349df8c3f4a452bbb3f49abd1195`，最终 SQLite 实现 `19cc5c686419255739776611d1fae25b8ed7b6fa`；主线 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。因此没有重复提交旧工作。Windows 已有修改和 warp-link 已有未跟踪产物不属本轮。结束前再次核验八个主仓库HEAD/status完全一致、Windows既有修改hash不变、9个原冻结二进制及11个C32源文件hash不变；`preservation-before-docs.json`留存逐项证据。原C32、CURRENT、C2/C3失败及冻结对照不被覆盖。

- `4b80d8e`：纠正 producer peak 定义，submitted−started 是等待开始 HTTP；started−finished 才是活跃 HTTP。
- `19c6c4c`：SQLite 健康栅栏及三处控制写入事务。该中间提交没有独立二进制；最终组合验证在后项。
- `f8ed62f94ce44e285414f1a0f6894878763f4dbe`：原生 PostgreSQL、共享 facade/runtime/HTTP 健康接线及两库合同测试。普通 fixture SHA256 `8d458bbf23e0306f4a78ee26a1735fa2795bee02f39a30a52acb11634559f80e`，最终客户端与外部故障均使用它。
- `d925b97fe30068b66aefb66e33284831df6d8e4f`：仅修写锁测试观察器的同步与阶段诊断，产品源与上述二进制不变。完整最终源码的有限容量补测另加相同 observer，测量二进制单列。
- 本文后续文档提交只绑定证据，不改变已验证产品代码。

| 产物 | 精确源码 / SHA256 |
|---|---|
| 最终普通fixture | f8ed62f产品源码（d925无产品差异），`8d458bbf23e0306f4a78ee26a1735fa2795bee02f39a30a52acb11634559f80e`，外部 `binaries/c4-ordinary-sqlite-pg`。 |
| PG aggregate测试 | f8ed62f，`773b95596c33578b067c01030bfdd283b80d437e6da2702d61faa7c69c1576af`。 |
| 修观察器后的SQLite测试 | d925b97，`783d9a9b94b8bca6c7f732ff9517ce1c775c71ee1087c2d014511d81d2b12793`。 |
| 最终C4测量fixture | d925b97另加固定observer，`83ab543e6e14760c20b2911e624fb33f80355afb6d466f1d753a589773d9c753`，不作为普通发布二进制。 |

复用的 `prototype/target` 当前可执行文件是最后的测量构建，不能凭这个可变路径宣称普通fixture身份。上表冻结副本和 `binaries/c4-identity.json` 才绑定客户端、故障及测试收据。所有 build 使用 `cargo +1.97.1 --release --offline --locked`，没有新增依赖版本或第二套target。

PG 不是主线数据库层的开关。它是新 C 的固定 `pushgo_c` schema，单机 Unix、单 owner 的适配；旧库导入、迁移、回滚及 MySQL 仍未实现验收。事务、字段、资源和数据库差异详见 [PG 实现边界](c4-postgres.md)。

## 已实现的合同及证据入口

| 合同 | C4 实现与直接 oracle |
|---|---|
| 输入及身份 | 共用 normalizer、完整 fingerprint、可省略 op_id、URL/图片/密文/其他已有字段；两后端共用同一 `run_oracles`，校验冲突、重复、绝对 TTL、首次时间及重启。 |
| 原子接纳 | 原生事务内身份+完整 fanout+容量 trigger，COMMIT 成功才响应；PG deferred FK COMMIT 故障验证回滚无新身份，单次失败不伪装接纳成功。 |
| 投递 | 同一 runtime/Provider transport；claim 前预算预留，授权再次校验 frozen route、attempt 和 epoch；receipt 采用冻结 owner，Pull 采用当前 owner。未知外部结果允许有限重复，不声明 exactly-once。 |
| 控制面 | register/身份合并/路由更新退出/token 退休/subscribe/unsubscribe/channel sync/delete/rename；取消订阅只改未来 fanout，退出与退休按既有 epoch/generation fencing。两后端共用业务 oracle。 |
| Pull / ACK | 真实生产 router 的路径前缀、共享认证先于解析、发送/重复/状态、V2 Pull 与持久 ACK；ACK 释放正文和队列，不提前移除身份。受支持直接 ACK 和 legacy destructive Pull 保留。 |
| 维护 | 历史默认 30 天，不加 history-full 拒收；每类有界批次。PG 固定一组最多256个 expiry ID 用于五步变更，257个同到期身份逐行验证，避免 MVCC 下重复 LIMIT 不同集合。 |
| 单实例 | 所有 SQL 复用持有 advisory lock 的同一 pinned session；持久 dataset UUID 对应同机 OS 文件锁。PG会话消失、URL别名或第二进程不能绕过残留 owner；非Unix明确不支持。 |
| 故障及停机 | pump / 连接失败 / runtime Drop 锁存共享 Health；HTTP 克隆、gate 排队接纳及控制写入均停止提交。没有新事务自动重试或外部请求重放循环。正常先停HTTP再join pumps/关闭连接/释放owner。 |

## 最终客户端与故障闭环

| 最终 C4 SQLite 客户端/重启闭环 | 结果及实际存储证据 |
|---|---|
| Apple | 7阶段/20次真实候选HTTP全部通过，进程43407→43550，GRDB持久ACK503后真实62.155秒剩余退避恢复；控制器、Direct/wakeup/Pull/ACK/取消及晚到回执。 |
| Android | 2方法通过、0跳过，真实进程3790→3922；Room canonical5→6、持久outbox1→0，生产Keystore/入站/协调与候选直连。 |
| Gateway | 44333→44339，coalescing、token retirement、未知结果强杀恢复通过；ACKed/retired/future三类外发计数1/1/2，最后targets0/body0。 |

最终626个缓存客户端源码/产物hash加候选二进制核验不变；全部产品Gateway source hash也在执行后复核。`native-final/summary.json`、`gateway-source-after.json` 和 `executed-harness-manifest.json` 绑定执行字节，`quiet.json` 确认自有emulator/fixture消失、ADB为空、lease释放。

首次 19cc 重新执行也全部通过，原收据在 `native/`，最终 C4 在 `native-final/`，两组不能混作同一二进制。Apple 使用真实生产控制器、GRDB 和持久 ACK 恢复；Android 使用未修改的生产仓库、Room、Keystore、入站 parser/coordinator/outbox，直接连候选 Gateway。协议或 Mock 返回并不替代真实客户端入库证据。缓存 JNI 的精确源码 revision 未追认，但该私有通道路径不参与本次旅程。

最终外部故障使用二进制 `8d458bbf23e0306f4a78ee26a1735fa2795bee02f39a30a52acb11634559f80e`：

- SQLite 真实外部 BEGIN IMMEDIATE 超过三秒，fixture **整个进程**退出70；并发POST返回现有503 temporarily unavailable，后续连接被拒。手动重启同库，identity/first/TTL/dedupe不变，未知attempt1恢复为attempt2，无第三次同op外发。原19cc的断开收据也保留，不能把最终503反写到旧结果。
- 库层原来依赖调用方 `wait_failure` 的缺口已修：测试故意不等待故障信号，已有router/store克隆和排队接纳仍被拒；对三条旧autocommit控制写入增加事务与提交前健康检查，真实Drop中断后无重命名或取消提交。
- PG第二进程及localhost别名启动拒绝；原Gateway SIGSTOP但仍存活时，精确终止其advisory session，确认数据库advisory已释放，第二进程仍被OS owner挡住。随后SIGKILL/重启，身份、时间、TTL、metadata及epoch不变，仅一次未知结果重发，Pull/ACK后usage三计数为0、保留一条身份。独立 native oracle 负责活跃会话丢失后的入口fence；不能拿SIGSTOP观察替代。

`fault/final-results.md` 与两个 `receipt.json` 保存PID/数据库session/请求和SQL证据。已停止自有fixture/mock，只删除本轮故障harness自己新建的PG数据库。全部PG测试结束后按captured ID/label/name清理唯一自有容器，确认无其他运行容器/VM/构建客户端才正常停止OrbStack，恢复初始Stopped；镜像/volume inventory不变，无新持久卷。现有systemd文档的Restart=always针对主线可执行文件，候选尚无已安装的自动重启监督；Docker示例也不证明候选自动恢复。因此此处只证明 fail-stop 与受控手动重启，部署自动拉起仍需最终交付验收。

## 执行结果与保留失败

| 执行 | 最终结果 / 身份 |
|---|---|
| Rust 全部默认测试 | `d925b97` Release测试二进制 `783d9a9b94b8bca6c7f732ff9517ce1c775c71ee1087c2d014511d81d2b12793`：86通过、0失败、3 ignored；`tests-final-writer-probe.log`。另写锁定向1通过。 |
| 真实PG aggregate | `f8ed62f`测试二进制 `773b95596c33578b067c01030bfdd283b80d437e6da2702d61faa7c69c1576af`：显式执行ignored aggregate，1通过，覆盖七个全新case DB；`tests-pg-final-verified.log`含实际原生EXPLAIN。后续d925仅SQLite测试同步，不改PG路径。 |
| PG H32 背压 | 40条消息/40目标，32个真实Transport future持有；独立SQLsession锁ledger row，网络结束后owned/receipts仍32且COMMIT0，100ms内不领取剩余8；解锁后40回执提交、ACK并正常join两pumps。 |
| Provider/容量/写失败 | 默认86覆盖截断/超限保留状态与retry header、真实Token Service所有者Mock、SQLite FULL与deferred COMMIT失败、调用方取消、receipt/claim互等停机恢复；PG新增deferred FK提交回滚和会话终止后拒收。不是实际OS ENOSPC或断电测试。 |
| 格式与静态检查 | Rustfmt及产品/普通源码diff whitespace通过；三份原样unified patch的空context行含单空格，被全量diff检查提示，保留补丁字节/hash，不视为源码尾空白通过；`cargo +1.97.1 clippy --release --offline --locked --all-targets --no-deps` exit0；保留3个既有WNS依赖dead-code和2个test-only claim wrapper dead-code警告，不声称-D warnings。 |
| 未运行 | 默认ignored中PG已另行真实执行；其余2项历史规模实跑本轮未重复，保留既有实测。原生客户端完整旅程使用SQLite，未把Apple/Android整套再跑在PG后端上；PG覆盖共享生产HTTP/真实存储/Runtime/进程故障。PG长期容量/物理磁盘/旧库迁移、真实Provider/物理设备/OS后台及部署均未运行。 |

最终所有权与原始失败收据另列保存：`tests-final-verified.log`曾85通过/1个短写锁测试通用三秒条件超时；隔离诊断通过，但该旧收据未记录具体await，**不能追认其准确失败阶段**。源码可见计数快照可能落在已开始的claim之后，而notify不会替换pending future。d925先持gate排完旧关键区再拿外部锁，随后快照/释放gate，且断言held claim不会因再notify增加计数；所有等待仍为原三秒，增加阶段与计数诊断。修后完整86及定向通过，不删旧失败或改生产超时。

- 首次集成测试编译缺HTTP测试import/Admission新health字段，首次连接超时补丁编译缺Duration限定名，均保留日志后修复。
- 首次真实PG共享及故障流程到EXPLAIN断言失败：小fixture选择 `targets_owner_delivery` 而非断言要求的 `targets_token_retirement`。修正测试判据接受合法原生JOIN计划，第二次定向查询也选择合法owner索引，仍因同一过窄断言失败。最终保留真实计划，并单独验证token索引定义、valid/ready，而不再强迫指定索引；没有为迎合断言强制产品计划。
- 独立审查找到PG重复expiry LIMIT集合风险与SQLite控制面autocommit健康缺口；已修并复核。新增oracle检验实际行为，审查本身不冒充执行证据。
- 原19cc外部故障脚本的bytes序列化失败、代理污染HTML503，以及native离线只读WAL快照打开失败均保留；修观察器，不把它们写成Gateway行为。最终直接loopback执行绕过系统代理，客户端断言未靠重试掩盖。

真实PG环境为已有授权隔离运行时上的本地固定镜像，**无拉取**；PostgreSQL16.14/aarch64，fsync/full_page_writes/synchronous_commit开启，全新UUID数据库，只供合成数据。容器1GiB RAM/2CPU/128PID，PGDATA640MiB tmpfs。真实SQL、约束、trigger、COMMIT、session/进程失败均能验证，但tmpfs不能证明物理磁盘断电持久性。没有连接线上或用户现有库、没有读生产秘密。

## 容量结论、限制及下一步

最终C4另两例使用同配置/输入/observer，分别2560消息、40960目标，全部成功。offer→postCOMMIT p95/p99分别13.267/13.577秒和14.465/14.763秒，firstSQL全部完成23.867/25.189秒；81920目标的失败/超时/unfinished/dropped/invalid/writeerror全0。C4比旧基线改动范围更大，不能将更快样本归因于某一行或宣称已找回/消除旧约五秒原因；后半段仍增长的积压不支持持续256。最后RSS采样在ack-start约24.52/24.92MiB，没有固定回落窗口，不能当回落值或泄漏结论。

原同工具链 ABBA 四例见 [有限性能复核](c4-capacity.md)。每例2560消息/40960实际目标，四例163840目标最终全COMMIT，失败/超时/未完成/遥测丢失均为0。offer→目标COMMIT p95为17.156–21.529秒，p99为17.521–21.979秒；包括入口等待、数据库排队、网络与结果提交。目标/s是输入加排空的完成平均率，所有256场景后半段积压增长，不能当持续256消息/s承诺。

gate hold占83–89%窗口，接纳gate等待均值11.8–15.4ms，pool等待约0.12–0.18ms；receipt gate约6.23–7.18ms，pool46–65µs。BEGIN成本可见但重复结果范围重叠，不能把原约五秒全部归因于修复；没有提高H32、连接池、批次或恢复动态控制器。SQL阶段包含SQLx/数据库工作排队和trigger，COMMIT不是纯fsync。

新PG每Provider预算和SQLite一致，32个网络/待结果COMMIT共用位置；真实PG阻塞ledger row后32份结果待提交而剩余8个任务不领取，解除锁后恢复。连接只有1条pinned session，无按积压建连接/任务；但这也串行化读写，尚未做PG持续吞吐、空闲唤醒/连接RSS、长期历史规模与物理存储性能测量。PG `PoolAcquire` 标签表示pinned连接mutex等待，不是连接池。

30天身份无数量/字节硬配额，因此**总磁盘不存在固定上限**。C4没有改变SQLite DDL（`sqlite-schema-unchanged.json`逐字hash核验），可按原分布复用 [C3 SQLite历史实测](c3-history.md)：默认46字节op_id的完整紧凑身份及索引426.435–429.425B/业务消息，ACK后0正文/0target，收件人数不乘这条身份。30天算术外推如下，没有执行30天长跑：

| 业务消息/s | 30天身份数 | 紧凑身份+索引 GB（10^9B） |
|---:|---:|---:|
| 1 | 2,592,000 | 1.105–1.113 |
| 64 | 165,888,000 | 70.740–71.236 |
| 128 | 331,776,000 | 141.481–142.473 |
| 256 | 663,552,000 | 282.962–284.946 |

仍待ACK的目标数为业务消息数×fanout（API最多32订阅者），正文每消息共享一次。既有C3物理布局probe在163B合成token分布下测得884.3264B/target含索引；该10k-target直接SQL仅测布局，不是合法单消息fanout或接纳能力。字段宽度、WAL、碎片和操作余量额外计算。**这些SQLite空间数值不能套用PG**；PG实际身份/索引成本与规模性能本轮未测。

逻辑删除、PG dead tuple/SQLite可复用页、实际文件大小不等同，维护批次数量有界不代表数据库扫描/排序工作恒定或存储上界。

普通FCM/APNs消息已具备在当前隔离候选中进行真实客户端接入与两库共享合同验证的实现条件；实际验收清单以最终执行栏为准。真实APNs/FCM、物理Watch后台、OS后台调度、旧PG/MySQL迁移与回滚、断电和部署监督仍未运行。未修改客户端展示或退休客户端兼容承诺。

建议审查本轮实现与证据后，再开展MySQL原生事务/约束/单实例适配，复用相同业务oracle。不要同时接入其他消息类型；上述部署与旧库验收留在统一最终阶段。没有新的产品行为决策项：本轮沿用身份保留、取消/ACK、接纳成功及有限重复语义。
