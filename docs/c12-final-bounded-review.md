# C12 最后一轮有界收尾

本轮结论是**部分达成**：普通消息的持久权威、正文副本和责任交接已减少；全产品代码净精简、吞吐改善及“没有可复现性能退步”尚未证明。没有发现新的产品正确性阻塞，也没有证据支持继续改变运行时、锁、并发或调度架构。应停止本轮架构探索并交审；由于固定配对验证未完成，暂不能签署性能收口或发布就绪结论。未发现回归不等于已验证无回归。

## 源码、提交和运行身份

隔离树：`/Users/ethan/Repo/PushGo/gateway/build/quality-results/c10-product-ordinary-20261016/workspace`；实际分支 `codex/gateway-c-product-ordinary-20261016`。起点 `2d2605504f1c135bbaf9fac492132c1666fdc802` 干净，运行源码对应 `11da17b92e05e886c6702b26164918eaa1d3a3a9`；主线保持 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。

- `0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886`：仅删除旧私有 `DispatchMessageInput`、专用 fingerprint helpers 和未引用的 `MessageCommand` 包装，共74行生产代码。保留活跃的 `MessageSend`、共享 Event/Thing/Widget 路径和旧数据拒启护栏。没有运行时、SQL、事务或调度调整，不能声称性能提升。
- `1d34f2d7d57a6301b445756a2e8ea108abc55ce7`：保存正常产品比较 harness，990行独立测试，不进入产品构建。修正注册平台并增加供给前身份/订阅断言；它已编译及独立源码复核，但本轮没有成功的性能运行。
- 本文为后续独立文档提交；最终完整 HEAD、状态及保全收据在下述 `audit/final-state.json`，不把报告提交冒充二进制源码版本。

外部证据根为 `/Users/ethan/Repo/PushGo/gateway/build/quality-results/c12-final-bounded-20261016`（C12OUT）。命令、退出码、日志及其 SHA256 见 `audit/verification-catalog-c12.json`；完整源码清单、构建收据、二进制身份见 `audit/binaries-corrected.json` 和 `audit/build-*-source.json`。使用正常 `pushgo-gateway` 的 main/router/Storage/Private 生命周期，没有 fixture server。

| 冻结版本 | 源码/构建 | 正常无QA二进制 SHA256 |
| --- | --- | --- |
| M 原main | `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6` 的原样 git archive，新构建 | `5e2274bea17762dc861d7098b8233cc28bfe957abefbe2fd4ecf1aaf07f50077` |
| P 前C11/C10 | 冻结 normal 源码等价 `ce6f7dd6c08504fc96f6bf1cf2440f20ba2a45a7`，复用已留存同工具链构建 | `0b5ed7ae31ba775d63eb1179a318903c6cc282b762adfa9188b6cff960183d11` |
| C 最终运行源码 | `0163e0ac27791cd4b08b3a9750fbc8e6bf1f8886`，新构建 | `643bdd9789d02c97adf2af0a493b70f230927d0b35e8a98bcada369becf3a4fe` |

三个版本均为 Rust1.97.1、aarch64-apple-darwin、dev、`CARGO_INCREMENTAL=0`、default features/noQA，构建命令 `cargo build --bin pushgo-gateway --offline`，退出0，构建前后源码清单一致。外层环境默认 rustc1.99.1不参与这些构建，实际工具链由各工作目录固定。P的旧构建收据单独保留，未重写旧源码。三个二进制 `--help` 均退出0且没有QA参数。这些是构建身份，不能代替产品运行或性能通过。

## 生产复杂度：减少协调，但没有净删代码

基于已提交Git blob的UTF-8物理行，包含注释/空行。混合文件按词法识别 `cfg(test)`/QA item，属于估算，不是编译可达图或复杂度评分；宏/模糊条件保守计生产。C12仅删除74生产行，其他分类沿用C11；新harness另计测试990行，本文另计文档。详见 `audit/complexity-analysis.{json,md}`、`complexity-analysis.final-addendum.md` 及27份源码引文清单。

| 分类 | 原main | C11 / C12变化 |
| --- | ---: | ---: |
| src生产部分（全产品） | 71,003 | 83,852 → **83,778**；仍比main多12,775 |
| src内独立测试 / 混合test-only | 20,576 / 9,734 | 24,620 / 13,626，不变 |
| src QA-only/QA-or-test | 0 | 734，不变 |
| tests集成测试 | 4,010 | 7,162 + 本轮990 |
| bench | 2,463 | 2,463 |
| 文档/设计/README/LICENSE | 2,173 | 2,481 + 本文 |
| prototype包装器/依赖元数据；文档 | 0 / 0 | 3,933 / 2,459 |
| prototype历史验证源码/脚本/快照；JSON证据等 | 0 / 0 | 69,945 / 29,230 |
| 其他tracked证据；构建/工具配置；根lockfile | 141 / 4,169 / 3,846 | 141 / 4,176 / 3,848 |

ignored二进制/数据库/日志不计代码；不扫描或删除它们来制造净删行。`src/ordinary` 约9,169生产行、5,863测试行、113 QA/test行。18个同名模块可追溯C9原型，当前10,103行中4,835行逐行匹配原文（含测试/注释/空行）；这是迁入来源证据，不是语义复用率或全新设计量。prototype现为产品实现包装/历史验证来源，原42份重复运行/fixture源已退出，不能把搬迁全部算新机制。

| 普通环节 | 原main → 当前产品C | 减少与保留成本 |
| --- | --- | --- |
| 接纳、身份/幂等 | semantic身份、sender状态、dispatch幂等/manifest多阶段 → 同一C事务提交身份、正文、冻结目标、容量及Widget marker后响应 | 普通退出旧多状态协调；保留校验/授权/状态投影与原生事务，不等于整个HTTP只执行一个SQL |
| 收件人展开 | Rust目标Vec及manifest→各lane materialize → 原生 `INSERT SELECT` 与接纳同事务 | 不再转移普通manifest责任；新增三库fanout、约束/触发器、route epoch，数据库工作仍随目标数变化 |
| 调度 | 普通旧outbox job、hint、lease/renew、恢复聚合 → C目标上的claim/attempt/receipt | 退避落SQL，3个Provider pump；旧workers留给其他业务及派生Widget，产品并非只有一个scheduler |
| 结果/状态 | outbox、outcome、op和sender状态汇合 → C目标结算及消息持久汇总 | 不再同步多份普通状态；仍需串行gate/COMMIT、失锁/未知结果处理和恢复 |
| Private/Pull/ACK与正文 | manifest、Provider job、Private payload、逐目标Pull正文 → 一份C规范正文+目标状态/能力 | 复用唯一Private session owner；只对有界活动工作编码。保留source tag、代际校验、frozen receipt owner/current Pull owner及非普通数据源接缝 |
| 正文释放/身份/维护 | 各副本各自删除/恢复 → 最后ACK清正文，身份30天，原维护owner分批清理 | 新增原生清理/索引和Widget continuation；保留256条清理，Widget每轮最多8页、每页128个元数据目标，不能为数字好看撤掉 |

普通入口经 `delivery_core::submit_message → accept_ordinary_message → ordinary.accept_authorized`，避开旧身份预留/写入。普通状态、Pull和ACK只读写C；旧非普通源分支不是普通故障回退。旧dispatch的普通producer/consumer有前置拒绝护栏。没有普通双写、双调度消费者或第二Private owner的引用证据。

必须保留的旧实现：Event/Thing仍使用semantic/status/manifest、Provider outbox及workers；Live Activity/派生Widget仍使用共享APNs预算/outbox；旧Private/Pull处理保留业务。旧ordinary历史解码及SQLite/PG/MySQL拒启检查用于阻止未迁移库误启动。完整引用分类见 `audit/residual-and-residency-review.md`。本轮只删除已证明无调用、无serde/trait/外部API义务的两类私有类型，没有整删共享模块。

源码证明责任交接和规范正文副本减少；没有测量每条消息的SQL总数、事务总数、WAL/fsync或设备物理写放大，因此不宣称物理写入总量下降。维护成本转移到三种具体后端、控制代际/独占健康、Private能力及有界Widget恢复，不能称全产品维护成本已降低。

## 性能对照：0组有效配对，保留全部失败和未运行

C11旧单对不是原main→C：基线为C10运行逻辑+同QA接线（`ece84c9c…3457`），最终为运行11da17b+QA（`c9beb48e…c0a9`），同一harness `38f3cbfb…616f`、Rust1.97.1 dev/test。213消息/637目标，两段330秒闲置，Mock Provider1秒、WS ACK刻意15秒。旧数据继续保留：

| C11单次口径 | 前 | 后 |
| --- | ---: | ---: |
| offer→完整成功HTTP响应p95 | 25.79ms | 33.93ms |
| MQTT ACK发送→数据库终态首次可见p95 | 383.95ms | 803.79ms |
| Gateway约739.5秒采样区间CPU（含660秒闲置/SQLite/QA） | 21.78s | 24.27s |

ACK可见含100ms观察间隔、调度/读等待，不是纯COMMIT；harness CPU也上升（29.98→33.83s），尚未隔离原因。15秒人为ACK hold主导总尾延迟。单对不能证明稳定回归；normal-only profiling删除不能由这组QA数据证明收益。详见 `audit/performance-comparability.md`，不将其与本轮normal结果混排。

本轮预注册3组顺序 **M/P/C、C/P/M、P/M/C**（非完全平衡位置），每run136小消息×2真实TCP MQTT5 peer=272目标：8@2/s、16@8/s、112@100/s；HTTP上限8；连接预热10秒、一个peer的burst ACK固定阶段hold至5秒、最后计划offer+30秒排空、35秒回落。新库、small、相同SQLite DELETE/EXTRA、相同二进制/输入/硬件，无并行构建/外库工作。EXTRA由写连接构造代码确认，不从独立只读连接PRAGMA推断。原main没有受控Provider生产入口，因此共同范围仅普通小消息MQTT，不改造main来跑分；Provider/48KiB性能不在本次比较范围。预注册SHA256 `985609bf4ae169648937140fa3da3268d5f97ce9c0871865d05fd01c99dcf9bd`。

| 原计划位置 | 初始执行 | 唯一修正后执行 |
| --- | --- | --- |
| g1 M | 退出101，48.75秒；错误注册平台，136成功响应/0收到/0 ACK | 退出101，0.51秒；证据父目录缺失，Gateway未启动 |
| g1 P / g1 C | 均未运行 | 均未运行 |
| g2 C / g2 P / g2 M | 均未运行 | 均未运行 |
| g3 P / g3 M / g3 C | 均未运行 | 均未运行 |

初始错误：harness先注册Android再MQTT CONNECT；原main按MQTT平台替换身份，事务删除旧订阅。隔离合成库只读核实两个mqtt设备但订阅0、outbox/payload0。因此136条是合法的**零目标受理**，不是272目标的性能样本；预计272目标未观察到，不是实际存在272条数据库积压。正向ACK oracle拒绝把空表当完成。未将48秒失败计为任何C退步。

仅做一次测试输入修正：开始就注册mqtt，CONNECT后检查原身份、2规范订阅/实际目标，业务success必须为true；固定负载/截止不变。修正harness源码SHA256 `a80f84fd8eca631f43c0ddf73e75c77c301dfea511acad3c11f1c1f155f8d5a4`，二进制 `a1525adb1df9e1dcfebbd4daa733e6bd15ce93f5428bb4d1ffead4301b345daf`。新driver没有创建 `evidence/corrected` 父目录，harness在 `fs::create_dir` 即ENOENT，尚未调用 `Product::spawn`。这是测试编排错误，不是Gateway/数据库/磁盘保护失败。保留两个campaign、首错日志、旧/新harness二进制；达到本轮最多初始+一次修正的边界后停止，没有再补目录重试。未来重用须先修正外部driver目录准备；本轮不执行。

所以 **有效配对run=0，完成配对组=0**。本轮接纳/逐目标p95/p99、供给/接纳/完成率比较、CPU/RSS差、积压/排空差均为未验证，不能给有限数值、排名或“无回归”结论。失败/超时和缺失槽位全部保留，未挑最好的一次；修正后没有产品样本，不能将未供给的136/272写作接纳失败/实际积压。统计文件为 `audit/paired-analysis-{initial,corrected}.{json,md}`。本轮未定位任何产品性能根因，未调H32、池、批次、SQL或控制器，未恢复C9撤回的MySQL实验，PG历史约25秒差异仍未解释。

## 常驻成本及边界（复核C11，不冒充新实跑）

C11两周期正确性213消息/637目标、48KiB、ACK延迟、TTL及两段330秒闲置结果保留。任务203→194是**Tokio活跃异步task采样**，该Gateway有10个runtime worker线程；不等于194线程或泄漏。HTTP连接9→1、普通owned/正文回0、2个主动peer继续连接，支持活动对象释放；聚合数据不能精确命名额外第9个task。

- 旧共享dispatch有176个预建worker+5个controller，原main同配置即存在。controller每500ms查旧outbox，最低7个活跃worker每约1秒空队列探测；恢复worker约5秒、runtime counters10秒、Private维护300秒。它们服务保留业务，不在本轮删除范围，也不能声称低流量零唤醒。C另有3个Provider pump，积压留SQL而非每目标常驻task。
- 五个SQLite连接来自四个池：core_write1、core_read2、delivery1、dispatch1；`min_connections(0)`，small idle30秒，不是最低连接数5。后台使用与存活peer可保持连接活跃；没有连接级寿命trace，不能归因到某个扫描或QA观察器（其仅读池原子stats，不checkout）。
- C11 Gateway RSS峰43,888KiB、最终运行中37,232KiB；malloc live约4.325MB、reserved32MiB，普通活动body/work和多项缓存回0，仍有2个频道信息cache/peer元数据与SQL缓存。它们与分配器保留、RSS是不同量，不把全部残留字节精确分摊或声明长期无泄漏。normal无QA HTTP-only30秒约33.8MiB仅为旧最小配置快照，不是部署RAM需求或长闲置证明。
- Provider先取唯一共享permit再入gate/claim，等待permit不持gate；网络和等待receipt COMMIT共用预算，成功提交后释放。退避不占网络位，Private复用单session owner，按领取编码，无空闲连接预分配128KiB。C11的Profile ZST删除约89,216B固定数组/热路径计时，仅证明实现成本退出，不证明测得CPU更低。
- pending目标预算100万（Provider pending/running/retry及Private waiting/issued）；Provider已accept待ACK不计此预算。30天身份、正文/目标/索引、Widget待处理频道没有新增全局字节/数量配额；消息数/正文产品配置近无硬额度。执行内存/单次分页有界**不等于磁盘总量有固定上限**；清理/容量COUNT/单消息大fanout仍可能增加DB工作。ACK后正文逻辑删除使页可复用，不保证文件缩小。

C11身体/任务/缓存释放证据足以解释已观察到的回落，但本轮没有新配对CPU/RSS及连接回收结果。无新增对象泄漏或唤醒热点证据，不进行常驻成本重构。

## 本轮验证、环境与交付限制

| 项目 | 结果与边界 |
| --- | --- |
| normal M/C构建、初始及修正harness编译 | 全部退出0；不是性能通过 |
| MessageSend纯模型 | 5/5通过，`cargo test --lib domain_model::message::tests:: --offline -- --nocapture --test-threads=1` |
| 普通旧producer前置护栏 | 1/1通过，exact `ordinary_legacy_guard_stops_before_identity_and_manifest_phases` |
| delivery_core_boundaries | 35/35通过，`cargo test --test delivery_core_boundaries --offline -- --nocapture --test-threads=1`；源码边界断言，不冒充网络/数据库合同 |
| 新正常产品三组配对 | 失败且未完成，见上表；0有效组 |
| 三库SQL/事务/维护、C10产品闭环 | 复用C11/C10原收据，本轮未重跑。无相关运行语义修改，不扩全矩阵 |
| 真实Provider/平台客户端/迁移/断电 | 本轮未运行，不是发布通过 |

环境Mac17,4/10核/32GiB、macOS27.0.1，SQLite嵌入Gateway，无法拆成独立DB CPU/RSS；harness/peers是另一进程。外部PG/MySQL隔离引擎保持原paused状态，本轮未对其运行SQL。起查约7.30GiB可用；保护线4GiB，负载另留512MiB。按已有缓存授权，仅删除本轮构建新产生、无进程打开的101个 `.rcgu.o`（992,695,224B逻辑，可用增加约0.925GiB），不删除历史源码/二进制/数据库/日志或用户数据。范围/逐文件身份及实际释放见 `audit/cache-created-C12-objects-{candidate,recovery}.json`；本轮两次失败都非resource STOP，修正尝试最低约6.20GiB。

必要状态/日志保全在 `audit/final-preservation.json`、`final-artifact-manifest.json`、`final-state.json`。主线、其他工作树及冻结证据不覆盖；本轮只提交相关类型删除、测试和本文，不合并/push/部署。此前一次测试文件写入被自动检查以疑似secret assignment拒绝，没有真实凭据；后续改用既有C11的进程内合成随机值注入，未重放拒绝写入、改变信任或读取生产秘密。未引入新的权限、CA或系统信任修改。

## 有顺序的后续验收（本轮不实施）

1. 审阅本轮部分达成与测试系统失败；若要求正式签署无明显退步，先在新授权轮次修正外部目录准备，完成已固定的共同范围配对。无需新增架构设计，不能用此轮0有效样本签性能结论；Provider/三库持续性能仍需按实际业务容量需求另定验收，256target/s不是SLA。
2. SQLite/PG/MySQL旧库迁移、索引及独占owner兼容、旧积压处理和回滚演练；现拒启护栏意味着不能直接切真实旧库。验证新旧版本回退数据关系和恢复时间。
3. 准备并发布配套Gateway/Warp/Android JNI/Windows客户端；48KiB整个 `/message` JSON，控制仍32KiB；128KiB完整Private帧含type/flags两字节、不含TCP/QUIC四字节长度前缀，WELCOME一致。旧Private客户端硬切（可在WELCOME拒连），先新版客户端后Gateway；不新增旧版协商/WSS旁路。
4. 真实Provider凭据/Token Service/连接池与共享预算、APNs/FCM/WNS限制、物理Watch后台；平台持久化/ACK outbox/restart闭环，Windows OS以及Android/Windows QUIC/WSS按实际支持范围分别验收，不能由协议peer或host组件测试代替。
5. 受控磁盘不足、进程/锁会话丢失和真正断电持久性；按实际消息率/fanout/ACK驻留与30天身份预算做容量规划，明确磁盘增长/清理速度和观测告警。有限突发、旧双周期不保证长期过载或长期无泄漏。

不继续架构/优化实验，不新增类型或实施发布清单，等待审阅。本轮协调简化已得到源码支持；净代码和性能收益保留未证明状态，性能签署缺口须明确保留。
