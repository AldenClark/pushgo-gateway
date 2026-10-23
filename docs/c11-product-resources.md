# C11 正常产品资源收口

本轮以 C10 `4411965b9cede750a2cd266b73a006cabb60fbcd` 为起点，使用隔离工作树 `build/quality-results/c10-product-ordinary-20261016/workspace`、分支 `codex/gateway-c-product-ordinary-20261016`。主线仍为 `dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`。没有合并、push、部署、旧库切换或删除历史证据。最终复核12个其他Git根与11份命名历史产物保持不变，见C11OUT/audit/final-preservation.json；Windows主树原有`src/release_smoke.rs`修改及Warp主树原有未跟踪证据保留。配套隔离树实查Warp `fded360134f2144876bb11b95e7431cb1d72aef3`、Android `07b634739ec10fb67720eaabaaec02d26b3932ea`、Windows `55c555e4de7e4372ddcc9fd7e13bf24f961ddaf7`，本轮均未修改/重建，Gateway依赖revision保持原锁定。

## 结论

可以结束本轮普通消息的架构/优化研究，转入已有发布前验收清单。正常产品有限两周期、10项聚焦合同和三库接缝通过；修复的是可重现的清理缺口与单轮无界工作，未发现需要新伸缩控制器的证据。没有获得性能更快、长期无泄漏或任意持续过载稳定的结论。当前候选仍仅供评审，不是发布批准。

## 最小改动与代价

1. `8c9bfe2dd8aecaa046e070fb8680f6d1eeb853cf`：正常 main 的 QA-only 有界观察器、Private/MQTT 协议 peer、独立已提交状态观察，以及聚焦回归测试。不是 prototype/fixture HTTP server。正式构建没有观察器参数和替身参数。
2. `8e0333224ad04d766a3aabe2ffa70287c757f337`：修复安静期 C 账本没有进入正常周期维护的问题；复用现有维护 owner，每次仅一轮原生有界维护。Widget 单次由“循环所有分页”改为最多8页×128元数据目标，使用一份内存 cursor/有限 order ceiling；满载仍保留原 marker 和持久责任，后续频道可继续，重启从持久 job order恢复。独立清理256条到期 marker，避免活跃头部挡住过期尾部；三库补 expiry 索引。没有新队列、调度器、持久进度表或全局配额。
3. `11da17b92e05e886c6702b26164918eaa1d3a3a9`：正常构建逐语句 Profile/Timer 为零大小并有编译期断言；移除约89,216B固定数组、每次 profile.sql 的两个计时器和六次原子更新。QA/test 保留原 profiling 以便同口径观察；必要主计数、Timings、health和预算不变。此为可证实的固定成本删除，不宣称实测吞吐提升。

Widget 新增复杂度仅限一个串行投影 continuation、频道轮次上界和原生选择接口。一次返回行数和Rust驻留有界，不等于SQL引擎恰好只扫描128行：现有Widget目标去重/排序和容量COUNT仍随注册规模工作。一个维护message也可能包含大量fanout，256个message并非256个target。共享dispatch仍被其他业务使用，没有为减少行数整删模块。

MySQL `CREATE TABLE IF NOT EXISTS`不能给旧候选表补索引，因此启动只读检查可见BTREE完整 `(expires_at,delivery_id)`前缀，缺失/截短/反序拒启；生产不自动ALTER。旧库升级/回滚验收仍是上线前置，本轮仅全新隔离库。

## 可复现身份与覆盖

所有外部收据位于 `/Users/ethan/Repo/PushGo/gateway/build/quality-results/c11-product-resources-20261016/`（下称C11OUT）。

- `audit/build-baseline-source.json`、`baseline-binaries.json`：C10运行逻辑加同一QA观察接线的冻结基线；原始测试TTL输入随后单独修正，原字节及两份manifest均保留。
- `audit/build-final-qa-source.json`、`build-final-normal-source.json`：367个源码/Cargo文件完全相同，构建前后hash一致；`committed-runtime-identity.json`确认与已提交运行源码11da17b一致。文档提交不改变运行字节。
- 最终QA正常Gateway SHA256 `c9beb48e201516af1ec49dc5d38ade58ee1a90e864d997d7d1c0b9670051c0a9`；正常无QA Gateway `fbe76249e171197d6735051b42785dcb5e202ddf69144ba2a63dac533b7370de`。路径/完整测试二进制hash见 `audit/final-qa-binaries.json`、`final-normal-binary.json`。
- baseline和after的资源harness字节相同：`38f3cbfb45f89e68e919c5df2f10c399c249fcec114c2fe5ca165b25b53b616f`。Rust1.97.1/aarch64-apple-darwin，同dev/test配置、`CARGO_INCREMENTAL=0`；不是release容量证明。
- 聚焦测试命令、退出码、日志SHA及输入引用均在对应`audit/*.receipt.json`；实际运行的exact名称见日志。所有数据库URL留0600私有文件，不把凭据写报告。

| 最终源码直接相关验证 | 结果 | 收据/范围 |
| --- | --- | --- |
| Widget聚焦用例 | 6/6通过 | `final-widget-absolute`；257目标分页、满载/合并/跨频道、10频道8/2页、重启/终态不复活、缺约束拒启 |
| SQLite / PG / MySQL正常Storage维护合同 | 各1/1通过 | `final-maintenance-{sqlite,pg,mysql}`；257同到期正文/目标与身份、marker独立256/1清理、ceiling/after不被新order延长、dry-run无写 |
| MySQL原生index/取消接缝 | 1/1通过 | `final-mysql-index-and-cancel-exact`；缺失/截短/反序expiry索引拒启并不自动修复，复用原控制/receipt/Private/取消事务断言 |
| 最终QA及无QA构建 | 均退出0，源码hash不变 | `build-final-qa` / `build-final-normal`；离线构建，normal含ZST编译断言 |
| normal无QA隔离 | 通过 | `normal-noqa-feature-isolation.json`；两个QA参数均拒绝，help中不存在 |
| normal小配置启动/关闭/重启 | 通过 | `normal-noqa-idle.receipt.json`；第二同数据集实例退出1，正常关闭/重启关闭均0；30秒只是minimum-config smoke |
| 同条件正常main双周期 | 1/1通过（742.57秒） | `product-after`；最终数据独立于原始baseline |

Widget满载用例采用测试构建内的已知容量回滚注入，覆盖恢复分支，不能据此证明百万行容量COUNT的代价。外库本轮只做上述新库正确性测试，没有重跑其容量矩阵。正常main负载实跑选SQLite；PG/MySQL正常main的既有C10闭环仅引用原记录，不能写成本轮重新通过。

C10已通过的控制权威、幂等/TTL/冻结目标、WNS/Watch普通目标、Private owner、共享Provider预算、失锁和重启测试复用原收据：`../c10-product-ordinary-20261016/audit/verification-catalog-c10-final.md`。本轮不重新宣称全矩阵，也未改变这些运行路径。三库新SQL只补与维护/Widget接缝直接相关的原生合同。

## 同进程负载与测量口径

正常 `pushgo-gateway` main / small / embedded SQLite；启用同一Private owner的loopback WS upgrade与TCP MQTT5，受控FCM替身每次1秒/202。HTTP producer最多8并发：每轮4条低流量1/s、16或8条升载4/s、112或64条短突发；Private WS ACK刻意延迟15秒，MQTT正常ACK。两轮间及最终各330秒闲置，跨300秒维护与30秒池idle设置。另4个完整49,152字节JSON，逐项核对body hash、metadata、message_id；1个45秒绝对TTL的Provider-only sentinel不ACK，检验停流后的正文/目标清理。共213message，637target=213Provider+212WS+212MQTT。

供给、成功HTTP响应（持久接纳后的上界）、Provider receipt COMMIT、Private/MQTT ACK COMMIT分列。独立100ms SQLite读取只给COMMIT可见时间上界，包含轮询/调度/读等待；QA五秒快照不是连续峰值。原生协议peer验证内容与ACK，不等于Android/Windows持久客户端存储。Provider Mock不经过真实HTTP连接池，不能声称实测了15秒Provider连接回收。SQLite嵌在Gateway中，CPU/RSS不能拆成独立数据库进程；harness+peer+观察器作为另一进程汇总。

`audit/{baseline-retry,after}-summary.json`及原JSONL为统计来源，完整命令/退出码见`verification-catalog-c11-final.json`。

| 同条件单次前后实跑 | 基线 | 最终 |
| --- | ---: | ---: |
| 持久接纳message / 完成target / 未完成 | 213 / 637 / 0 | 213 / 637 / 0 |
| Provider receipt / 客户端ACK / ACK释放正文message | 213 / 636 / 212 | 213 / 636 / 212 |
| 最终到期sentinel正文/目标 | 573B / 1，清理失败 | 0B / 0，清理通过；身份仍213 |
| offer→成功响应p95/p99 | 25.79 / 26.86ms | 33.93 / 37.28ms |
| offer→Provider COMMIT可见p95/p99 | 3870.47 / 3890.49ms | 3889.87 / 3914.03ms |
| offer→全部637终态可见p95/p99 | 15442.83 / 15576.51ms | 15395.23 / 15539.55ms |
| MQTT ACK发送→持久消失p95/p99 | 383.95 / 395.42ms | 803.79 / 852.05ms |
| 两轮最后offer→Provider排空 | 3.853 / 2.918s | 3.878 / 2.883s |
| 四条48KiB→12target完整终态，首offer到末终态 | 1.141s | 1.063s |
| 原子计数network/owned峰；receipt等待峰 | 32 / 32；8 | 32 / 32；9 |
| pending usage采样峰 target / private_pending / 正文 | 341 / 226 / 197740B | 341 / 226 / 197740B |
| SQL采样Private已发行 / 未发行（两设备合计） | 174 / 198 | 174 / 179 |
| Gateway RSS采样峰 / 最终运行中回落 | 44000 / 37200KiB | 43888 / 37232KiB |
| Gateway CPU全观察区间增量 | 21.78s | 24.27s |
| 两段330秒回落CPU（单核心占比） | 0.995% / 0.888% | 1.198% / 1.105% |
| malloc live冷闲置末 / 峰 / 第一回落末 / 最终运行中 | 3765504 / 5586528 / 4270112 / 4334976B | 3781456 / 5630064 / 4260560 / 4325344B |
| malloc reserved / 活跃task采样峰→运行回落 | 32MiB / 203→194 | 32MiB / 203→194 |
| harness+peer+SQL观察器CPU / RSS峰 | 29.98s / 19824KiB | 33.83s / 19824KiB |

最终运行中的Provider owned/network、Private work/payload/resume、hint队列和重复dispatch/device cache均回零；2个主动测试peer、5个数据库池连接、2个频道info cache仍活着，HTTP连接9→1，任务203→194。关闭后5任务是另一个时点，不拿它当运行中自动收缩。live从第一回落到第二回落约增65KB，且新增一个sentinel频道；有证据的对象释放、存活池/cache和32MiB分配器保留分开列出，未做完整allocation tree，不能把所有剩余字节精确分摊或排除微小长期泄漏。

正常无QA、HTTP-only small/SQLite的30秒快照RSS为34272→34608KiB（33.47→33.80MiB），CPU增0.42s；它只提供本机最小配置的实测开销，不是机器RAM最低要求。两次330秒周期结论来自正常main加QA观察构建，观察器本身计入Gateway成本。五个池连接在窗口内保持，并未证明其都回收到零；Mock不能验证真实Provider池回收。

本轮没有性能收益证明：成功响应、MQTT ACK可见延迟和CPU后值更高，原数据保留，单对实跑未隔离原因，不归咎或归功于某条SQL。Profile删除只作用于无QA构建，不能拿QA前后RSS/CPU差当收益。保留优化的理由是修复正确性/资源边界及退出无人消费的正常逐语句计时，而非跑分。

瓶颈结论只限此负载：网络人为固定1秒、H32，Provider排空约3–4秒；Private尾延迟主要由刻意15秒ACK hold决定。最终213次receipt的含gate等待时间合计1.469s，receipt COMMIT合计0.131s，network合计213.314s（并发累计，不能当进程墙钟相加）；receipt COMMIT最大5.53ms、pool checkout最大54.69ms、receipt gate wait最大37.25ms。存在串行gate/checkout等待，但证据不支持其先于慢下游成为本例主要容量限制，不调整H32/连接池/批量。BEGIN/SQLinclusive/COMMIT及nested fanout分项见summary的`final_lifetime_profile_phases`；SQLinclusive含worker队列/trigger，不能当纯engine时间或互相求和。

供给设定为1/s、4/s与有限并发8突发，实际按phase列出offer/持久响应/逐目标速率；整轮含闲置的平均不叫持续容量。最终固定1秒观察bin最多34个Provider完成（基线32），受批次跨bin/轮询影响，是瞬时计数。两轮完整终态速率17.66/11.29target/s包含慢速供给和人为ACK hold，同样不能当持续吞吐。受控ACK延迟产生148个重复WS接收（基线140、MQTT均0），正文/metadata/身份一致；重复不是新增投递目标。213次Provider尝试都有receipt，最终无inflight/unfinished；本轮未新增未知外部结果故障注入，不由此宣称任意故障均无迟到/未知。

样本缺失策略：失败、超时、未完成保留637分母；仅全部目标都有终态观察才报告完整分位数。Provider accepted receipt与客户端ACK是不同终点。全部目标分位数包含人为15秒ACK延迟；不能把此值或一秒窗32次Provider完成叫生产持续容量。低流量1/s、升载4/s与有限突发只验证这些情景，256target/s没有产品SLA含义，本轮也不重跑原型容量矩阵。没有直接采集SQL最老积压年龄；分析提供offer到终态尚未可见的保守年龄上界，不能冒充精确due-age。

## 资源归属和仍保留的开销

完整源码核对见 `C11OUT/audit/c11-product-resource-ownership.md`（含25个源码hash）。Provider先取同一共享公平permit，再进gate/claim；直到receipt COMMIT才释放，等待permit不持gate，退避不占网络执行位。离线积压在SQL，不创建逐目标task/正文副本；Private活跃工作最多4096、每设备最多96，按实际领取编码，共享Arc，不为空连接预分配128KiB。

正常产品pending target预算100万，包含Private waiting/issued和Provider pending/running/retry；Provider accepted待ACK不计该pending预算。产品max_messages/max_payload_bytes为i64::MAX，不是原型10,000消息实验默认。30天身份、等待ACK的正文/索引/日志、Widget待处理频道数没有新增全局数量/字节配额。故内存执行与单次处理有边界，磁盘不具有固定硬上限。ACK释放最后正文，身份保留；逻辑释放变可复用页，物理文件不必缩小。到期清理有256条/轮的处理速度限制，不能把30天当所有字节准时消失保证。

正常共享dispatch保留176个预建worker和5个controller，仍服务Event/Thing等已有业务及普通派生Widget；不是C重新建立的普通双调度。本轮不扩大范围重构它们。低流量仍有owner/恢复/维护/runtime counters和pool维护唤醒，并非零任务/零唤醒。池保留5连接、2个主动保持的协议peer与频道信息cache属于存活对象；malloc live、malloc reserved、RSS分别报告，不能把RSS差值全部归因某一个缓存或据两周期排除长期泄漏。

SQLite只读空间收据为`audit/{baseline-sqlite-space-complete,after-sqlite-space}.json`。最终213条身份、正文0、目标0；主库995328B=243×4096B，其中73页（299008B）可复用；基线987136B、72空闲页且仍有573B正文。正文逻辑删除没有缩文件，两个fresh库的页布局/新增索引也有差异，不以文件大小差判泄漏。本轮未VACUUM或删除数据库。

最终消息表及其全部索引的逻辑cell payload实测约323.06B/身份（213条小样本，不含页/空闲/WAL、控制记录和待ACK目标/正文）；不能把它当跨库固定记录大小。仅按该cell成本外推，1个新message/s的30天约259.2万身份、0.78GiB；10/s约7.80GiB、100/s约78.0GiB。它是容量规划下界量级，不是30天实跑。fanout增加target数，不增加同次message身份数；正文只保留一份，目标/索引另计。规划还需加`消息率×fanout×目标驻留时间`的目标记录，以及ACK/TTL前正文、页/索引/WAL/备份余量；磁盘无硬配额的限制明确保留。

## 首错、环境与退出

保留原始维护/Widget红测；最早维护用例误把`ttl=600`当相对时间，产品实际为绝对毫秒，随后只修fixture为now+600000，并保留原始源码/收据。修正fixture后的基线仍真实失败：257条过期正文/目标未清理；Widget每turn1页预算实际生成257job而非128。

首轮资源跑在74.6秒由测试器4GiB+512MiB增长保护中止，后续观察连接关闭错误属于该中止；不是Gateway内存失败。原记录及分类 `audit/product-baseline-interruption.json`不覆盖。另保留一次runner相对路径spawn失败（0测试），一次MySQL错误module过滤0测试（不计通过）；正确绝对路径/exact名另有收据。没有延长窗口、删失败lane或降低输入。

用户授权后仅删除精确清单中的32,011个可再生Gradle transform/build-cache文件，逻辑2.027GiB，但即时物理可用仅增加10.7MB，不把逻辑大小当实际释放量；未删除历史产物/日志/数据库/源码/用户数据。空间不足后所有构建负载停止，待用户释放空间、实查约8GiB后恢复。全过程保留4GiB硬线，测试另留512MiB增长余量。PG/MySQL原隔离引擎分别只建全新测试库，测试后0client/事务/用户锁并恢复paused、释放lease，见`env/final-quiet-environment-restored.json`。PG16.14、read committed、fsync/full_page_writes/synchronous_commit on、768MiB tmpfs；MySQL8.4.11/InnoDB/RR、flush_at_trx_commit=1/sync_binlog=1、disk-backed volume。它们只作原生正确性证据，不是断电持久性证明。

## 发布前清单与停止

- 真实Provider及连接池/凭据生命周期；物理Watch后台；Android/Windows实际平台持久闭环及Windows OS、客户端QUIC/WSS。
- SQLite/PG/MySQL旧库迁移、回滚、索引兼容及正常产品规模下启动恢复；断电持久性和真正磁盘故障。
- 依据实际负载/设备数/fanout/正文/ACK延迟和磁盘预算做产品路径容量验收；本轮有限SQLite负载不覆盖长期过载/长期无泄漏/三库性能。
- 保留48KiB整个/message JSON、32KiB控制、128KiB完整Private帧/WELCOME（含type/flags两字节，不含TCP/QUIC四字节长度前缀）。旧Private客户端硬切，Gateway/Warp/JNI/Windows必须配套升级；先准备并发布新版客户端再切Gateway，本任务不执行发布。
- PG历史约25秒差异未获得本轮匹配复现，继续未解释；C9撤回MySQL试验未恢复。真实Provider、旧库迁移与其他消息类型均未追加。

最终独立数值与范围复核见`C11OUT/review/c11-final-evidence-review.md`。本轮实现、直接相关验证与有限资源观察已收口；保持H32与现有简单所有权，不增加伸缩控制器，不追加性能研究。源码运行提交11da17b之后仅提交本报告；最终HEAD/干净状态及各仓库保全见外部`audit/final-state.json`。等待审阅，不自动启动下一阶段。
