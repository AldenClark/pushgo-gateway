# C3 容量与资源结果

当前 QUIET，所有候选、Mock、采样与日志线程均已退出。匹配主八例全部 PASS；第九例旧控制 DB-block 真实失败后停止，原余七例 NOT RUN。随后 writerfix 独立九例全部 PASS，无追加测试。零进程的 common.py 观察器启动失败另行保留，不计产品容量成败。

主比较只绑定完整合同候选 `10e59ec` 与控制 `cb0da19`：两份完整源码只差 retirement 查询的一行 SQL。最终安全修复版为 `19cc5c6`，binary SHA `6a6e760f51db767ef7a7a69287a63b4cbb252d5812a701caa59dce63eac046f1`。后九例是该版回归，不是优化匹配 A/B，不能把旧八例算作最终版本性能。

| 匹配主场景 | firstSQL r1/r2 s | target/s 含排空 r1/r2 | producer peak 消息 | 输入结束DB积压目标 |
|---|---:|---:|---:|---:|
| baseline128 | 29.818/30.794 | 686.83/665.06 | 222/240 | 8648/8498 |
| baseline256 | 140.602/161.403 | 291.32/253.78 | 1464/1430 | 11531/14009 |
| candidate128 | 10.376/10.380 | 1973.88/1972.95 | 1/1 | 426/312 |
| candidate256 | 23.863/23.363 | 1716.46/1753.20 | 562/480 | 17180/18754 |

128/256 是消息/秒，每条16个真实目标、输入10秒。H32为每provider上限、Q32、Remote Token Service、合成认证、相同20ms Provider适配延迟。完成平均率含排空，不是持续吞吐。旧匹配候选256两例的独占gate hold占窗口73.83%/77.35%，完整network duration积分对应平均47.66/47.02个网络槽（全局64）；不能把不同轴峰值相加，也不能将跨调用累计wait当墙钟。

| writerfix 后续场景 | 源码 | 消息/目标 | firstSQL s | 结果 |
|---|---|---:|---:|---|
| candidate DB-block | 19cc5c6 | 16/256 | 2.487 | PASS |
| control fanout32 | cb0da19 | 2/64 | 0.276 | PASS |
| candidate fanout32 | 19cc5c6 | 2/64 | 0.289 | PASS |
| control cleanup | cb0da19 | 16/256 | 0.340 | PASS |
| candidate cleanup | 19cc5c6 | 16/256 | 0.336 | PASS |
| candidate idle60 | 19cc5c6 | 0/0 | — | PASS |
| candidate burst/falloff | 19cc5c6 | 67/1072 | 3.716 | PASS |
| candidate128 | 19cc5c6 | 1280/20480 | 10.614 | PASS |
| candidate256 | 19cc5c6 | 2560/40960 | 28.726 | PASS |

全部 PASS 均通过独立SQL全目标/收据、完整wire身份内容、Pull/ACK和joined退出校验。fanout32是公共API合法最大值；此前256接收者建议在静态检查时撤回，未运行、未用SQL绕过。

DB-block保持原样：独立SQLite连接 `BEGIN IMMEDIATE` 持锁约2.02秒，释放后同身份第二波。旧控制gateway日志第6行报 `FATAL owner driver: database: ... (code: 5) database is locked`，对应fixture第155行exit70；旧失败原DB、日志和首次响应完整保留。19cc将预期写事务改为BEGIN IMMEDIATE，仍为3秒busy_timeout、无runtime自动retry，新场景通过256个目标和全部退出校验。更长锁超时的fail-closed/restart范围另由native证据限定。

| 最终19cc单次正常回归 | 128/s×10s | 256/s×10s |
|---|---:|---:|
| 完成 target/s（含排空） | 1929.59 | 1425.87 |
| producer peak 消息 | 2 | 1128 |
| 输入结束DB积压目标 | 1280 | 10267 |
| 后半DB积压增长目标 | 1211 | 2944 |
| 后半producer增长消息 | 0 | 634 |
| accepted→COMMIT mean ms | 193.038 | 6626.004 |
| accepted→COMMIT p95/p99 桶上界 ms | 1048.575/1048.575 | 16777.215/16777.215 |
| 首次attempt queue mean ms | 166.032 | 6589.279 |
| queue p95/p99 桶上界 ms | 1048.575/1048.575 | 16777.215/16777.215 |
| network mean ms | 23.802 | 32.051 |
| network p95/p99 桶上界 ms | 32.767/32.767 | 65.535/65.535 |
| receipt mean ms（含gate+COMMIT） | 3.204 | 4.672 |
| receipt p95/p99 桶上界 ms | 8.191/32.767 | 16.383/65.535 |
| direct COMMIT mean ms | 0.060 | 0.060 |
| direct COMMIT p95/p99 桶上界 ms | 0.127/0.127 | 0.127/0.255 |
| 输入窗口CPU user+sys s | 10.707 | 7.367 |
| load→firstSQL marker CPU user+sys s | 11.283 | 22.109 |
| peak RSS MiB（time -l） | 22.250 | 23.156 |
| 最近SQLx语句总数（读/写） | 328940（101172/227768） | 598822（176244/422578） |
| SQL统计采样晚于firstSQL ms | 265 | 466 |

两个最终短场景后半DB积压均增长，不能据10秒窗口宣称可持续。直方图是固定32个log2微秒桶，给出分位上界而非精确p95/p99。E2E从首次accepted_at至durable receipt COMMIT，不含接纳前producer/HTTP等待。SQL数是所列偏移的最近样本，非firstSQL原子计数；按SQLx语句动词计，不能当成功事务或SQLite trigger内部操作数。

| 前端等待，mean / p95 / p99 ms | 10e 256 r1 | 10e 256 r2 | 19cc 128 | 19cc 256 |
|---|---:|---:|---:|---:|
| HTTP admission | 40.94/76.28/87.23 | 34.68/70.16/90.36 | 11.84/20.43/70.40 | 62.35/91.49/117.10 |
| offer事件→HTTP start | 1133/4007/4481 | 772/3028/3435 | 0.572/1/16 | 4251/9500/9919 |
| offer事件→HTTP response | 1174/4074/4559 | 806/3084/3495 | 12.43/21/80 | 4313/9571/9990 |

上表按op_id/label完整关联，排除warmup；HTTP用原单调时钟latency，producer/response用保留Unix-ms事件时间（1ms分辨率）。19cc接纳前等待更长，因此较低accepted→COMMIT均值不代表更快总完成。精确offer→每target COMMIT p95未采得；不能相加分位数，不能用receipt_at意图时间冒充COMMIT。明细见 `capacity-frontend-admission-comparison.json`。

19cc 256单次28.726秒，10e两次23.863/23.363秒，版本与时序同时变化。BEGIN accept/claim/receipt累计合计0.554/0.590→1.209秒，多约0.62–0.66秒，不能单独解释全部4.86–5.36秒墙钟差。claim pool累计11.015/10.703→14.838秒、独占gate hold17.811/18.273→19.765秒、CPU21.396/21.691→22.109秒。native network均值28.07/27.12→32.05ms，而各40960个完整Mock响应均值23.704/23.638→24.021ms。安全修复有可见BEGIN成本，其余差异未隔离，不能全归锁或纯DB。逐路径BEGIN/pool/SQL/COMMIT/gate及hostcontext在 `capacity-writerfix256-cost-comparison.json`。

| 最终资源观测 | idle60s | falloff后至少10s |
|---|---:|---:|
| 实际marker窗口 s | 60.024 | 10.428（含phase观察边界） |
| CPU user+sys s | 0.061773 | 0.018518 |
| interrupt / package idle wakes | 135 / 50 | 24 / 4 |
| RSS MiB | median/max12.047 | 18.50–18.95 |
| malloc live bytes 起→终 | 1188400→1188784 | 2580496→2561632 |
| malloc blocks 起→终 | 4515→4521 | 5751→5744 |
| malloc reserved MiB 起→终 | 20→24 | 36→36 |
| provider client owners | false,false | false,false |
| owned/network/receipts；provider targets | 0/0/0；0,0 | 0/0/0；0,0 |

falloff为64条burst加3条稀疏消息，共67条/1072目标，全部收据与ACK校验通过；burst直方图窗口不含之后3条稀疏消息，不能混作完整67条分位数。末端vmmap：malloc resident9888K、allocated2242K、free/fragmented7646K（78%），physical footprint11.4M。它与RSS口径不同，支持分配器空闲驻留/碎片，且观测到provider客户端所有者和占位归零；不能泛化为无泄漏或量化SQLite缓存贡献。

idle数字包含fixture每秒一次完整profile统计心跳；observer每250ms执行ps，phase取stats/Mach，falloff另取vmmap。不是未instrument的生产idle成本。host load/CPU/thermal仅观察，不干预其它应用。

原始证据与身份：`capacity-final-state.json`、`capacity-source-handoff-current.json`、两份 `artifacts-profile-*.json`、`capacity-matched-primary8-analysis.json`、`capacity-writerfix9-analysis.json`。实际执行源码保留于 `executed-sources/`，resource_monitor及common均原样归档，不依赖旧ignored路径。
