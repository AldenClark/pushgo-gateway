# 四仓发布前审阅与集成准备（2026-10-19）

结论：四仓可以进入精确候选的正常分支评审。未发现新的已证实产品运行链缺陷；本轮修复两项会误判当前候选的 Gateway CI 契约。尚未执行远端 CI、合并或发行，不能据本报告直接切换部署。

## 冻结身份与证据

- Warp：b474dd906f7e6d4244f4c821b49af6a47f42956f，codex/warp-main-private128-20261018；本地 main 2d901be4ff596e84d4a96efda327ef0441b0f640。
- Android：9f6d127997ec1a4cde19b8a4d1efcf9c73f32af1，codex/android-api37-permission-20261018；本地 main b831a5eadbe8f67b64535868af91aa74dbe1ba3f。
- Windows：db8b243d71ef9e9a664602435a198891a77181a8，codex/windows-warp-b474-20261018；本地 main f39598ed7b1854584320f63f005f837c18e8a650。
- Gateway：起点652c10bd5cf497952a456c9f41f44495f7506758，codex/gateway-c-product-ordinary-20261016；本地 main dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6。本文件所在提交仅增加 CI 工具修复、测试及说明；正常运行源码、依赖、SQL、预算、生命周期均未变化，已有正常 Release 不重建。

完整最终 SHA、工作树/远端查询、原始命令退出码、逐提交范围、产物和校验见候选内 build/quality-results/preintegration-review-20261019/{integration-report.md,delivery-manifest.json,delivery-seal.json}。本轮核对上一轮 normal-release-acceptance-20261018 封存62项全部匹配；旧失败、pending快照和报告原样保留。

## 审阅与最小修复

Android 完整权限/大字体链检查了保存前预检、取消/连续拒绝、Settings 返回、正常 capability null/NONE/QA 分离、Private 单 owner 重启和 API28/public 地址分类。没有验证出需修改生产代码的缺陷。真实公网 Gateway 成功、正常 GMS 可用时显式 FCM→Private 仍未运行；不能用注入回调证明它们通过。字体证据只覆盖已有 font1.5/窗口/语言，未外推 TalkBack、所有字体/语言。

两个客户端正常 manifest/lock 均精确 b474；Gateway 有意保持 fded360134f2144876bb11b95e7431cb1d72aef3。正常路径无新 QA CA、临时绝对依赖、source replacement 或测试 endpoint。归档 prototype QA manifest 与正常 root crate 构建隔离；Windows release_smoke 模块仅在 test+Windows 编译，不包含在正常 EXE。未升级依赖或改变这些 pin。

Gateway 抽查正常入口→ordinary、唯一控制记录、Private Hub、ACK/正文释放、owner/permit及v13切换恢复路径，未发现新的已证实运行缺陷。这是有界风险审阅，不是全量 SQL/所有故障窗口重证。

本轮两项修复均为测试/CI接缝：

1. preflight Private 冒烟原查询旧 private_outbox/private_payloads，普通消息已写 ordinary_messages/ordinary_targets，会把健康接纳误判成丢队列。改为逐条核对身份、唯一目标、未ACK、完整正文、TTL和重启事实；保留旧队列表零写入反向断言，不恢复双写。32次输入、重启deadline和产品合同不变。
2. 历史 v11/v12 drill 原把当前 v13 二进制当 V12_BIN。保留其精确 v11/v12断言，默认独立构建固定dfb6b7c2…真实v12；两个workflow改传V12_SOURCE_COMMIT。显式传入v13也在写入演练backlog前明确拒绝。此历史演练不是v13切换证明，不扩大旧库支持。

## 新执行与复用

- PASS：获本轮明确授权，新空 API37 arm64 AVD emulator-5582；四条 public-action instrumented 方法单次4/4，0 failure/error/skip，真实ViewModel/Room、受控服务/fake native。验证显式切换保留FCM/解释可取消，自动回退不弹解释，两类失败不误保存；不证明真实FCM或OS授权。使用现有debug签名/JNI，未创建密钥、改网络/信任、启动Gateway/VM或触碰物理设备。AVD已停止、PID消失、租约释放，证据保留。
- PASS：新增12项host工具契约回归；既有static_release_audit自动发现，总16项通过；Bash语法、当前diff检查通过。首轮12项中1个fake-git测试器动态作用域错误，修测试器后通过，原FAIL保留。它们不是真实历史二进制/数据库迁移验收。
- REUSED PASS：正常Android API37/API28、Windows11 ARM64 TCP/TLS旅程，共6消息/6持久化/6目标ACK，3个49153字节请求拒绝且无身份，服务端正文/目标清零。正常产物/源码绑定未变，未机械重跑。37项JVM原在0fd480b执行，后续layout未改其逻辑；不称本轮新执行37项。
- REUSED PASS：b474帧codec/feature证据、C17窄迁移与固定旧main v13拒绝、正式URL干净Git/Cargo解析。正常HTTP同op重放不是wire ACK丢失重投；历史QA故障回执单独保留。
- NOT RUN：修复后的完整正常preflight、真实固定v11/v12构建及drill、远端CI；需要在获准的集成CI运行。没有重新跑三库矩阵、容量矩阵、Windows或正常Release旅程。

全范围 main→Gateway 的 git diff --check 仍报告归档CSV/patch的历史空白；本轮diff通过。不改写历史证据以消除该旧结果。

## 集成顺序与门槛

1. Warp b474 正常分支PR/CI；既有远端候选精确存在，不重复push。保留该revision可解析，即使之后merge main，客户端仍pin精确b474。
2. Android9f6和Windowsdb8可并行评审/CI，再按各仓审批整合；不是只挑最后pin提交。完整main/远端main到候选的清单随交付提供。Windows主工作区未知release_smoke修改和Warp主工作区build/不纳入候选、不覆盖。
3. Gateway本文件所在候选评审/CI。两CI修复不变更运行源码，正常二进制证据继续绑定原运行树。只有required checks实际通过后才能按授权合并。不得为过CI回退普通旧链或放宽断言。
4. 合并代码、构建发行物、分发客户端、迁移现有库、切换Gateway分别审批。切换128KiB WELCOME前，先升级该部署实际Private消费者，确认131072整帧能力；旧客户端硬切，无旧WSS兼容旁路。49152是整个HTTP JSON，131072帧含type/flags不含TCP/QUIC4字节前缀；不重开尺寸设计。

CI应实际运行：Warp ci/check、feature-matrix、supply-chain、ffi-miri；Android android-quality/fast-regression、device-regression（变化选择器与四项精确方法）、observation；Windows windows-native/native及supply-chain；Gateway route-transition和release-preflight（含新host回归、当前ordinary preflight、真实历史drill）。Gateway dependency-policy和实际目标Linux构建/asset inventory须在对应发布前运行；label/manual动作另行批准。不得dispatch Windows workflow代替PR，因为dispatch还会进入signed-msix。不触发tag/release、签名/分发或部署workflow。

现有库仅沿用C17固定main/v12、严格排空、可证明来源、停止旧写入、独占和完整一致备份的窄切换范围；激活/业务或维护写入后仅前向恢复，不恢复旧快照。新库不需要伪造迁移。合成验证不授权取用真实用户库。

正式Android签名/分发、Windows目标发行包装/签名、实际Linux部署产物、真实Provider/物理Watch及后台平台、断电持久性属于对应发布范围门槛。QUIC/WSS、Windows x64/安装器/所有平台并不因本地TCP/TLS通过而自动受支持，也不自动全部成为Gateway代码评审阻塞。不增加Apple Private。

下一步只建议授权精确候选远端交付及四仓普通PR/CI；不包含merge、dispatch、tag、release、正式签名或部署。具体远端、ref、SHA和触发项由本轮 external-actions.json 列明，未获授权不执行。
