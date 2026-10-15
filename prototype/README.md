# C 普通消息第一切片原型

独立 Rust crate，入口仅允许本地合成 SQLite 和 loopback Provider Mock，不接真实凭据或用户数据库。冻结原 C32 在另一个目录；本目录是本轮候选。

正文保存一次，收件人/Provider结果/ACK保存在targets；接纳与全部冻结目标一笔事务提交。两个Provider驱动按需持有attempt futures，领取reservation在payload加载前限制数量。Direct/Pull共享稳定字符串payload，包括可信配置base_url、ID、首次时间和绝对expiry。支持legacy/V2 ACK及带路径前缀的路由。

本轮执行策略为固定H32/Q32的懒执行，actual0→64→0，目标上限不缩放；无per-attempt Tokio task。FCM/APNs各自按需创建HTTP client，连续积压保留各≤32 idle connection，空claim提交且工作完成后释放，无连接清理timer。库实验默认仍是H8/Q8+demand，fixture显式选fixed32。demand选项仅为可复核消融保留，产品接入前应收敛默认值和模式。

单连接SQLite事务使用WAL+FULL；进程内mutation mutex串行化写入；规范化路径OS文件锁防止重复启动。正常退出停止HTTP、释放attempt/receipt事务、等待保留claim、关闭pool，再释放锁。异常Drop保留锁到进程退出；新owner恢复running行。断电、存储故障及硬链接别名保护未验证。

Root已运行25个原生Rust测试、Clippy all-targets -Dwarnings、Release负载比较，以及原样Apple Shared/GRDB+URLSession和Android5文件/JVM HttpURLConnection两个真实网络oracle。精确范围、原始失败、资源与复杂度见上两级report.md。

可在本目录使用缓存依赖复现 cargo test --locked --offline --lib 及 cargo clippy --locked --offline --all-targets -- -D warnings，不写冻结C32目录。

fixture参数：--db-url sqlite://…?mode=rwc --http-addr 127.0.0.1:0 --mock-endpoint http://127.0.0.1:<port> --provider-budget 32 --claim-quantum 32 --concurrency-mode fixed --public-base-url http://127.0.0.1:<port>/gateway。

完整SenderDTO、安全、正式sender-status、Event/Thing/Watch/WNS、真实通知wakeup及PG/MySQL适配尚未实施。35天保留、10,000 messages、1,000,000 targets、64MiB aggregate payload都是继承的实验配置，ACK不释放容量，不是产品默认或百万规模承诺。任务数量有界不等于全SQL扫描/事务时长/RSS有界；Provider回复及HTTP2输入预算仍需补齐。
