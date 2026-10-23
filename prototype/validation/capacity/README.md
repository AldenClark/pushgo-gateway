# 容量收据源码归档

此目录只保留实际执行源码、归约器、macOS PID C helper和真实revision字节。它不是重新定位后的可直接运行工具：脚本内OUT相对定位保留执行时原样，复现须使用manifest指向的原OUT/harness和新label。

[source-receipt-manifest.json](source-receipt-manifest.json)包含SHA、编译源身份、每个run/matrix的原始收据路径及可用的精确source版本。某些早期coordinator及原3smoke只有hash，明确未重建。详细结果见[容量说明](../../docs/capacity-results.md)。

不包含Apple/Android脚本、binary、cache、原始大JSON、日志或SQLite数据库。不同revision目录内的小JSON仅为源码hash/custom plan元数据，不是测量原始数据。
