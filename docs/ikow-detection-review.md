# ikow/php2shell-poc 检测逻辑复核

参考：https://github.com/ikow/php2shell-poc ，2026-10-29 快照 `caffb96b0a165eb3796828a9a1dc7445ec7ff77d`。只阅读 scanner、detection、文档，没有运行其 PoC 或 exploit；本项目独立实现下面的观察与校验，没有复制利用载荷。

## 判据不能直接照搬

| 社区实现中的推断 | 本项目采用的判据 |
| --- | --- |
| Apache → mod_php，nginx → FPM | 响应头不能确认 SAPI；用实际 Web 运行时报告、进程与模块证据复核 |
| 上传进度 POST 收到 PHPSESSID → handler active | 仅记 Cookie 名称线索。普通业务 session_start() 也可产生，不确认配置或漏洞 |
| 文件名标记在响应中出现 → session injection confirmed | 反射不是会话写入证明；本工具不做此推断、不指定 SID、不回读会话 |
| 空白 500、502、连接中断 → worker crash / patched | 代理、业务错误、限流均可产生；没有进程/日志证据不能确认 worker 崩溃或补丁 |
| PHP 版本达到基线 → PATCHED | 版本声明与实际实例、发行版回补、进程重启要分别核验，仍保留待核验 |
| EOL → no fix | 只证明上游停止支持；厂商或商业 LTS 回补需要单独证据 |
| 请求含默认上传进度字段 → exploitation attempt | 正常上传也可能使用它；IDS 告警需要上下文，不直接判恶意或漏洞 |
| 上传进度关闭 → 完整修复 | 只阻断部分路径，不替代官方修补与运行实例核验 |

## 已实现的观察流程

1. 管理员允许基础观察，开发者为本次任务勾选；程序固定策略与特征版本快照。
2. 做既有 GET/范围/DNS/TLS 检查，保留响应版本声明、上传表单和错误类别。挑战页/异常响应停止后续观察。
3. 可选提交单次小型普通文本文件及默认进度字段。无需也不接受自定义载荷、会话 ID、编码器或任意请求模板。
4. 仅记录 HTTP 状态与 Cookie 名称是否出现；同时保留 GET 基线是否已有 Cookie。反射、Cookie 和状态差异都不升级漏洞结论。
5. 由开发团队通过受保护的现有管理入口采集实际 Web SAPI、PHP 版本及选定 INI；与 CLI 配置分开。关联已提交主机材料、厂商补丁记录和 worker 重启状态。
6. 对照官方公告核对适用实例、回补修订和缓解范围；证据不足保持未知。已有内存、会话解码/销毁和文件包含错误文本只作为日志复核线索。

在线观察不能独立验证完整利用链或证明已修复；报告不会将 exploitation_verified 改为 true。本项目不实现会话固定、会话污染、LFI 执行、UAF、内存耗尽或故障注入。源码注释说明为什么不作这些推断，而不会补出利用链步骤。

## 可学习的防守代码

核心是分别保存事实和解释，不把相关信号升级成漏洞确认。等价的最小 Rust 表达如下：

```rust
let evidence = serde_json::json!({
    "session_cookie_observed": cookie_name_seen,
    "upload_progress_configuration": "unknown",
    "confidence": "low",
    "exploitation_verified": false,
    "next_step": "核对实际 Web INI、同一请求日志及官方修补包",
});
```

这里的 cookie_name_seen 只是响应中是否出现名称，不记录值。生产实现还保留时间、目标和连接 IP；不因该布尔值修改 CVE 判定。

## 防守规则的落地条件

项目提供的 Suricata/Sigma/ModSecurity/OpenResty 思路可用于已有流量及日志关联，但规则不应自动等同于漏洞确认。部署前需要本地语法校验、合法上传样本与告警样本回放、字段映射、TLS 解密位置、请求体截断范围和误报基线。访问日志通常不含请求体，不能假设 Sigma 规则能看到上传进度字段。默认进度字段可改名，攻击观察缺失不代表没有风险。PHP 子进程、会话文件事件和错误响应也需要关联同一实例及时间窗口，不能单独归因于某个 CVE。

本次没有修改或部署 WAF/IDS 规则，没有运行外部目标 PoC，也没有宣称其全部规则已验证。
