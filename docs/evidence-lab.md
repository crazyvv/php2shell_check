# 离线证据实验与报告对比

实现位于 `src/evidence_lab.rs`。模块只处理 `serde_json::Value` 和本地文件，不包含 HTTP 客户端、进程执行、PHP 调用或漏洞载荷生成逻辑。

## 六项规则

| ID | 规则 | 防止的误判 |
| --- | --- | --- |
| E1 | CLI 与 Web 运行时严格分离 | 本机 `php -v` 达到基线就认定 Web 已修复 |
| E2 | 版本只产生基线线索 | 响应或报告中的版本号被当作独立补丁证明 |
| E3 | 配置证据绑定运行时范围 | CLI 的 upload_progress / handler 被套用到 FPM 或 mod_php |
| E4 | SAPI 只约束链路适用面 | nginx、Apache 响应头或单个错误被当作 SAPI/漏洞证明 |
| E5 | 五类链路都列出缺失证据 | 单一 Cookie、500、表单或错误关键词补齐整条链 |
| E6 | 修复前后对比不升级为独立验证 | “字段变好”被写成“漏洞已修复” |

`php-selfcheck offline-poc --json` 使用两份合成报告：修复前报告故意让 CLI 为 8.5.12、Web FPM 为 8.4.26，以验证 CLI 不能覆盖 Web；修复后 Web 为 8.4.27，并提供合成的公告、包修订、运行映像、worker 重启和后端覆盖声明。即使六项规则通过，输出仍保持 `patch_independently_verified: false`、`exploitability_confirmed: false`。

## 五类链路矩阵

`chain_matrix` 输出 A–E 五条记录，每条包含：

- `prerequisites`：必须同时成立的前置条件；
- `propagation`：只描述防守理解所需的数据或状态传播；
- `defenses`：优先处置与复核点；
- `missing_evidence`：当前材料尚未提供的证据；
- `status: incomplete` 与 `exploitation_verified: false`。

矩阵不接受远程响应作为 LFI、内存破坏、同一 worker 或命令执行证明。需要服务端代码审计、实际 Web 运行时、运行映像、进程/请求关联及受控测试环境材料。

## 报告输入与输出

`compare-reports` 接受顶层含 `runtime_observations` 的 `php-selfcheck-host/v1`，也能处理导入后的 `assessment.runtime_observations`。每份文件最大 1 MiB，根节点必须是 JSON 对象，运行时最多 128 条。

范围由 SAPI 决定：`cli`、`phpdbg` 始终归为 `cli_only`；`apache2handler`、`fpm-fcgi`、`cgi-fcgi`、`frankenphp`、`litespeed` 和 `cli-server` 归为 Web；其他值保持未知。输入中的自报 `scope` 不可覆盖该映射。

对比字段包括 Web 版本、版本基线、SAPI、upload_progress、serialize_handler，CLI 版本及修复材料完整声明。输出不修改输入报告，不连接目标，也不写入数据库。

## 来源

- PHP 官方：GHSA-w8hw-w9fx-j79w、GHSA-6wmf-4rv5-p3rp；
- `ikow/php2shell-poc`：`caffb96b0a165eb3796828a9a1dc7445ec7ff77d`，用于五类链路和补丁边界的防守整理；
- `murrez/php2shell`：`7de30d56887d20e4bfc1b3f90b47f067917742c7`，借鉴 SAPI 分流、事件类别和条件展示；
- `spcaeo/php2shell-check`：`78afcd9b8d88e76549f5d2fc9d61e9f077fe081e`，借鉴逐项证据、受阻即未知和版本隐藏不猜测原则。

本模块为独立实现，没有复制或执行三个社区项目的利用载荷。社区结论不替代 PHP 官方公告和发行版厂商通告。
