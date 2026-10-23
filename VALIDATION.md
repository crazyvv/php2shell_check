# Rust 迁移验证记录

验证时间：2026-10-23。环境：Debian 13、Linux x86_64、Rust/Cargo 1.99.1。

- `cargo build --release --locked -j 4`：通过，生成 stripped 发布版程序。
- `cargo test --locked -j 4`：23 项通过（7 单元测试、16 集成测试），0 失败，0 忽略。
- `cargo fmt --all --check`：通过。
- `cargo clippy --locked --all-targets -j 4 -- -D warnings`：通过。
- 完整环境安装脚本重复执行：通过，已安装工具链和缓存构建可复用。
- 发布版真实命令验证：init 创建 600 权限配置、拒绝覆盖、add-user 增加账号、拒绝重复用户、启动 HTTP 服务、401 认证挑战、中文静态界面、/api/me、异步任务、空范围拒绝扫描、collect 输出 schema、报告导入、CSV 导出、SIGINT 正常退出均通过。临时账号密码未输出到验证日志，临时配置和数据库在测试后删除。
- HTTP 传输测试使用本地模拟站点并仅在私有单元测试中注入连接地址；生产范围规则没有回环放行开关。验证了原域名 Host、固定连接 IP、PHP 版本提取与 128 KiB 正文截断。
- 白名单、混合 DNS、特殊地址、逐跳范围重校验、重定向上限、HTTP 阻断状态、TLS 协议拒绝、账号数据隔离、任务与请求限额、未签名材料信任标记、Python PBKDF2 兼容和重启中断均有测试覆盖。

本次没有对公司资产或公网目标执行扫描。未验证 Docker 构建、企业证书/代理、生产负载或跨架构运行。TLS 测试验证协议不匹配时拒绝连接，未模拟企业 CA 的完整证书链。PHP 官方 GHSA、php-src NEWS 与 CVE 记录的版本基线已核实；实际部署的回补补丁仍须单独核实。

预编译程序动态依赖 glibc（所需符号最高 GLIBC_2.39）、libm、libgcc。只适用于相应 Linux x86_64 环境；源码与 Cargo.lock 随包提供。

新增配置验证：免密码 HTTP 访问、共享 anonymous 身份、免白名单任意常规地址/端口、非空列表继续生效、特殊地址继续拒绝和旧配置默认值兼容均通过。

域名兼容修复：先用 `http://erp_api.xxxx.com` 回归用例复现“域名格式错误”，允许下划线后验证默认协议、端口/路径/查询、大小写与末尾空白归一化，危险输入与白名单限制仍有效。未请求该真实地址。

扩展证据功能验证：
- SAPI 不由 Server 头推定；multipart 表单与上传进度字段仅作为页面线索；无证据保持未知。
- EOL 与缺少补丁分别判定；版本达到上游基线仍标为远程声明。
- 小型 multipart POST 真实本地 HTTP 传输通过：请求小于 1 KiB、没有文件或上传进度字段、不跟随返回的元数据地址重定向。
- 主机材料/手工复核按账号和目标 URL 关联；CLI 即使自称 Web 仍归为 cli_only；材料中的“已修复”不会提升远程结论；CSV 包含补丁来源。
- 手工复核字段枚举、长度、公告 URL 校验与未知字段剔除通过。
- `node --check assets/ui.js` 通过。
- 使用从 Debian 签名仓库下载并校验的软件包，在 /tmp 解包 PHP 8.4 CLI，验证采集器读取选定 INI 并标记 CLI-only；Web 助手 PHP 语法检查通过。
- 实际 PHP 本地 HTTP 服务验证：助手未授权返回 403 且无内容，已有入口授权后返回指定配置 JSON，SAPI 为 cli-server。未测试真实 FPM/Apache 部署或全部 worker。
