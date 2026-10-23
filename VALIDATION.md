# Rust 迁移验证记录

验证时间：2026-10-23。环境：Debian 13、Linux x86_64、Rust/Cargo 1.99.1。

- `cargo build --release --locked -j 4`：通过，生成 stripped 发布版程序。
- `cargo test --locked -j 4`：15 项通过（6 单元测试、9 集成测试），0 失败，0 忽略。
- `cargo fmt --all --check`：通过。
- `cargo clippy --locked --all-targets -j 4 -- -D warnings`：通过。
- 完整环境安装脚本重复执行：通过，已安装工具链和缓存构建可复用。
- 发布版真实命令验证：init 创建 600 权限配置、拒绝覆盖、add-user 增加账号、拒绝重复用户、启动 HTTP 服务、401 认证挑战、中文静态界面、/api/me、异步任务、空范围拒绝扫描、collect 输出 schema、报告导入、CSV 导出、SIGINT 正常退出均通过。临时账号密码未输出到验证日志，临时配置和数据库在测试后删除。
- HTTP 传输测试使用本地模拟站点并仅在私有单元测试中注入连接地址；生产范围规则没有回环放行开关。验证了原域名 Host、固定连接 IP、PHP 版本提取与 128 KiB 正文截断。
- 白名单、混合 DNS、特殊地址、逐跳范围重校验、重定向上限、HTTP 阻断状态、TLS 协议拒绝、账号数据隔离、任务与请求限额、未签名材料信任标记、Python PBKDF2 兼容和重启中断均有测试覆盖。

本次没有对公司资产或公网目标执行扫描。未验证 Docker 构建、企业证书/代理、生产负载或跨架构运行。TLS 测试验证协议不匹配时拒绝连接，未模拟企业 CA 的完整证书链。原版漏洞公告与版本基线没有重新核实；见 README。

预编译程序动态依赖 glibc（所需符号最高 GLIBC_2.39）、libm、libgcc。只适用于相应 Linux x86_64 环境；源码与 Cargo.lock 随包提供。
