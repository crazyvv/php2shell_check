# PHP 安全自查台 · Rust 版 v0.2

由 `php2shell-selfcheck-v0.1.zip` 中的 Python 项目迁移。Web 后端、检测器和 Linux 主机采集器均使用 Rust；原中文 HTML/CSS/JavaScript 界面内嵌到可执行文件，不需要 Python、Node.js 或外部 SQLite 服务。

## 发布包中的预编译程序

ZIP 中的 `bin/linux-x86_64/php-selfcheck` 是本次构建并测试的 Linux x86_64 程序，需要 glibc 2.39 或更新版本、libgcc 和系统 CA 证书。它不适用于 macOS、Windows、ARM 或旧版 Linux；其他平台请使用源码构建。运行前可执行 `chmod +x bin/linux-x86_64/php-selfcheck`，然后用该路径执行 `init`、`serve`、`collect` 等子命令。

## 构建与启动

需要 Rust 1.99.1（`rust-toolchain.toml` 固定版本）、C 编译器和系统 CA 证书。SQLite 由 Cargo 编译，TLS 使用 rustls 和系统根证书。

```bash
cargo build --release --locked -j 4
./target/release/php-selfcheck init
# 保存终端显示的随机 admin 密码，编辑 config.json 中的资产范围
./target/release/php-selfcheck serve
```

默认监听 `127.0.0.1:8080`。浏览器通过 Basic 认证登录。`init` 不覆盖已有配置；配置权限为 600，密码使用 PBKDF2-SHA256（260000 次迭代），不存明文密码。不要将配置、报告和数据库提交到 Git。

初始化的 `allowed_networks` 为空，默认拒绝全部扫描。修改配置时保留 `users`、`database` 等其他字段。例如：

```json
{
  "public_origin": "http://127.0.0.1:8080",
  "allowed_networks": ["10.20.0.0/16"],
  "allowed_domains": ["your-company.example"],
  "allowed_ports": [80, 443, 8080, 8443]
}
```

替换为实际授权资产，不要照搬示例。网段必须使用严格 CIDR 网络地址（`10.20.0.0/16`，不能写 `10.20.1.1/16`）。域名限制非空时，域名必须匹配该域或子域，且**全部 DNS 地址**必须处于资产网段。IP 输入按网段控制。回环、链路本地、组播、IPv4 映射 IPv6、已列入规则的云元数据地址等始终拒绝；不会因配置宽泛网段而放开。

新增账号、修改监听地址或使用独立状态目录：

```bash
./target/release/php-selfcheck add-user --user developer01
./target/release/php-selfcheck init --config /path/to/existing-state-directory/config.json
./target/release/php-selfcheck serve --config /path/to/existing-state-directory/config.json --bind 127.0.0.1 --port 8080
```

账号、范围、端口和 public_origin 的修改在重启后生效。数据库相对路径以配置文件所在目录为基准。默认 `data/selfcheck.sqlite3`，使用 SQLite WAL。运行中备份请使用 SQLite backup API，不要仅复制主数据库文件。

## 免密码与无白名单配置

新建配置可直接启用两个选项：

```bash
./target/release/php-selfcheck init --allow-anonymous --allow-without-whitelist
./target/release/php-selfcheck serve
```

也可将 `config.open.example.json` 复制为 `config.json` 后启动（已有配置请先备份）。

已有配置在 `config.json` 中设置以下字段，然后重启；保留 `public_origin`、`database` 等其他字段：

```json
{
  "allow_anonymous": true,
  "allow_without_whitelist": true,
  "users": {},
  "allowed_networks": [],
  "allowed_domains": [],
  "allowed_ports": []
}
```

`allow_anonymous` 启用后无需输入账号密码，所有访问者共用 `anonymous` 工作台，包括任务、报告、审计身份和每分钟请求额度。`allow_without_whitelist` 启用后，空网段列表表示不限网段，空端口列表表示不限端口；空域名列表一直表示不限域名。**非空的列表仍会限制目标**。使用 `--allow-without-whitelist` 初始化时，网段、域名、端口列表均为空。

两个开关独立，默认均为 `false`，旧配置保持原有认证和范围要求。特殊地址拒绝、逐跳地址校验、TLS、Host/Origin 校验和任务限额在这两种模式下仍然生效。

## 功能与原版兼容

- 个人账号认证；任务、历史与主机报告按账号隔离，管理员审计记录保存在 `audit` 表。
- 一次 1–50 个目标，去重，默认 HTTPS，支持域名、IP、端口、完整 URL 与 IPv6 URL；兼容 `erp_api.example.com` 等带下划线的实际主机名，仍须能被扫描节点 DNS 解析。
- 后台最多 4 个任务运行，最多 8 个待完成任务，每人最多 2 个；任务内目标串行，间隔至少 0.5 秒。每账号每分钟最多 120 个入站请求，同一客户端每分钟 12 次失败认证后暂时拒绝。
- HTTP 头、PHPSESSID 名称、页面 `.php` 引用作为证据；Cookie 值不进入结果；仅从 PHP 专属版本声明提取 PHP 版本。
- 每次请求及每个重定向重新校验全部 DNS 结果，再固定已验证的 IP 连接；保留原域名 Host 和 TLS SNI，不使用环境 HTTP 代理，不跳过 TLS 校验。最多 4 次请求，正文最多保留 128 KiB。
- JSON/CSV 导出；CSV 单元格对公式前缀进行中和。服务重启时将旧的 queued/running 任务标记为 interrupted。
- 主机材料 JSON 导入保留“开发者提交，未经独立核验”标记，不提升远程检测结论。

原版 `config.json` 中的 PBKDF2 密码哈希、数据库表和 `php-selfcheck-host/v1` 报告格式继续兼容。迁移时停止旧服务，备份原配置和 SQLite，再使用 Rust 服务指向该配置；不要两个服务同时运行同一任务库。Rust 不调用 Python。数据库没有自动清理，长期使用前制定保留策略。

## 主机采集

把匹配目标机器操作系统和架构的二进制拷贝到目标 Linux 主机，以普通账号执行：

```bash
php-selfcheck collect > host-report.json
```

只读取可见进程名称/可执行文件路径和 PHP 包信息，对 PATH 中的常见 PHP/FPM 二进制执行 `-n -v`。外部命令有 10 秒超时与输出保留上限；不读取进程环境或命令行，不自动上传。通过 Web 界面关联业务 URL 并导入报告。CLI 版本不能证明 Web/FPM、容器及所有后端实例的版本与补丁状态，报告未签名，关联关系由提交人指定。

## 团队部署

默认仅允许本机 HTTP 试用。团队使用应由公司 HTTPS 反向代理终止 TLS，配置准确的 `public_origin`（无尾斜线、路径），并限制后端端口仅代理可达。非回环监听要求 HTTPS public_origin。参见 `nginx.conf.example`；自定义外部端口时确保 Host 带端口。使用低权限专用账号，独立保护状态目录，不要多人共享 admin 账号。

可选容器构建（本次环境未验证 Docker）：

```bash
docker build -t php-selfcheck:0.2 .
mkdir -m 700 state
# 先使用本机构建的二进制生成 state/config.json，并修改范围与 HTTPS public_origin。
# 将 state 所有权交给容器 UID/GID 10001，再运行：
docker run -d --name php-selfcheck --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v "$PWD/state:/state" php-selfcheck:0.2
```

## 规则与使用边界

**本次是语言迁移，不是公告真实性核实或漏洞利用验证。** 以下 CVE、公告链接、2026-10-23 日期以及 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 基线沿用附件原版，迁移时未独立重新核实。上线判定前需由维护者核实官方公告与厂商补丁适用范围。JSON 结果新增 `rule_provenance` 明确来源。

- 原版来源：https://www.php.net/archive/2026.php#2026-10-21-5
- 原版 CVE：CVE-2026-109618、CVE-2026-109619

检测只发起指定入口的常规 GET，不执行命令、不发送漏洞利用载荷，不自动发现目录、phpinfo、FastCGI 或额外端口。“疑似受影响”需要核实回补补丁；“达到修复基线”“版本未知”“未发现特征”和“检测受阻”均不能证明无漏洞或已修复。提交只读业务页面，URL 中不要包含令牌。主机命令执行仅用于本地运行已有 PHP 获取版本，不接受网络用户提供任意命令。

## 开发验证

```bash
cargo test --locked -j 4
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
```

测试覆盖基线边界、特征误报与 Cookie 脱敏、危险 URL、混合 DNS、特殊地址、逐跳范围校验、重定向上限、HTTP 阻断状态、固定 IP 的真实模拟 HTTP 传输、响应体截断、TLS 协议拒绝、Python 密码哈希兼容、配置权限、HTTP 认证、Host/Origin、任务隔离、报告导入、CSV 导出与重启中断。网络测试只访问进程内本地测试服务，不扫描真实资产。生产扫描规则没有本地地址放行开关。

真实公司资产、企业证书/代理、Docker 构建、生产容量和跨架构分发仍需在对应部署环境验证。
