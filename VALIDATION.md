# Rust 迁移验证记录

验证时间：2026-10-23。环境：Debian 13、Linux x86_64、Rust/Cargo 1.99.1。

- `cargo build --release --locked -j 4`：通过，生成 stripped 发布版程序。
- `cargo test --locked -j 4`：35 项通过（14 单元测试、21 集成测试），0 失败，0 忽略。
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

当前任务与管理员后台验证：
- 两个独立访客会话的任务、同目标材料、JSON/CSV 导出隔离；知道其他会话任务 ID 仍返回 404。
- 普通页面不请求历史列表；新任务替换旧任务；同标签页刷新恢复当前任务，新标签页不自动加载旧任务。`node --test tests/ui-state.cjs`：3 项通过。
- 管理员 API 无登录返回 401，普通账号不能当作管理员；错误密码被拒绝，缺少 Origin 的登录被拒绝。
- 管理员登录后查看多会话与旧版 anonymous 历史，验证全站汇总、搜索、分页及跨会话导出。
- 管理员退出后旧 Cookie 重放返回 401；会话令牌哈希存储、角色隔离、过期、管理员密码变更失效有测试。
- 增加 sessions 表与索引，不删除原任务/主机材料/审计。

发布版真实命令验证：旧配置 add-admin 添加两个独立管理员、拒绝覆盖；旧 SQLite 历史迁移、访客 Cookie 在页面刷新/资源加载中保持稳定、跨会话拒绝导出、后台密码登录与汇总、重启后会话仍可用、退出不影响访客身份均通过。新 init 的管理员随机密码与保存哈希已在内存中核对，未输出密码。

管理员删除/排序/筛选验证：混合结论任务只返回命中目标、导出沿用筛选、四种排序、搜索与结果组合匹配、非法排序拒绝、未登录/缺少 Origin/未确认删除拒绝、运行中删除 409、删除后详情 404、统计同步与其他材料保留、事务内删除审计均通过。前端测试覆盖筛选参数、导出链接、取消确认不发请求以及确认删除。

发布版实际 HTTP 验证：管理员登录、风险排序、混合任务结果筛选、筛选 CSV、未确认删除拒绝、确认后删除整次扫描、详情 404、剩余任务数量/汇总与删除审计更新均通过。仅使用临时数据库合成记录。

中间件采集验证：
- Apache/httpd、Nginx/Tengine、PHP-FPM 分类、PHP 映射库和模块声明提取、socket inode 归属关联、IPv4/IPv6 LISTEN 解析与权限不足标记均通过。
- 配置文件与命令行开关覆盖、默认全部关闭、开关依赖、Host/路径/协议/请求数限制校验通过。
- 本地真实模拟 HTTP 验证 Host 固定、Cookie 值脱敏、不跟随元数据跳转；跨网络命名空间和 PHP-FPM 不发 HTTP，Host IP 不能把连接改向其他地址。
- 页面开关依赖、命令生成和不安全 Host 拒绝有前端测试；导入的中间件材料保持 unverified 且不提升结论。
- 从 Debian 签名仓库获取并校验 Nginx 包，解包到 /tmp，以当前普通账号启动临时本机 Nginx。发布版正确识别 PID、版本/构建线索、实际监听端口；Web 开关关闭时访问日志没有 GET，显式开启后只对本机端口 GET，保留指定 Host 并读取模拟 PHP 头。关闭采集开关也已验证。临时服务已停止。
- 实际 Apache、Tengine、LiteSpeed、真实 PHP 模块加载、跨容器运行与企业 TLS 仍需在对应环境验证；这部分通过构造 /proc/模块输出的测试验证，不声称生产覆盖。

## Rust 1.91.1 兼容性验证

使用 Rust/Cargo 1.91.1 执行 `cargo +1.91.1 test --locked -j 4`，项目与 Cargo.lock 锁定依赖编译成功，35 项测试全部通过。`Cargo.toml` 的最低版本声明调整为 1.91；工具链默认仍使用 stable，也可显式选择已安装的兼容稳定版。

## 版本解析、轻量扫描、CI 与可选本地采集验证

验证环境：Rust/Cargo 1.91.1、Debian 13 x86_64。

- `cargo +1.91.1 test --locked -j 4`：51 项通过（24 单元测试、27 集成测试）。
- `node --test tests/ui-state.cjs`：4 项通过。
- `cargo +1.91.1 build --release --locked -j 4`、格式检查及 stable Clippy（全部 target，拒绝 warnings）：通过。
- 完整版本声明保留，RC/beta/dev 与未知分支不误判为正式修复版；多版本冲突保留风险声明、维持未知结论。
- 本地 HTTP 服务验证 HEAD 在 405/501 时回退 GET，其他状态不回退，均不读取正文；仅响应头模式不跟随跳转。Web 提交验证模式字段类型，任务和导出保留扫描模式，特殊地址继续拒绝。
- CI 命令验证非法目标/配置退出 2，特殊地址拒绝退出 3 且输出 JSON；分类器覆盖达到上游基线退出 0、疑似受影响退出 1。没有扫描真实公网或公司资产。
- 使用独立子进程与临时 PHP 脚本验证：默认不调用 PHP，显式 `--php-command` 才查询版本/CLI 配置，可指定 PHP 路径，命令行 false 覆盖配置文件 true；未修改进程全局环境变量。
- 软件包归属测试使用隔离命令夹具：Ubuntu 源包与已安装修订号的官方归档匹配、RPM 架构/源包/Vendor/模块流及 Epoch/Version/Release 分别比较；不同发行版、来源或流不套用阈值。Debian 版本排序使用本机真实 dpkg 验证。
- 进程/模块夹具验证已删除或替换映像提示重启、文件不可见保持未知、跨挂载命名空间不查询主机软件包库。导入材料不提升远程结论，参考规则不标记为独立核实。
- 大报告优先省略原始命令条目，记录省略数量并保持在网页上传限制内；CLI 配置路径在导入证据中保留。
- 实际运行发布版 `collect --package-audit` 成功，识别本机 Debian 13，PHP 命令状态 disabled，CLI 运行观测为空，报告可解析且未超限。

厂商修复参考表来自 openai/php2shell-checker 固定提交，保留 Apache 2.0 许可和来源。本次未独立核实全部厂商公告；参考匹配不是确认修复。本机没有部署生产 PHP-FPM/Apache 实例；真实 RHEL/Ubuntu 软件包、生产进程更新及容器部署仍需在相应环境复核。Docker 构建未实际运行。

## Windows / Linux Release 发布验证

版本标签：v0.2.0；发布流程源提交：09c9d9a。

- 修正 Linux 专用中间件测试的平台条件；Windows 使用 MSVC 构建及原生测试，Linux 使用 musl 静态目标。
- 本地 Rust 1.91.1 `x86_64-unknown-linux-musl` 发布构建成功，51 项测试通过；4 项前端测试通过。
- Linux ELF 确认为 stripped static-pie。原始程序和打包后解压程序均通过版本/帮助、本机 Web 启动、页面与 API、特殊地址拒绝、默认不调用 PHP 的采集检查。
- Linux tar.gz 保留程序执行权限，包含公开示例、文档及许可证，不包含真实 config.json、数据库或状态目录。
- Release workflow 通过 actionlint v1.7.7；发布脚本通过语法检查及隔离模拟 API 验证：必须具备两个平台附件，下载校验成功后才能公开；下载被篡改时不执行公开发布。
- 云端 Windows MSVC 与 Linux musl 两个任务均通过测试、发布构建和本地启动检查；发布脚本上传附件后下载回验 SHA-256，再公开 Release。已从 release-manifests 分支取得成功回执，核对源提交与 v0.2.0 标签一致。当前环境的 GitHub API 仍返回 403，最终发布状态通过该 Git 回执确认。

发布地址：https://github.com/crazyvv/php2shell_check/releases/tag/v0.2.0

云端构建记录：https://github.com/crazyvv/php2shell_check/actions/runs/39947139307

已发布附件的 SHA-256（以 Release 的 SHA256SUMS 为准）：

- `php-selfcheck-v0.2.0-linux-x86_64.tar.gz`：`7a1af611d777b4fa37243e2d0a8c254e59597cd3c7fc3b4fe6e2d46b99ec3480`
- `php-selfcheck-v0.2.0-windows-x86_64.zip`：`4c6071c85116e9f2b522648ee9bd10c594d7b456b8f308869bf8404ff613874c`

## v0.3.0 可配置网站特征库验证

验证日期：2026-10-26。Rust/Cargo 1.91.1，Linux x86_64。

- 完整测试：`cargo +1.91.1 test --locked -j 4 -- --test-threads=2`，63 项通过（25 单元、38 集成）；前端 5 项通过。静态检查、格式检查和发布构建通过。
- 内置 51 条被动规则，覆盖 CMS/框架、静态生成器、托管平台、中间件、CDN/WAF 与挑战页。保留 spcaeo/php2shell-check 的固定提交来源、MIT 许可及 NOTICE。
- 验证扩展/覆盖/禁用/替换、all/any 条件、非法字段/重复 ID/无效正则/敏感头/错误版本来源/过大文件拒绝、配置及采集器选项的相对路径、CLI 导出不覆盖及校验、普通检查的显式库覆盖。
- Cookie 值不匹配、不导出；资源查询参数省略；外部资源引用不推断目标 PHP；普通页面提及、注释和脚本中的示例不冒充实际资源。CMS 产品版本不进入 PHP 版本判定，托管/CDN 特征不认定修复。
- 自定义规则通过真实本机监听 HTTP 夹具进入采集结果；扫描循环使用同一份已加载规则，保留来源 URL、版本及有效库 SHA-256。明确挑战页保持未知并停止跳转；普通 CDN 不单独认定为受阻。匹配器不增加请求。
- 页面与管理员共用特征展示，按文本渲染规则/名称，不执行 HTML；JSON/CSV 保留特征；历史缺少新字段仍可展示。
- 发布版在本机通过启动及本机 API 检查；内置完整 JSON 和扩展示例分别校验为 51 / 52 条有效规则。未扫描公网或公司实际业务。规则只提供证据线索，不能证明运行环境、后端归属或补丁状态。

GitHub Actions 已完成 Windows MSVC 与 Linux musl 的原生测试、构建、启动检查；上传后下载附件回验 SHA-256，再发布 v0.3.0。已取得 release-manifests 成功回执并核对源提交与标签一致。

发布地址：https://github.com/crazyvv/php2shell_check/releases/tag/v0.3.0

云端记录：https://github.com/crazyvv/php2shell_check/actions/runs/40266325395

本地另外验证 Linux musl 包包含自定义示例、完整库和 MIT 许可：解压后使用相对路径加载 company-1 库，实际启动服务后 API 显示 52 条规则，不暴露服务器文件路径。

- `php-selfcheck-v0.3.0-linux-x86_64.tar.gz`：`db23dfec40f9dfe611bef7d076412ce4f6deeff0b7275466f6d82b3703c7c514`
- `php-selfcheck-v0.3.0-windows-x86_64.zip`：`0f195e1e7f06719cf4952ecd4cae3362b3182139feebc09afdb45d1181539b49`
