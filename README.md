# PHP 安全自查台

面向开发团队的 PHP 安全自查工具，使用 Rust 实现 Web 服务、远程检测器和 Linux 主机采集器。中文 Web 界面内嵌于程序，扫描结果保存在 SQLite，无需外部数据库服务。运行服务不需要 Node.js。

开发者页面只展示当前扫描，管理员通过独立账号访问历史记录与汇总。支持免密码扫描、可选资产白名单、检测证据展示、主机材料导入和 JSON/CSV 导出。

## 下载与运行

从 [GitHub Releases](https://github.com/crazyvv/php2shell_check/releases) 下载与系统匹配的程序包：Windows x86_64 使用 ZIP，Linux x86_64 使用 musl 静态构建的 tar.gz。解压后阅读 `START-HERE.txt`，使用同一 Release 的 `SHA256SUMS` 校验文件。

Windows 在 PowerShell 中执行 `./php-selfcheck.exe`，Linux 执行 `./php-selfcheck`。两者都支持 Web 服务和 URL 检查，`collect` 主机采集仅支持 Linux。Linux 的 HTTPS 请求需要系统 CA 证书；Windows 如提示缺少运行库，安装微软官方 Visual C++ 2015–2022 Redistributable x64。

```powershell
# Windows：初始化、保存随机管理员密码后启动
./php-selfcheck.exe init --allow-anonymous --allow-without-whitelist
./php-selfcheck.exe serve
```

```bash
# Linux：初始化、保存随机管理员密码后启动
./php-selfcheck init --allow-anonymous --allow-without-whitelist
./php-selfcheck serve
```

发布包不包含真实配置或数据库。上述示例显式启用免密码和无白名单扫描，其他配置方式见下文；团队部署仍需配置 HTTPS 反向代理与准确的 public_origin。

## 构建与启动

需要 Rust 稳定版工具链（含 Cargo）、C 编译器和系统 CA 证书。`rust-toolchain.toml` 使用 `stable` 通道；最低要求为 Rust 1.91（见 `Cargo.toml` 的 `rust-version`），支持 1.91.1 及满足要求的更新稳定版。使用已安装的兼容工具链时，可用 `cargo +1.91.1 build --release --locked -j 4` 显式选择版本。SQLite 由 Cargo 编译，TLS 使用 rustls 和系统根证书。

```bash
cargo build --release --locked -j 4
./target/release/php-selfcheck init
# 保存终端显示的随机 admin 密码，编辑 config.json 中的资产范围
./target/release/php-selfcheck serve
```

默认监听 `127.0.0.1:8080`。默认普通账号通过 Basic 认证登录；启用免密码后使用浏览器独立会话。管理员入口始终使用独立账号密码。`init` 不覆盖已有配置；配置权限为 600，密码使用 PBKDF2-SHA256（260000 次迭代），不存明文密码。不要将配置、报告和数据库提交到 Git。

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

`allow_anonymous` 启用后，开发者无需输入密码，每个浏览器会话由服务端随机 Cookie 分配独立 `visitor:` 身份。任务、材料与请求额度按身份隔离。`allow_without_whitelist` 启用后，空网段列表表示不限网段，空端口列表表示不限端口；空域名列表一直表示不限域名。**非空的列表仍会限制目标**。使用 `--allow-without-whitelist` 初始化时，网段、域名、端口列表均为空。

两个开关独立，默认均为 `false`；未启用时需要普通账号认证及资产范围配置。特殊地址拒绝、逐跳地址校验、TLS、Host/Origin 校验和任务限额在这两种模式下仍然生效。

## 开发者页面与管理员历史

开发者页面 `/` 不加载历史列表，只展示本标签页当前扫描。新提交替换可见结果；刷新页面可通过 sessionStorage 恢复本次任务 ID。页面不保存管理员密码或会话令牌，令牌在 HttpOnly Cookie 中；直接请求任务详情或导出时，服务端仍校验归属。普通 `/api/jobs` 接口最多返回本身份最新一条记录。

所有历史结果仍写入 SQLite，管理员访问 `/admin` 登录后可以查看全站汇总、搜索目标 URL/访问者标识/任务 ID、分页查看全部历史、展开证据并导出。普通扫描会话与管理员登录是两套独立权限，启用免密码扫描不会放开后台。

### 管理员账号

在服务器终端创建管理员：

```bash
./target/release/php-selfcheck add-admin --user admin
# 如需多个管理员，每人建立独立账号
./target/release/php-selfcheck add-admin --user security02
# 保存各自随机密码，重启服务后访问 /admin
```

命令默认读取 `config.json`，自定义路径可加 `--config /path/to/config.json`。只增加 `admins` 中的 PBKDF2 密码哈希，不修改既有账号或数据库、不覆盖已有同名管理员。管理员权限只由 `admins` 配置决定，`users` 中名为 admin 的普通账号不具有管理员权限；没有配置管理员时，后台始终拒绝登录。

新执行 `init` 会同时生成首个管理员，账号由 `--user` 指定（默认 admin）。即使启用 `--allow-anonymous`，也会在终端显示独立管理员登录所需的随机密码；务必保存。`config.open.example.json` 提供免密码、无白名单扫描配置，但不包含可用管理员密码，复制后仍须执行 add-admin。

### 后台结果筛选、排序与删除

- “只看某个检测结论”支持全部已有结论。多目标任务只展示命中结论的目标，并显示本次扫描原有结果数；JSON/CSV 导出沿用所选结论。搜索目标时，关键字与结论需在同一个目标结果上匹配。
- 排序支持最新优先、最早优先、结果优先复核、结果反向排序。结果排序按**整次扫描中最高复核级别**排列：疑似受影响 → 无法完成检测 → 无法判断 → PHP 特征版本未知 → 疑似使用 PHP → 达到修复基线待核验 → 未发现 PHP 特征；无结果的任务置后，同级按时间倒序。这个顺序是复核优先级，不是漏洞成立证明。
- 每次扫描提供“删除本次扫描”按钮。确认框明确提示整次扫描的结果数量；即使当前筛选只显示其中部分目标，删除也会移除该次扫描的全部结果。
- 排队/执行中的任务不允许删除。删除与管理员审计在同一事务中提交；其他扫描、独立主机材料和审计记录保留。删除后刷新列表和全站汇总，最后一页空出时自动回到有效页。

管理员接口增加 `GET /api/admin/jobs?verdict=<检测结论>&sort=risk_desc`，sort 也可为 `newest`、`oldest`、`risk_asc`。详情与导出可带相同 verdict 参数。删除接口为 `POST /api/admin/jobs/<id>/delete`，JSON 请求体 `{ "confirm": true }`，仍需管理员 Cookie、正确 Origin 和 X-Requested-With。普通访客不能调用删除接口。

### 会话与数据隔离

免密码模式识别的是**浏览器会话，不是员工实名**。不同浏览器配置/无痕窗口独立隔离；同一浏览器配置内的标签页共享访问身份，但各标签页只显示自己的当前任务。如需按员工身份严格区分，请使用个人账号模式或独立浏览器配置，不要共享浏览器会话。

访客 Cookie 为浏览器会话 Cookie，服务端最长有效 7 天；关闭会话、清除 Cookie 或过期后，旧结果只能由管理员查阅。管理员登录有效 8 小时，可主动退出；退出会撤销数据库令牌，删除管理员或更换其密码哈希并重启也会让其旧登录失效。Cookie 为 HttpOnly、SameSite=Strict，HTTPS public_origin 下设置 Secure。数据库仅保存令牌哈希。管理员登录具有失败次数限制，登录、查询、导出、退出有审计记录。

任务、主机材料、审计和会话保存在数据库中。数据库和配置文件应纳入访问保护与备份；数据库没有自动清理功能，应按团队要求制定保留策略。

## 扫描功能

- 普通扫描页仅展示当前标签页提交的任务；免密码访问按浏览器会话隔离，密码访问按个人账号隔离。任务与材料持久保存至 SQLite。
- `/admin` 为独立账号密码保护的历史与汇总页，支持搜索、分页、详情与 JSON/CSV 导出；管理员操作写入 `audit`。
- 一次 1–50 个目标，去重，默认 HTTPS，支持域名、IP、端口、完整 URL 与 IPv6 URL；兼容 `erp_api.example.com` 等带下划线的实际主机名，仍须能被扫描节点 DNS 解析。
- 后台最多 4 个任务运行，最多 8 个待完成任务，每人最多 2 个；任务内目标串行，间隔至少 0.5 秒。每账号每分钟最多 120 个入站请求，同一客户端每分钟 12 次失败认证后暂时拒绝。
- HTTP 头、PHPSESSID 名称、页面 `.php` 引用作为证据；Cookie 值不进入结果；仅从 PHP 专属版本声明提取 PHP 版本。
- 每次请求及每个重定向重新校验全部 DNS 结果，再固定已验证的 IP 连接；保留原域名 Host 和 TLS SNI，不使用环境 HTTP 代理，不跳过 TLS 校验。最多 4 次请求，正文最多保留 128 KiB。
- JSON/CSV 导出；CSV 单元格对公式前缀进行中和。服务重启时将旧的 queued/running 任务标记为 interrupted。
- 主机材料 JSON 导入保留“开发者提交，未经独立核验”标记，不提升远程检测结论。

## 管理员后台维护特征库

登录 `/admin` 后使用“网站特征库维护”，可筛选和选择规则，编辑单条 JSON、新增、启用/禁用、删除自定义项，也可修改完整 JSON 和特征库版本。

1. 单条编辑后点击“应用单条修改到草稿”。
2. 点击“校验草稿”，检查 JSON、规则 ID、正则和资源限制。
3. 点击“保存并立即启用”。只有保存才会改变当前规则；不需要重启。

保存后的规则与修订号持久化到 SQLite，重启后恢复，并优先于 `fingerprint_file` 启动文件。初次没有后台保存记录时，加载启动文件或内置库。后台不会改写原 JSON 文件；要采用更新后的文件，可在完整 JSON 中粘贴并校验保存。本机采集器仍使用所在机器上的文件，可复制后台完整 JSON 作为 `--fingerprints` 文件。数据库、规则和审计应一起备份。

多管理员保存使用修订号检查，发现冲突返回提示并保留草稿；备份草稿、重新加载后合并再保存。保存与审计写入同一事务，失败时保留原规则。已提交的任务持有原规则快照，只有新提交的任务使用更新，历史结果不会重判。“将内置库加载为草稿”也须保存才生效。

管理接口仅允许独立管理员会话：`GET /api/admin/fingerprints`、`POST /api/admin/fingerprints/validate`、`POST /api/admin/fingerprints/save`。POST 沿用 Origin 与请求格式检查；提交 `document` JSON 文本，保存另需读取时的 `revision`，冲突返回 409。普通扫描会话不能维护规则。

“证据与下一步”将版本声明与直接响应头单独展示：等宽粗体突出 PHP 版本，红色标记版本风险线索，琥珀色提示受阻/待核验状态，蓝色强调产品名称和命中位置，并单列下一步。颜色同时配有文字含义；达到上游基线仍显示待核验，所有目标和证据均以文本渲染。

## 可配置的网站特征库

扫描结果可展示 CMS/商城、框架、运行时声明、静态生成器、托管平台、Web 中间件、CDN/WAF 和挑战页等特征。内置 51 条规则，覆盖 WordPress/WooCommerce、Drupal、Joomla、Magento、Laravel、ThinkPHP、Discuz!、Next.js、Nuxt、Shopify、Nginx、Tengine、Cloudflare 等。

匹配仅使用已经取得的响应头、Cookie **名称**、generator 标签、标题、资源路径及有限正文；不会请求额外路径、登录页或外部资源。每个命中保留规则 ID、表达式、来源 URL、证据位置、资源来源和可信度。页面、管理员历史、JSON/CSV 导出和本机端口 Web 观测均展示这些信息；结果记录特征库版本、有效规则数和内容 SHA-256，已有历史不因修改规则而重判。

产品特征是线索：CMS/框架版本不当作 PHP 版本；第三方资源单独标为外部引用，不据此推断当前站点运行 PHP。Next.js 等也可能来自静态导出；CDN、WAF 或托管平台命中不代表没有 PHP 后端或已修复。明确的挑战页线索使检测保持“无法完成检测”，保留命中依据，不自动绕过或继续跳转。普通 CDN 特征不会单独认定为受阻。

### 使用自己的规则文件

特征文件采用 UTF-8 JSON。在服务器 `config.json` 中设置以下字段，保留其他字段并重启服务。相对路径以该配置文件所在目录为基准：

```json
{
  "fingerprint_file": "fingerprints.json"
}
```

不设置或设为 `null` 时使用内置库。可先复制 `fingerprints.example.json` 作为扩展示例；也可导出完整库后编辑：

```bash
php-selfcheck fingerprints export --output fingerprints.json
php-selfcheck fingerprints validate --file fingerprints.json
```

导出不会覆盖已有文件。校验检查 schema、ID、正则、字段和资源上限；文件缺失或规则错误会阻止服务启动，避免静默使用其他规则。尚无后台保存记录时，文件修改后须重启服务；后台保存后以数据库规则为准。单次任务使用同一份已加载规则。

也可显式指定文件（这里相对路径以当前终端目录为基准），作为启动文件或覆盖单次 check 的规则（已有后台保存时，服务仍优先使用数据库规则）：

```bash
php-selfcheck serve --config config.json --fingerprints fingerprints.json
php-selfcheck check https://app.example.com/ --config config.json --fingerprints fingerprints.json --json
php-selfcheck collect --middleware --ports --web-probe --fingerprints fingerprints.json > host-report.json
```

本机采集的 `collector.options.example.json` 也支持 `fingerprint_file`，相对路径以采集器选项文件所在目录为基准；该文件需要放在被采集的机器上。命令行文件优先于选项文件。仅响应头模式不会匹配未取得的页面正文、generator、标题或资源路径。

### 规则格式

下面是一份完整的扩展文件，要求响应头和 Cookie 名称同时命中：

```json
{
  "schema": "php-selfcheck-fingerprints/v1",
  "version": "company-1",
  "mode": "extend",
  "disabled_rules": [],
  "rules": [
    {
      "id": "company-php-app",
      "name": "公司 PHP 应用",
      "category": "framework",
      "runtime": "php",
      "confidence": "low",
      "all": [
        { "source": "header", "header": "x-company-app", "pattern": "(?i)^erp$" },
        { "source": "cookie_name", "pattern": "^company_session$" }
      ],
      "any": [],
      "advice": "应用特征命中，实际 PHP 版本和补丁仍需核验。"
    }
  ]
}
```

- `mode: "extend"` 保留内置库；相同 ID 覆盖原规则，新 ID 追加。`disabled_rules` 按 ID 禁用规则，未知/重复 ID 报错。先覆盖、追加，再禁用。
- `mode: "replace"` 完全采用文件中的规则；可用空 `rules` 关闭技术特征匹配，`disabled_rules` 在两种模式下均按 ID 禁用规则。PHP 专属版本声明和漏洞基线检查独立运行，不能由特征库替换或关闭。
- `all` 中所有条件均须命中；`any` 非空时至少命中一个。两者同时存在时都需满足，至少提供一个条件。
- `source` 支持 `header`、`cookie_name`、`meta_generator`、`title`、`resource_path`、`body`。`header` 条件必须提供头名称；Cookie 和认证敏感头禁止作为 header 匹配，以免读取其值。Cookie 仅匹配名称，不匹配或保存值。
- `pattern` 使用 Rust regex 语法，默认区分大小写，可加 `(?i)`。不支持反向引用或环视。`resource_path` 匹配已引用资源的路径，不包含查询和片段；`same_origin` 默认 `true`，设为 `false` 可记录外部资源引用，但不请求资源，也不把外部引用当作当前站点运行时证明。
- 仅 `header` 和 `meta_generator` 可用 `(?P<version>...)` 捕获产品自己的版本声明；冲突会显式显示，不能把资源文件名、CMS 版本或自定义捕获结果加入 PHP 漏洞版本判定。
- `category` 可选 `cms`、`framework`、`runtime`、`static_generator`、`hosted_platform`、`hosting`、`web_server`、`cdn`、`waf`、`challenge`；`runtime` 可选 `php`、`nodejs`、`static`、`unknown`；`confidence` 为 `low` 或 `medium`，都不是已核实结论。

库文件最多 512 KiB，有效规则最多 256 条，每条 1–16 个条件；表达式最多 4096 字节并限制编译规模。最多输出 64 个命中、每项 8 条证据；表达式展示超过 256 字符会截断并标记，完整规则保留在文件中。正文沿用扫描的 128 KiB 上限，本机端口观测最多 16 KiB；仅解析最多 256 个相关标签，较长/复杂页面可能漏识别。规则与说明会出现在命中结果中，请勿把密码或密钥写入特征库。

内置覆盖参考 [spcaeo/php2shell-check](https://github.com/spcaeo/php2shell-check)，Rust 匹配引擎及配置格式在本项目实现，MIT 许可与来源见 `THIRD_PARTY_NOTICES.md`。

## 轻量扫描与 CI 命令

扫描页可勾选“仅检查响应头”，只发送 HEAD；收到 405/501 才回退 GET，回退请求也不读取正文。此模式不跟随跳转、不进行页面特征分析或 multipart POST，隐藏版本时保持未知。每次请求仍校验资产范围、重新解析 DNS 并固定已校验的 IP，保持 TLS 验证。

服务端 `config.json` 可设置 `"headers_only": true` 并重启，为全部扫描强制启用此模式；开发者无法通过取消勾选覆盖管理员设置。默认 `false`，开发者可按次选择。API 提交 `POST /api/scan` 时可附 `"headers_only": true`，结果记录 `scan_mode`；轻量模式还记录 HEAD/GET 请求方法和状态。

命令行检查复用相同的资产范围及检测规则，不启动 Web 服务、不写入扫描历史：

```bash
./target/release/php-selfcheck check https://app.example.com/ --config config.json --json
./target/release/php-selfcheck check https://app.example.com/ --config config.json --headers-only --json
```

命令读取已初始化的配置，范围限制与 Web 扫描一致；目标可不写协议，默认 HTTPS。退出码用于 CI：

| 退出码 | JSON patch_status | 含义 |
| --- | --- | --- |
| 0 | `ok` | 声明的正式版本达到上游修复基线，实际实例和回补情况仍待核验 |
| 1 | `potentially_vulnerable` | 版本命中疑似受影响范围，不代表漏洞已确认 |
| 2 | 无检测结果 | 参数或配置错误 |
| 3 | `unknown` | 版本未知、声明冲突、规则未覆盖、范围拒绝或传输失败 |

版本保留完整原值，RC、alpha、beta、dev 等预发布声明不会按正式修复版判断。发行版后缀会保留，但不会仅凭后缀断定已回补。出现多个不同声明时保留“无法判断”；若其中包含疑似受影响版本，`version_warnings` 和复核优先级会保留风险提示。

## 主机采集

把匹配目标机器操作系统和架构的二进制拷贝到目标 Linux 主机，以普通账号执行：

```bash
php-selfcheck collect > host-report.json
```

默认读取可见进程名称、可执行文件路径和 PHP 包信息，**不执行 PHP 命令**，不自动上传。通过 Web 界面关联业务 URL 并导入报告。采集与命令查询有数量、时间和输出上限；权限不足时保留未知。报告按网页上传限制控制体积，过大时优先省略原始命令输出等条目，在 `report_limits` 记录省略数量，页面提示结果不完整。

### 可选 PHP 命令采集

```bash
# 调用 PATH 中的 PHP/FPM 程序查询版本，并读取 PHP CLI 的选定配置
php-selfcheck collect --php-command > host-report.json

# 指定实际使用的 PHP CLI 路径
php-selfcheck collect --php-command --php-binary /opt/php/bin/php > host-report.json

# 配置文件开启时，也可在命令行显式关闭
php-selfcheck collect --options collector.options.example.json --php-command=false > host-report.json
```

`--php-command` 默认关闭，独立于中间件采集。`--php-binary` 需要同时开启此选项，接受存在的绝对文件路径；不指定时检查常见 PHP/FPM 程序并去重，最多 16 个。版本查询使用 `-n -v`；CLI 配置使用 `-r` 读取选定 INI 项、SAPI、版本、PHP 程序及加载的 INI 文件路径，不调用 phpinfo 或输出环境。FPM 不执行 CLI 配置脚本。PHP-FPM 的中间件版本查询也受此开关控制。

PHP 命令所得配置始终标为 `cli_only`，不能证明 Web/FPM、容器或全部后端实例的配置与补丁状态。外部命令超时 10 秒，保留输出最多 24 KB。不读取进程环境或完整命令行，报告未签名，业务关联由提交人指定。

### 可选运行实例与厂商补丁参考核验

```bash
# 独立启用，不执行 PHP 命令
php-selfcheck collect --package-audit > host-report.json

# 与 CLI 配置及中间件采集一起使用
php-selfcheck collect --php-command --package-audit --middleware --php-modules --ports > host-report.json
```

`--package-audit` 默认关闭。它从可见的 PHP-FPM/CGI 程序和 Apache/Nginx 等进程的 PHP 模块映射反查所属软件包，不使用 CLI 或 `php` 元包代替 Web 实例：

- Debian/Ubuntu 记录二进制包、源包、完整修订号，检查已安装修订号对应的官方归档来源及发行版代号，用 `dpkg --compare-versions` 比较源包修订号；候选更新的来源不能代替已安装包的来源。
- RHEL 记录包名、Epoch、Version、Release、架构、源 RPM、Vendor 和模块流；先比较 Epoch，再分别使用 RPM 原生规则比较 Version 与 Release。其他发行版或第三方仓库不能套用 RHEL 阈值。
- 对照进程映像/模块与磁盘文件的设备及 inode，发现已删除或替换的运行映像时提示重启复核；采集前后复核进程身份和映射。磁盘包已更新不等于运行程序已更新。
- 不同或未知挂载命名空间、根目录、进程变化、权限不足、来源不明、无适用规则均保留未知；容器应在对应环境采集。即使映像一致，也不能证明它服务于所提交的 URL。

参考规则见 [`rules/vendor-patches.json`](rules/vendor-patches.json)，涵盖 Debian 12/13、Ubuntu 所列 LTS/Pro 与当前发行版、RHEL 8.10 PHP 7.4 和 9.8 PHP 8.0 的特定范围。数据来自固定提交的外部参考表，保留公告链接与日期，**尚未独立核实全部厂商公告**。输出只表示 `meets_vendor_reference`（达到参考修订号）、`below_vendor_reference`（低于参考修订号）或 `unknown`，不会生成“已确认修复”。`running_patch_status` 只有在运行映像与磁盘一致且检查完整时才沿用参考匹配，否则为未知。主机报告导入后仍作为未经独立核验的材料展示，不提升远程结论。

本项最多检查 128 个相关进程、每进程 16 个映像/模块、32 个不同文件路径的软件包归属。规则来源及许可见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)。

## 可选 Web 中间件、PHP 模块与端口采集

PHP 命令、软件包核验、中间件、PHP 模块、端口与 Web 探测六个开关**默认全部关闭**。不添加这些选项时，仅读取基础进程和包信息。页面“主机采集”区域可勾选功能，生成在目标主机手工执行的命令；不会通过网页远程执行系统命令。

```bash
# 仅识别 Web 中间件
php-selfcheck collect --middleware > host-report.json

# 中间件 + PHP 模块线索 + 关联监听端口，不发送 Web 请求
php-selfcheck collect --middleware --php-modules --ports > host-report.json

# 额外尝试本机监听端口的 HTTP/HTTPS GET
php-selfcheck collect --middleware --php-modules --ports --web-probe > host-report.json

# 指定虚拟主机 Host/SNI、只尝试 HTTPS、指定只读路径和请求上限
php-selfcheck collect --middleware --ports --web-probe \
  --web-host app.example.com --web-schemes https --web-path /index.php \
  --max-web-probes 8 > host-report.json
```

六个开关均接受显式 `=true` / `=false`。模块、端口与 Web 功能需要 `--middleware`，Web 功能还需要 `--ports`；不满足依赖会给出错误，不会静默扩大采集。Web Host 用于虚拟主机和证书校验，不用于指定远端地址；IP Host 必须与已关联的本机连接地址一致。

也可复制 `collector.options.example.json`，修改布尔值后使用：

```bash
php-selfcheck collect --options collector.options.example.json --web-probe=false > host-report.json
```

命令行显式值覆盖文件。采集器配置与服务端 `config.json` 分开，示例文件包含六个开关、php_binary、web_host、web_path、web_schemes、max_web_probes。

检测范围与证据边界：

- 识别可见的 Apache/httpd、Nginx、Tengine、LiteSpeed、Lighttpd、FrankenPHP 和 PHP-FPM 进程，以及 PATH/常见路径中的已安装程序。Nginx 名称运行的 Tengine 可结合安装路径和版本识别；已安装不等于正在运行。
- Apache 检查当前进程 maps 中的 libphp/mod_php 映射，并尝试 `-M` 中的 PHP、proxy_fcgi、fcgid 声明。`-M` 读取的是默认磁盘配置，不一定等于当前 PID 启动时的配置。Nginx/Tengine 检查 PHP 动态库映射及 `-V` 构建线索，不把 FastCGI 与 mod_php 混为一谈。没有 PHP 映射不能否定 PHP-FPM 使用。
- 通过 `/proc/PID/fd` 中 socket inode 与该 PID 网络命名空间的 tcp/tcp6 LISTEN 表关联 **TCP** 监听端口，不做端口范围扫描。仅在进程身份未变化、网络命名空间与采集器相同、地址确认属于本机时才尝试 Web GET。容器内端口需在对应容器/命名空间采集；Unix socket、UDP、隐藏/无权限进程不在 TCP 探测覆盖内。
- Web 开关默认关闭；开启后默认分别尝试 HTTP/HTTPS，每次只 GET 指定路径，不跟随跳转、不使用环境代理、不传递自查台凭据、不尝试 FastCGI 端口、不扫描额外端口，TLS 校验保持开启。默认最多 16 次尝试，可设 1–64；每次请求最长 4 秒，只保留最多 16 KiB 正文用于指纹识别，不保存 Cookie 值。普通 GET 仍需选择只读业务入口。
- 通配监听地址转为本机回环连接；明确绑定的地址需出现在本机地址信息中。共享监听、SO_REUSEPORT 或反向代理可能使响应来自其他 worker/后端，端口归属不等于响应实例证明。证书/虚拟主机可能需要正确 web_host；TLS、权限、命名空间、进程退出等失败会保留未知/跳过原因，不认定为安全或未使用 PHP。
- 默认最多 128 个进程、16 个不同程序版本检查、每进程 8192 个 FD；达到上限或权限不足时可能不完整。不会自动提升权限、修改配置或重启中间件，不读取进程环境和完整命令行、不导出 Nginx/Apache 完整配置。

导入后，开发者当前结果和管理员历史中会显示中间件、PID、PHP 模块线索、关联端口和本机 Web 观测。JSON/CSV 保留同一份主机证据，仍标为“开发者提交，未经独立核验”，不会自动提升远程漏洞结论。

## 扩展证据与复核

结果的 `assessment` 包含 Web 服务器声明、SAPI、multipart、upload_progress、版本维护状态、补丁状态和复核优先级。每项包含 `status`、`source`、`confidence`、`detail`；`sources` 指向两份 PHP 官方 GHSA。Apache/nginx 头不能确定 SAPI；GET 页面中的 multipart 表单和上传进度字段仅是线索，没有线索则保持“未知”，不会推断为关闭。EOL 单独显示，补丁状态仍可为未知。

### 可选 multipart 可达性检查

在 `config.json` 中设置 `"probe_multipart": true` 并重启，或保留默认 `false`。开启时，只在最终 GET 成功后对同一 URL 额外发送一次约百字节的普通表单 POST，重新校验 DNS/范围并固定连接 IP。不含文件、上传进度字段、嵌套数据或漏洞载荷，不跟随 POST 重定向；保留 TLS 验证且不传递自查台凭据。请只对允许普通表单 POST 的业务页面开启，常规 POST 也可能产生业务副作用。

2xx 仅记为“收到响应，未确认 PHP 解析”，405/415 记为“当前请求被拒绝”，其他状态或错误保持未知；500、超时等不会提升为漏洞成立。POST 的 IP、URL、时间与状态单独记录。此检查不验证 upload_progress，也不执行内存压力或会话污染探测。

### 主机材料与手工复核

Web 界面可导入 collect 报告，或不选文件直接填写手工复核：Web SAPI、upload_progress 开关、补丁厂商/来源、软件包完整修订号、厂商公告链接、实例归属说明。所有内容始终标为“开发者提交，未经独立核验”；“已修复/未修复”只是提交人的声明，不自动提升远程结论。HTTP API 为 `POST /api/reports`，除 `target` / `report` 外可附 `review` 对象，例如：

```json
{
  "target": "https://app.example.com/",
  "report": {"schema": "php-selfcheck-host/v1"},
  "review": {
    "sapi": "fpm-fcgi",
    "upload_progress": "disabled",
    "patch_status": "fixed_claimed",
    "patch_vendor": "Your Linux/LTS vendor",
    "package_revision": "实际软件包完整修订号",
    "advisory_url": "https://vendor.example/security/advisory",
    "notes": "实际实例标识、配置核对时间和修复依据"
  }
}
```

已有受认证内部管理入口可在完成权限检查后，定义 `PHP_SELFCHECK_AUTHORIZED=true` 并 include `tools/web-runtime-report.php`，下载只含选定配置的运行时 JSON 后导入。助手未获得这个常量授权时直接拒绝访问；不要部署为公开诊断接口。通过 Web 执行才能取得该请求实例的 SAPI/配置，通过 CLI 执行得到的仍仅代表 CLI。报告不包含所有 worker，也没有签名或实例归属证明。

导入材料通过**同一账号、相同标准化目标 URL**关联，最新 5 份以 `host_evidence` 附在记录和导出中，包含导入时间；这是展示时关联，不会改写历史扫描结论。不同路径、不同账号和重定向后的其他目标不会自动拼接。

官方说明：关闭 upload_progress 只阻断部分 session 路径，完整修复仍需包含两个漏洞完整补丁的 PHP 版本或已核实回补包。

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/NCSC-NL/php2shell

## 团队部署

默认仅允许本机 HTTP 试用。团队使用应由公司 HTTPS 反向代理终止 TLS，配置准确的 `public_origin`（无尾斜线、路径），并限制后端端口仅代理可达。非回环监听要求 HTTPS public_origin。参见 `nginx.conf.example`；自定义外部端口时确保 Host 带端口。使用低权限专用账号，独立保护状态目录，不要多人共享 admin 账号。

也可使用项目提供的 Dockerfile 从源码构建容器镜像：

```bash
docker build -t php-selfcheck:local .
mkdir -m 700 state
# 先使用本机构建的二进制生成 state/config.json，并修改范围与 HTTPS public_origin。
# 将 state 所有权交给容器 UID/GID 10001，再运行：
docker run -d --name php-selfcheck --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v "$PWD/state:/state" php-selfcheck:local
```

## 规则与使用边界

截至 2026-10-23，已交叉核对 PHP 官方安全通告、php-src NEWS 与 CVE 记录，确认两个 CVE 和 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 修复基线。版本声明不等于实际运行版本，EOL 不等于没有回补补丁；实际实例与厂商补丁仍须核实。JSON 中的 `rule_provenance` 记录规则来源。

- PHP 公告：https://www.php.net/archive/2026.php#2026-10-21-5
- CVE：CVE-2026-109618、CVE-2026-109619

默认检测只发起指定入口的常规 GET；可选小型 multipart POST 见“可选 multipart 可达性检查”。远程扫描不执行目标主机命令、不发送漏洞利用载荷，不自动发现目录、phpinfo、FastCGI 或额外端口。“疑似受影响”需要核实回补补丁；“达到修复基线”“版本未知”“未发现特征”和“检测受阻”均不能证明无漏洞或已修复。提交只读业务页面，URL 中不要包含令牌。主机采集器仅在启用 `--php-command` 后运行已有 PHP 获取版本与选定配置；启用中间件采集时，也会运行相应程序的版本或模块查询命令，不接受网络用户提供任意命令。

## 开发验证

```bash
cargo test --locked -j 4 -- --test-threads=2
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
```

测试覆盖基线边界、特征误报与 Cookie 脱敏、危险 URL、混合 DNS、特殊地址、逐跳范围校验、重定向上限、HTTP 阻断状态、固定 IP 的真实模拟 HTTP 传输、响应体截断、TLS 协议拒绝、PBKDF2 密码校验、配置权限、HTTP 认证、Host/Origin、任务隔离、报告导入、CSV 导出与重启中断。网络测试只访问进程内本地测试服务，不扫描真实资产。生产扫描规则没有本地地址放行开关。

`node --test tests/ui-state.cjs` 可选验证前端任务状态（需 Node.js，运行服务不需要）。

真实公司资产、企业证书/代理、Docker 构建、生产容量和跨架构分发仍需在对应部署环境验证。

## 发布流程

`.github/workflows/release.yml` 在推送与 Cargo.toml 版本一致的 `vX.Y.Z` 标签时执行，也支持从 Actions 页面手工选择已有标签运行。Windows MSVC 与 Linux musl 在各自系统上执行测试、发布构建和本地启动检查，再打包两个平台的程序、示例配置、文档及许可证。

两个平台都通过后才创建草稿 Release、上传附件、下载回验 SHA-256 并公开发布；已公开的附件不会被自动覆盖。`release-manifests` 分支保存发布回执（链接、源提交及校验值），便于核对发布状态。
