//! Local Linux inventory. Never reads process environment or command lines; never uploads.
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
pub(crate) fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(name))
        .find(|p| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                p.metadata()
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
            }
            #[cfg(not(unix))]
            {
                p.is_file()
            }
        })
}
pub(crate) async fn run(exe: &Path, args: &[&str]) -> Value {
    use tokio::io::AsyncReadExt;
    let command: Vec<_> = std::iter::once(exe.to_string_lossy().to_string())
        .chain(args.iter().map(|s| s.to_string()))
        .collect();
    let result: anyhow::Result<(i32, String)> = async {
        let mut child = tokio::process::Command::new(exe)
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // Drain both pipes while retaining at most 24 KB. Avoid unbounded output allocation.
        async fn read(mut pipe: impl tokio::io::AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
            let mut output = vec![];
            let mut buf = [0; 4096];
            loop {
                let n = pipe.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let take = n.min(24000 - output.len());
                output.extend_from_slice(&buf[..take]);
            }
            Ok(output)
        }
        let (out, err, status) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(read(stdout), read(stderr), child.wait())
        })
        .await?;
        let mut bytes = out?;
        bytes.extend(err?);
        bytes.truncate(24000);
        Ok((
            status?.code().unwrap_or(-1),
            String::from_utf8_lossy(&bytes).into_owned(),
        ))
    }
    .await;
    match result {
        Ok((code, out)) => json!({"command":command,"exit_code":code,"output":out}),
        Err(e) => json!({"command":command,"error":e.to_string()}),
    }
}
pub async fn collect() -> Value {
    collect_with_options(&CollectOptions::default()).await
}
pub async fn collect_with_options(options: &CollectOptions) -> Value {
    let mut checks = vec![];
    let mut runtime_observations = vec![];
    if options.php_command {
        let mut binaries = std::collections::BTreeSet::new();
        if let Some(path) = &options.php_binary {
            binaries.insert(path.clone());
        } else {
            for name in [
                "php",
                "php5.6",
                "php7.0",
                "php7.1",
                "php7.2",
                "php7.3",
                "php7.4",
                "php8.0",
                "php8.1",
                "php8.2",
                "php8.3",
                "php8.4",
                "php8.5",
                "php-fpm",
                "php-fpm7.4",
                "php-fpm8.0",
                "php-fpm8.1",
                "php-fpm8.2",
                "php-fpm8.3",
                "php-fpm8.4",
                "php-fpm8.5",
            ] {
                if let Some(path) = which(name) {
                    binaries.insert(std::fs::canonicalize(&path).unwrap_or(path));
                }
            }
        }
        for exe in binaries.into_iter().take(16) {
            checks.push(run(&exe, &["-n", "-v"]).await);
            if !exe
                .file_name()
                .is_some_and(|n| n.to_string_lossy().contains("fpm"))
            {
                let runtime = run(&exe, &["-r", PHP_RUNTIME]).await;
                if runtime["exit_code"] == 0
                    && let Some(output) = runtime["output"].as_str()
                    && let Ok(mut parsed) = serde_json::from_str::<Value>(output)
                    && parsed.is_object()
                {
                    parsed["scope"] = json!("cli_only");
                    parsed["source"] = json!("local_php_command");
                    parsed["command_binary"] = json!(exe);
                    runtime_observations.push(parsed);
                } else {
                    checks.push(runtime);
                }
            }
        }
    }
    if let Some(exe) = which("dpkg-query") {
        checks.push(run(&exe, &["-W", "-f=${Package}\t${Version}\n", "*php*"]).await)
    }
    if let Some(exe) = which("rpm") {
        checks.push(
            run(
                &exe,
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\t%{VENDOR}\n",
                    "*php*",
                ],
            )
            .await,
        )
    }
    let mut processes = vec![];
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name().to_string_lossy().into_owned();
            if !pid.bytes().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(name) = std::fs::read_to_string(entry.path().join("comm")) {
                let name = name.trim();
                if name.to_lowercase().contains("php")
                    || ["apache2", "httpd", "lshttpd", "frankenphp"].contains(&name)
                {
                    let exe = std::fs::read_link(entry.path().join("exe"))
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| "无读取权限".into());
                    processes.push(json!({"pid":pid,"name":name,"exe":exe}));
                }
            }
        }
    }
    let middleware = crate::middleware::collect(options).await;
    let package_audit = crate::hostaudit::collect(options.package_audit).await;
    bounded_report(
        json!({"php_command":{"status":if options.php_command {"enabled"}else{"disabled"},"scope":"cli_only","detail":"显式开启才运行 PHP；CLI 配置不能代表 Web/FPM"},"package_audit":package_audit,"collection_options":options,"middleware":middleware,"schema":"php-selfcheck-host/v1","hostname":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),"collected_at":chrono::Utc::now().to_rfc3339(),"platform":format!("{} {}",std::env::consts::OS,std::env::consts::ARCH),"source":"developer_supplied_unverified","checks":checks,"runtime_observations":runtime_observations,"processes":processes,"limitations":["CLI 版本不等于 Web/FPM 实例版本；报告不自动证明补丁或漏洞状态。","仅检查当前主机可见进程与标准路径；容器、远端主机、自定义安装目录需另行核验。","此报告未签名，平台记录为开发者提交材料。"]}),
    )
}

// Keep the pretty JSON below the browser upload limit, and make every omission explicit.
fn bounded_report(mut report: Value) -> Value {
    let mut omitted = std::collections::BTreeMap::<String, usize>::new();
    for pointer in [
        "/checks",
        "/middleware/binaries",
        "/middleware/instances",
        "/processes",
        "/middleware/web_probes",
        "/runtime_observations",
        "/package_audit/instances",
    ] {
        while serde_json::to_vec_pretty(&report).map_or(usize::MAX, |v| v.len()) > 190_000 {
            let removed = match report.pointer_mut(pointer) {
                Some(Value::Array(a)) => a.pop().is_some(),
                Some(Value::Object(m)) => {
                    let key = m.keys().next_back().cloned();
                    key.is_some_and(|k| m.remove(&k).is_some())
                }
                _ => false,
            };
            if !removed {
                break;
            }
            *omitted.entry(pointer.into()).or_default() += 1;
        }
    }
    let truncated = !omitted.is_empty();
    report["report_limits"] =
        json!({"truncated":truncated,"omitted_items":omitted,"pretty_json_budget":190000});
    if truncated && let Some(a) = report["limitations"].as_array_mut() {
        a.push(json!("报告超过大小预算，已按 report_limits 省略部分条目；结果不完整，未知或未列出不代表不存在。"));
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_reports_remain_importable_and_explain_omissions() {
        let r = bounded_report(
            json!({"schema":"php-selfcheck-host/v1","checks":vec![json!({"output":"X".repeat(24000)});20],"runtime_observations":[{"sapi":"cli"}],"limitations":[]}),
        );
        assert!(serde_json::to_vec_pretty(&r).unwrap().len() < 200000);
        assert_eq!(r["report_limits"]["truncated"], true);
        assert!(
            r["report_limits"]["omitted_items"]["/checks"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(r["runtime_observations"][0]["sapi"], "cli");
    }
}

// Selected configuration only, never phpinfo() or the process environment.
const PHP_RUNTIME: &str = r#"$settings=[]; foreach(['session.upload_progress.enabled','session.upload_progress.cleanup','session.serialize_handler','session.save_handler','session.use_strict_mode','session.use_only_cookies','session.upload_progress.name','session.upload_progress.freq','session.upload_progress.min_freq','file_uploads','enable_post_data_reading','memory_limit','post_max_size','upload_max_filesize','max_file_uploads','max_multipart_body_parts','fatal_error_backtraces'] as $key){$value=ini_get($key);$settings[$key]=$value===false?null:$value;} echo json_encode(['sapi'=>PHP_SAPI,'version'=>PHP_VERSION,'binary'=>PHP_BINARY,'loaded_ini'=>php_ini_loaded_file(),'scanned_ini'=>php_ini_scanned_files(),'settings'=>$settings]);"#;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectOptions {
    pub fingerprint_file: Option<PathBuf>,
    pub php_command: bool,
    pub php_binary: Option<PathBuf>,
    pub package_audit: bool,
    pub middleware: bool,
    pub php_modules: bool,
    pub ports: bool,
    pub web_probe: bool,
    pub web_host: Option<String>,
    pub web_path: String,
    pub web_schemes: Vec<String>,
    pub max_web_probes: usize,
}
impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            fingerprint_file: None,
            php_command: false,
            php_binary: None,
            package_audit: false,
            middleware: false,
            php_modules: false,
            ports: false,
            web_probe: false,
            web_host: None,
            web_path: "/".into(),
            web_schemes: vec!["http".into(), "https".into()],
            max_web_probes: 16,
        }
    }
}
impl CollectOptions {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(file) = &self.fingerprint_file {
            crate::fingerprints::Library::load(file)?;
        }
        anyhow::ensure!(
            self.php_binary.is_none() || self.php_command,
            "--php-binary 需要启用 --php-command"
        );
        if let Some(path) = &self.php_binary {
            anyhow::ensure!(
                path.is_absolute() && path.is_file(),
                "PHP 程序必须是存在的绝对文件路径"
            );
        }

        anyhow::ensure!(
            self.middleware || !(self.php_modules || self.ports || self.web_probe),
            "模块、端口与 Web 探测需要先启用 --middleware"
        );
        anyhow::ensure!(
            !self.web_probe || self.ports,
            "Web 探测需要启用 --ports，仅检查已关联的监听端口"
        );
        anyhow::ensure!(
            (1..=64).contains(&self.max_web_probes),
            "max_web_probes 必须为 1–64"
        );
        anyhow::ensure!(
            !self.web_schemes.is_empty()
                && self
                    .web_schemes
                    .iter()
                    .all(|s| matches!(s.as_str(), "http" | "https")),
            "web_schemes 只允许 http、https"
        );
        anyhow::ensure!(
            self.web_path.starts_with('/')
                && !self.web_path.starts_with("//")
                && self.web_path.len() <= 2048
                && !self
                    .web_path
                    .chars()
                    .any(|c| c <= ' ' || c == '\u{7f}' || c == '#' || c == '\\'),
            "Web 路径应为不含控制字符、片段和反斜线的本地绝对路径"
        );
        if let Some(host) = &self.web_host {
            anyhow::ensure!(host.len() <= 253, "Web Host 过长");
            url::Host::parse(host)?;
        }
        Ok(())
    }
}
#[derive(clap::Args, Debug)]
pub struct CollectArgs {
    /// 本机 Web 探测使用的被动特征库 JSON
    #[arg(long)]
    pub fingerprints: Option<PathBuf>,
    /// 显式运行 PHP 获取版本和选定 CLI 配置；默认关闭
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub php_command: Option<bool>,
    /// 自定义 PHP CLI 的绝对路径（需要 --php-command）
    #[arg(long)]
    pub php_binary: Option<PathBuf>,
    /// 从运行进程/模块反查软件包，核对厂商参考规则与旧进程状态
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub package_audit: Option<bool>,

    /// 采集器 JSON 开关配置；命令行显式开关优先
    #[arg(long)]
    pub options: Option<PathBuf>,
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub middleware: Option<bool>,
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub php_modules: Option<bool>,
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub ports: Option<bool>,
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub web_probe: Option<bool>,
    /// 仅用于已发现的本机端口的 Host/SNI，不用于选择远端目标
    #[arg(long)]
    pub web_host: Option<String>,
    #[arg(long)]
    pub web_path: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub web_schemes: Option<Vec<String>>,
    #[arg(long)]
    pub max_web_probes: Option<usize>,
}
impl CollectArgs {
    pub fn resolve(self) -> anyhow::Result<CollectOptions> {
        let options_dir = self
            .options
            .as_ref()
            .and_then(|p| p.parent())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let mut options: CollectOptions = match self.options {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => CollectOptions::default(),
        };
        if let Some(path) = options.fingerprint_file.as_mut()
            && !path.is_absolute()
        {
            *path = options_dir.join(&*path);
        }
        if let Some(path) = self.fingerprints {
            options.fingerprint_file = Some(std::fs::canonicalize(path)?);
        }
        if let Some(value) = self.php_command {
            options.php_command = value;
        }
        if let Some(value) = self.php_binary {
            options.php_binary = Some(value);
        }
        if let Some(value) = self.package_audit {
            options.package_audit = value;
        }
        if let Some(value) = self.middleware {
            options.middleware = value;
        }
        if let Some(value) = self.php_modules {
            options.php_modules = value;
        }
        if let Some(value) = self.ports {
            options.ports = value;
        }
        if let Some(value) = self.web_probe {
            options.web_probe = value;
        }
        if let Some(value) = self.web_host {
            options.web_host = Some(value);
        }
        if let Some(value) = self.web_path {
            options.web_path = value;
        }
        if let Some(value) = self.web_schemes {
            options.web_schemes = value;
        }
        if let Some(value) = self.max_web_probes {
            options.max_web_probes = value;
        }
        options.validate()?;
        Ok(options)
    }
}
