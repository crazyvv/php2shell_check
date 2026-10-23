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
    for name in [
        "php",
        "php8.2",
        "php8.3",
        "php8.4",
        "php8.5",
        "php-fpm",
        "php-fpm8.2",
        "php-fpm8.3",
        "php-fpm8.4",
        "php-fpm8.5",
    ] {
        if let Some(exe) = which(name) {
            checks.push(run(&exe, &["-n", "-v"]).await);
            if !name.contains("fpm") {
                let runtime = run(&exe, &["-r", PHP_RUNTIME]).await;
                if runtime["exit_code"] == 0
                    && let Some(output) = runtime["output"].as_str()
                    && let Ok(mut parsed) = serde_json::from_str::<Value>(output)
                    && parsed.is_object()
                {
                    parsed["scope"] = json!("cli_only");
                    parsed["source"] = json!("local_cli_configuration");
                    runtime_observations.push(parsed);
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
                &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n", "*php*"],
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
    json!({"collection_options":options,"middleware":middleware,"schema":"php-selfcheck-host/v1","hostname":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),"collected_at":chrono::Utc::now().to_rfc3339(),"platform":format!("{} {}",std::env::consts::OS,std::env::consts::ARCH),"source":"developer_supplied_unverified","checks":checks,"runtime_observations":runtime_observations,"processes":processes,"limitations":["CLI 版本不等于 Web/FPM 实例版本；报告不自动证明补丁或漏洞状态。","仅检查当前主机可见进程与标准路径；容器、远端主机、自定义安装目录需另行核验。","此报告未签名，平台记录为开发者提交材料。"]})
}

// Selected configuration only, never phpinfo() or the process environment.
const PHP_RUNTIME: &str = r#"$settings=[]; foreach(['session.upload_progress.enabled','file_uploads','enable_post_data_reading','memory_limit','post_max_size','upload_max_filesize','max_file_uploads','max_multipart_body_parts','fatal_error_backtraces'] as $key){$value=ini_get($key);$settings[$key]=$value===false?null:$value;} echo json_encode(['sapi'=>PHP_SAPI,'version'=>PHP_VERSION,'settings'=>$settings]);"#;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectOptions {
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
        let mut options = match self.options {
            Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
            None => CollectOptions::default(),
        };
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
