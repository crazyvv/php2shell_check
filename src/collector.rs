//! Local Linux inventory. Never reads process environments or uploads data. Java inspection
//! retains only allowlisted mitigation flags from command lines and discards all other arguments.
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
async fn run_command(exe: &Path, args: &[&str], clear_java_options: bool) -> Value {
    use tokio::io::AsyncReadExt;
    let command: Vec<_> = std::iter::once(exe.to_string_lossy().to_string())
        .chain(args.iter().map(|s| s.to_string()))
        .collect();
    let result: anyhow::Result<(i32, String)> = async {
        let mut process = tokio::process::Command::new(exe);
        process.args(args);
        if clear_java_options {
            process
                .env_remove("JAVA_TOOL_OPTIONS")
                .env_remove("JDK_JAVA_OPTIONS")
                .env_remove("_JAVA_OPTIONS");
        }
        let mut child = process
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // PrintFlagsFinal is commonly larger than the ordinary command limit. It is only used by
        // the explicit Java collector and is reduced to allowlisted flags before serialization.
        let output_limit = if clear_java_options { 262_144 } else { 24_000 };
        async fn read(
            mut pipe: impl tokio::io::AsyncRead + Unpin,
            output_limit: usize,
        ) -> std::io::Result<Vec<u8>> {
            let mut output = vec![];
            let mut buf = [0; 4096];
            loop {
                let n = pipe.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let take = n.min(output_limit.saturating_sub(output.len()));
                output.extend_from_slice(&buf[..take]);
            }
            Ok(output)
        }
        let (out, err, status) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                read(stdout, output_limit),
                read(stderr, output_limit),
                child.wait()
            )
        })
        .await?;
        let mut bytes = out?;
        bytes.extend(err?);
        bytes.truncate(output_limit);
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
pub(crate) async fn run(exe: &Path, args: &[&str]) -> Value {
    run_command(exe, args, false).await
}
pub(crate) async fn run_clean_java(exe: &Path, args: &[&str]) -> Value {
    run_command(exe, args, true).await
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
    let java_scoped = options.java_processes_only
        || options.java_no_processes
        || !options.java_pid.is_empty()
        || !options.java_jdk.is_empty();
    let java4shell = if let Some(path) = &options.java_path {
        let row = crate::java4shell::launcher_gate(path).await;
        json!({"status":"collected","scope":"explicit_launcher","cve":crate::java4shell::CVE,"runtimes":[row]})
    } else if java_scoped {
        json!({"status":"collected","checks":{},"scope":"runtime_audit"})
    } else {
        crate::java4shell::collect(options.java_command).await
    };
    #[cfg(target_os = "linux")]
    let java4shell = if options.java_command && options.java_path.is_none() {
        let mut java4shell = java4shell;
        java4shell["checks"]["process_attach_requested"] = json!(options.java_attach);
        let audit = crate::java_runtime_audit::collect(options).await;
        java4shell["checks"]["process_attached"] = json!(
            audit["processes"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|p| p["runtime_build"].is_string()
                    || matches!(p["flag_status"].as_str(), Some("read" | "flags_missing")))
        );
        java4shell["runtime_audit"] = audit;
        java4shell
    } else {
        java4shell
    };
    let mut java4shell = java4shell;
    if let Some(path) = &options.java_apps {
        java4shell["applications"] =
            crate::java4shell::application_inventory(path, options.java_apps_depth.unwrap_or(3));
    }
    let mut nginx2root = crate::nginx2root::collect(
        options.nginx2root || options.middleware,
        options.nginx_path.as_deref(),
        &options.nginx_config,
    );
    if options.package_audit && nginx2root["status"] == "collected" {
        crate::nginx2root::add_package_evidence(&mut nginx2root).await;
    }
    let mut apache2root = crate::apache2root::collect(
        options.apache2root || options.middleware,
        options.apache_path.as_deref(),
        &options.apache_config,
    );
    if options.package_audit {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        for section in ["installations", "module_installations"] {
            for row in apache2root[section]
                .as_array_mut()
                .into_iter()
                .flatten()
                .take(8)
            {
                if let Some(path) = row["path"].as_str().filter(|p| p.starts_with('/')) {
                    row["package_evidence"] = tokio::time::timeout_at(
                        deadline,
                        crate::hostaudit::nginx_package_metadata(path),
                    )
                    .await
                    .unwrap_or_else(
                        |_| json!({"status":"unknown","reason":"package_lookup_timeout"}),
                    );
                    row["package_evidence"]["patch_status"] = json!("unverified");
                }
            }
        }
    }
    let rows = |report: &Value, sections: &[&str]| -> Vec<Value> {
        sections
            .iter()
            .flat_map(|section| report[*section].as_array().into_iter().flatten().cloned())
            .collect()
    };
    let java_rows = if options.java_path.is_some() {
        rows(&java4shell, &["runtimes"])
    } else {
        rows(
            &java4shell["runtime_audit"],
            &["processes", "installations"],
        )
    };
    let nginx_rows = rows(&nginx2root, &["running_processes", "installations"]);
    let apache_rows = rows(
        &apache2root,
        &["running_processes", "installations", "module_installations"],
    );
    let nginx_cves: Vec<_> = nginx_rows
        .iter()
        .flat_map(|row| row["cves"].as_array().into_iter().flatten())
        .collect();
    let audit_checks = [
        (
            "java4shell",
            options.java_command,
            java_rows
                .iter()
                .any(|r| matches!(r["status"].as_str(), Some("affected" | "potential"))),
            java_rows.is_empty()
                || java_rows.iter().any(|r| r["status"] == "unknown")
                || java4shell["applications"]["coverage_incomplete"] == true
                || java4shell["runtime_audit"]["coverage"]["proc_available"] == false
                || java4shell["runtime_audit"]["coverage"]["process_limit_reached"] == true
                || java4shell["runtime_audit"]["coverage"]["disk_budget_exhausted"] == true
                || [
                    "unreadable_maps",
                    "unstable_snapshots",
                    "unreadable_directories",
                    "root_depth_truncated",
                ]
                .iter()
                .any(|key| {
                    java4shell["runtime_audit"]["coverage"][*key]
                        .as_u64()
                        .unwrap_or(0)
                        > 0
                }),
        ),
        (
            "nginx2root",
            options.nginx2root || options.middleware,
            nginx_cves.iter().any(|r| r["status"] == "potential"),
            nginx_rows.is_empty()
                || nginx_cves.iter().any(|r| r["status"] == "unknown")
                || inventory_incomplete(&nginx2root, &nginx_rows),
        ),
        (
            "apache2root",
            options.apache2root || options.middleware,
            apache_rows
                .iter()
                .any(|r| r["version_status"] == "potential"),
            apache_rows.iter().any(|r| r["version_status"] == "unknown")
                || inventory_incomplete(&apache2root, &apache_rows),
        ),
    ];
    let mut audit = json!({"risk_gate_hit":false,"evidence_incomplete":false,"exit_codes":{}});
    for (name, enabled, risk, incomplete) in audit_checks {
        if !enabled {
            continue;
        }
        if risk {
            audit["risk_gate_hit"] = json!(true);
        }
        if incomplete {
            audit["evidence_incomplete"] = json!(true);
        }
        audit["exit_codes"][name] = json!(if risk {
            1
        } else if incomplete {
            3
        } else {
            0
        });
    }
    bounded_report(
        json!({"php_command":{"status":if options.php_command {"enabled"}else{"disabled"},"scope":"cli_only","detail":"显式开启才运行 PHP；CLI 配置不能代表 Web/FPM"},"java4shell":java4shell,"nginx2root":nginx2root,"apache2root":apache2root,"package_audit":package_audit,"collection_options":options,"audit":audit,"middleware":middleware,"schema":"php-selfcheck-host/v1","hostname":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),"collected_at":chrono::Utc::now().to_rfc3339(),"platform":format!("{} {}",std::env::consts::OS,std::env::consts::ARCH),"source":"developer_supplied_unverified","checks":checks,"runtime_observations":runtime_observations,"processes":processes,"limitations":["CLI 版本不等于 Web/FPM 实例版本；报告不自动证明补丁或漏洞状态。","Java4Shell 核验只检查版本、VM、当前 CPU 与受限参数线索，不触发漏洞或确认可利用性。","仅检查当前主机可见进程与标准路径；容器、远端主机、自定义安装目录需另行核验。","此报告未签名，平台记录为开发者提交材料。"]}),
    )
}

fn inventory_incomplete(report: &Value, rows: &[Value]) -> bool {
    report["coverage"]["proc_available"] == false
        || report["coverage"]["truncated"] == true
        || report["configuration"]["skipped"].as_u64().unwrap_or(0) > 0
        || rows.iter().any(|row| {
            row["configuration"]["skipped"].as_u64().unwrap_or(0) > 0
                || row["disk_identity_matched"] == false
        })
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
        "/java4shell/runtime_audit/installations",
        "/java4shell/runtime_audit/processes",
        "/apache2root/installations",
        "/apache2root/running_processes",
        "/apache2root/module_installations",
        "/nginx2root/installations",
        "/nginx2root/running_processes",
        "/java4shell/applications/findings",
        "/java4shell/runtimes",
        "/java4shell/running_processes",
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
    pub java_command: bool,
    pub java_attach: bool,
    pub java_apps: Option<PathBuf>,
    pub java_apps_depth: Option<usize>,
    pub java_cpuinfo: Option<PathBuf>,
    pub java_assume_flags_effective: bool,
    pub java_root: Vec<PathBuf>,
    pub java_jdk: Vec<PathBuf>,
    pub java_path: Option<PathBuf>,
    pub java_root_depth: Option<usize>,
    pub java_pid: Vec<u32>,
    pub java_processes_only: bool,
    pub java_no_processes: bool,
    pub nginx2root: bool,
    pub apache2root: bool,
    pub nginx_path: Option<PathBuf>,
    pub nginx_config: Vec<PathBuf>,
    pub apache_path: Option<PathBuf>,
    pub apache_config: Vec<PathBuf>,
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
            java_command: false,
            java_attach: false,
            java_apps: None,
            java_apps_depth: None,
            java_cpuinfo: None,
            java_assume_flags_effective: false,
            java_root: vec![],
            java_jdk: vec![],
            java_path: None,
            java_root_depth: None,
            java_pid: vec![],
            java_processes_only: false,
            java_no_processes: false,
            nginx2root: false,
            apache2root: false,
            nginx_path: None,
            nginx_config: vec![],
            apache_path: None,
            apache_config: vec![],
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
        anyhow::ensure!(
            self.java_path.is_none()
                || (self.java_command
                    && !self.java_attach
                    && self.java_pid.is_empty()
                    && !self.java_processes_only
                    && !self.java_no_processes
                    && self.java_root.is_empty()
                    && self.java_jdk.is_empty()
                    && self.java_root_depth.is_none()
                    && self.java_cpuinfo.is_none()
                    && !self.java_assume_flags_effective),
            "--java-path 为独立版本门禁，不能与 JVM 运行或安装盘点参数混用"
        );
        anyhow::ensure!(
            self.java_cpuinfo.is_none() || self.java_no_processes,
            "--java-cpuinfo 需要 --java-no-processes，以免将离线 CPU 证据用于运行进程"
        );
        anyhow::ensure!(
            !self.java_no_processes || !self.java_assume_flags_effective,
            "--java-assume-flags-effective 需要进程采集"
        );
        anyhow::ensure!(
            self.java_apps_depth.is_none() || self.java_apps.is_some(),
            "--java-apps-depth 需要 --java-apps"
        );
        anyhow::ensure!(
            self.java_apps_depth.unwrap_or(3) <= 16,
            "--java-apps-depth 必须在 0 至 16 之间"
        );
        anyhow::ensure!(
            self.java_command || (self.java_apps.is_none() && !self.java_assume_flags_effective),
            "Java 应用或估算参数需要 --java-command 或 --all"
        );
        anyhow::ensure!(
            self.nginx_config.is_empty() || self.nginx2root || self.middleware,
            "--nginx-config 需要 --nginx2root、--middleware 或 --all"
        );
        anyhow::ensure!(
            (self.apache_path.is_none() && self.apache_config.is_empty())
                || self.apache2root
                || self.middleware,
            "Apache 路径选项需要 --apache2root、--middleware 或 --all"
        );
        anyhow::ensure!(!self.java_pid.contains(&0), "--java-pid 必须为正整数");
        anyhow::ensure!(
            self.java_root_depth.unwrap_or(8) <= 32,
            "--java-root-depth 必须在 0 至 32 之间"
        );
        anyhow::ensure!(
            !self.java_no_processes
                || (!self.java_processes_only && self.java_pid.is_empty() && !self.java_attach),
            "--java-no-processes 与进程筛选、仅进程采集或诊断附加冲突"
        );
        anyhow::ensure!(
            self.java_command
                || (!self.java_processes_only
                    && !self.java_no_processes
                    && self.java_pid.is_empty()
                    && self.java_root.is_empty()
                    && self.java_jdk.is_empty()
                    && self.java_root_depth.is_none()),
            "Java 范围参数需要 --java-command 或 --all"
        );
        anyhow::ensure!(
            self.java_pid.len() <= 128 && self.java_root.len() + self.java_jdk.len() <= 64,
            "Java PID 或根目录数量超出上限"
        );
        anyhow::ensure!(
            !self.java_processes_only
                || (self.java_root.is_empty()
                    && self.java_jdk.is_empty()
                    && self.java_root_depth.is_none()),
            "--java-processes-only 与 Java 安装盘点范围冲突"
        );
        anyhow::ensure!(
            !self.java_attach || self.java_command,
            "--java-attach 需要 --java-command"
        );
        if let Some(path) = &self.nginx_path {
            anyhow::ensure!(
                self.nginx2root || self.middleware,
                "--nginx-path 需要 --nginx2root 或 --middleware"
            );
            anyhow::ensure!(
                path.is_absolute() && path.is_file(),
                "NGINX 路径必须是存在的绝对文件路径"
            );
        }
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
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum CollectFormat {
    #[default]
    Json,
    Txt,
    Csv,
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
    /// Java4Shell 主机核验：运行 java -version/PrintFlagsFinal 并读取 CPU 与受限 JVM 参数
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub java_command: Option<bool>,
    /// 读取目标 JVM 的生效参数（需要 --java-command）
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub java_attach: Option<bool>,
    /// Java 应用目录清单，按目录名收集产品线索
    #[arg(long)]
    pub java_apps: Option<PathBuf>,
    #[arg(long)]
    pub java_apps_depth: Option<usize>,
    /// 离线 CPU flags 文件，需使用仅安装模式
    #[arg(long)]
    pub java_cpuinfo: Option<PathBuf>,
    /// 显式允许在生效参数缺失时按 JVM 启动参数估算
    #[arg(long)]
    pub java_assume_flags_effective: bool,
    /// 报告格式，文本和 CSV 适用于仅启用 Java 的采集
    #[arg(long, value_enum, default_value = "json")]
    pub format: CollectFormat,
    /// Java 安装盘点额外递归根目录，可重复
    #[arg(long)]
    pub java_root: Vec<PathBuf>,
    /// 对指定 Java 启动器执行一次 -version，仅判断构建证据
    #[arg(long)]
    pub java_path: Option<PathBuf>,
    /// 内置 Java 判定演示，使用固定数据
    #[arg(long, conflicts_with_all = ["all","java_command","java_path","nginx2root","apache2root","middleware","options","fail_on_risk"])]
    pub demo: bool,
    /// 指定 JDK Home，可重复，替代默认安装目录
    #[arg(long)]
    pub java_jdk: Vec<PathBuf>,
    /// Java 安装扫描最大深度，默认 8
    #[arg(long)]
    pub java_root_depth: Option<usize>,
    /// 只检查指定 JVM PID，可重复
    #[arg(long)]
    pub java_pid: Vec<u32>,
    #[arg(long)]
    pub java_processes_only: bool,
    #[arg(long)]
    pub java_no_processes: bool,
    /// 采集 Nginx2Root 本机二进制与 SCTP 线索
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub nginx2root: Option<bool>,
    /// Apache HTTP Server CVE-2026-119618 本机核验
    #[arg(long,num_args=0..=1,default_missing_value="true",require_equals=true)]
    pub apache2root: Option<bool>,
    /// 将指定的 NGINX 文件加入本机盘点
    #[arg(long)]
    pub nginx_path: Option<PathBuf>,
    /// 仅检查指定 NGINX 配置入口，可重复
    #[arg(long)]
    pub nginx_config: Vec<PathBuf>,
    /// 将指定的 httpd 文件加入盘点
    #[arg(long)]
    pub apache_path: Option<PathBuf>,
    /// 仅检查指定 Apache 配置文件，可重复
    #[arg(long)]
    pub apache_config: Vec<PathBuf>,
    /// 一次开启 Java、NGINX、Apache 主机采集
    #[arg(long)]
    pub all: bool,
    /// 报告输出后按风险和证据完整性返回 1 或 3
    #[arg(long)]
    pub fail_on_risk: bool,
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
        for path in options
            .nginx_config
            .iter_mut()
            .chain(options.apache_config.iter_mut())
            .chain(options.nginx_path.iter_mut())
            .chain(options.apache_path.iter_mut())
        {
            if path.is_relative() {
                *path = options_dir.join(&*path);
            }
        }
        for path in options
            .java_apps
            .iter_mut()
            .chain(options.java_cpuinfo.iter_mut())
        {
            if path.is_relative() {
                *path = options_dir.join(&*path);
            }
        }
        if self.java_apps.is_some() {
            options.java_apps = self.java_apps;
        }
        if self.java_apps_depth.is_some() {
            options.java_apps_depth = self.java_apps_depth;
        }
        if self.java_cpuinfo.is_some() {
            options.java_cpuinfo = self.java_cpuinfo;
        }
        options.java_assume_flags_effective |= self.java_assume_flags_effective;
        for path in options
            .java_root
            .iter_mut()
            .chain(options.java_jdk.iter_mut())
        {
            if path.is_relative() {
                *path = options_dir.join(&*path);
            }
        }
        if let Some(path) = options.java_path.as_mut() {
            if path.is_relative() {
                *path = options_dir.join(&*path);
            }
        }
        if self.java_path.is_some() {
            options.java_path = self.java_path;
        }
        if let Some(path) = options.java_path.as_mut() {
            *path = std::fs::canonicalize(&*path)?;
            anyhow::ensure!(path.is_file(), "--java-path 需要存在的普通文件");
        }
        if !self.java_jdk.is_empty() {
            options.java_jdk = self.java_jdk;
        }
        if !self.java_root.is_empty() {
            options.java_root = self.java_root;
        }
        if self.java_root_depth.is_some() {
            options.java_root_depth = self.java_root_depth;
        }
        if !self.java_pid.is_empty() {
            options.java_pid = self.java_pid;
        }
        options.java_processes_only |= self.java_processes_only;
        options.java_no_processes |= self.java_no_processes;
        if !self.nginx_config.is_empty() {
            options.nginx_config = self.nginx_config;
        }
        if !self.apache_config.is_empty() {
            options.apache_config = self.apache_config;
        }
        if self.apache_path.is_some() {
            options.apache_path = self.apache_path;
        }
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
        if let Some(value) = self.java_attach {
            options.java_attach = value;
        }
        if let Some(path) = self.nginx_path {
            options.nginx_path = Some(path);
        }
        if let Some(path) = options.nginx_path.as_mut() {
            *path = std::fs::canonicalize(&*path)?;
        }
        if let Some(path) = options.apache_path.as_mut() {
            *path = std::fs::canonicalize(&*path)?;
            anyhow::ensure!(path.is_file(), "Apache 路径必须是存在的普通文件");
        }
        if let Some(value) = self.apache2root {
            options.apache2root = value;
        }
        if let Some(value) = self.nginx2root {
            options.nginx2root = value;
        }
        if let Some(value) = self.java_command {
            options.java_command = value;
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
        if self.all {
            options.java_command = self.java_command.unwrap_or(true);
            options.nginx2root = self.nginx2root.unwrap_or(true);
            options.apache2root = self.apache2root.unwrap_or(true);
        }
        if options.java_path.is_some() {
            options.java_command = true;
        }
        options.validate()?;
        Ok(options)
    }
}
