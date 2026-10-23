//! Local Linux inventory. Never reads process environment or command lines; never uploads.
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
fn which(name: &str) -> Option<PathBuf> {
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
async fn run(exe: &Path, args: &[&str]) -> Value {
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
    let mut checks = vec![];
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
            checks.push(run(&exe, &["-n", "-v"]).await)
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
    json!({"schema":"php-selfcheck-host/v1","hostname":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),"collected_at":chrono::Utc::now().to_rfc3339(),"platform":format!("{} {}",std::env::consts::OS,std::env::consts::ARCH),"source":"developer_supplied_unverified","checks":checks,"processes":processes,"limitations":["CLI 版本不等于 Web/FPM 实例版本；报告不自动证明补丁或漏洞状态。","仅检查当前主机可见进程与标准路径；容器、远端主机、自定义安装目录需另行核验。","此报告未签名，平台记录为开发者提交材料。"]})
}
