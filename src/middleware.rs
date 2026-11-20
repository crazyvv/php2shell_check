//! Local middleware inventory. No configuration dumps, process environments or command lines.
use crate::collector::{CollectOptions, which};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    io::{Error, ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Listener {
    pub transport: String,
    pub address: String,
    pub port: u16,
    pub inode: u64,
}
fn read(path: &Path) -> std::io::Result<String> {
    let mut data = String::new();
    fs::File::open(path)?
        .take(2_097_153)
        .read_to_string(&mut data)?;
    if data.len() > 2_097_152 {
        return Err(Error::new(ErrorKind::InvalidData, "文件超过 2 MiB 限制"));
    }
    Ok(data)
}
pub fn family(name: &str, exe: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    let e = exe.to_ascii_lowercase();
    let base = Path::new(&e)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if n.contains("tengine") || e.contains("/tengine/") {
        Some("tengine")
    } else if n == "nginx" || base == "nginx" {
        Some("nginx")
    } else if n.starts_with("apache2") || n.starts_with("httpd") || base.starts_with("httpd") {
        Some("apache")
    } else if n.starts_with("php-fpm") || base.starts_with("php-fpm") {
        Some("php-fpm")
    } else if n == "frankenphp" || base == "frankenphp" {
        Some("frankenphp")
    } else if ["lshttpd", "litespeed", "openlitespeed"].contains(&n.as_str()) {
        Some("litespeed")
    } else if n == "lighttpd" {
        Some("lighttpd")
    } else {
        None
    }
}
pub fn parse_tcp(data: &str, ipv6: bool) -> Vec<Listener> {
    data.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" {
                return None;
            }
            let (address, port) = fields[1].split_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            let ip = if ipv6 {
                if address.len() != 32 {
                    return None;
                }
                let mut bytes = [0; 16];
                for i in 0..4 {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(
                        &u32::from_str_radix(&address[i * 8..i * 8 + 8], 16)
                            .ok()?
                            .to_ne_bytes(),
                    );
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            } else {
                if address.len() != 8 {
                    return None;
                }
                IpAddr::V4(Ipv4Addr::from(
                    u32::from_str_radix(address, 16).ok()?.to_ne_bytes(),
                ))
            };
            Some(Listener {
                transport: "tcp".into(),
                address: ip.to_string(),
                port,
                inode: fields[9].parse().ok()?,
            })
        })
        .collect()
}
fn mapped_php(data: &str) -> Vec<String> {
    data.lines()
        .filter_map(|line| {
            let path = line
                .split_whitespace()
                .skip(5)
                .collect::<Vec<_>>()
                .join(" ");
            let name = Path::new(&path).file_name()?.to_str()?.to_lowercase();
            ((name.starts_with("libphp")
                || name.starts_with("mod_php")
                || name.starts_with("ngx_http_php"))
                && name.contains(".so"))
            .then_some(path)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
pub fn module_lines(data: &str) -> Vec<String> {
    data.lines()
        .map(str::trim)
        .filter(|line| {
            let lower = line.to_lowercase();
            [
                "php_module",
                "php5_module",
                "php7_module",
                "php8_module",
                "proxy_fcgi_module",
                "fcgid_module",
            ]
            .iter()
            .any(|m| lower.split_whitespace().next() == Some(m))
        })
        .map(|s| s.chars().take(300).collect())
        .collect()
}
struct PortInventory {
    fd_remaining: usize,
    table_reads_remaining: usize,
    tables: HashMap<PathBuf, Vec<Listener>>,
}

impl Default for PortInventory {
    fn default() -> Self {
        Self {
            fd_remaining: 32_768,
            table_reads_remaining: 16,
            tables: HashMap::new(),
        }
    }
}

fn listeners(
    root: &Path,
    namespace: Option<&Path>,
    inventory: &mut PortInventory,
) -> (Vec<Listener>, Vec<Value>) {
    let mut errors = vec![];
    let mut owned = HashSet::new();
    match fs::read_dir(root.join("fd")) {
        Ok(entries) => {
            for (i, e) in entries.enumerate() {
                if inventory.fd_remaining == 0 {
                    errors.push(json!({"step":"fd","error":"达到本次巡检的 32768 个 FD 上限"}));
                    break;
                }
                if i >= 8192 {
                    errors
                        .push(json!({"step":"fd","error":"超过 8192 个 FD 上限，结果可能不完整"}));
                    break;
                }
                inventory.fd_remaining -= 1;
                match e {
                    Ok(entry) => match fs::read_link(entry.path()) {
                        Ok(target) => {
                            if let Some(inode) = target
                                .to_str()
                                .and_then(|s| s.strip_prefix("socket:["))
                                .and_then(|s| s.strip_suffix(']'))
                                .and_then(|s| s.parse::<u64>().ok())
                            {
                                owned.insert(inode);
                            }
                        }
                        Err(e) => {
                            if errors.len() < 8 {
                                errors.push(json!({"step":"fd_link","error":e.to_string()}));
                            }
                        }
                    },
                    Err(e) => {
                        if errors.len() < 8 {
                            errors.push(json!({"step":"fd_entry","error":e.to_string()}));
                        }
                    }
                }
            }
        }
        Err(e) => {
            errors.push(json!({"step":"fd","error":e.to_string()}));
            return (vec![], errors);
        }
    }
    if owned.is_empty() {
        return (vec![], errors);
    }
    let Some(namespace) = namespace else {
        errors.push(json!({"step":"netns","error":"无法核实进程的网络命名空间"}));
        return (vec![], errors);
    };
    let filter = |entries: &[Listener]| {
        entries
            .iter()
            .filter(|entry| owned.contains(&entry.inode))
            .cloned()
            .collect()
    };
    if !fs::read_link(root.join("ns/net")).is_ok_and(|current| current == namespace) {
        errors.push(json!({"step":"netns","error":"采集期间进程网络命名空间发生变化"}));
        return (vec![], errors);
    }
    if let Some(entries) = inventory.tables.get(namespace) {
        return (filter(entries), errors);
    }
    if inventory.table_reads_remaining == 0 {
        errors.push(json!({"step":"netns","error":"达到本次巡检的 16 次 TCP 表读取上限"}));
        return (vec![], errors);
    }
    inventory.table_reads_remaining -= 1;
    let errors_before_read = errors.len();
    let mut entries = vec![];
    for (file, v6) in [("tcp", false), ("tcp6", true)] {
        match read(&root.join("net").join(file)) {
            Ok(data) => entries.extend(parse_tcp(&data, v6)),
            Err(e) => errors.push(json!({"step":file,"error":e.to_string()})),
        }
    }
    if !fs::read_link(root.join("ns/net")).is_ok_and(|current| current == namespace) {
        errors.push(json!({"step":"netns","error":"采集期间进程网络命名空间发生变化"}));
        return (vec![], errors);
    }
    let result = filter(&entries);
    if errors.len() == errors_before_read {
        inventory.tables.insert(namespace.to_path_buf(), entries);
    }
    (result, errors)
}
pub async fn collect(options: &CollectOptions) -> Value {
    if !options.middleware || options.validate().is_err() {
        return collect_with_sources(options, &Value::Null, &Value::Null).await;
    }
    let nginx =
        crate::nginx2root::collect(true, options.nginx_path.as_deref(), &options.nginx_config);
    let apache =
        crate::apache2root::collect(true, options.apache_path.as_deref(), &options.apache_config);
    collect_with_sources(options, &nginx, &apache).await
}

pub(crate) async fn collect_with_sources(
    options: &CollectOptions,
    nginx: &Value,
    apache: &Value,
) -> Value {
    if let Err(e) = options.validate() {
        return json!({"status":"invalid_options","error":e.to_string()});
    }
    if !options.middleware {
        return json!({"status":"disabled","instances":[],"binaries":[],"web_probes":[]});
    }
    collect_at(options, Path::new("/proc"), nginx, apache).await
}
fn binary_hints(nginx: &Value, apache: &Value, kind: &str, exe: &str, pid: Option<&str>) -> Value {
    let report = match kind {
        "apache" => apache,
        "nginx" | "tengine" => nginx,
        _ => &Value::Null,
    };
    let section = if pid.is_some() {
        "running_processes"
    } else {
        "installations"
    };
    let matching = report[section]
        .as_array()
        .into_iter()
        .flatten()
        .find(|row| {
            row["path"] == exe
                && pid.is_none_or(|id| {
                    row["pid"].as_str() == Some(id)
                        || row["pid"]
                            .as_u64()
                            .is_some_and(|value| id.parse() == Ok(value))
                })
        });
    let version = matching.and_then(|row| row["version"].as_str().or(row["plus_release"].as_str()));
    json!({"status":if version.is_some(){"observed"}else{"unknown"},
        "version":version.unwrap_or(""),"source":"passive_binary_metadata",
        "flavor":matching.map(|row| &row["flavor"]),"modules":{"status":"use_process_maps"}})
}

async fn collect_at(options: &CollectOptions, proc: &Path, nginx: &Value, apache: &Value) -> Value {
    let library = if let Some(file) = &options.fingerprint_file {
        match crate::fingerprints::Library::load(file) {
            Ok(lib) => lib,
            Err(e) => return json!({"status":"invalid_options","error":e.to_string()}),
        }
    } else {
        crate::fingerprints::builtin()
    };
    let mut instances = vec![];
    let mut errors = vec![];
    let mut cache: HashMap<String, Value> = HashMap::new();
    let mut probes = vec![];
    let mut seen = HashSet::new();
    let mut port_inventory = PortInventory::default();
    let namespace = fs::read_link(proc.join("self/ns/net")).ok();
    let local_addresses = local_addresses(proc);
    let entries = match fs::read_dir(proc) {
        Ok(e) => e,
        Err(e) => {
            return json!({"status":"unavailable","error":e.to_string(),"instances":[],"binaries":[],"web_probes":[]});
        }
    };
    let mut inspected = 0;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push(json!({"step":"proc","error":e.to_string()}));
                continue;
            }
        };
        let pid = entry.file_name().to_string_lossy().into_owned();
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if inspected == crate::collector::PROCESS_SCAN_LIMIT {
            errors.push(json!({"step":"proc","error":"进程检查达到上限"}));
            break;
        }
        inspected += 1;
        let root = entry.path();
        let identity = process_identity(&root);
        let name = match fs::read_to_string(root.join("comm")) {
            Ok(n) => n.trim().to_owned(),
            Err(_) => continue,
        };
        let executable = fs::read_link(root.join("exe")).ok();
        let exe = executable
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(mut kind) = family(&name, &exe) else {
            continue;
        };
        if instances.len() >= 128 {
            errors.push(json!({"step":"proc","error":"达到 128 个中间件进程上限"}));
            break;
        }
        let binary = binary_hints(nginx, apache, kind, &exe, Some(&pid));
        if binary["flavor"] == "tengine" {
            kind = "tengine";
        }
        if !exe.is_empty() {
            if let Some(previous) = cache.get_mut(&exe) {
                if binary["status"] == "observed" {
                    *previous = binary.clone();
                }
            } else if cache.len() < 16 {
                cache.insert(exe.clone(), binary.clone());
            }
        }
        let maps = if options.php_modules {
            match read(&root.join("maps")) {
                Ok(data) => {
                    json!({"status":"observed","php_libraries":mapped_php(&data),"source":"proc_maps","detail":"仅保存 PHP 相关映射路径；未发现不代表未加载或未使用 PHP"})
                }
                Err(e) => json!({"status":"unknown","error":e.to_string()}),
            }
        } else {
            json!({"status":"disabled"})
        };
        let process_namespace = fs::read_link(root.join("ns/net")).ok();
        let (ports, port_errors) = if options.ports {
            listeners(&root, process_namespace.as_deref(), &mut port_inventory)
        } else {
            (vec![], vec![])
        };
        let same_namespace = namespace.is_some() && process_namespace == namespace;
        let port_status = if !options.ports {
            "disabled"
        } else if port_errors.is_empty() {
            "observed"
        } else {
            "partial"
        };
        let stable_identity = identity.is_some() && identity == process_identity(&root);
        if options.web_probe && same_namespace && stable_identity && kind != "php-fpm" {
            for listener in &ports {
                for scheme in &options.web_schemes {
                    if probes.len() >= options.max_web_probes {
                        break;
                    }
                    let key = format!("{scheme}:{}:{}", listener.address, listener.port);
                    if !seen.insert(key) {
                        continue;
                    }
                    let allowed = listener.address.parse::<IpAddr>().is_ok_and(|a| {
                        a.is_loopback() || a.is_unspecified() || local_addresses.contains(&a)
                    });
                    if allowed {
                        probes.push(
                            probe_with_library(listener, &pid, scheme, options, &library).await,
                        );
                    } else {
                        probes.push(json!({"pid":pid,"bind_address":listener.address,"port":listener.port,"scheme":scheme,"status":"skipped","reason":"无法确认监听地址属于本机，不发起连接"}));
                    }
                }
            }
        }
        instances.push(json!({"pid":pid,"name":name,"family":kind,"executable":exe,"binary":binary,"php_modules":maps,"listeners":{"status":port_status,"items":ports,"errors":port_errors},"same_network_namespace":same_namespace,"process_identity_stable":stable_identity,"web_probe_status":if !options.web_probe{"disabled"}else if !same_namespace{"skipped_other_or_unknown_network_namespace"}else if !stable_identity{"skipped_process_changed_or_identity_unavailable"}else if kind=="php-fpm"{"skipped_fastcgi_not_http"}else{"see_web_probes"}}));
    }
    // Installed-but-not-running binaries are separate from runtime evidence.
    for name in [
        "apache2",
        "httpd",
        "nginx",
        "tengine",
        "frankenphp",
        "lighttpd",
        "lshttpd",
    ] {
        let paths = [
            which(name),
            Some(std::path::PathBuf::from(format!("/usr/sbin/{name}"))),
            Some(std::path::PathBuf::from(format!(
                "/usr/local/{name}/sbin/{name}"
            ))),
        ];
        for path in paths.into_iter().flatten() {
            let key = path.to_string_lossy().into_owned();
            if path.is_file() && !cache.contains_key(&key) && cache.len() < 16 {
                let kind = family(name, &key).unwrap_or("unknown");
                cache.insert(key.clone(), binary_hints(nginx, apache, kind, &key, None));
            }
        }
    }
    json!({"status":if errors.is_empty(){"completed"}else{"partial"},"instances":instances,"binaries":cache,"web_probes":probes,"errors":errors,"web_probe_limit_reached":options.web_probe && seen.len()>=options.max_web_probes,"limitations":["进程、FD 或 maps 权限不足时结果不完整，未知不等于没有中间件/模块/端口。","版本采用静态二进制证据；PHP 模块依据进程映射。","nginx/Tengine 通常通过 FastCGI 连接 PHP-FPM，不要求加载 mod_php。","仅探测同一网络命名空间中已关联进程的监听地址；PHP-FPM 端口不发送 HTTP。","默认 Host/路径可能命中默认虚拟主机，TLS 证书验证保持开启。"]})
}
fn process_identity(root: &Path) -> Option<String> {
    let data = read(&root.join("stat")).ok()?;
    data.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}
fn local_addresses(proc: &Path) -> HashSet<IpAddr> {
    let mut addresses = HashSet::new();
    if let Ok(data) = read(&proc.join("net/fib_trie")) {
        let mut previous = None;
        for line in data.lines() {
            if line.contains("host LOCAL") {
                if let Some(ip) = previous {
                    addresses.insert(IpAddr::V4(ip));
                }
            } else if let Some(ip) = line
                .split_whitespace()
                .last()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
            {
                previous = Some(ip);
            } else {
                previous = None;
            }
        }
    }
    if let Ok(data) = read(&proc.join("net/if_inet6")) {
        for line in data.lines() {
            if let Some(raw) = line.split_whitespace().next()
                && raw.len() == 32
                && let Ok(ip) = u128::from_str_radix(raw, 16)
            {
                addresses.insert(IpAddr::V6(Ipv6Addr::from(ip)));
            }
        }
    }
    addresses
}
#[cfg(all(test, unix))]
async fn probe(listener: &Listener, pid: &str, scheme: &str, options: &CollectOptions) -> Value {
    probe_with_library(
        listener,
        pid,
        scheme,
        options,
        &crate::fingerprints::builtin(),
    )
    .await
}
async fn probe_with_library(
    listener: &Listener,
    pid: &str,
    scheme: &str,
    options: &CollectOptions,
    library: &crate::fingerprints::Library,
) -> Value {
    let address: IpAddr = match listener.address.parse() {
        Ok(a) => a,
        Err(_) => return json!({"status":"unknown","reason":"无效监听地址"}),
    };
    let address = if address.is_unspecified() {
        if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        }
    } else {
        address
    };
    let host = options
        .web_host
        .clone()
        .unwrap_or_else(|| address.to_string());
    let mut report = json!({"pid":pid,"scheme":scheme,"bind_address":listener.address,"connected_ip":address.to_string(),"port":listener.port,"host":host,"path":options.web_path,"checked_at":chrono::Utc::now().to_rfc3339(),"source":"local_listener_http","status":"unknown"});
    let result: anyhow::Result<Value> = async {
        let authority = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let url = url::Url::parse(&format!(
            "{scheme}://{authority}:{}{}",
            listener.port, options.web_path
        ))?;
        match url.host() {
            Some(url::Host::Ipv4(ip)) => anyhow::ensure!(
                IpAddr::V4(ip) == address,
                "Web Host IP 必须等于已关联的本机连接地址"
            ),
            Some(url::Host::Ipv6(ip)) => anyhow::ensure!(
                IpAddr::V6(ip) == address,
                "Web Host IP 必须等于已关联的本机连接地址"
            ),
            _ => {}
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .resolve(
                url.host_str().unwrap(),
                SocketAddr::new(address, listener.port),
            )
            .build()?;
        let mut response = client
            .get(url.clone())
            .header(
                "User-Agent",
                format!("PHP-SelfCheck-Local/{}", env!("CARGO_PKG_VERSION")),
            )
            .header("Accept-Encoding", "identity")
            .send()
            .await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect::<Vec<_>>();
        let mut body = vec![];
        while let Some(chunk) = response.chunk().await? {
            let n = chunk.len().min(16385 - body.len());
            body.extend_from_slice(&chunk[..n]);
            if body.len() > 16384 {
                break;
            }
        }
        let findings = crate::scanner::inspect_with_library(
            &headers,
            &body[..body.len().min(16384)],
            Some(&url),
            library,
        );
        Ok(json!({"http_status":status,"findings":findings,"body_truncated":body.len()>16384}))
    }
    .await;
    match result {
        Ok(v) => {
            report["status"] = json!("responded");
            report["response"] = v;
        }
        Err(e) => {
            report["error"] = json!(e.to_string().chars().take(300).collect::<String>());
        }
    }
    report
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn table(port: u16, inode: u64) -> String {
        format!(
            "header\n0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 {inode}\n"
        )
    }
    fn fixture(kind: &str, port: u16) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for path in ["self/ns", "100/ns", "100/fd", "100/net"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        symlink("net:[123]", root.join("self/ns/net")).unwrap();
        symlink("net:[123]", root.join("100/ns/net")).unwrap();
        fs::write(root.join("100/comm"), kind).unwrap();
        fs::write(
            root.join("100/stat"),
            format!("100 ({kind}) S {} 123", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        let exe = root.join("binary");
        fs::write(&exe,"#!/bin/sh\nprintf '%s\\n' 'nginx version: Tengine/3.1.0'\nprintf '%s\\n' 'configure arguments: --without-http_fastcgi_module'\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&exe, root.join("100/exe")).unwrap();
        fs::write(root.join("100/maps"),"1000-2000 r-xp 00000000 00:00 1 /opt/php/libphp8.so\n2000-3000 r-xp 00000000 00:00 2 /lib/libc.so.6\n").unwrap();
        symlink("socket:[12345]", root.join("100/fd/3")).unwrap();
        fs::write(root.join("100/net/tcp"), table(port, 12345)).unwrap();
        fs::write(root.join("100/net/tcp6"), "header\n").unwrap();
        dir
    }
    #[test]
    fn classification_and_module_evidence() {
        assert_eq!(
            family("nginx", "/usr/local/tengine/sbin/nginx"),
            Some("tengine")
        );
        assert_eq!(family("apache2", "/usr/sbin/apache2"), Some("apache"));
        assert_eq!(
            family("php-fpm8.4", "/usr/sbin/php-fpm8.4"),
            Some("php-fpm")
        );
        assert_eq!(family("worker", "/usr/bin/worker"), None);
        assert_eq!(
            module_lines(
                " php_module (shared)\n proxy_fcgi_module (shared)\n other_module (shared)\n"
            )
            .len(),
            2
        );
        assert_eq!(
            mapped_php(
                "10-20 r-xp 0 00:00 1 /lib/libphp8.so\n20-30 r-xp 0 00:00 2 /lib/libc.so.6\n"
            ),
            vec!["/lib/libphp8.so"]
        );
    }
    #[test]
    fn listening_inodes_and_permission_unknowns() {
        let dir = fixture("nginx", 8080);
        let (ports, errors) = listeners(
            &dir.path().join("100"),
            Some(Path::new("net:[123]")),
            &mut PortInventory::default(),
        );
        assert!(errors.is_empty());
        assert_eq!(ports[0].address, "127.0.0.1");
        assert_eq!(ports[0].port, 8080);
        fs::remove_file(dir.path().join("100/fd/3")).unwrap();
        let (ports, _) = listeners(
            &dir.path().join("100"),
            Some(Path::new("net:[123]")),
            &mut PortInventory::default(),
        );
        assert!(ports.is_empty());
        fs::remove_dir(dir.path().join("100/fd")).unwrap();
        let (_, errors) = listeners(
            &dir.path().join("100"),
            Some(Path::new("net:[123]")),
            &mut PortInventory::default(),
        );
        assert!(!errors.is_empty());
        let ipv6 = "header\n0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n";
        if cfg!(target_endian = "little") {
            assert_eq!(parse_tcp(ipv6, true)[0].address, "::1");
        }
    }

    #[test]
    fn tcp_tables_are_shared_by_namespace_and_fds_have_a_shared_budget() {
        let first = fixture("nginx", 8080);
        let second = fixture("nginx", 9090);
        fs::remove_file(second.path().join("100/net/tcp")).unwrap();
        let ns = Some(Path::new("net:[123]"));
        let mut inventory = PortInventory {
            fd_remaining: 2,
            table_reads_remaining: 1,
            ..PortInventory::default()
        };
        let (ports, errors) = listeners(&first.path().join("100"), ns, &mut inventory);
        assert_eq!(ports[0].port, 8080);
        assert!(errors.is_empty());
        let (ports, errors) = listeners(&second.path().join("100"), ns, &mut inventory);
        assert_eq!(ports[0].port, 8080);
        assert!(errors.is_empty());
        let (ports, errors) = listeners(&second.path().join("100"), ns, &mut inventory);
        assert!(ports.is_empty());
        assert_eq!(errors[0]["step"], "fd");
    }
    #[tokio::test]
    async fn optional_local_http_keeps_host_and_redacts_cookies() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = fixture("nginx", port);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let n = socket.read(&mut bytes).await.unwrap();
            let request = String::from_utf8_lossy(&bytes[..n]).to_lowercase();
            assert!(request.starts_with("get / "));
            assert!(request.contains(&format!("host: app.internal:{port}")));
            assert!(!request.contains("authorization:"));
            socket.write_all(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.35\r\nX-Owned-App: yes\r\nSet-Cookie: PHPSESSID=PRIVATECOOKIE\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let rules = dir.path().join("fingerprints.json");
        fs::write(&rules,r#"{"schema":"php-selfcheck-fingerprints/v1","version":"custom-web-1","mode":"replace","rules":[{"id":"custom-web","name":"Local app","category":"framework","any":[{"source":"header","header":"x-owned-app","pattern":"^yes$"}]}]}"#).unwrap();
        let options = CollectOptions {
            fingerprint_file: Some(rules),
            middleware: true,
            php_modules: true,
            ports: true,
            web_probe: true,
            web_host: Some("app.internal".into()),
            web_schemes: vec!["http".into()],
            max_web_probes: 1,
            ..Default::default()
        };
        let nginx = json!({"running_processes":[{"pid":"100","path":dir.path().join("binary"),"flavor":"tengine","version":"3.1.0"}]});
        let report = collect_at(&options, dir.path(), &nginx, &Value::Null).await;
        server.await.unwrap();
        assert_eq!(report["instances"][0]["family"], "tengine");
        assert_eq!(
            report["instances"][0]["php_modules"]["php_libraries"][0],
            "/opt/php/libphp8.so"
        );
        assert_eq!(report["web_probes"][0]["response"]["http_status"], 200);
        assert!(!report.to_string().contains("PRIVATECOOKIE"));
        assert_eq!(
            report["web_probes"][0]["response"]["findings"]["fingerprints"]["matches"][0]["id"],
            "custom-web"
        );
    }
    #[tokio::test]
    async fn switches_namespaces_and_fastcgi_prevent_requests() {
        let options = CollectOptions {
            middleware: true,
            ports: true,
            web_probe: true,
            web_schemes: vec!["http".into()],
            ..Default::default()
        };
        let dir = fixture("php-fpm8.4", 9);
        let report = collect_at(&options, dir.path(), &Value::Null, &Value::Null).await;
        assert!(report["web_probes"].as_array().unwrap().is_empty());
        assert_eq!(
            report["instances"][0]["web_probe_status"],
            "skipped_fastcgi_not_http"
        );
        let dir = fixture("nginx", 9);
        fs::remove_file(dir.path().join("100/ns/net")).unwrap();
        symlink("net:[999]", dir.path().join("100/ns/net")).unwrap();
        let report = collect_at(&options, dir.path(), &Value::Null, &Value::Null).await;
        assert!(report["web_probes"].as_array().unwrap().is_empty());
        assert_eq!(
            collect(&CollectOptions::default()).await["status"],
            "disabled"
        );
        let options = CollectOptions {
            middleware: true,
            ..Default::default()
        };
        let report = collect_at(&options, dir.path(), &Value::Null, &Value::Null).await;
        assert_eq!(report["instances"][0]["php_modules"]["status"], "disabled");
        assert_eq!(report["instances"][0]["listeners"]["status"], "disabled");
    }
    #[tokio::test]
    async fn host_ip_cannot_redirect_connection_and_redirects_are_not_followed() {
        let options = CollectOptions {
            middleware: true,
            ports: true,
            web_probe: true,
            web_host: Some("8.8.8.8".into()),
            ..Default::default()
        };
        let socket = Listener {
            transport: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 9,
            inode: 1,
        };
        let report = probe(&socket, "100", "http", &options).await;
        assert_eq!(report["status"], "unknown");
        assert!(report["error"].as_str().unwrap().contains("Host IP"));
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut data = [0; 4096];
            let n = s.read(&mut data).await.unwrap();
            assert!(n > 0);
            s.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let options = CollectOptions {
            middleware: true,
            ports: true,
            web_probe: true,
            ..Default::default()
        };
        let socket = Listener { port, ..socket };
        let report = probe(&socket, "100", "http", &options).await;
        assert_eq!(report["response"]["http_status"], 302);
        server.await.unwrap();
    }
    #[test]
    fn local_interface_addresses_are_required_for_non_loopback() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("net")).unwrap();
        fs::write(
            dir.path().join("net/fib_trie"),
            "  |-- 10.1.2.3\n     /32 host LOCAL\n  |-- 8.8.8.8\n     /32 universe UNICAST\n",
        )
        .unwrap();
        let addresses = local_addresses(dir.path());
        assert!(addresses.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!addresses.contains(&"8.8.8.8".parse().unwrap()));
    }
}
