//! Passive upstream version references for Nginx2Root.
#[cfg(target_os = "linux")]
use regex::bytes::Regex;
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::sync::LazyLock;

const ADVISORY: &str = "https://nginx.org/en/security_advisories.html";
const CERT: &str = "https://cert.europa.eu/publications/security-advisories/2026-022/";
const RULES: [(&str, [u32; 3], &str); 5] = [
    ("CVE-2026-123007", [1, 9, 5], "http2"),
    ("CVE-2026-123633", [1, 19, 7], "http2_upstream"),
    ("CVE-2026-123634", [0, 6, 18], "resolver_proxy_mirror"),
    ("CVE-2026-121810", [1, 25, 0], "http3_upstream"),
    ("CVE-2026-113425", [0, 5, 33], "mail_proxy_auth_http"),
];
#[cfg(target_os = "linux")]
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"nginx/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5})\b").unwrap());

fn version(raw: &str) -> Option<[u32; 3]> {
    let mut pieces = raw.split('.');
    let values = [
        pieces.next()?.parse().ok()?,
        pieces.next()?.parse().ok()?,
        pieces.next()?.parse().ok()?,
    ];
    pieces.next().is_none().then_some(values)
}

fn reference(raw: Option<&str>) -> Vec<Value> {
    let version = raw.and_then(version);
    RULES
        .iter()
        .map(|(cve, minimum, feature)| {
            let status = match version {
                Some(v)
                    if (v[0] == 1 && v[1] == 30 && v[2] >= 7)
                        || (v[0] == 1 && v[1] == 31 && v[2] >= 9) =>
                {
                    "meets_upstream_reference"
                }
                Some(v) if v < *minimum => "outside_upstream_range",
                Some(v) if v <= [1, 31, 8] => "potential",
                _ => "unknown",
            };
            json!({"cve":cve,"status":status,"feature":feature})
        })
        .collect()
}

pub(crate) fn remote(headers: &[(String, String)], blocked: bool) -> Value {
    let servers: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.trim())
        .collect();
    let banners: std::collections::BTreeSet<_> = servers
        .iter()
        .copied()
        .filter(|v| v.eq_ignore_ascii_case("nginx") || v.starts_with("nginx/"))
        .collect();
    let raw = (banners.len() == 1 && servers.len() == 1 && !blocked)
        .then(|| {
            banners
                .first()
                .and_then(|b| b.trim().strip_prefix("nginx/"))
                .filter(|v| version(v).is_some())
        })
        .flatten();
    json!({"status":if banners.is_empty() {"not_observed"} else {"nginx_hint"},
        "source":"passive_server_header","version":raw,"cves":reference(raw),
        "patch_verified":false,"exploitability_confirmed":false,"sources":[ADVISORY,CERT]})
}

const CONFIG_HINTS: [&str; 12] = [
    "http2_on",
    "http2_off",
    "http3_or_quic",
    "upstream",
    "resolver",
    "dynamic_proxy_pass",
    "mirror",
    "mirror_request_body_off",
    "ssi",
    "mail",
    "mail_proxy",
    "auth_http",
];

#[cfg(target_os = "linux")]
fn config_hints(files: impl IntoIterator<Item = std::path::PathBuf>) -> Value {
    use std::{collections::BTreeSet, fs, io::Read};
    let mut hints = BTreeSet::new();
    let mut files_examined = 0;
    let mut skipped = 0;
    for path in files {
        if !path.is_file() {
            continue;
        }
        if files_examined + skipped >= 64 {
            skipped += 1;
            break;
        }
        let mut content = Vec::new();
        if !fs::File::open(&path)
            .and_then(|f| f.take(65_537).read_to_end(&mut content))
            .is_ok_and(|n| n <= 65_536)
        {
            skipped += 1;
            continue;
        }
        files_examined += 1;
        for line in String::from_utf8_lossy(&content).lines() {
            let line = line.split_once('#').map_or(line, |(text, _)| text);
            for fragment in line.split([';', '{', '}']) {
                let mut words = fragment.split_whitespace();
                let name = words.next().unwrap_or_default();
                let first = words.next().unwrap_or_default();
                let hint = match (name, first) {
                    ("http2", "on") => "http2_on",
                    ("http2", "off") => "http2_off",
                    ("http3", "on") => "http3_or_quic",
                    ("listen", _) => {
                        let options = words.collect::<Vec<_>>();
                        if options.contains(&"http2") {
                            hints.insert("http2_on");
                        }
                        if options.contains(&"quic") {
                            hints.insert("http3_or_quic");
                        }
                        continue;
                    }
                    ("proxy_pass", _) => {
                        if first.contains('$') {
                            hints.insert("dynamic_proxy_pass");
                        }
                        "upstream"
                    }
                    ("grpc_pass" | "fastcgi_pass" | "uwsgi_pass" | "scgi_pass", _) => "upstream",
                    ("resolver", _) if !first.is_empty() => "resolver",
                    ("mirror", _) if !first.is_empty() && first != "off" => "mirror",
                    ("mirror_request_body", "off") => "mirror_request_body_off",
                    ("ssi", "on") => "ssi",
                    ("mail", "") if line.contains('{') => "mail",
                    ("proxy", "on") => "mail_proxy",
                    ("auth_http", _) if !first.is_empty() => "auth_http",
                    _ => continue,
                };
                hints.insert(hint);
            }
        }
    }
    let mut report =
        json!({"scope":"disk_directive_hints","files_examined":files_examined,"skipped":skipped});
    for key in CONFIG_HINTS {
        report[key] = json!(hints.contains(key));
    }
    report
}

#[cfg(target_os = "linux")]
fn local_config() -> Value {
    use std::{fs, path::PathBuf};
    let mut files = vec![
        PathBuf::from("/etc/nginx/nginx.conf"),
        PathBuf::from("/usr/local/nginx/conf/nginx.conf"),
    ];
    for root in ["/etc/nginx/conf.d", "/etc/nginx/sites-enabled"] {
        files.extend(
            fs::read_dir(root)
                .into_iter()
                .flatten()
                .flatten()
                .take(65)
                .map(|entry| entry.path())
                .filter(|path| {
                    root.ends_with("sites-enabled") || path.extension().is_some_and(|s| s == "conf")
                }),
        );
    }
    config_hints(files)
}

#[cfg(target_os = "linux")]
fn sctp_block_hint() -> bool {
    use std::{fs, io::Read, path::Path};
    ["/etc/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"]
        .into_iter()
        .any(|root| {
            fs::read_dir(root)
                .into_iter()
                .flatten()
                .flatten()
                .take(128)
                .any(|entry| {
                    let path = entry.path();
                    if path.extension().is_none_or(|ext| ext != "conf") || !path.is_file() {
                        return false;
                    }
                    let mut text = String::new();
                    if fs::File::open(&path)
                        .and_then(|f| f.take(65_536).read_to_string(&mut text))
                        .is_err()
                    {
                        return false;
                    }
                    text.lines().any(|line| {
                        let mut fields = line.split_whitespace();
                        fields.next() == Some("install")
                            && fields.next() == Some("sctp")
                            && fields.next().is_some_and(|s| {
                                matches!(
                                    Path::new(s).to_str(),
                                    Some("/bin/false" | "/usr/bin/false")
                                )
                            })
                    })
                })
        })
}

#[cfg(target_os = "linux")]
fn binary_evidence(path: &std::path::Path) -> Option<(std::fs::Metadata, Option<String>)> {
    use std::io::Read;
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
        return None;
    }
    let mut data = Vec::new();
    file.take(16 * 1024 * 1024).read_to_end(&mut data).ok()?;
    let raw = if data.starts_with(b"\x7fELF")
        && ![b"nginx-plus".as_slice(), b"Tengine", b"openresty"]
            .iter()
            .any(|token| data.windows(token.len()).any(|window| window == *token))
    {
        let mut versions = VERSION
            .captures_iter(&data)
            .filter_map(|capture| std::str::from_utf8(capture.get(1)?.as_bytes()).ok());
        versions
            .next()
            .filter(|first| versions.all(|v| v == *first))
            .map(str::to_owned)
    } else {
        None
    };
    Some((meta, raw))
}

pub(crate) fn collect(enabled: bool, explicit: Option<&std::path::Path>) -> Value {
    if !enabled {
        return json!({"status":"disabled"});
    }
    #[cfg(target_os = "linux")]
    {
        use std::{
            collections::{BTreeMap, BTreeSet},
            fs,
            os::unix::fs::MetadataExt,
            path::Path,
        };
        let mut paths = BTreeSet::new();
        paths.extend(explicit.map(std::path::Path::to_path_buf));
        if let Some(path) = crate::collector::which("nginx") {
            paths.insert(path);
        }
        paths.extend(
            ["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx"]
                .into_iter()
                .map(std::path::PathBuf::from),
        );
        let mut running = Vec::new();
        let mut cache = BTreeMap::new();
        let mut truncated = false;
        let proc = fs::read_dir("/proc");
        let proc_available = proc.is_ok();
        for entry in proc.into_iter().flatten().flatten() {
            let dir = entry.path();
            if !entry
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
            {
                continue;
            }
            let name = fs::read_to_string(dir.join("comm")).unwrap_or_default();
            if name.trim() != "nginx" {
                continue;
            }
            if running.len() == 24 {
                truncated = true;
                break;
            }
            let exe = dir.join("exe");
            let path = fs::read_link(&exe).ok();
            let metadata = fs::metadata(&exe).ok();
            let id = metadata.as_ref().map(|m| (m.dev(), m.ino()));
            let version = id.and_then(|key| {
                cache
                    .entry(key)
                    .or_insert_with(|| {
                        let (m, v) = binary_evidence(&exe)?;
                        (key == (m.dev(), m.ino())).then_some(v).flatten()
                    })
                    .clone()
            });
            let stable = id.is_some()
                && fs::metadata(&exe)
                    .ok()
                    .is_some_and(|m| id == Some((m.dev(), m.ino())));
            let version = version.filter(|_| stable);
            let disk_match = stable
                && path.as_ref().is_some_and(|p| {
                    p.strip_prefix("/")
                        .ok()
                        .and_then(|p| fs::metadata(dir.join("root").join(p)).ok())
                        .is_some_and(|m| id == Some((m.dev(), m.ino())))
                });
            let host_package_eligible = disk_match
                && fs::read_link(dir.join("ns/mnt"))
                    .ok()
                    .zip(fs::read_link("/proc/self/ns/mnt").ok())
                    .is_some_and(|(a, b)| a == b)
                && path
                    .as_ref()
                    .and_then(|p| fs::metadata(p).ok())
                    .is_some_and(|m| id == Some((m.dev(), m.ino())));
            running.push(
                json!({"pid":entry.file_name().to_string_lossy(),"path":path,"version":version,
                "disk_identity_matched":disk_match,"host_package_eligible":host_package_eligible,"cves":reference(version.as_deref())}),
            );
        }
        let installations: Vec<_> = paths
            .iter()
            .filter_map(|path| {
                let (meta, version) = binary_evidence(path)?;
                if cache.contains_key(&(meta.dev(), meta.ino())) && version.is_some() {
                    return None;
                }
                Some(json!({"path":path,"version":version,"cves":reference(version.as_deref())}))
            })
            .collect();
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|v| v.trim().to_owned());
        json!({"status":"collected","source":"local_binary_inventory","running_processes":running,
            "installations":installations,"configuration":local_config(),"coverage":{"proc_available":proc_available,"truncated":truncated},
            "sctp":{"kernel_release":kernel_release,"module_visible":Path::new("/sys/module/sctp").exists(),"modprobe_install_block_hint":sctp_block_hint(),"patch_status":"unknown"},
            "patch_verified":false,"exploitability_confirmed":false,"sources":[ADVISORY,CERT]})
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = explicit;
        json!({"status":"unknown","reason":"linux_required"})
    }
}

pub(crate) async fn add_package_evidence(report: &mut Value) {
    use std::collections::BTreeMap;
    let mut cache = BTreeMap::<String, Value>::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    for section in ["running_processes", "installations"] {
        for row in report[section].as_array_mut().into_iter().flatten() {
            if section == "running_processes" && row["host_package_eligible"] != true {
                continue;
            }
            let Some(path) = row["path"]
                .as_str()
                .filter(|p| p.starts_with('/'))
                .map(str::to_owned)
            else {
                continue;
            };
            if !cache.contains_key(&path) {
                if cache.len() >= 8 || tokio::time::Instant::now() >= deadline {
                    return;
                }
                let value = tokio::time::timeout_at(
                    deadline,
                    crate::hostaudit::nginx_package_metadata(&path),
                )
                .await
                .unwrap_or_else(|_| json!({"status":"unknown","reason":"package_lookup_timeout"}));
                cache.insert(path.clone(), value);
            }
            row["package_evidence"] = cache[&path].clone();
            row["package_evidence"]["patch_status"] = json!("unverified");
        }
    }
}

pub(crate) fn sanitize_host(raw: &Value) -> Value {
    if raw["status"] == "disabled" || raw.is_null() {
        return json!({"status":"disabled"});
    }
    let rows = |key: &str| -> Vec<Value> {
        raw[key].as_array().into_iter().flatten().filter(|item| item.is_object()).take(24).map(|item| {
            let version = item["version"].as_str().filter(|v| version(v).is_some() && v.len() <= 20);
            json!({"version":version,"pid":item["pid"].as_str().filter(|p| p.len() <= 20 && p.bytes().all(|c| c.is_ascii_digit())),
                "path":item["path"].as_str().map(|p| p.chars().take(400).collect::<String>()),
                "disk_identity_matched":item["disk_identity_matched"].as_bool(),"cves":reference(version),
                "package_evidence":{"manager":item["package_evidence"]["manager"].as_str().filter(|v| matches!(*v,"dpkg"|"rpm")),
                    "name":item["package_evidence"]["name"].as_str().map(|v|v.chars().take(100).collect::<String>()),
                    "version":item["package_evidence"]["version"].as_str().map(|v|v.chars().take(150).collect::<String>()),
                    "patch_status":"unverified"}})
        }).collect()
    };
    let mut configuration = json!({"scope":"disk_directive_hints",
        "files_examined":raw["configuration"]["files_examined"].as_u64(),
        "skipped":raw["configuration"]["skipped"].as_u64()});
    for key in CONFIG_HINTS {
        configuration[key] = json!(raw["configuration"][key].as_bool());
    }
    json!({"status":"unverified","running_processes":rows("running_processes"),"installations":rows("installations"),"configuration":configuration,
        "coverage":{"proc_available":raw["coverage"]["proc_available"].as_bool(),"truncated":raw["coverage"]["truncated"].as_bool()},
        "sctp":{"kernel_release":raw["sctp"]["kernel_release"].as_str().map(|v| v.chars().take(128).collect::<String>()),
            "module_visible":raw["sctp"]["module_visible"].as_bool(),"modprobe_install_block_hint":raw["sctp"]["modprobe_install_block_hint"].as_bool(),"patch_status":"unknown"},
        "patch_verified":false,"exploitability_confirmed":false,"sources":[ADVISORY,CERT]})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn config_directives_are_hints_and_ignore_commented_listeners() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx.conf");
        std::fs::write(&path, "# listen 443 ssl http2;\nserver { http2 off; listen 443 quic; resolver 192.0.2.53; proxy_pass http://$upstream; }\nmail { proxy on; auth_http localhost; }").unwrap();
        let evidence = config_hints([path]);
        assert_eq!(evidence["http2_on"], false);
        assert_eq!(evidence["http2_off"], true);
        assert_eq!(evidence["http3_or_quic"], true);
        assert_eq!(evidence["dynamic_proxy_pass"], true);
        assert_eq!(evidence["mail_proxy"], true);
        assert_eq!(evidence["auth_http"], true);
        assert_eq!(evidence["files_examined"], 1);
    }

    #[test]
    fn advisory_boundaries_and_remote_scope() {
        assert_eq!(reference(Some("1.30.6"))[0]["status"], "potential");
        assert_eq!(
            reference(Some("1.30.7"))[0]["status"],
            "meets_upstream_reference"
        );
        assert_eq!(reference(Some("1.31.8"))[0]["status"], "potential");
        assert_eq!(
            reference(Some("1.31.9"))[0]["status"],
            "meets_upstream_reference"
        );
        assert_eq!(
            reference(Some("1.24.0"))[3]["status"],
            "outside_upstream_range"
        );
        let headers = [("Server".into(), "nginx/1.31.8".into())];
        assert_eq!(remote(&headers, false)["cves"][0]["status"], "potential");
        assert!(remote(&headers, true)["version"].is_null());
    }
}
