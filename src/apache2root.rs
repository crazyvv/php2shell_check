//! Defensive Apache HTTP/2 inventory and passive response evidence.
use serde_json::{Value, json};

const CVE: &str = "CVE-2026-119618";
const ADVISORY: &str = "https://httpd.apache.org/security/vulnerabilities_24#CVE-2026-119618";
const PROTOCOLS: &str = "https://httpd.apache.org/docs/2.4/mod/mod_http2.html";

fn triplet(raw: &str) -> Option<[u32; 3]> {
    if raw.len() > 24 || !raw.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return None;
    }
    let mut parts = raw.split('.');
    let result = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(result)
}

fn version_status(raw: Option<&str>, module: bool) -> &'static str {
    let Some(v) = raw.and_then(triplet) else {
        return "unknown";
    };
    let (first, last) = if module { (8, 42) } else { (55, 70) };
    if v[..2] != if module { [2, 0] } else { [2, 4] } {
        return "unknown";
    }
    match v[2] {
        v if v < first => "outside_upstream_range",
        v if v <= last => "potential",
        _ if module => "outside_upstream_range",
        _ => "meets_upstream_reference",
    }
}

fn evidence(status: &str) -> Value {
    json!({"cve":CVE,"status":status,"patch_verified":false,"exploitability_confirmed":false,
        "sources":[ADVISORY,PROTOCOLS]})
}

pub(crate) fn remote(headers: &[(String, String)], blocked: bool, protocol: Option<&str>) -> Value {
    let servers: Vec<_> = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("server"))
        .collect();
    let apache: Vec<_> = servers
        .iter()
        .filter(|(_, value)| {
            value
                .split_whitespace()
                .next()
                .is_some_and(|v| v.eq_ignore_ascii_case("apache") || v.starts_with("Apache/"))
        })
        .collect();
    let raw = if !blocked && servers.len() == 1 && apache.len() == 1 {
        apache[0]
            .1
            .split_whitespace()
            .next()
            .and_then(|v| v.strip_prefix("Apache/"))
            .filter(|v| triplet(v).is_some())
    } else {
        None
    };
    let advertised = !blocked
        && headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("upgrade"))
            .flat_map(|(_, value)| value.split(','))
            .any(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "h2" | "h2c"));
    let mut out = evidence(if apache.is_empty() {
        "not_observed"
    } else {
        "apache_hint"
    });
    out["version"] = json!(raw);
    let version_status = version_status(raw, false);
    out["version_status"] = json!(version_status);
    if !apache.is_empty() {
        out["response_protocol"] = json!(protocol);
        out["http2_negotiated"] = json!(protocol.map(|value| value == "h2"));
        out["http2_screening"] = crate::scanner::http2_screening(
            "CVE-2026-119618",
            Some(version_status),
            protocol,
            headers,
            blocked,
        );
    }
    out["http2_advertised"] = json!(advertised);
    out["source"] = json!("passive_response_headers");
    out
}

#[cfg(target_os = "linux")]
fn installed_config(explicit: &[std::path::PathBuf]) -> Value {
    use std::{fs, io::Read, path::PathBuf};
    let mut paths: Vec<PathBuf> = [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    if explicit.is_empty() {
        for root in [
            "/etc/apache2/mods-enabled",
            "/etc/apache2/conf-enabled",
            "/etc/apache2/sites-enabled",
            "/etc/httpd/conf.d",
            "/etc/httpd/conf.modules.d",
        ] {
            paths.extend(
                fs::read_dir(root)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .take(65)
                    .map(|entry| entry.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "conf" || e == "load")),
            );
        }
    } else {
        paths = explicit.to_vec();
    }
    let (mut files, mut skipped, mut h2, mut h2c, mut h1, mut module) =
        (0, 0, false, false, false, false);
    let (mut inside_h2, mut outside_h2, mut direct, mut upgrade, mut include) =
        (false, false, false, false, false);
    for path in paths {
        if !path.is_file() {
            skipped += usize::from(!explicit.is_empty());
            continue;
        }
        if files + skipped >= 64 {
            skipped += 1;
            break;
        }
        let mut text = String::new();
        if !fs::File::open(&path)
            .and_then(|f| f.take(65_537).read_to_string(&mut text))
            .is_ok_and(|n| n <= 65_536)
        {
            skipped += 1;
            continue;
        }
        files += 1;
        let mut virtual_host = false;
        for line in text.lines() {
            let mut words = line.split_whitespace().map(|s| s.trim_matches('"'));
            match words
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "<virtualhost" => virtual_host = true,
                "</virtualhost>" => virtual_host = false,
                "include" | "includeoptional" => include = true,
                "h2direct" => direct |= words.next().is_some_and(|v| v.eq_ignore_ascii_case("on")),
                "h2upgrade" => {
                    upgrade |= words.next().is_some_and(|v| v.eq_ignore_ascii_case("on"))
                }
                "protocols" => {
                    let protocols: Vec<_> = words.take_while(|s| !s.starts_with('#')).collect();
                    let http2 = protocols
                        .iter()
                        .any(|v| v.eq_ignore_ascii_case("h2") || v.eq_ignore_ascii_case("h2c"));
                    inside_h2 |= virtual_host && http2;
                    outside_h2 |= !virtual_host && http2;
                    h2 |= protocols.iter().any(|v| v.eq_ignore_ascii_case("h2"));
                    h2c |= protocols.iter().any(|v| v.eq_ignore_ascii_case("h2c"));
                    h1 |= protocols.len() == 1 && protocols[0].eq_ignore_ascii_case("http/1.1");
                }
                "loadmodule" => {
                    module |= words
                        .next()
                        .is_some_and(|v| v.eq_ignore_ascii_case("http2_module"))
                }
                _ => {}
            }
        }
    }
    json!({"scope":"disk_directive_hints","files_examined":files,"skipped":skipped,"h2":h2,"h2c":h2c,"http1_only_directive":h1,"load_module":module,"h2_in_virtualhost":inside_h2,"h2_outside_virtualhost":outside_h2,"h2_direct_on":direct,"h2_upgrade_on":upgrade,"include_observed":include})
}

#[cfg(target_os = "linux")]
fn elf_version(path: &std::path::Path, module: bool) -> Option<String> {
    use regex::bytes::Regex;
    use std::{fs, io::Read, sync::LazyLock};
    static HTTPD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"Apache/([0-9]+\.[0-9]+\.[0-9]+)\b").unwrap());
    static MOD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"mod_http2(?:/| \(v)([0-9]+\.[0-9]+\.[0-9]+)\b").unwrap());
    if !path.is_file() {
        return None;
    }
    let mut data = vec![];
    fs::File::open(path)
        .ok()?
        .take(16_777_217)
        .read_to_end(&mut data)
        .ok()?;
    if !data.starts_with(b"\x7fELF") || data.len() > 16_777_216 {
        return None;
    }
    let mut releases = if module { &*MOD } else { &*HTTPD }
        .captures_iter(&data)
        .filter_map(|c| std::str::from_utf8(c.get(1)?.as_bytes()).ok());
    releases
        .next()
        .filter(|first| triplet(first).is_some() && releases.all(|v| v == *first))
        .map(str::to_owned)
}

pub(crate) fn collect(
    enabled: bool,
    explicit: Option<&std::path::Path>,
    configs: &[std::path::PathBuf],
) -> Value {
    if !enabled {
        return evidence("disabled");
    }
    #[cfg(target_os = "linux")]
    {
        use std::{
            collections::{BTreeMap, BTreeSet},
            fs,
            io::Read,
            os::unix::fs::MetadataExt,
            path::{Path, PathBuf},
        };
        let mut out = evidence("collected");
        let mut running = vec![];
        let mut matched = BTreeSet::new();
        let mut version_cache = BTreeMap::<(u64, u64), Option<String>>::new();
        let paths = [
            "/usr/sbin/apache2",
            "/usr/sbin/httpd",
            "/usr/local/apache2/bin/httpd",
        ];
        let paths: BTreeSet<_> = paths
            .into_iter()
            .map(PathBuf::from)
            .chain(
                explicit.map(|path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())),
            )
            .chain(
                ["apache2", "httpd"]
                    .into_iter()
                    .filter_map(crate::collector::which),
            )
            .collect();
        let proc = fs::read_dir("/proc");
        let proc_available = proc.is_ok();
        let mut truncated = false;
        let entries = proc.into_iter().flatten().flatten().filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            Some((pid, entry))
        });
        for (index, (pid, entry)) in entries.enumerate() {
            if index == crate::collector::PROCESS_SCAN_LIMIT {
                truncated = true;
                break;
            }
            let dir = entry.path();
            let comm = fs::read_to_string(dir.join("comm")).unwrap_or_default();
            if !matches!(comm.trim(), "apache2" | "httpd") {
                continue;
            }
            if running.len() >= 24 {
                truncated = true;
                break;
            }
            let start = crate::java_runtime_audit::start_time(&dir);
            let exe = dir.join("exe");
            let path = fs::read_link(&exe).ok();
            let id = |p: &Path| fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
            let before = id(&exe);
            let raw = before.and_then(|key| {
                if let Some(version) = version_cache.get(&key) {
                    return version.clone();
                }
                let version = elf_version(&exe, false);
                if id(&exe) == before {
                    version_cache.insert(key, version.clone());
                }
                version
            });
            let mut map_data = String::new();
            let readable = fs::File::open(dir.join("maps"))
                .and_then(|f| f.take(1_048_577).read_to_string(&mut map_data))
                .is_ok_and(|n| n <= 1_048_576);
            let module_mapped = readable
                && map_data.lines().any(|line| {
                    let line = line.strip_suffix(" (deleted)").unwrap_or(line);
                    line.ends_with("/mod_http2.so")
                });
            let stable = before.is_some()
                && start.is_some()
                && before == id(&exe)
                && start == crate::java_runtime_audit::start_time(&dir);
            let disk_identity_matched = stable
                && path.as_ref().is_some_and(|p| {
                    p.strip_prefix("/")
                        .ok()
                        .is_some_and(|p| before == id(&dir.join("root").join(p)))
                });
            if disk_identity_matched {
                matched.extend(before);
            }
            let raw = raw.filter(|_| stable);
            running.push(json!({"pid":pid,"path":path,"version":raw,"version_status":version_status(raw.as_deref(),false),
                "disk_identity_matched":disk_identity_matched,"mod_http2_mapped":(readable && stable).then_some(module_mapped),
                "status":if version_status(raw.as_deref(),false)=="potential" {"potential"} else {"unknown"}}));
        }
        let installations: Vec<_> = paths.into_iter().filter_map(|path| {
            let meta = fs::metadata(&path).ok()?;
            if !meta.is_file() || !matched.insert((meta.dev(),meta.ino())) { return None; }
            let raw = elf_version(&path,false);
            Some(json!({"path":path,"version":raw,"version_status":version_status(raw.as_deref(),false)}))
        }).collect();
        let modules: Vec<_> = [
            "/usr/lib/apache2/modules/mod_http2.so",
            "/usr/lib64/httpd/modules/mod_http2.so",
            "/usr/lib/httpd/modules/mod_http2.so",
            "/usr/local/apache2/modules/mod_http2.so",
        ]
        .into_iter()
        .filter(|path| Path::new(path).is_file())
        .map(|path| {
            let raw = elf_version(Path::new(path), true);
            json!({"path":path,"version":raw,"version_status":version_status(raw.as_deref(),true),"httpd_association":"unverified"})
        })
        .collect();
        if running.is_empty() && installations.is_empty() && modules.is_empty() && proc_available {
            out["status"] = json!("not_observed");
        }
        out["running_processes"] = json!(running);
        out["installations"] = json!(installations);
        out["module_installations"] = json!(modules);
        out["configuration"] = installed_config(configs);
        out["coverage"] = json!({"proc_available":proc_available,"truncated":truncated});
        out
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (explicit, configs);
        evidence("unknown")
    }
}

pub(crate) fn sanitize_host(raw: &Value) -> Value {
    if raw.is_null() || raw["status"] == "disabled" {
        return evidence("disabled");
    }
    let mut out = evidence("unverified");
    for section in ["running_processes", "installations", "module_installations"] {
        let rows: Vec<_> = raw[section].as_array().into_iter().flatten().filter(|r|r.is_object()).take(24).map(|r| {
            let raw = r["version"].as_str().filter(|v|triplet(v).is_some());
            json!({"pid":r["pid"].as_u64(),"path":r["path"].as_str().map(|p|p.chars().take(400).collect::<String>()),
                "version":raw,"version_status":version_status(raw,section == "module_installations"),
                "disk_identity_matched":r["disk_identity_matched"].as_bool(),"mod_http2_mapped":r["mod_http2_mapped"].as_bool()})
        }).collect();
        out[section] = json!(rows);
        if section == "module_installations" {
            for row in out[section].as_array_mut().into_iter().flatten() {
                row["httpd_association"] = json!("unverified");
            }
        }
    }
    let cfg = &raw["configuration"];
    out["configuration"] = json!({"scope":"disk_directive_hints","files_examined":cfg["files_examined"].as_u64(),
        "skipped":cfg["skipped"].as_u64(),"h2":cfg["h2"].as_bool(),"h2c":cfg["h2c"].as_bool(),
        "http1_only_directive":cfg["http1_only_directive"].as_bool(),"load_module":cfg["load_module"].as_bool()});
    for key in [
        "h2_in_virtualhost",
        "h2_outside_virtualhost",
        "h2_direct_on",
        "h2_upgrade_on",
        "include_observed",
    ] {
        out["configuration"][key] = json!(cfg[key].as_bool());
    }
    out["coverage"] = json!({"proc_available":raw["coverage"]["proc_available"].as_bool(),"truncated":raw["coverage"]["truncated"].as_bool()});
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_boundaries_and_passive_protocol_hints() {
        assert_eq!(
            version_status(Some("2.4.54"), false),
            "outside_upstream_range"
        );
        for v in ["2.4.55", "2.4.70"] {
            assert_eq!(version_status(Some(v), false), "potential");
        }
        assert_eq!(
            version_status(Some("2.4.71"), false),
            "meets_upstream_reference"
        );
        assert_eq!(version_status(Some("2.0.42"), true), "potential");
        assert_eq!(
            version_status(Some("2.0.43"), true),
            "outside_upstream_range"
        );
        let headers = [
            ("Server".into(), "Apache/2.4.70".into()),
            ("Upgrade".into(), "h2c".into()),
        ];
        assert_eq!(remote(&headers, false, None)["http2_advertised"], true);
        assert!(remote(&headers, true, None)["version"].is_null());
    }
}
