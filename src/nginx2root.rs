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
            running.push(
                json!({"pid":entry.file_name().to_string_lossy(),"path":path,"version":version,
                "disk_identity_matched":disk_match,"cves":reference(version.as_deref())}),
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
            "installations":installations,"coverage":{"proc_available":proc_available,"truncated":truncated},
            "sctp":{"kernel_release":kernel_release,"module_visible":Path::new("/sys/module/sctp").exists(),"patch_status":"unknown"},
            "patch_verified":false,"exploitability_confirmed":false,"sources":[ADVISORY,CERT]})
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = explicit;
        json!({"status":"unknown","reason":"linux_required"})
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
                "disk_identity_matched":item["disk_identity_matched"].as_bool(),"cves":reference(version)})
        }).collect()
    };
    json!({"status":"unverified","running_processes":rows("running_processes"),"installations":rows("installations"),
        "coverage":{"proc_available":raw["coverage"]["proc_available"].as_bool(),"truncated":raw["coverage"]["truncated"].as_bool()},
        "sctp":{"kernel_release":raw["sctp"]["kernel_release"].as_str().map(|v| v.chars().take(128).collect::<String>()),
            "module_visible":raw["sctp"]["module_visible"].as_bool(),"patch_status":"unknown"},
        "patch_verified":false,"exploitability_confirmed":false,"sources":[ADVISORY,CERT]})
}

#[cfg(test)]
mod tests {
    use super::*;
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
