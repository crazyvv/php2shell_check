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
    LazyLock::new(|| Regex::new(r"(?i)nginx/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5})\b").unwrap());

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
            json!({"cve":cve,"status":status,"feature":feature,"reference":format!("https://www.cve.org/CVERecord?id={cve}"),"upstream_advisory":ADVISORY,"upstream_fixed_versions":["1.30.7","1.31.9"]})
        })
        .collect()
}

const OPENRESTY: &str = "https://openresty.org/en/ann-1031008001.html";
const TENGINE: &str = "https://github.com/alibaba/tengine/blob/3.2.0-rc5/src/core/nginx.h";
const INGRESS: &str = "https://docs.nginx.com/nginx-ingress-controller/releases/";
const PLUS_RELEASES: &str = "https://docs.nginx.com/nginx/releases/";
const OPENRESTY_125: &str = "https://openresty.org/en/changelog-1025003.html";
const OPENRESTY_127: &str = "https://openresty.org/en/changelog-1027001.html";
const SOURCES: [&str; 8] = [
    ADVISORY,
    CERT,
    OPENRESTY,
    TENGINE,
    INGRESS,
    PLUS_RELEASES,
    OPENRESTY_125,
    OPENRESTY_127,
];

fn plus_version(value: &str) -> Option<[u32; 4]> {
    let core = match value.split_once("-p") {
        Some((core, patch)) if !patch.is_empty() && patch.bytes().all(|c| c.is_ascii_digit()) => {
            core
        }
        Some(_) => return None,
        None => value,
    };
    let mut result = [0; 4];
    for (index, component) in core.split('.').enumerate() {
        if component.is_empty() || !component.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        *result.get_mut(index)? = component.parse().ok()?;
    }
    Some(result)
}

fn valid_product_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
}

#[derive(Default, Clone)]
struct Product {
    flavor: Option<&'static str>,
    version: Option<String>,
    core: Option<String>,
    plus: Option<String>,
    module_hints: Vec<String>,
}

impl Product {
    fn report(&self) -> Value {
        let flavor = self.flavor.unwrap_or("unknown");
        let core = self
            .core
            .as_deref()
            .or_else(|| match (flavor, self.version.as_deref()) {
                ("openresty", Some("1.31.8.1")) => Some("1.31.8"),
                ("openresty", Some("1.25.3.1")) => Some("1.25.3"),
                ("openresty", Some("1.27.1.2")) => Some("1.27.1"),
                ("tengine", Some("3.2.0-rc5")) => Some("1.31.5"),
                _ => None,
            });
        let mut cves = reference(core);
        for row in &mut cves {
            if flavor == "plus" {
                let affected = self
                    .plus
                    .as_deref()
                    .and_then(plus_version)
                    .is_some_and(|v| {
                        matches!(v[0], 34..=36)
                            || ([37, 0, 0, 0]..=[37, 0, 7, 1]).contains(&v)
                            || ([37, 1, 0, 0]..=[37, 2, 0, 1]).contains(&v)
                    });
                let release = self
                    .plus
                    .as_deref()
                    .filter(|value| plus_version(value).is_some())
                    .map(|value| value.split_once("-p").map_or(value, |(core, _)| core));
                let vendor_reference = matches!(release, Some("37.0.8.1" | "37.3.0.1"))
                    || (row["cve"] == "CVE-2026-123633"
                        && matches!(release, Some("37.0.7.1" | "37.2.0.1")));
                row["vendor_reference"] = json!(PLUS_RELEASES);
                row["vendor_fixed_versions"] = if row["cve"] == "CVE-2026-123633" {
                    json!(["37.0.7.1", "37.2.0.1"])
                } else {
                    json!(["37.0.8.1", "37.3.0.1"])
                };
                row["status"] = json!(if vendor_reference {
                    "meets_vendor_reference"
                } else if affected {
                    "potential"
                } else {
                    "unknown"
                });
            } else if flavor != "nginx" {
                row["embedded_upstream_status"] = row["status"].clone();
                if row["status"] != "potential" || flavor == "unknown" {
                    row["status"] = json!("unknown");
                }
            }
        }
        json!({"flavor":flavor,"product_version":self.version,"embedded_nginx_version":core,
            "version":if flavor=="nginx" {core} else {self.version.as_deref()},
            "plus_release":self.plus,"plus_release_unresolved":flavor=="plus" && self.plus.is_none(),
            "patch_status":"unverified","binary_module_hints":self.module_hints,"cves":cves})
    }

    fn from_report(row: &Value) -> Self {
        let flavor = match row["flavor"].as_str() {
            Some("nginx") | None => Some("nginx"),
            Some("plus") => Some("plus"),
            Some("openresty") => Some("openresty"),
            Some("tengine") => Some("tengine"),
            _ => None,
        };
        let core = row["embedded_nginx_version"]
            .as_str()
            .or_else(|| {
                (flavor == Some("nginx"))
                    .then(|| row["version"].as_str())
                    .flatten()
            })
            .filter(|v| v.len() <= 20 && version(v).is_some())
            .map(str::to_owned);
        Self {
            flavor,
            core,
            version: row["product_version"]
                .as_str()
                .filter(|v| valid_product_version(v))
                .map(str::to_owned),
            module_hints: row["binary_module_hints"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|hint| {
                    matches!(*hint, "http_v2" | "http_v3" | "http_mirror" | "mail_proxy")
                })
                .take(4)
                .map(str::to_owned)
                .collect(),
            plus: row["plus_release"]
                .as_str()
                .filter(|v| v.len() <= 40 && plus_version(v).is_some())
                .map(str::to_owned),
        }
    }
}

fn banner_product(banner: &str) -> Option<Product> {
    let (name, raw) = banner.split_once('/').unwrap_or((banner, ""));
    let flavor = match name.to_ascii_lowercase().as_str() {
        "nginx" => "nginx",
        "nginx-plus" => "plus",
        "openresty" => "openresty",
        "tengine" => "tengine",
        _ if banner.starts_with("nginx-plus-r") => "plus",
        _ => return None,
    };
    let raw = raw.split_ascii_whitespace().next().unwrap_or_default();
    let plus = banner
        .strip_prefix("nginx-plus-r")
        .unwrap_or(raw.trim_start_matches(['R', 'r']));
    Some(Product {
        module_hints: vec![],
        flavor: Some(flavor),
        core: (flavor == "nginx" && version(raw).is_some()).then(|| raw.to_owned()),
        version: (flavor != "nginx" && flavor != "plus" && valid_product_version(raw))
            .then(|| raw.to_owned()),
        plus: (flavor == "plus" && plus.len() <= 40 && plus_version(plus).is_some())
            .then(|| plus.to_owned()),
    })
}

pub(crate) fn remote(headers: &[(String, String)], blocked: bool) -> Value {
    let servers: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("server"))
        .map(|(_, value)| value.trim())
        .collect();
    let observed = servers.iter().any(|value| banner_product(value).is_some());
    let product = if servers.len() == 1 && !blocked {
        banner_product(servers[0]).unwrap_or_default()
    } else {
        Product::default()
    };
    let mut report = product.report();
    report["status"] = json!(if observed {
        "nginx_hint"
    } else {
        "not_observed"
    });
    report["source"] = json!("passive_server_header");
    report["patch_verified"] = json!(false);
    report["exploitability_confirmed"] = json!(false);
    report["sources"] = json!(SOURCES);
    report
}

const CONFIG_HINTS: [&str; 14] = [
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
    "proxy_http_version_2",
    "grpc_upstream",
];

#[cfg(target_os = "linux")]
fn include_paths(base: &std::path::Path, value: &str) -> Option<Vec<std::path::PathBuf>> {
    use std::{fs, path::Path};
    let value = value.trim_matches(['\'', '"']);
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-*".contains(&b))
    {
        return None;
    }
    let path = base.join(Path::new(value));
    if !value.contains('*') {
        return Some(vec![path]);
    }
    let suffix = path.file_name()?.to_str()?.strip_prefix('*')?;
    let directory = path.parent()?;
    if directory.to_str()?.contains('*') || suffix.contains('*') {
        return None;
    }
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(directory).ok()?.take(66).enumerate() {
        if index == 65 {
            return None;
        }
        let entry = entry.ok()?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| !name.starts_with('.') && name.ends_with(suffix))
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Some(paths)
}

#[cfg(target_os = "linux")]
fn process_config_entry(proc: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::{fs::File, io::Read};
    let mut bytes = Vec::new();
    File::open(proc.join("cmdline"))
        .ok()?
        .take(4097)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    let original = std::str::from_utf8(&bytes).ok()?;
    let args: Vec<_> = original
        .split_terminator('\0')
        .take_while(|arg| !arg.is_empty())
        .collect();
    if args.len() > 1 {
        return config_from_words(args.into_iter().skip(1), true);
    }
    let text = original.replace('\0', " ");
    config_from_words(text.split_ascii_whitespace(), false)
}

#[cfg(target_os = "linux")]
fn config_from_words<'a>(
    words: impl Iterator<Item = &'a str>,
    original_argv: bool,
) -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut words = words.peekable();
    let mut config = None;
    while let Some(word) = words.next() {
        if word == "-g" {
            if !original_argv {
                break;
            }
            words.next()?;
            continue;
        }
        if word == "-c" {
            let path = words.next()?;
            if config.is_some()
                || !path.starts_with('/')
                || !path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
                || words.peek().is_some_and(|next| !next.starts_with('-'))
            {
                return None;
            }
            config = Some(PathBuf::from(path));
        }
    }
    config
}

#[cfg(target_os = "linux")]
fn layout_config(binary: &std::path::Path) -> Option<std::path::PathBuf> {
    if !binary.is_absolute() {
        return None;
    }
    let directory = binary.parent()?;
    if !matches!(directory.file_name()?.to_str()?, "bin" | "sbin") {
        return None;
    }
    let prefix = directory.parent()?;
    let config = prefix.join("conf/nginx.conf");
    config.is_file().then_some(config)
}

#[cfg(target_os = "linux")]
fn config_hints(files: impl IntoIterator<Item = std::path::PathBuf>) -> Value {
    use std::{
        collections::{BTreeSet, VecDeque},
        fs,
        io::Read,
    };
    let mut hints = BTreeSet::new();
    let mut files_examined = 0;
    let mut skipped = 0;
    let mut pending: VecDeque<_> = files
        .into_iter()
        .take(65)
        .map(|path| {
            let base = path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_path_buf();
            (path, base, 0)
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut evidence = Vec::new();
    let mut include_observed = false;
    while let Some((path, base, depth)) = pending.pop_front() {
        if files_examined + skipped >= 64 {
            skipped += 1;
            break;
        }
        if !path.is_file() {
            skipped += usize::from(depth > 0);
            continue;
        }
        let Ok(identity) = fs::canonicalize(&path) else {
            skipped += 1;
            continue;
        };
        if !seen.insert(identity) {
            continue;
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
        for (index, line) in String::from_utf8_lossy(&content).lines().enumerate() {
            let mut record = |key| {
                if hints.insert(key) {
                    evidence.push(json!({"hint":key,"file":path,"line":index+1}));
                }
            };
            let line = line.split_once('#').map_or(line, |(text, _)| text);
            for fragment in line.split([';', '{', '}']) {
                let mut words = fragment.split_whitespace();
                let name = words.next().unwrap_or_default();
                let first = words.next().unwrap_or_default();
                let hint = match (name, first) {
                    ("include", value) => {
                        include_observed = true;
                        if depth < 8 && words.next().is_none() {
                            if let Some(paths) = include_paths(&base, value) {
                                if pending.len() + paths.len() <= 65 {
                                    pending.extend(
                                        paths.into_iter().map(|p| (p, base.clone(), depth + 1)),
                                    );
                                    continue;
                                }
                            }
                        }
                        skipped += 1;
                        continue;
                    }
                    ("http2", "on") => "http2_on",
                    ("http2", "off") => "http2_off",
                    ("http3", "on") => "http3_or_quic",
                    ("listen", _) => {
                        let options = words.collect::<Vec<_>>();
                        if options.contains(&"http2") {
                            record("http2_on");
                        }
                        if options.contains(&"quic") {
                            record("http3_or_quic");
                        }
                        continue;
                    }
                    ("proxy_pass", _) => {
                        if first.contains('$') {
                            record("dynamic_proxy_pass");
                        }
                        "upstream"
                    }
                    ("grpc_pass", _) => {
                        record("grpc_upstream");
                        "upstream"
                    }
                    ("proxy_http_version", "2") => "proxy_http_version_2",
                    ("fastcgi_pass" | "uwsgi_pass" | "scgi_pass", _) => "upstream",
                    ("resolver", _) if !first.is_empty() => "resolver",
                    ("mirror", _) if !first.is_empty() && first != "off" => "mirror",
                    ("mirror_request_body", "off") => "mirror_request_body_off",
                    ("ssi", "on") => "ssi",
                    ("mail", "") if line.contains('{') => "mail",
                    ("proxy", "on") => "mail_proxy",
                    ("auth_http", _) if !first.is_empty() => "auth_http",
                    _ => continue,
                };
                record(hint);
            }
        }
    }
    let mut report = json!({"scope":"disk_directive_hints","files_examined":files_examined,"skipped":skipped,"include_observed":include_observed,"evidence":evidence,"scope_resolution":"file_directive_only"});
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
fn binary_evidence(path: &std::path::Path) -> Option<(std::fs::Metadata, Product)> {
    use std::io::Read;
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut data = Vec::new();
    file.take(16 * 1024 * 1024).read_to_end(&mut data).ok()?;
    if !data.starts_with(b"\x7fELF") {
        return Some((meta, Product::default()));
    }
    let marker = |token: &[u8]| {
        data.windows(token.len())
            .any(|window| window.eq_ignore_ascii_case(token))
    };
    static PRODUCT_VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(openresty|tengine)/([0-9]+(?:\.[0-9]+){1,3}(?:-rc[0-9]+)?)\b").unwrap()
    });
    static PLUS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)nginx-plus-r([0-9]+(?:\.[0-9]+){0,3}(?:-p[0-9]+)?)\b").unwrap()
    });
    let unique = |values: &mut dyn Iterator<Item = &str>| {
        let first = values.next()?;
        for value in values {
            if value != first {
                return None;
            }
        }
        Some(first.to_owned())
    };
    let flavor = if marker(b"nginx-plus") {
        "plus"
    } else if marker(b"Tengine") {
        "tengine"
    } else if marker(b"openresty") {
        "openresty"
    } else {
        "nginx"
    };
    let core = unique(
        &mut VERSION
            .captures_iter(&data)
            .filter_map(|c| std::str::from_utf8(c.get(1)?.as_bytes()).ok()),
    );
    let version = unique(&mut PRODUCT_VERSION.captures_iter(&data).filter_map(|c| {
        c.get(1)?
            .as_bytes()
            .eq_ignore_ascii_case(flavor.as_bytes())
            .then_some(())?;
        std::str::from_utf8(c.get(2)?.as_bytes())
            .ok()
            .filter(|v| valid_product_version(v))
    }));
    let plus = unique(&mut PLUS.captures_iter(&data).filter_map(|c| {
        std::str::from_utf8(c.get(1)?.as_bytes())
            .ok()
            .filter(|v| v.len() <= 40 && plus_version(v).is_some())
    }));
    let module_hints = [
        (
            "http_v2",
            marker(b"ngx_http_v2_module") || marker(b"--with-http_v2_module"),
        ),
        (
            "http_v3",
            marker(b"ngx_http_v3_module") || marker(b"--with-http_v3_module"),
        ),
        ("http_mirror", marker(b"ngx_http_mirror_module")),
        (
            "mail_proxy",
            marker(b"ngx_mail_proxy_module") || marker(b"--with-mail"),
        ),
    ]
    .into_iter()
    .filter(|(_, present)| *present)
    .map(|(name, _)| name.to_owned())
    .collect();
    Some((
        meta,
        Product {
            flavor: Some(flavor),
            version,
            core,
            plus,
            module_hints,
        },
    ))
}

fn annotate_config(row: &mut Value) {
    let config = row["configuration"].clone();
    for cve in row["cves"].as_array_mut().into_iter().flatten() {
        let keys: &[&str] = match cve["feature"].as_str() {
            Some("http2") => &["http2_on"],
            Some("http2_upstream") => &["http2_on", "upstream"],
            Some("http3_upstream") => &["http3_or_quic", "upstream"],
            Some("resolver_proxy_mirror") => &[
                "resolver",
                "dynamic_proxy_pass",
                "mirror",
                "mirror_request_body_off",
            ],
            Some("mail_proxy_auth_http") => &["mail_proxy", "auth_http"],
            _ => &[],
        };
        let mut missing = keys
            .iter()
            .copied()
            .filter(|key| config[*key] != true)
            .collect::<Vec<_>>();
        let status = if config["files_examined"].as_u64().unwrap_or(0) == 0 {
            "configuration_not_attributed"
        } else if config["skipped"].as_u64().unwrap_or(0) > 0 {
            "configuration_incomplete"
        } else if missing.is_empty() {
            "disk_hints_present"
        } else {
            "condition_not_observed"
        };
        if matches!(
            status,
            "configuration_not_attributed" | "configuration_incomplete"
        ) {
            missing.clear();
        }
        cve["config_evidence"] = json!(status);
        cve["missing_disk_hints"] = json!(missing);
    }
}

pub(crate) fn collect(
    enabled: bool,
    explicit: Option<&std::path::Path>,
    configs: &[std::path::PathBuf],
) -> Value {
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
        let explicit_config = (!configs.is_empty()).then(|| {
            let mut config = config_hints(configs.iter().cloned());
            config["skipped"] = json!(
                config["skipped"].as_u64().unwrap_or(0)
                    + configs.iter().filter(|path| !path.is_file()).count() as u64
            );
            config
        });
        let mut paths = BTreeSet::new();
        paths.extend(
            explicit.map(|path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())),
        );
        paths.extend(
            ["nginx", "openresty", "tengine"]
                .into_iter()
                .filter_map(crate::collector::which),
        );
        paths.extend(
            [
                "/usr/sbin/nginx",
                "/usr/local/nginx/sbin/nginx",
                "/usr/local/openresty/nginx/sbin/nginx",
                "/usr/local/tengine/sbin/nginx",
            ]
            .into_iter()
            .map(std::path::PathBuf::from),
        );
        let mut running = Vec::new();
        let mut cache = BTreeMap::new();
        let mut matched_images = BTreeSet::new();
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
            if !matches!(name.trim(), "nginx" | "openresty" | "tengine") {
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
                        (key == (m.dev(), m.ino())).then_some(v)
                    })
                    .clone()
            });
            let stable = id.is_some()
                && fs::metadata(&exe)
                    .ok()
                    .is_some_and(|m| id == Some((m.dev(), m.ino())));
            let product = version.filter(|_| stable).unwrap_or_default();
            let disk_match = stable
                && path.as_ref().is_some_and(|p| {
                    p.strip_prefix("/")
                        .ok()
                        .and_then(|p| fs::metadata(dir.join("root").join(p)).ok())
                        .is_some_and(|m| id == Some((m.dev(), m.ino())))
                });
            if let Some(id) = id.filter(|_| disk_match) {
                matched_images.insert(id);
            }
            let host_package_eligible = disk_match
                && fs::read_link(dir.join("ns/mnt"))
                    .ok()
                    .zip(fs::read_link("/proc/self/ns/mnt").ok())
                    .is_some_and(|(a, b)| a == b)
                && path
                    .as_ref()
                    .and_then(|p| fs::metadata(p).ok())
                    .is_some_and(|m| id == Some((m.dev(), m.ino())));
            let mut row = product.report();
            row["pid"] = json!(entry.file_name().to_string_lossy());
            row["path"] = json!(path);
            row["disk_identity_matched"] = json!(disk_match);
            row["host_package_eligible"] = json!(host_package_eligible);
            if let Some(config) = &explicit_config {
                row["configuration"] = config.clone();
                row["configuration_entry_source"] = json!("explicit");
            } else if host_package_eligible
                && fs::metadata(dir.join("root"))
                    .ok()
                    .zip(fs::metadata("/proc/self/root").ok())
                    .is_some_and(|(a, b)| (a.dev(), a.ino()) == (b.dev(), b.ino()))
                && let Some(config) = process_config_entry(&dir)
            {
                let configuration = config_hints([config.clone()]);
                row["configuration_entry"] = json!(config);
                row["configuration"] = configuration;
                row["configuration_entry_source"] = json!("process_argument");
            }
            annotate_config(&mut row);
            running.push(row);
        }
        let installations: Vec<_> = paths
            .iter()
            .filter_map(|path| {
                let (meta, product) = binary_evidence(path)?;
                if cache
                    .get(&(meta.dev(), meta.ino()))
                    .is_some_and(Option::is_some)
                {
                    return None;
                }
                let mut row = product.report();
                row["path"] = json!(path);
                let system = path == Path::new("/usr/sbin/nginx")
                    && product.flavor == Some("nginx")
                    && Path::new("/etc/nginx/nginx.conf").is_file();
                let config = if system {
                    Some("/etc/nginx/nginx.conf".into())
                } else {
                    layout_config(path)
                };
                if let Some(config) = &explicit_config {
                    row["configuration"] = config.clone();
                    row["configuration_entry_source"] = json!("explicit");
                } else if let Some(config) = config {
                    row["configuration_entry"] = json!(config);
                    row["configuration"] = config_hints([config]);
                    row["configuration_entry_source"] = json!(if system {
                        "system_layout"
                    } else {
                        "installation_layout"
                    });
                }
                annotate_config(&mut row);
                Some(row)
            })
            .collect();
        let mut config_counts = std::collections::BTreeMap::from([
            ("configuration_not_attributed", 0),
            ("configuration_incomplete", 0),
            ("potential_condition_not_observed", 0),
            ("unknown_condition_not_observed", 0),
            ("condition_not_observed", 0),
        ]);
        let mut unmapped = BTreeSet::new();
        for row in running.iter().chain(&installations) {
            if row["embedded_nginx_version"].is_null()
                && matches!(row["flavor"].as_str(), Some("openresty" | "tengine"))
                && let Some(version) = row["product_version"].as_str()
            {
                unmapped.insert(format!(
                    "{}/{version}",
                    row["flavor"].as_str().unwrap_or_default()
                ));
            }
            for cve in row["cves"].as_array().into_iter().flatten() {
                if let Some(count) =
                    config_counts.get_mut(cve["config_evidence"].as_str().unwrap_or_default())
                {
                    *count += 1;
                }
                if cve["config_evidence"] == "condition_not_observed" {
                    match cve["status"].as_str() {
                        Some("potential") => {
                            *config_counts
                                .entry("potential_condition_not_observed")
                                .or_default() += 1
                        }
                        Some("unknown") => {
                            *config_counts
                                .entry("unknown_condition_not_observed")
                                .or_default() += 1
                        }
                        _ => {}
                    }
                }
            }
        }
        let config_incomplete = config_counts["configuration_incomplete"] > 0
            || config_counts["configuration_not_attributed"] > 0;
        let mut summary = json!(config_counts);
        summary["unmapped_product_versions"] = json!(unmapped);
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|v| v.trim().to_owned());
        let associations = fs::File::open("/proc/net/sctp/assocs")
            .ok()
            .and_then(|file| {
                use std::io::{BufRead, BufReader, Read};
                let mut lines = BufReader::new(file.take(65_537)).lines();
                lines.next()?.ok()?;
                match lines.next() {
                    Some(Ok(line)) if !line.trim().is_empty() => Some(true),
                    None => Some(false),
                    _ => None,
                }
            });
        json!({"status":"collected","source":"local_binary_inventory","running_processes":running,
            "installations":installations,"configuration":explicit_config.unwrap_or_else(local_config),"coverage":{"proc_available":proc_available,"truncated":truncated,"configuration_incomplete":config_incomplete},"summary":summary,
            "sctp":{"kernel_release":kernel_release,"module_visible":Path::new("/sys/module/sctp").exists(),"associations_visible":associations,"modprobe_install_block_hint":sctp_block_hint(),"patch_status":"unknown"},
            "patch_verified":false,"exploitability_confirmed":false,"sources":SOURCES})
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (explicit, configs);
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

fn sanitize_configuration(raw: &Value) -> Value {
    let mut configuration = json!({"scope":"disk_directive_hints",
        "files_examined":raw["files_examined"].as_u64(),
        "skipped":raw["skipped"].as_u64()});
    for key in CONFIG_HINTS {
        configuration[key] = json!(raw[key].as_bool());
    }
    configuration["evidence"] = json!(
        raw["evidence"]
            .as_array()
            .into_iter()
            .flatten()
            .take(16)
            .filter_map(|item| {
                let hint = item["hint"]
                    .as_str()
                    .filter(|value| CONFIG_HINTS.contains(value))?;
                let file: String = item["file"].as_str()?.chars().take(400).collect();
                let line = item["line"]
                    .as_u64()
                    .filter(|line| *line > 0 && *line <= 65_536)?;
                Some(json!({"hint":hint,"file":file,"line":line}))
            })
            .collect::<Vec<_>>()
    );
    configuration["include_observed"] = json!(raw["include_observed"].as_bool());
    configuration["scope_resolution"] = json!("file_directive_only");
    configuration
}

pub(crate) fn sanitize_host(raw: &Value) -> Value {
    if raw["status"] == "disabled" || raw.is_null() {
        return json!({"status":"disabled"});
    }
    let rows = |key: &str| -> Vec<Value> {
        raw[key].as_array().into_iter().flatten().filter(|item| item.is_object()).take(24).map(|item| {
            let mut row = Product::from_report(item).report();
            row["pid"] = json!(item["pid"].as_str().filter(|p| p.len() <= 20 && p.bytes().all(|c| c.is_ascii_digit())));
            row["path"] = json!(item["path"].as_str().map(|p| p.chars().take(400).collect::<String>()));
            row["disk_identity_matched"] = json!(item["disk_identity_matched"].as_bool());
            row["configuration_entry"] = json!(item["configuration_entry"].as_str().map(|p|p.chars().take(400).collect::<String>()));
            row["configuration_entry_source"] = json!(item["configuration_entry_source"].as_str()
                .filter(|source| matches!(*source, "system_layout" | "installation_layout" | "process_argument" | "explicit")));
            if item["configuration"].is_object() {
                row["configuration"] = sanitize_configuration(&item["configuration"]);
            }
            annotate_config(&mut row);
            row["package_evidence"] = json!({
                "manager":item["package_evidence"]["manager"].as_str().filter(|v| matches!(*v,"dpkg"|"rpm")),
                "name":item["package_evidence"]["name"].as_str().map(|v|v.chars().take(100).collect::<String>()),
                "version":item["package_evidence"]["version"].as_str().map(|v|v.chars().take(150).collect::<String>()),
                "patch_status":"unverified"
            });
            row
        }).collect()
    };
    let configuration = sanitize_configuration(&raw["configuration"]);
    json!({"status":"unverified","running_processes":rows("running_processes"),"installations":rows("installations"),"configuration":configuration,
        "coverage":{"proc_available":raw["coverage"]["proc_available"].as_bool(),"truncated":raw["coverage"]["truncated"].as_bool()},
        "sctp":{"kernel_release":raw["sctp"]["kernel_release"].as_str().map(|v| v.chars().take(128).collect::<String>()),
            "module_visible":raw["sctp"]["module_visible"].as_bool(),"associations_visible":raw["sctp"]["associations_visible"].as_bool(),"modprobe_install_block_hint":raw["sctp"]["modprobe_install_block_hint"].as_bool(),"patch_status":"unknown"},
        "patch_verified":false,"exploitability_confirmed":false,"sources":SOURCES})
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

    #[cfg(target_os = "linux")]
    #[test]
    fn config_provenance_includes_globs_and_terminates_cycles() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nginx.conf");
        let snippets = dir.path().join("sites");
        let child = snippets.join("site.conf");
        std::fs::create_dir(&snippets).unwrap();
        std::fs::write(&root, "include sites/*.conf;\ninclude missing.conf;\n").unwrap();
        std::fs::write(&child, "# header\nhttp2 on;\ninclude nginx.conf;\n").unwrap();
        let parsed = config_hints([root.clone()]);
        assert_eq!(parsed["files_examined"], 2);
        assert_eq!(parsed["skipped"], 1);
        assert_eq!(
            parsed["evidence"][0],
            json!({"hint":"http2_on","file":child,"line":2})
        );
        std::fs::write(
            dir.path().join("cmdline"),
            format!(
                "nginx: master process nginx -c {} -g daemon off;\0",
                root.display()
            ),
        )
        .unwrap();
        assert_eq!(process_config_entry(dir.path()), Some(root.clone()));
        std::fs::write(
            dir.path().join("cmdline"),
            format!("nginx\0-g\0daemon off;\0-c\0{}\0", root.display()),
        )
        .unwrap();
        assert_eq!(process_config_entry(dir.path()), Some(root));
        let config = dir.path().join("conf/nginx.conf");
        std::fs::create_dir(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "http2 on;").unwrap();
        assert_eq!(layout_config(&dir.path().join("sbin/nginx")), Some(config));
    }

    #[test]
    fn derivatives_keep_product_and_core_evidence_separate() {
        let headers = [("Server".into(), "openresty/1.31.8.1".into())];
        let observed = remote(&headers, false);
        assert_eq!(observed["flavor"], "openresty");
        assert_eq!(observed["product_version"], "1.31.8.1");
        assert_eq!(observed["embedded_nginx_version"], "1.31.8");
        assert_eq!(observed["cves"][0]["status"], "potential");
        assert!(remote(&headers, true)["product_version"].is_null());

        let report = sanitize_host(&json!({"running_processes":[
            {"flavor":"tengine","product_version":"3.2.0","embedded_nginx_version":"1.31.5"},
            {"flavor":"openresty","product_version":"1.31.8.1","embedded_nginx_version":"1.31.9"},
            {"flavor":"plus","plus_release":"37-p1"},
            {"flavor":"plus","plus_release":"37.2.0.2"},
            {"flavor":"plus","plus_release":"37.2.0.1"},
            {"flavor":"plus","plus_release":"37.3.0.1-p2"}
        ]}));
        let rows = report["running_processes"].as_array().unwrap();
        assert_eq!(rows[0]["cves"][0]["status"], "potential");
        assert_eq!(rows[1]["cves"][0]["status"], "unknown");
        assert_eq!(
            rows[1]["cves"][0]["embedded_upstream_status"],
            "meets_upstream_reference"
        );
        assert_eq!(rows[2]["cves"][0]["status"], "potential");
        assert_eq!(rows[3]["cves"][0]["status"], "unknown");
        assert_eq!(rows[4]["cves"][0]["status"], "potential");
        assert_eq!(rows[4]["cves"][1]["status"], "meets_vendor_reference");
        assert!(
            rows[5]["cves"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["status"] == "meets_vendor_reference")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn derivative_elf_is_read_without_execution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nginx");
        std::fs::write(&path, b"\x7fELF nginx/1.31.5 Tengine/3.2.0").unwrap();
        let (_, evidence) = binary_evidence(&path).unwrap();
        assert_eq!(evidence.report()["flavor"], "tengine");
        assert_eq!(evidence.report()["embedded_nginx_version"], "1.31.5");
        std::fs::write(&path, b"\x7fELF nginx/1.27.4 nginx-plus-r37-p1").unwrap();
        let (_, evidence) = binary_evidence(&path).unwrap();
        assert_eq!(evidence.report()["plus_release"], "37-p1");
        assert_eq!(evidence.report()["cves"][0]["status"], "potential");
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
