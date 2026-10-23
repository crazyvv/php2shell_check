//! Local running-image/package association. Reference matches never establish a verified fix.
use crate::collector::{run, which};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Default)]
struct Tools {
    query: Option<PathBuf>,
    compare: Option<PathBuf>,
    policy: Option<PathBuf>,
    rpm: Option<PathBuf>,
}
impl Tools {
    fn discover() -> Self {
        Self {
            query: which("dpkg-query"),
            compare: which("dpkg"),
            policy: which("apt-cache"),
            rpm: which("rpm"),
        }
    }
}
const REFERENCE: &str = include_str!("../rules/vendor-patches.json");
#[derive(Clone, Debug, Deserialize)]
struct Rule {
    os_id: String,
    os_version: String,
    branch: String,
    source_package: String,
    manager: String,
    fixed_version: String,
    advisory: String,
    required_stream: String,
}
fn read(path: &Path) -> std::io::Result<String> {
    let mut s = String::new();
    fs::File::open(path)?
        .take(2_097_153)
        .read_to_string(&mut s)?;
    if s.len() > 2_097_152 {
        return Err(std::io::Error::other("文件超过 2 MiB 限制"));
    }
    Ok(s)
}
fn os_release(data: &str) -> BTreeMap<String, String> {
    data.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            ["ID", "VERSION_ID", "VERSION_CODENAME", "PRETTY_NAME"]
                .contains(&key)
                .then(|| {
                    (
                        key.into(),
                        value.trim_matches(['\'', '"']).chars().take(200).collect(),
                    )
                })
        })
        .collect()
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Image {
    path: String,
    inode: u64,
    device: Option<(u64, u64)>,
    deleted: bool,
}
fn php_maps(data: &str) -> Vec<Image> {
    let mut out = vec![];
    let mut seen = BTreeSet::new();
    for line in data.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let full = f[5..].join(" ");
        let path = full.strip_suffix(" (deleted)").unwrap_or(&full);
        let name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !path.starts_with('/')
            || path.contains('\\')
            || !name.contains(".so")
            || !["libphp", "mod_php", "ngx_http_php"]
                .iter()
                .any(|p| name.starts_with(p))
        {
            continue;
        }
        if seen.insert(full.clone()) {
            let device = f[3].split_once(':').and_then(|(a, b)| {
                Some((
                    u64::from_str_radix(a, 16).ok()?,
                    u64::from_str_radix(b, 16).ok()?,
                ))
            });
            out.push(Image {
                path: path.into(),
                inode: f[4].parse().unwrap_or(0),
                device,
                deleted: full.ends_with(" (deleted)"),
            });
        }
    }
    out
}
#[cfg(unix)]
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn file_id(_: &Path) -> Option<(u64, u64)> {
    None
}
fn linux_device(dev: u64) -> (u64, u64) {
    (
        ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000),
        (dev & 0xff) | ((dev >> 12) & 0xffffff00),
    )
}
fn image_state(image: &Image, process_root: &Path) -> &'static str {
    if image.deleted {
        return "restart_required";
    }
    if image.inode == 0 {
        return "unknown";
    }
    let Some((dev, ino)) = file_id(&process_root.join(image.path.trim_start_matches('/'))) else {
        return "unknown";
    };
    if ino != image.inode || image.device.is_some_and(|d| d != linux_device(dev)) {
        "restart_required"
    } else {
        "matches_disk_image"
    }
}
fn identity(root: &Path) -> Option<String> {
    read(&root.join("stat"))
        .ok()?
        .rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
}
fn package_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 200
        && !s.starts_with('-')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"+.-:_".contains(&c))
}
fn version_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 250
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".+~:_-%^".contains(&c))
}
fn applicable<'a>(
    rules: &'a [Rule],
    os: &BTreeMap<String, String>,
    package: &Value,
) -> Option<&'a Rule> {
    let version = package["version"]
        .as_str()?
        .split_once(':')
        .map_or(package["version"].as_str()?, |(_, v)| v);
    rules.iter().find(|r| {
        os.get("ID") == Some(&r.os_id)
            && os.get("VERSION_ID") == Some(&r.os_version)
            && package["manager"] == r.manager
            && package["source_package"] == r.source_package
            && version.starts_with(&format!("{}.", r.branch))
            && (r.required_stream.is_empty()
                || package["module_stream"].as_str() == Some(&r.required_stream))
    })
}
// Only the installed revision's official archive entry counts; candidate origins do not.
fn apt_origin(policy: &str, installed: &str, os: &str, codename: &str) -> bool {
    if codename.is_empty() {
        return false;
    }
    let mut active = false;
    for line in policy.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let f = if fields.first() == Some(&"***") {
            &fields[1..]
        } else {
            &fields[..]
        };
        if f.len() == 2 && version_text(f[0]) && f[1].parse::<i32>().is_ok() {
            active = f[0] == installed;
            continue;
        }
        if !active {
            continue;
        }
        for (i, field) in fields.iter().enumerate() {
            let Ok(u) = url::Url::parse(field) else {
                continue;
            };
            let host = u.host_str().unwrap_or("");
            let official = match os {
                "debian" => [
                    "deb.debian.org",
                    "security.debian.org",
                    "archive.debian.org",
                ]
                .contains(&host),
                "ubuntu" => {
                    [
                        "archive.ubuntu.com",
                        "security.ubuntu.com",
                        "ports.ubuntu.com",
                        "esm.ubuntu.com",
                        "old-releases.ubuntu.com",
                    ]
                    .contains(&host)
                        || host.ends_with(".archive.ubuntu.com")
                }
                _ => false,
            };
            let suite = fields
                .get(i + 1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("");
            if official
                && matches!(u.scheme(), "http" | "https")
                && u.username().is_empty()
                && (suite == codename || suite.starts_with(&format!("{codename}-")))
            {
                return true;
            }
        }
    }
    false
}
async fn native_compare(tools: &Tools, manager: &str, version: &str, fixed: &str) -> Option<bool> {
    if !version_text(version) || !version_text(fixed) {
        return None;
    }
    if manager == "dpkg" {
        let exe = tools.compare.as_ref()?;
        return match run(exe, &["--compare-versions", version, "ge", fixed]).await["exit_code"]
            .as_i64()?
        {
            0 => Some(true),
            1 => Some(false),
            _ => None,
        };
    }
    let split = |value: &str| -> Option<(u64, String)> {
        if let Some((epoch, rest)) = value.split_once(':') {
            Some((epoch.parse().ok()?, rest.into()))
        } else {
            Some((0, value.into()))
        }
    };
    let (a, av) = split(version)?;
    let (b, bv) = split(fixed)?;
    if a != b {
        return Some(a > b);
    }
    let exe = tools.rpm.as_ref()?;
    // Characters are allowlisted above; no shell or user-supplied Lua can enter the expression.
    let (av, ar) = av.rsplit_once('-')?;
    let (bv, br) = bv.rsplit_once('-')?;
    let expression = format!(
        "%{{lua:local c=rpm.vercmp('{av}','{bv}'); if c==0 then c=rpm.vercmp('{ar}','{br}') end; print(c)}}"
    );
    let result = run(exe, &["--eval", &expression]).await;
    if result["exit_code"] != 0 {
        return None;
    }
    Some(result["output"].as_str()?.trim().parse::<i32>().ok()? >= 0)
}
async fn package_for(
    tools: &Tools,
    path: &str,
    os: &BTreeMap<String, String>,
    rules: &[Rule],
) -> Value {
    let mut pkg = json!({"status":"unknown","path":path});
    match os.get("ID").map(String::as_str) {
        Some("debian" | "ubuntu") => {
            let Some(exe) = &tools.query else {
                return pkg;
            };
            let owner = run(exe, &["-S", path]).await;
            let names: BTreeSet<_> = owner["output"]
                .as_str()
                .unwrap_or("")
                .lines()
                .filter_map(|l| l.rsplit_once(": "))
                .filter(|(_, p)| *p == path)
                .flat_map(|(n, _)| n.split(", "))
                .filter(|n| package_name(n))
                .collect();
            if owner["exit_code"] != 0 || names.len() != 1 {
                pkg["reason"] = json!("无法取得唯一软件包归属（可能为自定义安装）");
                return pkg;
            }
            let name = *names.first().unwrap();
            let found = run(exe,&["-W","-f=${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Status}\\n",name]).await;
            let text = found["output"].as_str().unwrap_or("");
            let f: Vec<_> = text.trim_end().split('\t').collect();
            if found["exit_code"] != 0 || f.len() != 5 || f[4] != "installed" {
                return pkg;
            }
            pkg = json!({"status":"observed","path":path,"manager":"dpkg","name":f[0],"version":f[1],"source_package":f[2],"source_version":f[3],"origin_status":"unknown"});
            if let Some(apt) = &tools.policy {
                let policy = run(apt, &["policy", name]).await;
                if policy["exit_code"] == 0
                    && apt_origin(
                        policy["output"].as_str().unwrap_or(""),
                        f[1],
                        os.get("ID").map(String::as_str).unwrap_or(""),
                        os.get("VERSION_CODENAME").map(String::as_str).unwrap_or(""),
                    )
                {
                    pkg["origin_status"] = json!("matches_official_archive_metadata");
                }
            }
        }
        Some("rhel") => {
            let Some(exe) = &tools.rpm else {
                return pkg;
            };
            let found=run(exe,&["-qf","--qf","%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{MODULARITYLABEL}\\t%{ARCH}\\t%{SOURCERPM}\\n",path]).await;
            let text = found["output"].as_str().unwrap_or("");
            let f: Vec<_> = text.trim_end().split('\t').collect();
            if found["exit_code"] != 0 || f.len() != 6 {
                return pkg;
            }
            let stream = f[3]
                .strip_prefix("php:")
                .and_then(|s| s.split(':').next())
                .unwrap_or("");
            let source = f[5]
                .strip_suffix(".src.rpm")
                .and_then(|s| s.rsplitn(3, '-').nth(2))
                .unwrap_or("unknown");
            pkg = json!({"architecture":f[4],"source_rpm":f[5],"status":"observed","path":path,"manager":"rpm","name":f[0],"version":f[1],"vendor":f[2],"module_stream":stream,"source_package":source,"origin_status":if f[2]=="Red Hat, Inc." {"matches_vendor_declaration"}else{"unknown"}});
        }
        _ => {
            pkg["reason"] = json!("未覆盖此发行版或软件包来源");
            return pkg;
        }
    }
    pkg["patch_status"] = json!("unknown");
    let Some(rule) = applicable(rules, os, &pkg) else {
        pkg["reason"] = json!("没有适用于该发行版、源包、分支和模块流的参考规则");
        return pkg;
    };
    pkg["reference_rule"] = rule_to_json(rule);
    if pkg["origin_status"] == "unknown" {
        pkg["reason"] = json!("包来源未匹配，不能套用厂商阈值");
        return pkg;
    }
    let installed = if rule.manager == "dpkg" {
        pkg["source_version"].as_str()
    } else {
        pkg["version"].as_str()
    };
    if let Some(v) = installed.and_then(|v| (!v.is_empty()).then_some(v)) {
        pkg["patch_status"] =
            json!(
                match native_compare(tools, &rule.manager, v, &rule.fixed_version).await {
                    Some(true) => "meets_vendor_reference",
                    Some(false) => "below_vendor_reference",
                    None => "unknown",
                }
            );
    }
    pkg["detail"] = json!("仅匹配外部参考规则；未独立核实厂商公告，也不证明当前站点已修复");
    pkg
}
fn rule_to_json(r: &Rule) -> Value {
    json!({"os_id":r.os_id,"os_version":r.os_version,"branch":r.branch,"fixed_version":r.fixed_version,"source_package":r.source_package,"advisory":r.advisory,"required_stream":r.required_stream,"independently_verified":false})
}

pub async fn collect(enabled: bool) -> Value {
    if !enabled {
        return json!({"status":"disabled","instances":[]});
    }
    collect_at(Path::new("/proc"), Path::new("/etc/os-release")).await
}
async fn collect_at(proc: &Path, release: &Path) -> Value {
    let tools = Tools::discover();
    let reference: Value = serde_json::from_str(REFERENCE).expect("bundled rule JSON");
    let rules: Vec<Rule> =
        serde_json::from_value(reference["rules"].clone()).expect("bundled rule schema");
    let os = os_release(&read(release).unwrap_or_default());
    let mut instances = vec![];
    let mut errors = vec![];
    let mut cache = HashMap::<String, Value>::new();
    let entries = match fs::read_dir(proc) {
        Ok(e) => e,
        Err(e) => return json!({"status":"unavailable","error":e.to_string(),"instances":[]}),
    };
    let self_ns = fs::read_link(proc.join("self/ns/mnt")).ok();
    for entry in entries.flatten() {
        let pid = entry.file_name().to_string_lossy().into_owned();
        if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let root = entry.path();
        let name = read(&root.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let exe = fs::read_link(root.join("exe")).ok();
        let text = exe
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if crate::middleware::family(&name, &text).is_none() && !name.starts_with("php-cgi") {
            continue;
        }
        if instances.len() >= 128 {
            errors.push("达到 128 个进程上限");
            break;
        }
        let before = identity(&root);
        let exe_id = file_id(&root.join("exe"));
        let maps = read(&root.join("maps")).map(|s| php_maps(&s));
        let maps_ok = maps.is_ok();
        let mapped = maps.unwrap_or_default();
        let mut images = mapped.clone();
        if name.starts_with("php-fpm") || name.starts_with("php-cgi") || name == "frankenphp" {
            let path = text.strip_suffix(" (deleted)").unwrap_or(&text);
            if path.starts_with('/') {
                images.push(Image {
                    path: path.into(),
                    inode: exe_id.map(|v| v.1).unwrap_or(0),
                    device: exe_id.map(|v| linux_device(v.0)),
                    deleted: text.ends_with(" (deleted)"),
                });
            }
        }
        let same_root =
            file_id(&root.join("root")).is_some_and(|id| Some(id) == file_id(Path::new("/")));
        let same_namespace =
            self_ns.is_some() && fs::read_link(root.join("ns/mnt")).ok() == self_ns;
        let mut artifacts = vec![];
        for image in images.iter().take(16) {
            let state = image_state(image, &root.join("root"));
            let package = if same_root && same_namespace {
                if let Some(p) = cache.get(&image.path) {
                    p.clone()
                } else if cache.len() < 32 {
                    let p = package_for(&tools, &image.path, &os, &rules).await;
                    cache.insert(image.path.clone(), p.clone());
                    p
                } else {
                    json!({"status":"unknown","reason":"达到 32 个软件包路径检查上限"})
                }
            } else {
                json!({"status":"unknown","reason":"不同或未知挂载命名空间/根目录，请在对应容器中采集"})
            };
            artifacts.push(json!({"path":image.path,"running_image_status":state,"package":package,"running_patch_status":"unknown"}));
        }
        let stable = same_root
            && same_namespace
            && before.is_some()
            && before == identity(&root)
            && exe == fs::read_link(root.join("exe")).ok()
            && exe_id.is_some()
            && exe_id == file_id(&root.join("exe"))
            && maps_ok
            && read(&root.join("maps")).is_ok_and(|s| php_maps(&s) == mapped)
            && fs::read_link(root.join("ns/mnt")).ok() == self_ns
            && file_id(&root.join("root")) == file_id(Path::new("/"));
        for (artifact, image) in artifacts.iter_mut().zip(images.iter()) {
            artifact["running_image_status"] = json!(if stable {
                image_state(image, &root.join("root"))
            } else {
                "unknown"
            });
            if stable && artifact["running_image_status"] == "matches_disk_image" {
                artifact["running_patch_status"] = artifact["package"]["patch_status"]
                    .as_str()
                    .map_or(json!("unknown"), |s| json!(s));
            }
        }
        instances.push(json!({"pid":pid,"name":name,"executable":text,"same_mount_namespace":same_namespace,"same_root":same_root,"process_identity_stable":stable,"php_maps_readable":maps_ok,"artifacts":artifacts,"detail":"映射与磁盘一致也不证明该进程服务于提交的业务 URL"}));
    }
    json!({"status":if errors.is_empty(){"completed"}else{"partial"},"os":os,"instances":instances,"errors":errors,"reference_source":reference["reference_source"],"reference_date":reference["reference_date"],"rules_independently_verified":false,"confidence":"unverified","limitations":["规则来自固定版本的外部项目参考表，厂商公告尚需独立复核；不产生已确认修复结论。","仅核对实际进程的二进制或 PHP 模块所属包；不会以 CLI 或 php 元包代替 Web 实例。","已删除/替换的运行映像提示需要重启；无权限、不同容器或进程变化均保持未知。","APT 源元数据或 RPM Vendor 声明不是软件包真实性的独立证明。"]})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::{
        fs::MetadataExt,
        fs::{PermissionsExt, symlink},
    };
    fn rules() -> Vec<Rule> {
        serde_json::from_value(serde_json::from_str::<Value>(REFERENCE).unwrap()["rules"].clone())
            .unwrap()
    }
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn official_origin_must_match_installed_revision_and_release() {
        let policy = "php8.3-fpm:\n Installed: 8.3.6-0ubuntu0.24.04.13\n Version table:\n 8.3.6-0ubuntu0.24.04.14 500\n  500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n *** 8.3.6-0ubuntu0.24.04.13 100\n  100 /var/lib/dpkg/status\n";
        assert!(!apt_origin(
            policy,
            "8.3.6-0ubuntu0.24.04.13",
            "ubuntu",
            "noble"
        ));
        let policy = policy.replace(
            "100 /var/lib/dpkg/status",
            "500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages",
        );
        assert!(apt_origin(
            &policy,
            "8.3.6-0ubuntu0.24.04.13",
            "ubuntu",
            "noble"
        ));
        assert!(!apt_origin(
            &policy,
            "8.3.6-0ubuntu0.24.04.13",
            "ubuntu",
            "jammy"
        ));
        assert!(!apt_origin(
            &policy.replace("security.ubuntu.com", "security.ubuntu.com.evil.test"),
            "8.3.6-0ubuntu0.24.04.13",
            "ubuntu",
            "noble"
        ));
    }
    #[tokio::test]
    async fn native_versions_and_epochs_do_not_use_lexicographic_order() {
        let tools = Tools::discover();
        if tools.compare.is_some() {
            assert_eq!(
                native_compare(
                    &tools,
                    "dpkg",
                    "8.3.6-0ubuntu0.24.04.13",
                    "8.3.6-0ubuntu0.24.04.9"
                )
                .await,
                Some(true)
            );
            assert_eq!(
                native_compare(&tools, "dpkg", "8.2.35-1~deb12u1", "8.2.35-1").await,
                Some(false)
            );
            assert_eq!(
                native_compare(&tools, "dpkg", "1:7.4.3-1", "7.4.33-1").await,
                Some(true)
            );
        }
        assert_eq!(
            native_compare(&tools, "rpm", "2:7.4.1-1", "1:8.4.1-1").await,
            Some(true)
        );
        assert_eq!(
            native_compare(&tools, "rpm", "0:8.4.1-1'bad", "0:8.4.1-1").await,
            None
        );
    }
    #[test]
    fn vendor_release_stream_and_source_package_are_required() {
        let os = os_release("ID=rhel\nVERSION_ID=8.10\n");
        let mut pkg = json!({"manager":"rpm","version":"0:7.4.33-8.module+el8.10.0+25117+30337cca","source_package":"php","module_stream":"7.4"});
        let r = rules();
        assert!(applicable(&r, &os, &pkg).is_some());
        pkg["module_stream"] = json!("8.0");
        assert!(applicable(&r, &os, &pkg).is_none());
        pkg["module_stream"] = json!("7.4");
        pkg["source_package"] = json!("third-party-php");
        assert!(applicable(&r, &os, &pkg).is_none());
        let os = os_release("ID=rocky\nVERSION_ID=8.10\n");
        pkg["source_package"] = json!("php");
        assert!(applicable(&r, &os, &pkg).is_none());
    }
    #[tokio::test]
    async fn serving_binary_package_is_compared_to_vendor_reference() {
        let dir = tempfile::tempdir().unwrap();
        let query = script(
            dir.path(),
            "query",
            r#"case "$1" in
-S) printf 'php8.3-fpm: %s\n' "$2";;
-W) printf 'php8.3-fpm\t8.3.6-0ubuntu0.24.04.13\tphp8.3\t8.3.6-0ubuntu0.24.04.13\tinstalled\n';;
esac"#,
        );
        let policy = script(
            dir.path(),
            "policy",
            r#"printf ' *** 8.3.6-0ubuntu0.24.04.13 500\n 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages\n'"#,
        );
        let mut tools = Tools {
            query: Some(query),
            policy: Some(policy),
            compare: which("dpkg"),
            rpm: None,
        };
        let os = os_release("ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n");
        let pkg = package_for(&tools, "/usr/sbin/php-fpm8.3", &os, &rules()).await;
        assert_eq!(pkg["source_package"], "php8.3");
        if tools.compare.is_some() {
            assert_eq!(pkg["patch_status"], "meets_vendor_reference");
        }
        assert_eq!(pkg["reference_rule"]["independently_verified"], false);
        tools.policy = None;
        let pkg = package_for(&tools, "/usr/sbin/php-fpm8.3", &os, &rules()).await;
        assert_eq!(pkg["patch_status"], "unknown");
        assert_eq!(pkg["origin_status"], "unknown");
    }
    #[tokio::test]
    async fn rpm_source_vendor_architecture_and_separate_version_release_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let rpm = script(
            dir.path(),
            "rpm",
            r#"if [ "$1" = '-qf' ]; then
printf 'php-fpm\t0:7.4.33-8.module+el8.10.0+25117+30337cca\tRed Hat, Inc.\tphp:7.4:123:abcd\tx86_64\tphp-7.4.33-8.module+el8.10.0+25117+30337cca.src.rpm\n'
else
case "$2" in
*"rpm.vercmp('7.4.33','7.4.33')"*"rpm.vercmp('8.module+el8.10.0+25117+30337cca','8.module+el8.10.0+25117+30337cca')"*) printf '0\n';;
*) exit 2;;
esac
fi"#,
        );
        let tools = Tools {
            rpm: Some(rpm),
            ..Default::default()
        };
        let os = os_release("ID=rhel\nVERSION_ID=8.10\n");
        let pkg = package_for(&tools, "/usr/sbin/php-fpm", &os, &rules()).await;
        assert_eq!(pkg["patch_status"], "meets_vendor_reference");
        assert_eq!(pkg["architecture"], "x86_64");
        assert_eq!(pkg["source_package"], "php");
        assert_eq!(pkg["module_stream"], "7.4");
        assert_eq!(pkg["reference_rule"]["independently_verified"], false);
    }
    #[test]
    fn deleted_or_replaced_images_require_restart_and_missing_files_are_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("libphp.so");
        fs::write(&file, "old").unwrap();
        let m = fs::metadata(&file).unwrap();
        let image = Image {
            path: "/libphp.so".into(),
            inode: m.ino(),
            device: Some(linux_device(m.dev())),
            deleted: false,
        };
        assert_eq!(image_state(&image, dir.path()), "matches_disk_image");
        let replacement = dir.path().join("new");
        fs::write(&replacement, "new").unwrap();
        fs::rename(replacement, &file).unwrap();
        assert_eq!(image_state(&image, dir.path()), "restart_required");
        fs::remove_file(file).unwrap();
        assert_eq!(image_state(&image, dir.path()), "unknown");
        let parsed = php_maps(
            "000-111 r-xp 000000 00:00 123 /opt/libphp.so (deleted)\n000-111 r-xp 000000 00:00 124 /opt/libssl.so\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(image_state(&parsed[0], dir.path()), "restart_required");
    }
    #[tokio::test]
    async fn other_namespace_never_uses_host_package_database_or_claims_running_fix() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("123");
        fs::create_dir_all(pid.join("ns")).unwrap();
        fs::create_dir_all(dir.path().join("self/ns")).unwrap();
        fs::write(pid.join("comm"), "php-fpm8.4").unwrap();
        fs::write(pid.join("maps"), "").unwrap();
        fs::write(
            pid.join("stat"),
            format!("123 (php) S {} 42", vec!["0"; 18].join(" ")),
        )
        .unwrap();
        symlink("/bin/sh", pid.join("exe")).unwrap();
        symlink("/", pid.join("root")).unwrap();
        symlink("mnt:[1]", dir.path().join("self/ns/mnt")).unwrap();
        symlink("mnt:[2]", pid.join("ns/mnt")).unwrap();
        let os = dir.path().join("release");
        fs::write(&os, "ID=debian\nVERSION_ID=13\n").unwrap();
        let report = collect_at(dir.path(), &os).await;
        assert_eq!(report["instances"][0]["same_mount_namespace"], false);
        assert_eq!(
            report["instances"][0]["artifacts"][0]["package"]["status"],
            "unknown"
        );
        assert_eq!(
            report["instances"][0]["artifacts"][0]["running_patch_status"],
            "unknown"
        );
        assert_eq!(collect(false).await["status"], "disabled");
    }
}
