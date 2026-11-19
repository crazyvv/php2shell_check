//! Defensive Java4Shell inventory. It never decodes attacker data or runs a PoC.
use regex::Regex;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::LazyLock,
};

pub const CVE: &str = "CVE-2026-114938";
pub const ORACLE_ADVISORY: &str = "https://www.oracle.com/security-alerts/cspunov2026.html";
pub const CVE_RECORD: &str = "https://www.cve.org/CVERecord?id=CVE-2026-114938";
pub const RESEARCH: &str = "https://calif.io/java4shell";
const REQUIRED_CPU_FLAGS: [&str; 4] = ["avx512f", "avx512bw", "avx512vbmi", "bmi2"];
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?im)(?:openjdk|java) version "([^"]+)""#).unwrap());
static BASE64_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*bool\s+UseBASE64Intrinsics\s+(?::=|=)\s+(true|false)\b").unwrap()
});
static AVX_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*(?:int|intx|uint|uintx)\s+UseAVX\s+(?::=|=)\s+([0-9]+)\b").unwrap()
});

fn text_file(path: &Path, limit: u64) -> Option<String> {
    let mut out = String::new();
    File::open(path)
        .ok()?
        .take(limit)
        .read_to_string(&mut out)
        .ok()?;
    Some(out)
}

fn hardware_from(arch: &str, cpuinfo: &str) -> Value {
    if arch != "x86_64" {
        return json!({"status":"not_applicable","arch":arch,"required_flags":REQUIRED_CPU_FLAGS,"observed_flags":[],"missing_flags":REQUIRED_CPU_FLAGS,"detail":"披露的 AVX-512 路径仅适用于 x86-64；迁移节点后需重新核验"});
    }
    let flags = cpuinfo
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "flags").then_some(value)
        })
        .map(|line| line.split_whitespace().collect::<BTreeSet<_>>());
    let Some(flags) = flags else {
        return json!({"status":"unknown","arch":arch,"required_flags":REQUIRED_CPU_FLAGS,"observed_flags":[],"missing_flags":REQUIRED_CPU_FLAGS,"detail":"无法读取当前执行环境可见的 CPU flags"});
    };
    let observed: Vec<_> = REQUIRED_CPU_FLAGS
        .iter()
        .filter(|flag| flags.contains(**flag))
        .copied()
        .collect();
    let missing: Vec<_> = REQUIRED_CPU_FLAGS
        .iter()
        .filter(|flag| !flags.contains(**flag))
        .copied()
        .collect();
    json!({"status":if missing.is_empty(){"eligible"}else{"not_applicable"},"arch":arch,"required_flags":REQUIRED_CPU_FLAGS,"observed_flags":observed,"missing_flags":missing,"detail":if missing.is_empty(){"当前执行环境可见全部必需指令集；仍需结合 JVM 与版本"}else{"当前执行环境缺少必需指令集；节点迁移后需重新核验"}})
}

fn numeric_version(raw: &str) -> Option<Vec<u64>> {
    // Build metadata such as 17.0.21+9 is not the .1 security component.
    let core = raw.split(['+', '-']).next().unwrap_or(raw);
    let values: Vec<u64> = core
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(5)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if values.starts_with(&[1, 8]) {
        Some(
            std::iter::once(8)
                .chain(values.into_iter().skip(2))
                .collect(),
        )
    } else {
        Some(values)
    }
}

fn version_range(raw: &str) -> (&'static str, &'static str) {
    if raw.bytes().all(|c| c.is_ascii_digit()) {
        return ("unknown", "仅有 Java 主版本号，缺少构建证据");
    }
    let Some(parts) = numeric_version(raw) else {
        return ("unknown", "版本格式无法解析");
    };
    let major = parts.first().copied().unwrap_or(0);
    let patch = parts.get(2).copied().unwrap_or(0);
    let security = parts.get(3).copied().unwrap_or(0);
    if major == 8 {
        return (
            "not_in_disclosed_range",
            "普通 Java 8 不在通用披露范围；java -version 不能可靠区分 Oracle 8u511b33-perf，须用供应商库存单独核验",
        );
    }
    if major <= 16 {
        return (
            "not_in_disclosed_range",
            "该版本不在已披露的 17.0.6+ / 18+ 范围",
        );
    }
    if major == 17 {
        if patch < 6 {
            return (
                "not_in_disclosed_range",
                "Java 17.0.0–17.0.5 早于受影响 intrinsic 回补",
            );
        }
        return if patch > 21 || (patch == 21 && security >= 1) {
            (
                "fixed_release",
                "达到公开的首个修复版本 17.0.21.1；仍须核对厂商构建",
            )
        } else {
            ("affected_candidate", "处于公开受影响范围 17.0.6–17.0.21")
        };
    }
    let boundary = match major {
        21 => Some(13),
        25 => Some(5),
        27 => Some(1),
        18..=27 => None,
        _ => {
            return ("unknown", "版本高于当前公告覆盖范围，需核对最新厂商通告");
        }
    };
    if let Some(boundary) = boundary {
        if patch > boundary || (patch == boundary && security >= 1) {
            ("fixed_release", "达到公开的 .1 修复构建；仍须核对厂商构建")
        } else {
            ("affected_candidate", "低于该版本线公开的首个 .1 修复构建")
        }
    } else {
        (
            "affected_candidate_eol",
            "该非 LTS 版本位于披露范围且没有当前支持线修复基线，应升级到受支持版本",
        )
    }
}

fn flag_value<'a>(regex: &Regex, text: &'a str) -> Option<&'a str> {
    regex
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|v| v.as_str())
}

pub fn assess_runtime(version_output: &str, flags_output: &str, hardware: &Value) -> Value {
    let version = VERSION
        .captures(version_output)
        .and_then(|c| c.get(1))
        .map(|v| v.as_str().chars().take(100).collect::<String>());
    let lower = version_output.to_ascii_lowercase();
    let vm = if lower.contains("openj9") || lower.contains("ibm j9") {
        "openj9"
    } else if lower.contains("server vm") || lower.contains("hotspot") || lower.contains("graalvm")
    {
        "hotspot"
    } else {
        "unknown"
    };
    let (range, range_detail) = version
        .as_deref()
        .map(version_range)
        .unwrap_or(("unknown", "未取得 Java 版本"));
    let base64 = flag_value(&BASE64_FLAG, flags_output);
    let base64_enabled = base64.map(|value| value == "true");
    let use_avx = flag_value(&AVX_FLAG, flags_output).and_then(|v| v.parse::<u8>().ok());
    let clean_defaults_mitigated = base64_enabled == Some(false) || use_avx.is_some_and(|v| v <= 2);
    let status = if vm == "openj9" {
        "not_applicable_vm"
    } else if vm == "unknown" || range == "unknown" {
        "unknown"
    } else if matches!(range, "fixed_release" | "not_in_disclosed_range") {
        range
    } else if hardware["status"] == "not_applicable" {
        "not_applicable_hardware"
    } else if hardware["status"] != "eligible" {
        "candidate_hardware_unknown"
    } else if clean_defaults_mitigated {
        "candidate_default_mitigated"
    } else {
        range
    };
    json!({
        "status":status,"version":version,"vm":vm,"version_range":range,
        "version_detail":range_detail,
        "collector_clean_defaults":{"use_base64_intrinsics":base64_enabled,"use_avx":use_avx,"mitigation_observed":clean_defaults_mitigated},
        "detail":match status {
            "not_applicable_vm"=>"OpenJ9/J9 不使用已披露的 HotSpot intrinsic",
            "not_applicable_hardware"=>"当前节点不具备披露路径所需 CPU 条件；迁移后需复核",
            "candidate_hardware_unknown"=>"版本/VM 可能适用，但 CPU 条件未知",
            "candidate_default_mitigated"=>"采集器清洁环境观察到缓解默认值；不能代表运行服务的实际参数",
            "fixed_release"=>"版本达到公开修复基线；厂商回补、运行映像与服务重启仍需核验",
            "not_in_disclosed_range"=>"不在当前披露版本范围；不能据此排除其他 Java 漏洞",
            "affected_candidate"|"affected_candidate_eol"=>"版本、VM 和当前硬件形成候选；尚未确认服务输入路径或可利用性",
            _=>"证据不足，无法判断"
        },
        "patch_verified":false,"exploitability_confirmed":false
    })
}

fn find_java(root: &Path, out: &mut BTreeSet<PathBuf>) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > 5 || visited >= 2048 || out.len() >= 32 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten().take(512) {
            visited += 1;
            let path = entry.path();
            if entry.file_name() == "java"
                && path.parent().is_some_and(|parent| parent.ends_with("bin"))
            {
                if path.is_file() {
                    out.insert(std::fs::canonicalize(&path).unwrap_or(path));
                }
            } else if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                stack.push((path, depth + 1));
            }
        }
    }
}

fn known_process_flags(raw: &[u8]) -> Vec<String> {
    let mut found = BTreeMap::<&str, String>::new();
    for value in raw
        .split(|byte| *byte == 0)
        .filter_map(|value| std::str::from_utf8(value).ok())
    {
        for (key, prefix) in [
            ("UseBASE64Intrinsics", "-XX:"),
            ("UseAVX", "-XX:UseAVX="),
            ("TieredStopAtLevel", "-XX:TieredStopAtLevel="),
        ] {
            if (key == "UseBASE64Intrinsics"
                && matches!(
                    value,
                    "-XX:-UseBASE64Intrinsics" | "-XX:+UseBASE64Intrinsics"
                ))
                || (key != "UseBASE64Intrinsics" && value.starts_with(prefix))
            {
                found.insert(key, value.chars().take(80).collect());
            }
        }
        if value == "-Xint" {
            found.insert("execution_mode", value.into());
        }
    }
    found.into_values().collect()
}

fn processes(proc_root: &Path, binaries: &mut BTreeSet<PathBuf>) -> Vec<Value> {
    let mut out = vec![];
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        if out.len() >= 128 {
            break;
        }
        let pid = entry.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let dir = entry.path();
        let name = std::fs::read_to_string(dir.join("comm"))
            .unwrap_or_default()
            .trim()
            .chars()
            .take(100)
            .collect::<String>();
        let maps = text_file(&dir.join("maps"), 262_144);
        let jvm_loaded = maps.as_deref().is_some_and(|maps| {
            maps.lines()
                .any(|line| line.contains("libjvm.so") || line.contains("libjvm.dylib"))
        });
        if !jvm_loaded && !name.to_ascii_lowercase().contains("java") {
            continue;
        }
        let exe = std::fs::read_link(dir.join("exe")).ok();
        if exe
            .as_ref()
            .is_some_and(|path| path.file_name().is_some_and(|name| name == "java"))
            && let Some(path) = &exe
        {
            binaries.insert(std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()));
        }
        let cmdline = std::fs::read(dir.join("cmdline")).unwrap_or_default();
        let flags = known_process_flags(&cmdline[..cmdline.len().min(65_536)]);
        out.push(json!({"pid":pid,"name":name,"executable":exe,"jvm_library_loaded":jvm_loaded,"known_command_line_flags":flags,"flag_scope":"仅保留 Java4Shell 相关参数；其他参数不保存，进程环境不读取","effective_flags_complete":false}));
    }
    out
}

#[derive(Default, Serialize)]
pub(crate) struct Release {
    pub(crate) version: Option<String>,
    pub(crate) full_build: Option<String>,
    pub(crate) vendor: Option<String>,
    pub(crate) vendor_version: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) graalvm_version: Option<String>,
}

pub(crate) fn release(data: &str) -> Release {
    let fields: BTreeMap<_, _> = data
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = value.trim().trim_matches('"');
            (!value.is_empty() && value.len() <= 256).then_some((key, value))
        })
        .collect();
    let get = |key| fields.get(key).map(|value| (*value).to_owned());
    let version = get("JAVA_VERSION");
    let full_build = get("JAVA_RUNTIME_VERSION")
        .or_else(|| get("FULL_VERSION"))
        .or_else(|| version.clone())
        .filter(|value| value.contains('+') || value.contains("-b") || value.contains("-perf"));
    let graalvm_version = get("GRAALVM_VERSION");
    let edition = get("GRAALVM_EDITION")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let product = if edition.contains("enterprise edition")
        || (edition == "ee"
            && graalvm_version
                .as_deref()
                .is_some_and(|v| v.starts_with("21.3.")))
    {
        Some("Oracle GraalVM Enterprise Edition".into())
    } else if graalvm_version.is_some() {
        Some("GraalVM".into())
    } else {
        get("JAVA_VM_NAME")
    };
    Release {
        version,
        full_build,
        vendor: get("IMPLEMENTOR"),
        vendor_version: get("IMPLEMENTOR_VERSION"),
        product,
        graalvm_version,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BuildStatus {
    Affected,
    NotAffected,
    Unknown,
}

pub(crate) fn build_status(r: &Release) -> BuildStatus {
    use BuildStatus::*;
    let vendor = r.vendor.as_deref().unwrap_or_default();
    let vendor_version = r.vendor_version.as_deref().unwrap_or_default();
    if r.product.as_deref().is_some_and(|p| p.contains("OpenJ9")) {
        return NotAffected;
    }
    if vendor == "Oracle Corporation"
        && r.product.as_deref() == Some("Oracle GraalVM Enterprise Edition")
        && r.graalvm_version.as_deref().or(r.version.as_deref()) == Some("21.3.20.0.3")
    {
        return Affected;
    }
    if r.product
        .as_deref()
        .is_some_and(|p| p.contains("GraalVM") || p.contains("OpenJ9"))
        || vendor_version.contains("GraalVM")
    {
        return Unknown;
    }
    static STANDARD_JAVA_8: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(?:1\.8\.0_|8u)([0-9]+)(?:-?b[0-9]+)?$").unwrap());
    let standard_openjdk8 = matches!(
        vendor.to_ascii_lowercase().as_str(),
        "openjdk"
            | "debian"
            | "ubuntu"
            | "canonical"
            | "eclipse adoptium"
            | "temurin"
            | "amazon.com inc."
            | "amazon.com inc"
            | "azul systems, inc."
            | "azul"
            | "red hat, inc."
            | "red hat"
    );
    if let Some(update) = r
        .full_build
        .as_deref()
        .or(r.version.as_deref())
        .and_then(|v| STANDARD_JAVA_8.captures(v))
        .and_then(|caps| caps.get(1)?.as_str().parse::<u32>().ok())
        && (standard_openjdk8 || (vendor == "Oracle Corporation" && update < 511))
    {
        return NotAffected;
    }
    let Some(full) = r.full_build.as_deref() else {
        return Unknown;
    };
    if vendor == "Oracle Corporation" {
        match full {
            "1.8.0_511-perf-b33" => return Affected,
            "1.8.0_513-perf-b4" | "1.8.0_513-perf-b04" => return NotAffected,
            _ => {}
        }
    }
    let Some((version, build)) = full.split_once('+') else {
        return Unknown;
    };
    let Ok(build) = build.split('-').next().unwrap_or_default().parse::<u32>() else {
        return Unknown;
    };
    let Ok(numbers) = version
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return Unknown;
    };
    let [major, minor, update, extra, ..] = {
        let mut padded = [0; 5];
        if numbers.len() > padded.len() {
            return Unknown;
        }
        padded[..numbers.len()].copy_from_slice(&numbers);
        padded
    };
    let (first, last) = match major {
        17 => (6, 21),
        21 => (0, 13),
        25 => (0, 5),
        27 => (0, 1),
        _ => return Unknown,
    };
    if minor != 0 {
        return Unknown;
    }
    let oracle = vendor == "Oracle Corporation";
    let corretto = vendor == "Amazon.com Inc.";
    let known_openjdk = matches!(vendor, "OpenJDK" | "Eclipse Adoptium");
    if !(oracle || corretto || known_openjdk) {
        return Unknown;
    }
    if update < first {
        return NotAffected;
    }
    if major == 17 && update == 6 && extra == 0 && build < 10 {
        return Unknown;
    }
    if oracle && full == "17.0.21.0.3+1" {
        return Affected;
    }
    if update < last || (update == last && numbers.len() <= 3) {
        return Affected;
    }
    // Oracle's November CSPU release notes identify +4 for each of these lines.
    if oracle && numbers.len() == 4 && update == last && extra == 1 && build == 4 {
        return NotAffected;
    }
    if vendor == "OpenJDK"
        && numbers.len() == 4
        && update == last
        && extra == 1
        && build == if major == 27 { 4 } else { 2 }
    {
        return NotAffected;
    }
    if corretto && numbers.len() == 4 {
        let fixed_build = if major == 27 { 4 } else { 2 };
        let vendor_build = vendor_version
            .strip_prefix("Corretto-")
            .unwrap_or(vendor_version);
        let fixed = format!("{major}.0.{last}.1.{fixed_build}");
        if update == last && extra == 1 && vendor_build == fixed && build == fixed_build {
            return NotAffected;
        }
    }
    Unknown
}

#[derive(Default, Serialize)]
pub(crate) struct Flags {
    #[serde(rename = "UseBASE64Intrinsics")]
    pub(crate) use_base64_intrinsics: Option<bool>,
    #[serde(rename = "UseAVX")]
    pub(crate) use_avx: Option<u32>,
}

pub(crate) fn decision(
    build: BuildStatus,
    cpu: Option<bool>,
    flags: &Flags,
) -> (&'static str, &'static str) {
    if build == BuildStatus::NotAffected || cpu == Some(false) {
        return ("not_affected", "excluded_build_or_cpu");
    }
    if (build == BuildStatus::Affected || cpu == Some(true))
        && (flags.use_base64_intrinsics == Some(false) || flags.use_avx.is_some_and(|avx| avx <= 2))
    {
        return ("mitigated", "effective_vm_flags");
    }
    if build == BuildStatus::Affected
        && cpu == Some(true)
        && flags.use_base64_intrinsics == Some(true)
        && flags.use_avx == Some(3)
    {
        return ("affected", "build_cpu_and_effective_vm_flags");
    }
    ("unknown", "incomplete_or_conflicting_evidence")
}

pub async fn launcher_gate(path: &Path) -> Value {
    let command = crate::collector::run_clean_java(path, &["-version"]).await;
    let output = command["output"].as_str().unwrap_or_default();
    let mut metadata = path
        .parent()
        .and_then(Path::parent)
        .and_then(|home| text_file(&home.join("release"), 65_536))
        .map(|data| release(&data))
        .unwrap_or_default();
    let banner = VERSION
        .captures(output)
        .and_then(|caps| caps.get(1))
        .map(|v| v.as_str());
    let build = output
        .lines()
        .filter(|line| line.contains("Runtime Environment"))
        .find_map(|line| {
            line.split_once("(build ")?
                .1
                .split(|c: char| c == ')' || c == ',' || c.is_whitespace())
                .next()
        })
        .filter(|value| !value.is_empty() && value.len() <= 128);
    let conflicting = banner
        .zip(metadata.version.as_deref())
        .is_some_and(|(running, disk)| running != disk)
        || build
            .zip(metadata.full_build.as_deref())
            .is_some_and(|(running, disk)| running != disk);
    metadata.version = banner.map(str::to_owned);
    metadata.full_build = build
        .filter(|value| value.contains('+') || value.contains("-perf"))
        .map(str::to_owned);
    let lower = output.to_ascii_lowercase();
    if lower.contains("openj9") || lower.contains("ibm j9") {
        metadata.product = Some("OpenJ9".into());
    }
    let status = if command["exit_code"] == 0 && !conflicting && banner.is_some() {
        build_status(&metadata)
    } else {
        BuildStatus::Unknown
    };
    let (verdict, reason) = match status {
        BuildStatus::NotAffected => ("not_affected", "excluded_build"),
        BuildStatus::Affected => ("potential", "version_gate_only"),
        BuildStatus::Unknown if conflicting => {
            ("unknown", "launcher_version_conflicts_with_release")
        }
        BuildStatus::Unknown => ("unknown", "insufficient_launcher_build_evidence"),
    };
    json!({"kind":"java-binary","binary":path,"version":metadata.full_build.as_ref().or(metadata.version.as_ref()),
        "build_status":status,"status":verdict,"reason":reason,"vendor":metadata.vendor,"product":metadata.product,
        "flag_source":"unavailable","effective_flags_complete":false,"command_exit_code":command["exit_code"]})
}

pub fn demo_report() -> Value {
    let enabled = Flags {
        use_base64_intrinsics: Some(true),
        use_avx: Some(3),
    };
    let disabled = Flags {
        use_base64_intrinsics: Some(false),
        use_avx: Some(3),
    };
    let mut findings = Vec::new();
    for (name, full, cpu, flags, expected) in [
        ("affected", "17.0.21+9", true, &enabled, "affected"),
        ("fixed", "21.0.13.1+2", true, &enabled, "not_affected"),
        ("boundary_build", "17.0.6+10", true, &enabled, "affected"),
        ("mitigated", "17.0.21+9", true, &disabled, "mitigated"),
        ("cpu_excluded", "17.0.21+9", false, &enabled, "not_affected"),
        ("build_gap", "17.0.21.0.4+2", true, &enabled, "unknown"),
    ] {
        let build = build_status(&Release {
            full_build: Some(full.into()),
            vendor: Some("OpenJDK".into()),
            ..Release::default()
        });
        let (status, reason) = decision(build, Some(cpu), flags);
        findings.push(json!({"name":name,"version":full,"expected":expected,"status":status,"reason":reason,"passed":status==expected}));
    }
    let passed = findings.iter().filter(|row| row["passed"] == true).count();
    json!({"scope":"synthetic_java_demo","java4shell":{"cve":CVE,"demo":findings},
        "audit":{"demo_passed":passed==findings.len(),"passed":passed,"total":findings.len()}})
}

pub(crate) fn application_inventory(root: &Path, depth: usize) -> Value {
    const PRODUCTS: [(&str, &str); 11] = [
        ("keycloak", "Keycloak"),
        ("jira", "Atlassian Jira"),
        ("confluence", "Atlassian Confluence"),
        ("artifactory", "JFrog Artifactory"),
        ("jenkins", "Jenkins"),
        ("pingfederate", "PingFederate"),
        ("kafka", "Apache Kafka Broker"),
        ("solr", "Apache Solr"),
        ("elasticsearch", "Elasticsearch"),
        ("gerrit", "Gerrit"),
        ("spinnaker", "Spinnaker"),
    ];
    let mut pending = vec![(root.to_path_buf(), 0)];
    let mut findings = Vec::new();
    let mut incomplete = !root.is_dir();
    let mut remaining = 4096;
    'scan: while let Some((path, level)) = pending.pop() {
        if level > 0 {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase()
                .replace(['-', '_'], "");
            if let Some((_, label)) = PRODUCTS.iter().find(|(key, _)| name.contains(key)) {
                findings.push(json!({"product":label,"path":path,"status":"directory_name_hint"}));
                if findings.len() == 128 {
                    incomplete = true;
                    break;
                }
            }
        }
        if level >= depth {
            continue;
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => {
                incomplete = true;
                continue;
            }
        };
        for entry in entries {
            if remaining == 0 {
                incomplete = true;
                break 'scan;
            }
            remaining -= 1;
            let Ok(entry) = entry else {
                incomplete = true;
                continue;
            };
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push((entry.path(), level + 1)),
                Ok(_) => {}
                Err(_) => incomplete = true,
            }
        }
    }
    json!({"scope":"directory_name_hints","coverage_incomplete":incomplete,"findings":findings,"max_depth":depth})
}

#[cfg(target_os = "macos")]
pub async fn collect_macos(options: &crate::collector::CollectOptions) -> Value {
    let mut java = if let Some(path) = &options.java_path {
        let row = launcher_gate(path).await;
        let code = match row["status"].as_str() {
            Some("potential") => 1,
            Some("not_affected") => 0,
            _ => 3,
        };
        return json!({"schema":"php-selfcheck-host/v1","source":"developer_supplied_unverified","platform":"macos",
            "java4shell":{"status":"collected","cve":CVE,"runtimes":[row]},
            "audit":{"risk_gate_hit":code==1,"evidence_incomplete":code==3,"exit_codes":{"java4shell":code}}});
    } else if options.java_processes_only {
        json!({"status":"collected","scope":"launcher_only_macos","cve":CVE})
    } else {
        collect(true).await
    };
    let mut launchers = Vec::new();
    if !options.java_no_processes {
        let command =
            crate::collector::run_clean_java(Path::new("/bin/ps"), &["-axo", "pid=,comm="]).await;
        for line in command["output"].as_str().unwrap_or_default().lines() {
            if launchers.len() >= 128 {
                break;
            }
            let Some((pid, executable)) = line.trim().split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(pid) = pid.parse::<u32>() else {
                continue;
            };
            let executable = executable.trim();
            if !options.java_pid.is_empty() && !options.java_pid.contains(&pid) {
                continue;
            }
            if Path::new(executable)
                .file_name()
                .is_some_and(|name| name == "java")
            {
                launchers.push(json!({"pid":pid,"path":executable,"status":"unknown","reason":"launcher_only_macos"}));
            }
        }
    }
    if options.java_processes_only {
        java["runtimes"] = json!([]);
    }
    java["runtime_audit"] = json!({"processes":launchers,"coverage":{"scope":"launcher_only_macos","process_scan_enabled":!options.java_no_processes}});
    if let Some(path) = &options.java_apps {
        java["applications"] = application_inventory(path, options.java_apps_depth.unwrap_or(3));
    }
    json!({"schema":"php-selfcheck-host/v1","source":"developer_supplied_unverified",
        "platform":format!("macos {}",std::env::consts::ARCH),"java4shell":java,
        "audit":{"risk_gate_hit":false,"evidence_incomplete":true,"exit_codes":{"java4shell":3}}})
}

pub fn format_audit(
    report: &Value,
    format: crate::collector::CollectFormat,
) -> anyhow::Result<String> {
    use crate::collector::CollectFormat;
    let java = &report["java4shell"];
    if matches!(format, CollectFormat::Json) {
        return Ok(serde_json::to_string_pretty(report)?);
    }
    let mut csv = csv::Writer::from_writer(Vec::new());
    let mut text = String::from("Java4Shell 主机报告\n");
    let cols = [
        "kind",
        "pid",
        "path",
        "version",
        "status",
        "reason",
        "flag_source",
    ];
    if matches!(format, CollectFormat::Csv) {
        csv.write_record(cols)?;
    }
    for (kind, rows) in [
        ("process", &java["runtime_audit"]["processes"]),
        ("installation", &java["runtime_audit"]["installations"]),
        ("launcher", &java["runtimes"]),
        ("demo", &java["demo"]),
        ("application", &java["applications"]["findings"]),
    ] {
        for row in rows.as_array().into_iter().flatten() {
            let pid = row["pid"]
                .as_u64()
                .map(|n| n.to_string())
                .unwrap_or_default();
            let path = row["installation"]["home"]
                .as_str()
                .or(row["path"].as_str())
                .or(row["binary"].as_str())
                .unwrap_or("");
            let version = row["runtime_build"]
                .as_str()
                .or(row["installation"]["release"]["full_build"].as_str())
                .or(row["version"].as_str())
                .unwrap_or("");
            let status = row["status"].as_str().unwrap_or("unknown");
            let reason = row["name"]
                .as_str()
                .or(row["reason"].as_str())
                .or(row["product"].as_str())
                .unwrap_or("");
            let source = row["flag_source"].as_str().unwrap_or("");
            if matches!(format, CollectFormat::Csv) {
                csv.write_record([kind, &pid, path, version, status, reason, source].map(
                    |field| {
                        if field.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) {
                            format!("'{field}")
                        } else {
                            field.to_owned()
                        }
                    },
                ))?;
            } else {
                use std::fmt::Write;
                writeln!(
                    text,
                    "{kind} · {pid} {path:?} {version} · {status} · {reason} · {source}"
                )?;
            }
        }
    }
    if matches!(format, CollectFormat::Csv) {
        return Ok(String::from_utf8(csv.into_inner()?)?);
    }
    use std::fmt::Write;
    writeln!(text, "覆盖与门禁 · {}", report["audit"])?;
    Ok(text)
}

pub async fn collect(enabled: bool) -> Value {
    if !enabled {
        return json!({"status":"disabled","cve":CVE,"detail":"需显式启用 --java-command；未运行 Java 命令或主机核验"});
    }
    let cpuinfo = text_file(Path::new("/proc/cpuinfo"), 2_097_152).unwrap_or_default();
    let hardware = hardware_from(std::env::consts::ARCH, &cpuinfo);
    let mut binaries = BTreeSet::new();
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("JAVA_HOME") {
            let path = std::path::PathBuf::from(home).join("bin/java");
            if path.is_file() {
                binaries.insert(path);
            }
        }
        find_java(
            Path::new("/Library/Java/JavaVirtualMachines"),
            &mut binaries,
        );
    }
    if let Some(path) = crate::collector::which("java") {
        binaries.insert(std::fs::canonicalize(&path).unwrap_or(path));
    }
    for root in ["/usr/lib/jvm", "/usr/java", "/opt/java", "/opt/jdk"] {
        find_java(Path::new(root), &mut binaries);
    }
    let running_processes = processes(Path::new("/proc"), &mut binaries);
    let mut runtimes = vec![];
    for exe in binaries.into_iter().take(16) {
        let version = crate::collector::run_clean_java(&exe, &["-version"]).await;
        let flags =
            crate::collector::run_clean_java(&exe, &["-XX:+PrintFlagsFinal", "-version"]).await;
        let version_output = version["output"].as_str().unwrap_or("");
        let flags_output = flags["output"].as_str().unwrap_or("");
        let mut assessment = assess_runtime(version_output, flags_output, &hardware);
        assessment["binary"] = json!(exe);
        assessment["version_command_status"] = if version["exit_code"] == 0 {
            json!("completed")
        } else {
            json!("failed")
        };
        assessment["version_banner"] = json!(
            version_output
                .lines()
                .take(4)
                .collect::<Vec<_>>()
                .join("\n")
                .chars()
                .take(1000)
                .collect::<String>()
        );
        runtimes.push(assessment);
    }
    let any_candidate = runtimes.iter().any(|runtime| {
        runtime["status"].as_str().is_some_and(|status| {
            status.starts_with("affected_candidate") || status.starts_with("candidate_")
        })
    });
    let unknown = runtimes
        .iter()
        .any(|runtime| runtime["status"] == "unknown");
    json!({
        "status":if any_candidate{"candidate_found"}else if runtimes.is_empty(){"no_runtime_found"}else if unknown{"unknown"}else{"no_candidate_in_discovered_scope"},
        "cve":CVE,"hardware":hardware,"runtimes":runtimes,"running_processes":running_processes,
        "sources":[ORACLE_ADVISORY,CVE_RECORD,RESEARCH],"source_snapshot_date":"2026-11-18",
        "checks":{"malformed_base64_sent":false,"poc_executed":false,"process_attached":false,"process_environment_read":false},
        "limitations":["只覆盖当前命名空间可见的标准目录、最多 16 个 Java 程序和 128 个 JVM 进程；容器与镜像须逐个采集。","采集器清洁环境中的 JVM 默认值不等于服务进程实际参数；进程环境、参数文件和后置覆盖未读取。","网页产品指纹、Java 版本或 CPU 条件均不能单独确认漏洞；厂商回补、输入路径与服务重启仍需核验。","当前节点缺少 CPU 指令集只说明当前放置不适用，迁移到其他节点后必须重新检查。"]
    })
}

pub fn remote(fingerprints: &Value) -> Value {
    let products: Vec<_> = fingerprints["matches"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| hit["runtime_hint"] == "java" && hit["relation"] == "response")
        .take(16)
        .map(|hit| json!({"id":hit["id"],"name":hit["name"],"versions":hit["versions"],"confidence":hit["confidence"]}))
        .collect();
    json!({
        "cve":CVE,"status":if products.is_empty(){"not_observed"}else{"java_product_hint"},"products":products,
        "confidence":if products.is_empty(){"none"}else{"low"},"source":"passive_http_fingerprint",
        "detail":if products.is_empty(){"当前响应未命中 Java 产品特征；不能排除 Java"}else{"响应命中 Java 产品线索；无法从 HTTP 确认 JVM build、VM 类型、CPU 指令集、启动参数或可达解码路径"},
        "required_evidence":["实际运行 JVM 厂商与完整 build","HotSpot/GraalVM 或 OpenJ9/J9","当前节点 x86-64 与 AVX-512 VBMI/BW/F/BMI2","运行服务的 UseBASE64Intrinsics、UseAVX 与 JIT 状态","外部输入是否到达 java.util.Base64 basic/URL decoder","升级后全部实例与容器已重启"],
        "safe_probe":{"http_requests_added":0,"malformed_base64_sent":false,"poc_executed":false},
        "patch_verified":false,"exploitability_confirmed":false,"sources":[ORACLE_ADVISORY,CVE_RECORD,RESEARCH]
    })
}

fn bounded_string(value: &Value, max: usize) -> Value {
    value
        .as_str()
        .map(|value| Value::String(value.chars().take(max).collect()))
        .unwrap_or(Value::Null)
}

fn bounded_strings(value: &Value, count: usize, width: usize) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(count)
        .map(|value| value.chars().take(width).collect())
        .collect()
}

pub fn sanitize_host(raw: &Value) -> Value {
    let runtimes = raw["runtimes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|value| value.is_object())
        .take(32)
        .map(|runtime| {
            let defaults = &runtime["collector_clean_defaults"];
            json!({
                "status":bounded_string(&runtime["status"], 80),
                "version":bounded_string(&runtime["version"], 100),
                "vm":bounded_string(&runtime["vm"], 40),
                "version_range":bounded_string(&runtime["version_range"], 80),
                "version_detail":bounded_string(&runtime["version_detail"], 500),
                "detail":bounded_string(&runtime["detail"], 500),
                "binary":bounded_string(&runtime["binary"], 500),
                "version_command_status":bounded_string(&runtime["version_command_status"], 40),
                "version_banner":bounded_string(&runtime["version_banner"], 1000),
                "collector_clean_defaults":{
                    "use_base64_intrinsics":defaults["use_base64_intrinsics"].as_bool(),
                    "use_avx":defaults["use_avx"].as_u64(),
                    "mitigation_observed":defaults["mitigation_observed"].as_bool()
                },
                "patch_verified":false,
                "exploitability_confirmed":false
            })
        })
        .collect::<Vec<_>>();
    let processes = raw["running_processes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|value| value.is_object())
        .take(128)
        .map(|process| json!({
            "pid":bounded_string(&process["pid"], 20),
            "name":bounded_string(&process["name"], 100),
            "executable":bounded_string(&process["executable"], 500),
            "jvm_library_loaded":process["jvm_library_loaded"].as_bool(),
            "known_command_line_flags":bounded_strings(&process["known_command_line_flags"], 16, 80),
            "flag_scope":"仅保留 Java4Shell 相关参数；导入材料未经服务器独立验证",
            "effective_flags_complete":false
        }))
        .collect::<Vec<_>>();
    let audit = &raw["runtime_audit"];
    let audit_processes: Vec<_> = audit["processes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item.is_object())
        .take(48)
        .map(|item| {
            let flags = &item["effective_flags"];
            let mappings: Vec<_> = item["mappings"]
                .as_array()
                .into_iter()
                .flatten()
                .take(4)
                .map(|m| {
                    let release = &m["disk_evidence"]["release"];
                    json!({"identity_source":bounded_string(&m["identity_source"],32),
                    "disk_identity_matched":m["disk_identity_matched"].as_bool(),
                    "disk_evidence":{"full_build":bounded_string(&release["full_build"],128),
                        "vendor":bounded_string(&release["vendor"],128),
                        "product":bounded_string(&release["product"],128),
                        "build_status":bounded_string(&m["disk_evidence"]["build_status"],32)}})
                })
                .collect();
            json!({"pid":item["pid"].as_u64(),"status":bounded_string(&item["status"],40),
                "runtime_build":bounded_string(&item["runtime_build"],128),
                "flag_status":bounded_string(&item["flag_status"],40),
                "flag_source":item["flag_source"].as_str().filter(|source| matches!(*source,"startup_arguments_estimated"|"jcmd VM.flags -all"|"unavailable")),
                "estimated_startup_flags":{"UseBASE64Intrinsics":item["estimated_startup_flags"]["UseBASE64Intrinsics"].as_bool(),
                    "UseAVX":item["estimated_startup_flags"]["UseAVX"].as_u64()},
                "effective_flags":{"UseBASE64Intrinsics":flags["UseBASE64Intrinsics"].as_bool(),
                    "UseAVX":flags["UseAVX"].as_u64()},"mappings":mappings})
        })
        .collect();

    let hardware = &raw["hardware"];
    json!({
        "status":bounded_string(&raw["status"], 80),
        "cve":CVE,
        "hardware":{
            "status":bounded_string(&hardware["status"], 80),
            "arch":bounded_string(&hardware["arch"], 40),
            "required_flags":bounded_strings(&hardware["required_flags"], 16, 40),
            "observed_flags":bounded_strings(&hardware["observed_flags"], 16, 40),
            "missing_flags":bounded_strings(&hardware["missing_flags"], 16, 40),
            "detail":bounded_string(&hardware["detail"], 500)
        },
        "runtimes":runtimes,
        "running_processes":processes,
        "runtime_audit":{"processes":audit_processes,"cpu":{"manual_review":audit["cpu"]["manual_review"].as_bool()}},
        "checks":{
            "malformed_base64_sent":false,
            "poc_executed":false,
            "process_attached":false,
            "process_environment_read":false
        },
        "limitations":bounded_strings(&raw["limitations"], 16, 1000),
        "confidence":"unverified",
        "source":"developer_supplied_host_report",
        "patch_verified":false,
        "exploitability_confirmed":false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_cpu_vm_and_mitigation_are_separate() {
        let eligible = hardware_from("x86_64", "flags : avx512f avx512bw avx512vbmi bmi2 sse2\n");
        let vulnerable = assess_runtime(
            "openjdk version \"17.0.21\"\nOpenJDK 64-Bit Server VM",
            " bool UseBASE64Intrinsics = true\n intx UseAVX = 3\n",
            &eligible,
        );
        assert_eq!(vulnerable["status"], "affected_candidate");
        assert_eq!(vulnerable["exploitability_confirmed"], false);
        let fixed = assess_runtime(
            "openjdk version \"17.0.21.1\"\nOpenJDK 64-Bit Server VM",
            " bool UseBASE64Intrinsics = true\n intx UseAVX = 3\n",
            &eligible,
        );
        assert_eq!(fixed["status"], "fixed_release");
        let build_metadata = assess_runtime(
            "openjdk version \"17.0.21+9\"\nOpenJDK 64-Bit Server VM",
            " bool UseBASE64Intrinsics = true\n intx UseAVX = 3\n",
            &eligible,
        );
        assert_eq!(build_metadata["status"], "affected_candidate");
        let generic_java_8 = assess_runtime(
            "java version \"1.8.0_511\"\nJava HotSpot(TM) 64-Bit Server VM (build 25.511-b33)",
            " bool UseBASE64Intrinsics = true\n intx UseAVX = 3\n",
            &eligible,
        );
        assert_eq!(generic_java_8["status"], "not_in_disclosed_range");
        assert!(
            generic_java_8["version_detail"]
                .as_str()
                .unwrap()
                .contains("perf")
        );
        let mitigated = assess_runtime(
            "openjdk version \"21.0.13\"\nOpenJDK 64-Bit Server VM",
            " bool UseBASE64Intrinsics = false\n intx UseAVX = 3\n",
            &eligible,
        );
        assert_eq!(mitigated["status"], "candidate_default_mitigated");
    }

    #[test]
    fn openj9_and_missing_hardware_do_not_become_vulnerable() {
        let eligible = hardware_from("x86_64", "flags : avx512f avx512bw avx512vbmi bmi2\n");
        let openj9 = assess_runtime(
            "openjdk version \"21.0.12\"\nEclipse OpenJ9 VM",
            "",
            &eligible,
        );
        assert_eq!(openj9["status"], "not_applicable_vm");
        let ineligible = hardware_from("x86_64", "flags : avx2 bmi2\n");
        let candidate = assess_runtime(
            "openjdk version \"21.0.12\"\nOpenJDK 64-Bit Server VM",
            "",
            &ineligible,
        );
        assert_eq!(candidate["status"], "not_applicable_hardware");
    }

    #[test]
    fn remote_fingerprints_never_confirm_exposure() {
        let result = remote(
            &json!({"matches":[{"id":"java-jenkins","name":"Jenkins","runtime_hint":"java","relation":"response","versions":[],"confidence":"medium"}]}),
        );
        assert_eq!(result["status"], "java_product_hint");
        assert_eq!(result["safe_probe"]["http_requests_added"], 0);
        assert_eq!(result["exploitability_confirmed"], false);
    }

    #[test]
    fn imported_host_evidence_is_bounded_and_never_trusted() {
        let result = sanitize_host(&json!({
            "status":"candidate_found",
            "hardware":{"status":"eligible","arch":"x86_64","observed_flags":["avx512f"]},
            "runtimes":[{"status":"affected_candidate","version":"17.0.21","patch_verified":true,"exploitability_confirmed":true,"unexpected":{"payload":"ignored"}}],
            "running_processes":[{"pid":"42","name":"java","known_command_line_flags":["-XX:UseAVX=3"],"secret":"ignored"}],
            "checks":{"poc_executed":true}
        }));
        assert_eq!(result["runtimes"][0]["patch_verified"], false);
        assert_eq!(result["runtimes"][0]["exploitability_confirmed"], false);
        assert!(result["runtimes"][0].get("unexpected").is_none());
        assert!(result["running_processes"][0].get("secret").is_none());
        assert_eq!(result["checks"]["poc_executed"], false);
        assert_eq!(result["confidence"], "unverified");
    }
}
