//! Local evidence for CVE-2026-114938.
use crate::collector::{run_clean_java, which};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

const FEATURES: [&str; 4] = ["avx512f", "avx512bw", "avx512vbmi", "bmi2"];
const ORACLE: &str = "https://www.oracle.com/security-alerts/cspunov2026.html";
const UPSTREAM: &str = "https://openjdk.org/groups/vulnerability/advisories/2026-11-17";
const DISCLOSURE: &str = "https://calif.io/java4shell/";
const ROOTS: [&str; 8] = [
    "/usr/lib/jvm",
    "/usr/lib64/jvm",
    "/usr/java",
    "/usr/local/lib/jvm",
    "/usr/local/java",
    "/opt",
    "/srv",
    "/app",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct FileId {
    device_major: u64,
    device_minor: u64,
    inode: u64,
}

fn file_id(meta: &fs::Metadata) -> FileId {
    let (device_major, device_minor) = crate::hostaudit::linux_device(meta.dev());
    FileId {
        device_major,
        device_minor,
        inode: meta.ino(),
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct Mapping {
    path: String,
    range: String,
    id: FileId,
    deleted: bool,
}

fn parse_mapping(line: &str) -> Option<Mapping> {
    // The first five fields contain no spaces. Preserve spaces within the path.
    let mut tail = line;
    let mut fields = [""; 5];
    for field in &mut fields {
        tail = tail.trim_start();
        let end = tail.find(char::is_whitespace)?;
        (*field, tail) = tail.split_at(end);
    }
    let path = tail.trim_start();
    let deleted = path.ends_with(" (deleted)");
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    if !path.starts_with('/') || !path.ends_with("/libjvm.so") {
        return None;
    }
    let (major, minor) = fields[3].split_once(':')?;
    let inode = fields[4].parse().ok()?;
    (inode != 0).then_some(Mapping {
        path: path.into(),
        range: fields[0].into(),
        id: FileId {
            device_major: u64::from_str_radix(major, 16).ok()?,
            device_minor: u64::from_str_radix(minor, 16).ok()?,
            inode,
        },
        deleted,
    })
}

fn mappings(proc_dir: &Path) -> io::Result<BTreeSet<Mapping>> {
    let mut reader = BufReader::new(File::open(proc_dir.join("maps"))?.take(8 * 1024 * 1024));
    let mut line = Vec::new();
    let mut found: BTreeSet<Mapping> = BTreeSet::new();
    while reader.read_until(b'\n', &mut line)? != 0 {
        if let Ok(line) = std::str::from_utf8(&line)
            && let Some(mapping) = parse_mapping(line.trim_end_matches('\n'))
        {
            if !found.iter().any(|item| {
                item.path == mapping.path
                    && item.id == mapping.id
                    && item.deleted == mapping.deleted
            }) {
                if found.len() >= 32 {
                    return Err(io::Error::other("mapping_count_limit"));
                }
                found.insert(mapping);
            }
        }
        line.clear();
    }
    if reader.get_ref().limit() == 0 {
        return Err(io::Error::other("maps_size_limit"));
    }
    Ok(found)
}

fn mapped_disk_id(proc_dir: &Path, mapping: &Mapping) -> Option<(FileId, &'static str)> {
    if mapping.deleted {
        return None;
    }
    let path = Path::new(&mapping.path).strip_prefix("/").ok()?;
    let disk = file_id(&fs::metadata(proc_dir.join("root").join(path)).ok()?);
    if disk == mapping.id {
        Some((disk, "maps"))
    } else if disk.inode == mapping.id.inode {
        let (start, end) = mapping.range.split_once('-')?;
        if ![start, end]
            .into_iter()
            .all(|part| !part.is_empty() && part.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return None;
        }
        let actual = fs::metadata(proc_dir.join("map_files").join(&mapping.range)).ok()?;
        (file_id(&actual) == disk).then_some((disk, "map_files"))
    } else {
        None
    }
}

fn reported_build(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let (_, tail) = line.split_once(" VM version ")?;
        let token = tail.split_whitespace().next()?;
        let (version, build) = token.split_once('+')?;
        (version.starts_with(|c: char| c.is_ascii_digit())
            && build.starts_with(|c: char| c.is_ascii_digit())
            && token.len() <= 128
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._+-~".contains(&c)))
        .then_some(token)
    })
}

fn build_conflicts(runtime: &str, disk: &str) -> bool {
    if disk.contains('+') {
        !runtime.eq_ignore_ascii_case(disk)
    } else {
        runtime.split_once('+').is_some_and(|(v, _)| v != disk)
    }
}

pub(crate) fn start_time(proc_dir: &Path) -> Option<u64> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    // Field 22, counting from field 3 after the parenthesized comm.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn handles_sigquit(proc_dir: &Path) -> bool {
    // HotSpot attach may signal the target to start its diagnostic listener.
    fs::read_to_string(proc_dir.join("status")).is_ok_and(|status| {
        status.lines().any(|line| {
            line.strip_prefix("SigCgt:")
                .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                .is_some_and(|mask| mask & (1 << 2) != 0)
        })
    })
}

fn small_file(path: &Path) -> Option<String> {
    if !path.metadata().ok()?.is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = String::new();
    file.take(65537).read_to_string(&mut data).ok()?;
    (data.len() <= 65536).then_some(data)
}

#[derive(Default, Serialize)]
struct Release {
    version: Option<String>,
    full_build: Option<String>,
    vendor: Option<String>,
    vendor_version: Option<String>,
    product: Option<String>,
    graalvm_version: Option<String>,
}

fn release(data: &str) -> Release {
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
enum BuildStatus {
    Affected,
    NotAffected,
    Unknown,
}

fn build_status(r: &Release) -> BuildStatus {
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
    if update < last || (update == last && extra == 0) {
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

#[derive(Serialize)]
struct Installation {
    home: String,
    libjvm: String,
    id: FileId,
    release: Release,
    build_status: BuildStatus,
}

fn installation(scope: &Path, lib: &Path, id: FileId) -> Option<Installation> {
    if file_id(&fs::metadata(scope.join(lib.strip_prefix("/").ok()?)).ok()?) != id {
        return None;
    }
    let lib_dir = lib
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "lib"))?;
    let home = lib_dir.parent()?;
    let mut candidates = vec![home];
    if home.file_name().is_some_and(|n| n == "jre") {
        candidates.extend(home.parent());
    }
    let release = candidates
        .into_iter()
        .find_map(|p| {
            let relative = p.strip_prefix("/").ok()?;
            small_file(&scope.join(relative).join("release")).map(|data| release(&data))
        })
        .unwrap_or_default();
    Some(Installation {
        home: home.to_string_lossy().into_owned(),
        libjvm: lib.to_string_lossy().into_owned(),
        id,
        build_status: build_status(&release),
        release,
    })
}

fn installations() -> (BTreeMap<PathBuf, Installation>, bool, usize) {
    let mut queue: VecDeque<_> = ROOTS.into_iter().map(|p| (PathBuf::from(p), 0)).collect();
    let mut seen = BTreeSet::new();
    let mut found = BTreeMap::new();
    let mut unreadable = 0;
    for home in std::env::var_os("JAVA_HOME")
        .map(PathBuf::from)
        .into_iter()
        .chain(
            which("java")
                .and_then(|p| p.canonicalize().ok())
                .and_then(|p| Some(p.parent()?.parent()?.to_path_buf())),
        )
    {
        queue.push_front((home, 0));
    }
    let mut budget = 30000;
    while let Some((path, depth)) = queue.pop_front() {
        if budget == 0 || found.len() >= 256 {
            return (found, true, unreadable);
        }
        budget -= 1;
        let Ok(path) = path.canonicalize() else {
            continue;
        };
        if !seen.insert(path.clone()) {
            continue;
        }
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        for entry in entries {
            if budget == 0 || found.len() >= 256 {
                return (found, true, unreadable);
            }
            budget -= 1;
            let Ok(entry) = entry else {
                unreadable += 1;
                continue;
            };
            let Ok(kind) = entry.file_type() else {
                unreadable += 1;
                continue;
            };
            if entry.file_name() == "libjvm.so" && (kind.is_file() || kind.is_symlink()) {
                let lib = entry.path();
                if let Ok(meta) = lib.metadata()
                    && meta.is_file()
                    && let Some(item) = installation(Path::new("/"), &lib, file_id(&meta))
                {
                    found.insert(lib, item);
                }
            } else if depth < 8 && kind.is_dir() {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }
    (found, false, unreadable)
}

type Features = [bool; 4];

#[cfg(target_arch = "x86_64")]
fn cpuid() -> Option<Features> {
    use std::arch::x86_64::{__cpuid, __cpuid_count};
    if __cpuid(0).eax < 7 {
        return Some([false; 4]);
    }
    let leaf = __cpuid_count(7, 0);
    Some([
        leaf.ebx & (1 << 16) != 0,
        leaf.ebx & (1 << 30) != 0,
        leaf.ecx & (1 << 1) != 0,
        leaf.ebx & (1 << 8) != 0,
    ])
}

#[cfg(not(target_arch = "x86_64"))]
fn cpuid() -> Option<Features> {
    None
}

fn cpu_profiles(data: &str) -> BTreeMap<Features, usize> {
    let mut profiles = BTreeMap::new();
    for (key, value) in data.lines().filter_map(|line| line.split_once(':')) {
        if key.trim() == "flags" {
            let flags: BTreeSet<_> = value.split_whitespace().collect();
            *profiles
                .entry(FEATURES.map(|flag| flags.contains(flag)))
                .or_default() += 1;
        }
    }
    profiles
}

fn named_flags(flags: Features) -> BTreeMap<&'static str, bool> {
    FEATURES.into_iter().zip(flags).collect()
}

fn cpu_evidence(
    cpuid: Option<Features>,
    profiles: BTreeMap<Features, usize>,
    x86: bool,
) -> (Option<bool>, Value) {
    let manual_review =
        cpuid.is_some_and(|raw| profiles.keys().any(|flags| *flags != raw)) || profiles.len() > 1;
    let eligible = if !x86 {
        Some(false)
    } else {
        cpuid
            .filter(|_| !manual_review && !profiles.is_empty())
            .map(|flags| flags.into_iter().all(|flag| flag))
    };
    let evidence = json!({
        "architecture":std::env::consts::ARCH,
        "cpuid_leaf_7_subleaf_0":cpuid.map(named_flags),
        "proc_cpuinfo_profiles":profiles.into_iter().map(|(flags,count)| json!({"flags":named_flags(flags),"logical_cpus":count})).collect::<Vec<_>>(),
        "manual_review":manual_review,"eligible":eligible
    });
    (eligible, evidence)
}

#[derive(Default, Serialize)]
struct Flags {
    #[serde(rename = "UseBASE64Intrinsics")]
    use_base64_intrinsics: Option<bool>,
    #[serde(rename = "UseAVX")]
    use_avx: Option<u32>,
}

fn parse_flags(data: &str) -> Flags {
    let mut flags = Flags::default();
    for line in data.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_type), Some(name), Some("=" | ":="), Some(value)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        match name {
            "UseBASE64Intrinsics" => flags.use_base64_intrinsics = value.parse().ok(),
            "UseAVX" => flags.use_avx = value.parse().ok(),
            _ => {}
        }
    }
    flags
}

fn decision(build: BuildStatus, cpu: Option<bool>, flags: &Flags) -> (&'static str, &'static str) {
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

pub(crate) async fn collect(attach: bool) -> Value {
    let (cpu, evidence) = cpu_evidence(
        cpuid(),
        fs::read_to_string("/proc/cpuinfo")
            .ok()
            .as_deref()
            .map(cpu_profiles)
            .unwrap_or_default(),
        cfg!(target_arch = "x86_64"),
    );
    let (disk, disk_budget_exhausted, unreadable_directories) = installations();
    let jcmd = attach.then(|| which("jcmd")).flatten();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut processes = vec![];
    let mut active = BTreeSet::new();
    let mut unreadable_maps = 0;
    let mut unstable_snapshots = 0;
    let owner = fs::metadata("/proc/self").ok().map(|m| m.uid());
    let entries = fs::read_dir("/proc");
    let proc_available = entries.is_ok();
    for entry in entries.into_iter().flatten().flatten() {
        if processes.len() >= 128 {
            break;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let proc_dir = entry.path();
        let started = start_time(&proc_dir);
        let maps = match mappings(&proc_dir) {
            Ok(maps) if maps.is_empty() => continue,
            Ok(maps) => maps,
            Err(error) => {
                unreadable_maps += 1;
                let named_java = fs::read_to_string(proc_dir.join("comm"))
                    .is_ok_and(|name| name.trim() == "java")
                    || fs::read_link(proc_dir.join("exe"))
                        .is_ok_and(|exe| exe.file_name().is_some_and(|name| name == "java"));
                if named_java {
                    processes.push(
                        json!({"pid":pid,"status":"unknown","reason":"maps_unavailable",
                        "maps_error":error.kind().to_string(),"effective_flags":Flags::default()}),
                    );
                }
                continue;
            }
        };
        let same_user = owner.is_some() && fs::metadata(&proc_dir).ok().map(|m| m.uid()) == owner;
        let single = maps.len() == 1;
        let (flags, flag_status) = match (&jcmd, single, started) {
            (Some(_), true, Some(_)) if !same_user || !handles_sigquit(&proc_dir) => {
                (Flags::default(), "attach_listener_unconfirmed")
            }
            (Some(exe), true, Some(started))
                if start_time(&proc_dir) == Some(started)
                    && mappings(&proc_dir).is_ok_and(|current| current == maps) =>
            {
                let pid = pid.to_string();
                let limit = deadline.min(tokio::time::Instant::now() + Duration::from_secs(2));
                if limit <= tokio::time::Instant::now() {
                    (Flags::default(), "attach_budget_exhausted")
                } else {
                    match tokio::time::timeout_at(
                        limit,
                        run_clean_java(exe, &[&pid, "VM.flags", "-all"]),
                    )
                    .await
                    {
                        Ok(command) if command["exit_code"] == 0 => {
                            let flags = parse_flags(command["output"].as_str().unwrap_or_default());
                            let status = if flags.use_base64_intrinsics.is_some()
                                && flags.use_avx.is_some()
                            {
                                "read"
                            } else {
                                "flags_missing"
                            };
                            (flags, status)
                        }
                        Ok(_) => (Flags::default(), "attach_failed"),
                        Err(_) => (Flags::default(), "attach_timeout"),
                    }
                }
            }
            (None, _, _) => (
                Flags::default(),
                if attach {
                    "jcmd_unavailable"
                } else {
                    "attach_disabled"
                },
            ),
            _ => (Flags::default(), "jvm_identity_unconfirmed"),
        };
        let runtime_build = if let (Some(exe), Some(started)) = (&jcmd, started)
            && !matches!(
                flag_status,
                "attach_listener_unconfirmed"
                    | "jvm_identity_unconfirmed"
                    | "attach_budget_exhausted"
            )
            && start_time(&proc_dir) == Some(started)
            && mappings(&proc_dir).is_ok_and(|current| current == maps)
            && let Ok(command) = tokio::time::timeout_at(
                deadline.min(tokio::time::Instant::now() + Duration::from_secs(2)),
                run_clean_java(exe, &[&pid.to_string(), "VM.version"]),
            )
            .await
            && command["exit_code"] == 0
        {
            command["output"]
                .as_str()
                .and_then(reported_build)
                .map(str::to_owned)
        } else {
            None
        };
        let runtimes: Vec<_> = maps
            .iter()
            .map(|mapping| {
                let matched = mapped_disk_id(&proc_dir, mapping);
                let disk = (!mapping.deleted)
                    .then(|| {
                        let rel = Path::new(&mapping.path).strip_prefix("/").ok()?;
                        let observed =
                            file_id(&fs::metadata(proc_dir.join("root").join(rel)).ok()?);
                        (observed.inode == mapping.id.inode)
                            .then(|| {
                                installation(
                                    &proc_dir.join("root"),
                                    Path::new(&mapping.path),
                                    observed,
                                )
                            })
                            .flatten()
                    })
                    .flatten();
                (mapping, matched, disk)
            })
            .collect();
        let stable = started.is_some()
            && started == start_time(&proc_dir)
            && mappings(&proc_dir).is_ok_and(|current| current == maps)
            && runtimes
                .iter()
                .all(|(mapping, matched, _)| mapped_disk_id(&proc_dir, mapping) == *matched)
            && started == start_time(&proc_dir);
        if !stable {
            unstable_snapshots += 1;
            processes.push(
                json!({"pid":pid,"status":"unknown","reason":"process_changed_during_collection",
                "mappings":maps,"effective_flags":Flags::default()}),
            );
            continue;
        }
        let identity = single && runtimes[0].1.is_some();
        let disk_evidence = single.then(|| runtimes[0].2.as_ref()).flatten();
        let conflict = runtime_build
            .as_deref()
            .zip(disk_evidence)
            .and_then(|(running, disk)| {
                disk.release
                    .full_build
                    .as_deref()
                    .or(disk.release.version.as_deref())
                    .map(|v| build_conflicts(running, v))
            })
            .unwrap_or(false);
        let build = disk_evidence
            .filter(|_| identity && !conflict)
            .map_or(BuildStatus::Unknown, |item| item.build_status);
        let (status, reason) = if conflict {
            ("unknown", "running_build_conflicts_with_disk")
        } else if !identity && disk_evidence.is_some() {
            ("potential", "disk_identity_unconfirmed")
        } else {
            decision(build, cpu, &flags)
        };
        if !conflict {
            for (_, matched, _) in &runtimes {
                if let Some((id, _)) = matched {
                    active.insert(*id);
                }
            }
        }
        processes.push(json!({
            "pid":pid,"start_time_ticks":started,"status":status,"reason":reason,
            "build_status":build,"runtime_build":runtime_build,"flag_source":"jcmd VM.flags -all","flag_status":flag_status,
            "effective_flags":flags,
            "mappings":runtimes.iter().map(|(mapping,matched,item)| json!({
                "mapping":mapping,"disk_evidence":item,"disk_identity_matched":matched.is_some(),
                "identity_source":matched.map(|(_,source)| source),
                "host_scan_match":item.as_ref().is_some_and(|i| disk.values().any(|disk_item| disk_item.id == i.id))
            })).collect::<Vec<_>>(),
        }));
    }
    processes.sort_by_key(|p| p["pid"].as_u64());
    let installations: Vec<_> = disk
        .values()
        .filter(|item| !active.contains(&item.id))
        .map(|item| {
            let (status, reason) = match (item.build_status, cpu) {
                (BuildStatus::NotAffected, _) | (_, Some(false)) => {
                    ("not_affected", "excluded_build_or_cpu")
                }
                (BuildStatus::Affected, Some(true)) => {
                    ("potential", "no_running_jvm_identity_match")
                }
                _ => ("unknown", "incomplete_or_conflicting_evidence"),
            };
            json!({"status":status,"reason":reason,"installation":item})
        })
        .collect();
    json!({
        "cve":"CVE-2026-114938","cpu":evidence,"processes":processes,"installations":installations,
        "advisories":[UPSTREAM, DISCLOSURE, ORACLE,
            "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3478.html",
            "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3479.html",
            "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3480.html",
            "https://alas.aws.amazon.com/AL2027/ALAS2027-2026-374.html"],
        "coverage":{"proc_available":proc_available,"unreadable_maps":unreadable_maps,
            "unstable_snapshots":unstable_snapshots,"process_limit_reached":processes.len() >= 128,"disk_roots":ROOTS,"disk_max_depth":8,
            "disk_budget_exhausted":disk_budget_exhausted,"unreadable_directories":unreadable_directories},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_require_device_and_inode_and_do_not_relabel_replaced_libraries() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("embedded JRE");
        let lib = home.join("lib/server/libjvm.so");
        fs::create_dir_all(lib.parent().unwrap()).unwrap();
        fs::write(&lib, "").unwrap();
        fs::write(
            home.join("release"),
            concat!(
                "IMPLEMENTOR=\"Oracle Corporation\"\n",
                "JAVA_VERSION=\"17.0.6\"\n",
                "JAVA_RUNTIME_VERSION=\"17.0.6+10-LTS\"\n",
            ),
        )
        .unwrap();

        let id = file_id(&lib.metadata().unwrap());
        let line = format!(
            "7e-8f r-xp 0 {:x}:{:x} {} {}",
            id.device_major,
            id.device_minor,
            id.inode,
            lib.display()
        );
        let mapping = parse_mapping(&line).unwrap();
        assert_eq!(mapping.id, id);
        assert_eq!(mapping.path, lib.to_str().unwrap());
        let result = installation(Path::new("/"), &lib, mapping.id).unwrap();
        assert_eq!(result.release.full_build.as_deref(), Some("17.0.6+10-LTS"));
        assert_eq!(result.build_status, BuildStatus::Affected);
        assert!(parse_mapping(&format!("{line} (deleted)")).unwrap().deleted);
        fs::rename(&lib, lib.with_extension("old")).unwrap();
        fs::write(&lib, "").unwrap();
        assert!(installation(Path::new("/"), &lib, mapping.id).is_none());
        let wrong_device = FileId {
            device_minor: id.device_minor ^ 1,
            ..file_id(&lib.metadata().unwrap())
        };
        assert!(installation(Path::new("/"), &lib, wrong_device).is_none());
    }

    #[test]
    fn build_rules_use_full_build_and_vendor() {
        let status = |vendor: &str, full: &str, vendor_version: &str| {
            build_status(&Release {
                vendor: Some(vendor.into()),
                full_build: Some(full.into()),
                vendor_version: Some(vendor_version.into()),
                ..Release::default()
            })
        };
        use BuildStatus::*;
        assert_eq!(status("Oracle Corporation", "17.0.5+9", ""), NotAffected);
        assert_eq!(status("Oracle Corporation", "17.0.6+9", ""), Unknown);
        assert_eq!(status("Oracle Corporation", "17.0.6+10", ""), Affected);
        assert_eq!(status("Oracle Corporation", "17.0.21.0.3+1", ""), Affected);
        assert_eq!(status("Oracle Corporation", "17.0.21.1+3", ""), Unknown);
        assert_eq!(status("Oracle Corporation", "17.0.21.1+4", ""), NotAffected);
        assert_eq!(status("OpenJDK", "17.0.21.1+4", ""), Unknown);
        assert_eq!(status("OpenJDK", "27.0.1.1+4", ""), NotAffected);
        assert_eq!(status("OpenJDK", "27.0.1.1+2", ""), Unknown);
        assert_eq!(
            status("Amazon.com Inc.", "27.0.1.1+2", "Corretto-27.0.1.1.4"),
            Unknown
        );
        assert_eq!(status("Unknown vendor", "17.0.21.1+4", ""), Unknown);
        assert_eq!(
            status("Amazon.com Inc.", "21.0.13.1+2-LTS", "Corretto-21.0.13.1.2"),
            NotAffected
        );
        assert_eq!(status("Amazon.com Inc.", "21.0.13.1+2-LTS", ""), Unknown);
        assert_eq!(
            status("Oracle Corporation", "1.8.0_511-perf-b33", ""),
            Affected
        );
        assert_eq!(status("Oracle Corporation", "1.8.0_511-b33", ""), Unknown);
    }

    #[test]
    fn cpu_disagreement_preserves_both_sources() {
        let (eligible, evidence) = cpu_evidence(
            Some([true; 4]),
            cpu_profiles(
                "flags : avx512f avx512bw avx512vbmi bmi2\nflags : avx512f avx512bw bmi2\n",
            ),
            true,
        );
        assert_eq!(eligible, None);
        assert_eq!(evidence["manual_review"], true);
        assert_eq!(evidence["cpuid_leaf_7_subleaf_0"]["avx512vbmi"], true);
        assert_eq!(
            evidence["proc_cpuinfo_profiles"].as_array().unwrap().len(),
            2
        );
        let (eligible, _) = cpu_evidence(Some([true; 4]), BTreeMap::new(), true);
        assert_eq!(eligible, None);
    }

    #[test]
    fn decisions_use_effective_flags_and_preserve_unknown() {
        use BuildStatus::*;
        let enabled = parse_flags(
            "bool UseBASE64Intrinsics = true {product} {default}\nint UseAVX := 3 {x86}",
        );
        let disabled_base64 =
            parse_flags("bool UseBASE64Intrinsics = false {product} {command line}");
        let disabled_avx = parse_flags("intx UseAVX = 2 {ARCH product} {command line}");
        assert_eq!(decision(Affected, Some(true), &enabled).0, "affected");
        assert_eq!(
            decision(Affected, Some(true), &disabled_base64).0,
            "mitigated"
        );
        assert_eq!(decision(Affected, None, &disabled_avx).0, "mitigated");
        assert_eq!(decision(Unknown, Some(true), &disabled_avx).0, "mitigated");
        assert_eq!(
            decision(Affected, Some(false), &disabled_avx).0,
            "not_affected"
        );
        assert_eq!(
            decision(NotAffected, None, &Flags::default()).0,
            "not_affected"
        );
        assert_eq!(
            decision(Affected, Some(true), &Flags::default()).0,
            "unknown"
        );
        assert_eq!(decision(Affected, None, &enabled).0, "unknown");
    }
}
