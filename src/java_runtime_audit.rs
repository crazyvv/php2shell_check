//! Local evidence for CVE-2026-114938.
use crate::collector::{run_clean_java, which};
use crate::java4shell::{BuildStatus, Flags, Release, build_status, decision, release};
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
const MAPS_READ_LIMIT: u64 = 8 * 1024 * 1024;
const MAPS_TOTAL_LIMIT: u64 = 64 * 1024 * 1024;
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

struct MapsBudget {
    remaining: u64,
    limited: bool,
}

impl MapsBudget {
    fn read(&mut self, proc_dir: &Path) -> io::Result<BTreeSet<Mapping>> {
        let cap = self.remaining.min(MAPS_READ_LIMIT + 1);
        if cap == 0 {
            self.limited = true;
            return Err(io::Error::other("maps_total_limit"));
        }
        let mut reader = BufReader::new(File::open(proc_dir.join("maps"))?.take(cap));
        let result = (|| {
            let mut line = Vec::new();
            let mut found: BTreeSet<Mapping> = BTreeSet::new();
            while reader.read_until(b'\n', &mut line)? != 0 {
                if let Ok(line) = std::str::from_utf8(&line)
                    && let Some(mapping) = parse_mapping(line.trim_end_matches('\n'))
                    && !found.iter().any(|item| {
                        item.path == mapping.path
                            && item.id == mapping.id
                            && item.deleted == mapping.deleted
                    })
                {
                    if found.len() >= 32 {
                        self.limited = true;
                        return Err(io::Error::other("mapping_count_limit"));
                    }
                    found.insert(mapping);
                }
                line.clear();
            }
            Ok(found)
        })();
        let unused = reader.get_ref().limit();
        self.remaining -= cap - unused;
        if unused == 0 {
            self.limited = true;
            return Err(io::Error::other("maps_size_limit"));
        }
        result
    }
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
    small_file_with_limit(path, 65_536)
}

fn small_file_with_limit(path: &Path, limit: u64) -> Option<String> {
    if !path.metadata().ok()?.is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = String::new();
    file.take(limit + 1).read_to_string(&mut data).ok()?;
    (data.len() as u64 <= limit).then_some(data)
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

fn installations(
    extra: &[PathBuf],
    homes: &[PathBuf],
    max_depth: usize,
) -> (BTreeMap<PathBuf, Installation>, bool, usize, usize) {
    let mut queue: VecDeque<_> = homes
        .iter()
        .chain(extra)
        .cloned()
        .map(|p| (p, 0, true))
        .chain(
            ROOTS
                .into_iter()
                .filter(|_| homes.is_empty())
                .map(|p| (PathBuf::from(p), 0, false)),
        )
        .collect();
    let mut depth_boundaries = 0;
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
        if homes.is_empty() {
            queue.push_front((home, 0, false));
        }
    }
    let mut budget = 30000;
    while let Some((path, depth, explicit)) = queue.pop_front() {
        if budget == 0 || found.len() >= 256 {
            return (found, true, unreadable, depth_boundaries);
        }
        budget -= 1;
        let Ok(path) = path.canonicalize() else {
            unreadable += usize::from(explicit);
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
                return (found, true, unreadable, depth_boundaries);
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
            } else if kind.is_dir() {
                if depth < max_depth {
                    queue.push_back((entry.path(), depth + 1, explicit));
                } else if explicit {
                    depth_boundaries += 1;
                }
            }
        }
    }
    (found, false, unreadable, depth_boundaries)
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

fn startup_flags(raw: &[u8]) -> Flags {
    let mut flags = Flags::default();
    // Once the launcher target or an argument file is encountered, later tokens are ambiguous.
    for arg in raw.split(|byte| *byte == 0).skip(1) {
        let Ok(arg) = std::str::from_utf8(arg) else {
            break;
        };
        if arg.is_empty()
            || !arg.starts_with('-')
            || matches!(arg, "-jar" | "-m" | "--module" | "--")
            || arg.starts_with("--module=")
            || !(arg.starts_with("-XX:")
                || arg.starts_with("-X")
                || arg.starts_with("-D")
                || matches!(arg, "-server" | "-client" | "-ea" | "-da"))
        {
            break;
        }
        match arg {
            "-XX:-UseBASE64Intrinsics" => flags.use_base64_intrinsics = Some(false),
            "-XX:+UseBASE64Intrinsics" => flags.use_base64_intrinsics = Some(true),
            value if value.starts_with("-XX:UseAVX=") => {
                flags.use_avx = value["-XX:UseAVX=".len()..].parse().ok()
            }
            _ => {}
        }
    }
    flags
}

pub(crate) async fn collect(options: &crate::collector::CollectOptions) -> Value {
    let attach = options.java_attach;
    let (cpu, evidence) = if let Some(path) = &options.java_cpuinfo {
        let content = small_file_with_limit(path, 2_097_152);
        let profiles = content.as_deref().map(cpu_profiles).unwrap_or_default();
        let eligible =
            (profiles.len() == 1).then(|| profiles.keys().next().unwrap().iter().all(|flag| *flag));
        (
            eligible,
            json!({"source":"offline_cpuinfo","file":path,"readable":content.is_some(),
            "cpuid_leaf_7_subleaf_0":null,"manual_review":profiles.len()>1,"eligible":eligible,
            "proc_cpuinfo_profiles":profiles.into_iter().map(|(flags,count)| json!({"flags":named_flags(flags),"logical_cpus":count})).collect::<Vec<_>>()}),
        )
    } else {
        cpu_evidence(
            cpuid(),
            small_file_with_limit(Path::new("/proc/cpuinfo"), 2_097_152)
                .as_deref()
                .map(cpu_profiles)
                .unwrap_or_default(),
            cfg!(target_arch = "x86_64"),
        )
    };
    let depth = options.java_root_depth.unwrap_or(8);
    let (disk, disk_budget_exhausted, unreadable_directories, depth_boundaries) =
        if options.java_processes_only {
            (BTreeMap::new(), false, 0, 0)
        } else {
            installations(&options.java_root, &options.java_jdk, depth)
        };
    let jcmd = attach.then(|| which("jcmd")).flatten();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut processes = vec![];
    let mut active = BTreeSet::new();
    let mut unreadable_maps = 0;
    let mut unstable_snapshots = 0;
    let mut process_limit_reached = false;
    let mut maps_budget = MapsBudget {
        remaining: MAPS_TOTAL_LIMIT,
        limited: false,
    };
    let owner = fs::metadata("/proc/self").ok().map(|m| m.uid());
    let entries =
        (!options.java_no_processes && options.java_pid.is_empty()).then(|| fs::read_dir("/proc"));
    let proc_available = options.java_no_processes
        || !options.java_pid.is_empty()
        || entries.as_ref().is_some_and(Result::is_ok);
    let targets = options.java_pid.iter().copied().chain(
        entries
            .into_iter()
            .flatten()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok()),
    );
    for (index, pid) in targets.enumerate() {
        if index == crate::collector::PROCESS_SCAN_LIMIT || processes.len() >= 128 {
            process_limit_reached = true;
            break;
        }
        if maps_budget.remaining == 0 {
            maps_budget.limited = true;
            break;
        }
        let proc_dir = PathBuf::from(format!("/proc/{pid}"));
        let started = start_time(&proc_dir);
        let maps = match maps_budget.read(&proc_dir) {
            Ok(maps) if maps.is_empty() => {
                if !options.java_pid.is_empty() {
                    processes.push(json!({"pid":pid,"status":"unknown","reason":"no_jvm_mapping"}));
                }
                continue;
            }
            Ok(maps) => maps,
            Err(error) => {
                unreadable_maps += 1;
                let named_java = fs::read_to_string(proc_dir.join("comm"))
                    .is_ok_and(|name| name.trim() == "java")
                    || fs::read_link(proc_dir.join("exe"))
                        .is_ok_and(|exe| exe.file_name().is_some_and(|name| name == "java"));
                if named_java || !options.java_pid.is_empty() {
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
                    && maps_budget.read(&proc_dir).is_ok_and(|current| current == maps) =>
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
            && maps_budget.read(&proc_dir).is_ok_and(|current| current == maps)
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
            && maps_budget.read(&proc_dir).is_ok_and(|current| current == maps)
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
        let mut estimated = None;
        if options.java_assume_flags_effective
            && identity
            && !conflict
            && flags.use_base64_intrinsics.is_none()
            && flags.use_avx.is_none()
            && fs::read_link(proc_dir.join("exe"))
                .is_ok_and(|p| p.file_name().is_some_and(|name| name == "java"))
        {
            let mut raw = Vec::new();
            if File::open(proc_dir.join("cmdline"))
                .and_then(|file| file.take(65_537).read_to_end(&mut raw))
                .is_ok_and(|n| n <= 65_536)
                && started.is_some()
                && start_time(&proc_dir) == started
                && maps_budget.read(&proc_dir).is_ok_and(|current| current == maps)
            {
                let hint = startup_flags(&raw);
                if hint.use_base64_intrinsics.is_some() || hint.use_avx.is_some() {
                    estimated = Some(hint);
                }
            }
        }
        let (status, reason) = if conflict {
            ("unknown", "running_build_conflicts_with_disk")
        } else if !identity && disk_evidence.is_some() {
            ("potential", "disk_identity_unconfirmed")
        } else {
            let measured = decision(build, cpu, &flags);
            if measured.0 == "unknown"
                && let Some(hint) = &estimated
            {
                let estimate = decision(build, cpu, hint);
                if matches!(estimate.0, "affected" | "mitigated") {
                    (estimate.0, "operator_trusted_startup_flags")
                } else {
                    measured
                }
            } else {
                measured
            }
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
            "build_status":build,"runtime_build":runtime_build,"flag_source":if reason == "operator_trusted_startup_flags" { "startup_arguments_estimated" }
                else if flags.use_base64_intrinsics.is_some() || flags.use_avx.is_some() { "jcmd VM.flags -all" }
                else { "unavailable" },
            "flag_status":flag_status,"effective_flags":flags,"estimated_startup_flags":estimated,
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
            "unstable_snapshots":unstable_snapshots,"process_limit_reached":process_limit_reached,"maps_budget_exhausted":maps_budget.limited,"disk_roots":if options.java_jdk.is_empty() && !options.java_processes_only { ROOTS.as_slice() } else { &[] },"explicit_jdk_homes":options.java_jdk,"extra_roots":options.java_root,"disk_max_depth":depth,"root_depth_truncated":depth_boundaries,"process_scan_enabled":!options.java_no_processes,
            "disk_budget_exhausted":disk_budget_exhausted,"unreadable_directories":unreadable_directories},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_mappings_use_the_same_byte_budget() {
        let dir = tempfile::tempdir().unwrap();
        let maps = "1000-2000 r-xp 00000000 00:2e 123 /opt/jdk/lib/server/libjvm.so\n";
        fs::write(dir.path().join("maps"), maps).unwrap();
        let mut budget = MapsBudget {
            remaining: maps.len() as u64 + 1,
            limited: false,
        };
        assert_eq!(budget.read(dir.path()).unwrap().len(), 1);
        assert_eq!(budget.remaining, 1);
        assert!(budget.read(dir.path()).is_err());
        assert!(budget.limited);
        assert_eq!(budget.remaining, 0);
    }

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
        assert_eq!(
            status("Oracle Corporation", "1.8.0_441-b07", ""),
            NotAffected
        );
        for vendor in [
            "Red Hat, Inc.",
            "Eclipse Adoptium",
            "Amazon.com Inc.",
            "Azul Systems, Inc.",
            "Debian",
        ] {
            assert_eq!(status(vendor, "1.8.0_442-b06", ""), NotAffected);
        }
        assert_eq!(status("Unknown vendor", "1.8.0_442-b06", ""), Unknown);
        assert_eq!(status("OpenJDK", "8u441", ""), NotAffected);
        assert_eq!(status("Oracle Corporation", "8u511", ""), Unknown);
        assert_eq!(
            status("Oracle Corporation", "1.8.0_511-perf-b33", ""),
            Affected
        );
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
    fn startup_estimate_ignores_application_arguments() {
        let prefix = startup_flags(b"/bin/java\0-XX:+UseBASE64Intrinsics\0-XX:UseAVX=3\0-jar\0app.jar\0-XX:-UseBASE64Intrinsics\0");
        assert_eq!(prefix.use_base64_intrinsics, Some(true));
        assert_eq!(prefix.use_avx, Some(3));
        let args = startup_flags(b"/bin/java\0example.Main\0-XX:UseAVX=2\0");
        assert_eq!(args.use_avx, None);
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
