#!/usr/bin/env bash
# check-java4shell.sh — CVE-2026-114938 (Java4Shell) 本地证据检测
# 基线: php2shell_check/scripts/check-java4shell.sh
# 增强: --json 机器可读汇总、--java-path 指定运行时、帮助信息完善
# 依赖: bash 4.4+, Linux /proc, awk/find/realpath/stat/timeout/uname。无需 Python/网络。

set -u
export LC_ALL=C
shopt -s nullglob

# ==================== 用法 ====================
usage() {
  cat <<'HELP'
Usage: check-java4shell.sh [--jcmd] [--root DIRECTORY]... [--json] [--java-path PATH]

  --jcmd              用 jcmd VM.flags -all 读取 JVM 实际生效的 flags
                      （可能启动 HotSpot 诊断监听器，建议以 JVM 服务账户运行）
  --root DIR          额外扫描嵌入式运行时目录（可重复）
  --json              输出 JSON 汇总到 stdout，TSV 证据到 stderr
  --java-path PATH    以指定的 JDK/JRE bin/java 增加磁盘搜索起点
                      （默认从 PATH 解析，仍扫描其他目录和运行中 JVM）
  --help              显示本帮助

默认输出制表符分隔的 TSV 证据到 stdout。
退出码: 0=excluded/mitigated, 1=affected, 2=用法/依赖错误,
        3=unknown/incomplete, 4=potential（有受影响安装但无运行中 JVM 匹配）
HELP
}

# ==================== 参数解析 ====================
attach=0
json_mode=0
java_path=""
roots=(/usr/lib/jvm /usr/lib64/jvm /usr/java /usr/local/lib/jvm /usr/local/java /opt /srv /app)

while (($#)); do
  case $1 in
    --jcmd)       attach=1 ;;
    --json)       json_mode=1 ;;
    --java-path)
      if (($# < 2)) || [[ ! -f $2 || ! -x $2 ]]; then
        printf '%s\n' '--java-path requires an executable file' >&2
        exit 2
      fi
      java_path=$2; shift ;;
    --root)
      if (($# < 2)) || [[ ! -d $2 ]]; then
        printf '%s\n' '--root requires an existing directory' >&2
        exit 2
      fi
      roots+=("$2"); shift ;;
    --help|-h)    usage; exit 0 ;;
    *)            usage >&2; exit 2 ;;
  esac
  shift
done

# ==================== 依赖与平台 ====================
for tool in awk find realpath stat timeout uname; do
  command -v "$tool" >/dev/null || { printf 'Missing command: %s\n' "$tool" >&2; exit 2; }
done
[[ $(uname -s) == Linux ]] || { printf '%s\n' 'Linux /proc is required' >&2; exit 2; }

if [[ -n $java_path ]]; then
  if ! java_bin=$(realpath -e -- "$java_path" 2>/dev/null) || [[ $java_bin != */bin/java ]]; then
    printf '%s\n' '--java-path must resolve to a JDK/JRE bin/java' >&2
    exit 2
  fi
elif java_bin=$(type -P java); then
  java_bin=$(realpath -e -- "$java_bin" 2>/dev/null) || java_bin=
fi

if ((json_mode)); then
  exec 3>&1 1>&2
fi

arch=$(uname -m)
printf 'check\tCVE-2026-114938\n'

# ==================== CPU 多 profile 聚合 ====================
cpu_rows=$(awk '
  /^flags[[:space:]]*:/ {
    text = $0; sub(/^[^:]+:/, "", text)
    n = split(text, flags, /[[:space:]]+/)
    f = bw = vbmi = bmi = 0
    for (i = 1; i <= n; ++i) {
      if (flags[i] == "avx512f")    f = 1
      if (flags[i] == "avx512bw")   bw = 1
      if (flags[i] == "avx512vbmi") vbmi = 1
      if (flags[i] == "bmi2")       bmi = 1
    }
    ++profiles[f bw vbmi bmi]
  }
  END { for (profile in profiles) print profile, profiles[profile] }
' /proc/cpuinfo 2>/dev/null) || cpu_rows=

cpu=unknown
profiles=0
all_flags=0
while read -r mask count; do
  [[ -n $mask ]] || continue
  ((profiles+=1))
  [[ $mask == 1111 ]] && all_flags=1
  printf 'cpu_flags\tavx512f=%s\tavx512bw=%s\tavx512vbmi=%s\tbmi2=%s\tlogical_cpus=%s\n' \
    "${mask:0:1}" "${mask:1:1}" "${mask:2:1}" "${mask:3:1}" "$count"
done <<< "$cpu_rows"

if [[ $arch != x86_64 ]]; then
  cpu=no
elif ((profiles == 1)); then
  if ((all_flags)); then cpu=yes; else cpu=no; fi
fi
printf 'cpu\tarchitecture=%s\tsource=/proc/cpuinfo\teligible=%s\tmanual_review=%s\n' \
  "$arch" "$cpu" "$((profiles > 1))"

# ==================== release 解析与构建裁决 ====================
read_release() {
  local lib=$1 scope=$2
  local parent key value full= plain= alternate= home=${lib%/*}
  # Reset the result even if the runtime has no readable release file.
  vendor= vendor_build= build= product= release_path=
  while [[ $home != / && $home != "" && ${home##*/} != lib ]]; do home=${home%/*}; done
  [[ ${home##*/} == lib ]] || return 0
  home=${home%/*}
  for parent in "$home" "${home%/*}"; do
    release_path="$parent/release"
    [[ -f $scope$release_path && -r $scope$release_path ]] && break
    release_path=
    [[ ${home##*/} == jre ]] || break
  done
  [[ -n $release_path ]] || return 0
  while IFS='=' read -r key value; do
    [[ ${#value} -le 256 ]] || continue
    value=${value%$'\r'}; value=${value#\"}; value=${value%\"}
    case $key in
      IMPLEMENTOR)         vendor=$value ;;
      IMPLEMENTOR_VERSION) vendor_build=$value ;;
      JAVA_RUNTIME_VERSION) full=$value ;;
      FULL_VERSION)        alternate=$value ;;
      JAVA_VERSION)        plain=$value ;;
      JAVA_VM_NAME)        product+=" $value" ;;
      GRAALVM_VERSION)     product+=' GraalVM' ;;
    esac
  done < "$scope$release_path"
  build=${full:-${alternate:-$plain}}
}

classify_build() {
  local major update extra revision n min max fixed
  build_state=unknown
  case "$vendor $vendor_build $product" in
    *GraalVM*|*OpenJ9*) return 0 ;;
  esac
  case $vendor in
    'Oracle Corporation')
      case $build in
        1.8.0_511-perf-b33) build_state=affected; return ;;
        1.8.0_513-perf-b4|1.8.0_513-perf-b04) build_state=not_affected; return ;;
      esac ;;
    'Amazon.com Inc.'|'Eclipse Adoptium'|OpenJDK) ;;
    *) return 0 ;;
  esac
  if [[ ! $build =~ ^([0-9]{1,2})(\.([0-9]{1,2})(\.([0-9]{1,3})(\.([0-9]{1,3})(\.([0-9]{1,3}))?)?)?)?\+([0-9]{1,5})(-[[:alnum:].+_-]+)?$ ]]; then
    return 0
  fi
  major=$((10#${BASH_REMATCH[1]}))
  ((10#${BASH_REMATCH[3]:-0} == 0)) || return 0
  update=$((10#${BASH_REMATCH[5]:-0}))
  extra=$((10#${BASH_REMATCH[7]:-0}))
  revision=${BASH_REMATCH[9]}
  n=$((10#${BASH_REMATCH[10]}))
  case $major in
    17) min=6; max=21; fixed=2 ;;
    21) min=0; max=13; fixed=2 ;;
    25) min=0; max=5;  fixed=2 ;;
    27) min=0; max=1;  fixed=4 ;;
    *) return 0 ;;
  esac
  if ((update < min)); then
    build_state=not_affected
  elif ((major == 17 && update == 6 && extra == 0 && n < 10)); then
    return 0
  elif ((update < max || (update == max && extra == 0))); then
    build_state=affected
  elif [[ $vendor == 'Oracle Corporation' && -z $revision ]] && ((update > max || extra > 1 || (extra == 1 && n >= 4))); then
    build_state=not_affected
  elif [[ $vendor == 'Amazon.com Inc.' && -z $revision && ${vendor_build#Corretto-} == "$major.0.$max.1.$fixed" ]] && ((update == max && extra == 1)); then
    build_state=not_affected
  fi
}

file_id() { stat -Lc '%Hd:%Ld:%i' -- "$1" 2>/dev/null; }

jvm_maps() {
  awk '
    /\/libjvm\.so( \(deleted\))?$/ && $5 != "0" {
      device = $4; inode = $5; path = $0
      for (i = 0; i < 5; ++i) sub(/^[[:space:]]*[^[:space:]]+/, "", path)
      sub(/^[[:space:]]+/, "", path)
      if (path !~ /^\//) next
      item = device " " inode " " path
      if (!seen[item]++) { if (++count > 32) exit 2; print item }
    }
  ' "$1/maps" 2>/dev/null
}

process_start() {
  local line tail
  local -a fields
  IFS= read -r line < "$1/stat" || return 1
  tail=${line##*) }
  read -ra fields <<< "$tail"
  [[ ${fields[19]:-} =~ ^[0-9]+$ ]] || return 1
  printf '%s' "${fields[19]}"
}

handles_sigquit() {
  local key mask
  while read -r key mask _; do
    if [[ $key == SigCgt: && $mask =~ ^[[:xdigit:]]+$ ]]; then
      (( (16#${mask: -1} & 4) != 0 )) && return 0
      return 1
    fi
  done < "$1/status"
  return 1
}

record() {
  case $1 in
    affected)     ((affected+=1)) ;;
    potential)    ((potential+=1)) ;;
    unknown)      ((unknown+=1)) ;;
    mitigated)    ((mitigated+=1)) ;;
    not_affected) ((excluded+=1)) ;;
  esac
}

# ==================== 初始化 ====================
declare -A active_ids=() scanned_paths=() visited_roots=()
affected=0 potential=0 unknown=0 mitigated=0 excluded=0
unreadable_maps=0 jvm_count=0 disk_count=0 disk_incomplete=0
jcmd_path=$(type -P jcmd || :)
SECONDS=0

# ==================== 运行中 JVM 扫描 ====================
for proc in /proc/[0-9]*; do
  [[ ${proc##*/} =~ ^[0-9]+$ ]] || continue
  pid=${proc##*/}
  start=$(process_start "$proc" 2>/dev/null) || start=

  if ! maps=$(jvm_maps "$proc"); then
    [[ -d $proc ]] || continue
    ((unreadable_maps+=1))
    if { IFS= read -r comm < "$proc/comm"; } 2>/dev/null && [[ $comm == java ]]; then
      printf 'process\tpid=%s\tstatus=unknown\treason=maps_unavailable\n' "$pid"
      record unknown
      ((jvm_count+=1))
    fi
    continue
  fi
  [[ -n $maps ]] || continue
  ((jvm_count+=1))

  base64=unknown avx=unknown flag_source=attach_disabled
  if [[ $maps == *$'\n'* ]]; then
    printf 'process\tpid=%s\tstatus=unknown\treason=multiple_libjvm_mappings\n' "$pid"
    record unknown
    continue
  fi

  if ((attach)); then
    flag_source=jcmd_unavailable
    if [[ -n $jcmd_path ]]; then
      flag_source=listener_unconfirmed
      if [[ -n $start ]] && handles_sigquit "$proc" 2>/dev/null \
         && [[ $(jvm_maps "$proc") == "$maps" && $(process_start "$proc" 2>/dev/null) == "$start" ]]; then
        flag_source=attach_budget_exhausted
        if ((SECONDS < 15)); then
          flag_source=attach_failed
          if flags=$(timeout -k 1s 2s "$jcmd_path" "$pid" VM.flags -all 2>/dev/null | awk '
            $2 == "UseBASE64Intrinsics" && ($3 == "=" || $3 == ":=") && $4 ~ /^(true|false)$/ { base64 = $4 }
            $2 == "UseAVX" && ($3 == "=" || $3 == ":=") && $4 ~ /^[0-3]$/ { avx = $4 }
            END { print (base64 == "" ? "unknown" : base64), (avx == "" ? "unknown" : avx) }
          '; exit "${PIPESTATUS[0]}"); then
            read -r base64 avx <<< "$flags"
            flag_source=jcmd_effective
          fi
        fi
      fi
    fi
  fi

  read -r device inode lib <<< "$maps"
  major=${device%:*}; minor=${device#*:}
  expected="$((16#$major)):$((16#$minor)):$inode"
  observed= build_state=unknown build= vendor= vendor_build= release_path= identity=unconfirmed

  if [[ $lib == *' (deleted)' ]]; then
    identity=deleted
  elif observed=$(file_id "$proc/root$lib") && [[ $observed == "$expected" ]]; then
    identity=matched
    read_release "$lib" "$proc/root" 2>/dev/null
    classify_build
  else
    identity=disk_identity_mismatch
  fi

  if [[ -z $start || $(jvm_maps "$proc") != "$maps" \
        || $(process_start "$proc" 2>/dev/null) != "$start" \
        || ( $identity == matched && $(file_id "$proc/root$lib") != "$expected" ) ]]; then
    printf 'process\tpid=%s\tstatus=unknown\treason=process_or_mapping_changed\n' "$pid"
    record unknown
    continue
  fi

  status=unknown reason=incomplete_evidence
  if [[ $identity == matched && ( $cpu == no || $build_state == not_affected ) ]]; then
    status=not_affected reason=excluded_by_cpu_or_build
  elif [[ ( $cpu == yes || $build_state == affected ) && ( $base64 == false || $avx =~ ^[0-2]$ ) ]]; then
    status=mitigated reason=effective_vm_flags
  elif [[ $cpu == yes && $build_state == affected && $base64 == true && $avx == 3 ]]; then
    status=affected reason=cpu_build_and_effective_flags
  fi

  printf 'process\tpid=%s\tstatus=%s\treason=%s\tidentity=%s\tdevice_inode=%s\tlibjvm=%q\trelease=%q\tvendor=%q\tvendor_build=%q\tbuild=%q\tbuild_status=%s\tUseBASE64Intrinsics=%s\tUseAVX=%s\tflags_source=%s\n' \
    "$pid" "$status" "$reason" "$identity" "$expected" "$lib" "$release_path" \
    "$vendor" "$vendor_build" "$build" "$build_state" "$base64" "$avx" "$flag_source"
  record "$status"
done

# ==================== 磁盘安装扫描 ====================
if [[ $java_bin == */bin/java ]]; then
  roots=("${java_bin%/bin/java}" "${roots[@]}")
fi
[[ -n ${JAVA_HOME:-} ]] && roots=("$JAVA_HOME" "${roots[@]}")

for root in "${roots[@]}"; do
  [[ -d $root ]] || continue
  root=$(realpath -e -- "$root") || { disk_incomplete=1; continue; }
  [[ ${visited_roots[$root]+found} ]] && continue
  visited_roots[$root]=1
  printf 'disk_root\tpath=%q\tmax_depth=8\n' "$root"

  while IFS= read -r -d '' lib; do
    if [[ $lib == find_status=* ]]; then
      [[ $lib == find_status=0 ]] || disk_incomplete=1
      break
    fi
    if ((disk_count >= 256)); then disk_incomplete=1; break; fi
    [[ ${scanned_paths[$lib]+found} ]] && continue
    scanned_paths[$lib]=1
    [[ -f $lib ]] || continue
    id=$(file_id "$lib") || { disk_incomplete=1; continue; }
    [[ ${active_ids[$id]+found} ]] && continue
    ((disk_count+=1))

    read_release "$lib" '' 2>/dev/null
    classify_build
    status=unknown reason=incomplete_evidence
    if [[ $cpu == no || $build_state == not_affected ]]; then
      status=not_affected reason=excluded_by_cpu_or_build
    elif [[ $cpu == yes && $build_state == affected ]]; then
      status=potential reason=no_running_jvm_match
    fi
    printf 'installation\tstatus=%s\treason=%s\tdevice_inode=%s\tlibjvm=%q\trelease=%q\tvendor=%q\tvendor_build=%q\tbuild=%q\tbuild_status=%s\n' \
      "$status" "$reason" "$id" "$lib" "$release_path" "$vendor" "$vendor_build" "$build" "$build_state"
    record "$status"
  done < <( timeout -k 1s 3s find "$root" -xdev -maxdepth 8 -name libjvm.so \( -type f -o -type l \) -print0 2>/dev/null; printf 'find_status=%s\0' "$?" )
  if ((disk_count >= 256)); then
    disk_incomplete=1
    break
  fi
done

# ==================== coverage ====================
printf 'coverage\tjvms=%s\tdisk_only=%s\tunreadable_maps=%s\tdisk_scan_incomplete=%s\n' \
  "$jvm_count" "$disk_count" "$unreadable_maps" "$disk_incomplete"

# ==================== 裁决 ====================
if ((affected)); then
  summary=affected; code=1
elif ((potential)); then
  summary=potential; code=4
elif ((unknown)) || { [[ $cpu != no ]] && ((unreadable_maps || disk_incomplete || jvm_count + disk_count == 0)); }; then
  summary=unknown; code=3
elif ((mitigated)); then
  summary=mitigated; code=0
else
  summary=not_affected; code=0
fi

printf 'summary\tstatus=%s\taffected=%s\tpotential=%s\tunknown=%s\tmitigated=%s\tnot_affected=%s\n' \
  "$summary" "$affected" "$potential" "$unknown" "$mitigated" "$excluded"

# ==================== JSON 汇总（可选） ====================
if ((json_mode)); then
  # 将 summary 和 coverage 的关键字段转为 JSON
  cat >&3 <<JSON
{
  "check": "CVE-2026-114938",
  "cpu": {
    "architecture": "$arch",
    "eligible": "$cpu",
    "manual_review": $((profiles > 1))
  },
  "coverage": {
    "jvms": $jvm_count,
    "disk_only": $disk_count,
    "unreadable_maps": $unreadable_maps,
    "disk_scan_incomplete": $disk_incomplete
  },
  "summary": {
    "status": "$summary",
    "affected": $affected,
    "potential": $potential,
    "unknown": $unknown,
    "mitigated": $mitigated,
    "not_affected": $excluded
  }
}
JSON
fi

exit "$code"