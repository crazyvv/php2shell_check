#!/usr/bin/env bash
# =============================================================================
#  java4shell-scan.sh —— CVE-2026-114938（Java4Shell）主机暴露面检测
#  单文件 · 只读 · 无 Python/Go 依赖（仅 bash + coreutils/grep/awk）
#
#  这是三个开源检测脚本的合并增强版：
#    1) ubitquity/cve-2026-114938-java4shell-remediation
#       scripts/check-java4shell.sh        —— 架构/CPU 特性/运行时进程 + 缓解参数
#    2) Mahgal/java4shell-check
#       java4shell_check.py                —— 精确受影响版本表、--json、--demo、
#                                             --apps 应用清点、CI 退出码
#    3) nu0l/Java4Shell-LocalScanner
#       java4shell.go                      —— JDK 目录发现、release 元数据解析、
#                                             进程内 libjvm.so 设备号/inode 校验、
#                                             容器线索、厂商/产品补丁规则、CSV/JSON 报告
#
#  设计原则（沿用三个上游的共同承诺）：
#    * 只读：不发送检测载荷，不联网，默认仅写临时报告数据；
#    * 只采集证据、不猜：证据不足时给出 unknown，而不是猜 affected / safe；
#    * 明确的退出码，可直接当 CI / 基线核查的门禁。
#
#  退出码：0 未命中失败级别；1 命中 --fail-on（默认 affected,potential）；
#          2 参数/IO 错误；3 无失败项但存在无法判断的资产。
# =============================================================================

set -u

CVE="CVE-2026-114938"
NICKNAME="Java4Shell"
RULES_AS_OF="2026-11-18"
PROG=${0##*/}
SCRIPT_VERSION="1.2.0"

OS=$(uname -s 2>/dev/null || echo unknown)
ARCH_RAW=$(uname -m 2>/dev/null || echo unknown)
ARCH_NORM=$(printf '%s' "$ARCH_RAW" | tr '[:upper:]' '[:lower:]')

# ---------------------------------------------------------------------------
# 默认参数
# ---------------------------------------------------------------------------
FORMAT=""
OUT=""
DETAILS=0
DEMO=0
NO_PROC=0
PROC_ONLY=0
QUIET=0
CPUINFO=""
APPS_DIR=""
APPS_DEPTH=3
FAIL_ON="affected,potential"
ASSUME_FEFF=0
JCMD=0
ROOT_DEPTH=8
JDK_ARGS=()
PID_ARGS=()
JAVA_BINS=()
ROOT_ARGS=()

WORK=""
FIND_FILE=""
WARN_FILE=""
APP_FILE=""
ACTIVE_FILE=""
CPU_STATE="unknown"
CPU_SOURCE=""
CPU_COUNTS="0 0 0"
LIMITED_PROCS=0
ROOT_COVERAGE_FILE=""
ROOT_DEPTH_BOUNDARIES=0
ROOT_SCAN_ERRORS=0

# 必需的 CPU 特性（x86-64）
REQ_FEATURES="avx512f avx512bw avx512vbmi bmi2"

# 应用清点：Calif 演示过的产品
PREAUTH_APPS="keycloak jira confluence artifactory jenkins pingfederate"
AUTH_APPS="kafka solr elasticsearch gerrit spinnaker"

# ---------------------------------------------------------------------------
# 帮助
# ---------------------------------------------------------------------------
usage() {
cat <<EOF
$NICKNAME · $CVE 主机暴露面检测（$PROG v$SCRIPT_VERSION）

用法:
  $PROG                         # 同时盘点 Java、NGINX 和 Apache
  $PROG --all [--json] [--jcmd]
  $PROG --java4shell [选项]
  $PROG --apache2root [--json]
  $PROG --nginx2root [--json] [--nginx-path PATH] [--nginx-config FILE]

  默认行为：发现本机 JDK 安装 + 检查运行中的 JVM 进程 + 探测 CPU 条件，
  输出中文结论；默认不修改被检查的运行时，不联网。

选项:
  --jdk PATH            指定 JDK Home（可重复）；指定后不再自动发现安装目录
  --root DIR            额外递归扫描该目录里的嵌入式运行时（可重复，找 libjvm.so）
  --root-depth N        配合 --root，最大递归深度（默认 8）
  --jcmd                用 jcmd 读取 JVM 真实生效的 flags（需 attach，可能短暂停顿
                        目标 JVM；仅在目标与当前用户相同时才会尝试）
  --pid PID             只检查指定进程（可重复）
  --processes-only      只检查进程，跳过安装目录发现
  --no-processes        跳过进程检查，只盘点安装目录
  --java-path PATH      额外对该 java 可执行文件跑一次 "java -version" 版本门禁
  --cpuinfo PATH        用指定文件替代 /proc/cpuinfo（离线/镜像核查用）
  --apps DIR            额外清点该目录下已知受影响的 Java 应用（默认深度 3）
  --apps-depth N        配合 --apps，指定递归深度（默认 3）
  --demo                跑内置固定样本（不采集本机任何数据，可重复复现）
  --json                等价于 --format json
  --csv                 等价于 --format csv
  --format FMT          txt | json | csv（默认 txt，或按 --out 扩展名推断）
  --out FILE            写入新文件（文件已存在则报错，不覆盖）
  --details             TXT 报告展开全部资产与证据
  --fail-on LIST        命中即退出 1，逗号分隔（默认 "affected,potential"）
  --assume-flags-effective
                        允许用明确的 JVM 启动参数进行估算；报告仍区分估算与 jcmd 实测
  --quiet               抑制进度提示
  -h, --help            显示本帮助
  -V, --version         显示版本

退出码:
  0  未命中 --fail-on
  1  命中 --fail-on（默认：存在 affected 或 potential 资产）
  2  参数或 IO 错误
  3  无失败项，但存在无法判断（unknown）的资产

示例:
  $PROG
  $PROG --details
  $PROG --json --out report.json
  $PROG --jdk /opt/jdk-17 --jdk /opt/jdk-21 --no-processes
  $PROG --processes-only --pid 1234
  $PROG --java-path /usr/bin/java --cpuinfo /mnt/image/proc_cpuinfo.txt
  $PROG --apps /opt
  $PROG --demo

判定口径:
  受影响 = 已知受影响构建 + 运行环境可见 AVX-512 VBMI + 未发现有效缓解参数
  待确认 = 版本/构建存在风险线索，但厂商补丁、CPU 或有效 JVM 参数未确认
  已缓解 = 有效参数证据显示已禁用 Base64 intrinsic 或限制 AVX 级别 <= 2
  不受影响 = 已确认修复，或构建/架构/CPU 条件超出影响范围
  无法判断 = 缺少构建身份或版本证据

临时缓解: -XX:-UseBASE64Intrinsics ，或仅在 x86-64 HotSpot 上用 -XX:UseAVX=2
修复构建: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1（Oracle）
          Corretto 对应 17.0.21.1.2 / 21.0.13.1.2 / 25.0.5.1.2 / 27.0.1.1.4
EOF
}

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

lower() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

trim() { printf '%s' "${1:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

die() { printf '错误: %s\n' "$*" >&2; exit 2; }

note_progress() { [ "$QUIET" -eq 1 ] || printf '[i] %s\n' "$*" >&2; }

# 追加一条采集提示（写文件，跨子 shell 安全）
warn() {
    printf '%s\n' "$*" >> "$WARN_FILE"
}

# 把可能破坏 TSV 的字符压平
san_field() {
    printf '%s' "${1:-}" | tr '\t\n' '  ' | tr -d '\037'
}

# 解析符号链接（相对目标也能处理）
resolve_symlinks() {
    local p=${1:-} t d i=0
    while [ -L "$p" ]; do
        i=$((i + 1))
        [ "$i" -gt 20 ] && break
        t=$(readlink "$p" 2>/dev/null) || break
        [ -n "$t" ] || break
        case $t in
            /*) p=$t ;;
            *) d=$(dirname "$p"); p="$d/$t" ;;
        esac
    done
    printf '%s' "$p"
}

# 规范化父目录（不解析最后一段，用于保留可能不存在的路径）
real_path() {
    local p=${1:-} d b
    [ -n "$p" ] || { printf ''; return; }
    b=${p##*/}
    d=${p%/*}
    [ -n "$d" ] || d=/
    if cd "$d" 2>/dev/null; then
        printf '%s/%s' "$(pwd -P)" "$b"
    else
        printf '%s' "$p"
    fi
}

# ---------------------------------------------------------------------------
# 版本号比较（纯数字元组，右补 0）
#   vcmp A B -> -1 / 0 / 1
# ---------------------------------------------------------------------------
vcmp() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN{
        na = split(a, A, ".")
        nb = split(b, B, ".")
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            pa = (i <= na) ? (A[i] + 0) : 0
            pb = (i <= nb) ? (B[i] + 0) : 0
            if (pa > pb) { print 1; exit }
            if (pa < pb) { print -1; exit }
        }
        print 0
    }'
}
vgt() { [ "$(vcmp "$1" "$2")" = 1 ]; }
vge() { [ "$(vcmp "$1" "$2")" != -1 ]; }
vlt() { [ "$(vcmp "$1" "$2")" = -1 ]; }
vle() { [ "$(vcmp "$1" "$2")" != 1 ]; }

# ---------------------------------------------------------------------------
# CPU 条件
#   cpu_from_text : stdin 为 cpuinfo 文本，输出 "state with without procs"
# ---------------------------------------------------------------------------
cpu_from_text() {
    awk '
    {
        line = $0
        sub(/\r$/, "", line)
        if (line ~ /^[ \t]*processor[ \t]*:/) {
            procs++
        } else if (line ~ /^[ \t]*flags[ \t]*:/) {
            sub(/^[^:]*:/, "", line)
            n = split(line, a, /[ \t]+/)
            has_f = 0; has_bw = 0; has_vbmi = 0; has_bmi2 = 0
            for (i = 1; i <= n; i++) {
                f = a[i]
                if (f == "avx512f") has_f = 1
                else if (f == "avx512bw") has_bw = 1
                else if (f == "avx512vbmi" || f == "avx512_vbmi") has_vbmi = 1
                else if (f == "bmi2") has_bmi2 = 1
            }
            if (has_f && has_bw && has_vbmi && has_bmi2) withf++; else without++
            flags++
        }
    }
    END {
        if (flags == 0 || procs == 0)            print "unknown 0 0 " procs + 0
        else if (flags != procs)                 print "unknown " withf + 0 " " without + 0 " " procs + 0
        else if (withf > 0 && without > 0)       print "mixed " withf + 0 " " without + 0 " " procs + 0
        else if (withf > 0)                      print "present " withf + 0 " " without + 0 " " procs + 0
        else                                     print "absent " withf + 0 " " without + 0 " " procs + 0
    }'
}

cpu_probe_darwin() {
    local complete=1 f
    if [ "$ARCH_NORM" = "arm64" ]; then printf 'absent 0 0 0'; return; fi
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
        printf 'absent 0 0 0'; return
    fi
    for f in hw.optional.avx512f hw.optional.avx512bw hw.optional.avx512vbmi hw.optional.bmi2; do
        case $(sysctl -n "$f" 2>/dev/null || echo "") in
            0) printf 'absent 0 0 0'; return ;;
            1) : ;;
            *) complete=0 ;;
        esac
    done
    if [ "$complete" -eq 1 ]; then printf 'present 1 0 1'; else printf 'unknown 0 0 0'; fi
}

cpu_probe() {
    local raw
    if [ -n "$CPUINFO" ]; then
        [ -r "$CPUINFO" ] || die "--cpuinfo 无法读取: $CPUINFO"
        raw=$(cpu_from_text < "$CPUINFO")
        CPU_SOURCE=$CPUINFO
    elif [ -r /proc/cpuinfo ] && grep -q . /proc/cpuinfo 2>/dev/null; then
        raw=$(cpu_from_text < /proc/cpuinfo)
        CPU_SOURCE=/proc/cpuinfo
    elif [ "$OS" = "Darwin" ] && have sysctl; then
        raw=$(cpu_probe_darwin)
        CPU_SOURCE="sysctl"
    else
        CPU_STATE="unknown"
        CPU_SOURCE="无 /proc/cpuinfo，CPU 条件未知"
        CPU_COUNTS="0 0 0"
        return
    fi
    CPU_STATE=$(printf '%s' "$raw" | cut -d' ' -f1)
    CPU_COUNTS=$(printf '%s' "$raw" | cut -d' ' -f2-)
}

# 归一化架构名
norm_arch() {
    case $(lower "${1:-}") in
        amd64|x86_64|x64)      printf 'amd64' ;;
        arm64|aarch64)         printf 'arm64' ;;
        386|x86|i386|i686)     printf '386' ;;
        arm|arm32|riscv64|s390x|ppc64|ppc64le|loong64|loongarch64|sparcv9)
                               lower "${1:-}" ;;
        *)                     printf '' ;;
    esac
}

# 结合架构与 CPU 采集结果 -> present|absent|mixed|unknown
cpu_assess() {
    local arch st
    arch=$(norm_arch "${1:-}")
    st=${2:-unknown}
    if [ -z "$arch" ]; then printf 'unknown'; return; fi
    if [ "$arch" != "amd64" ]; then printf 'absent'; return; fi
    case $st in
        present|absent|mixed) printf '%s' "$st" ;;
        *) printf 'unknown' ;;
    esac
}

# ---------------------------------------------------------------------------
# JDK release 元数据
# ---------------------------------------------------------------------------
release_is_jdk() {
    local f=$1
    [ -f "$f" ] || return 1
    grep -q '^JAVA_VERSION=' "$f" 2>/dev/null && return 0
    grep -q '^JAVA_RUNTIME_VERSION=' "$f" 2>/dev/null && return 0
    return 1
}

release_get() {
    local f=$1 key=$2
    [ -r "$f" ] || return 0
    awk -v k="$key" '
        {
            line = $0
            sub(/\r$/, "", line)
            i = index(line, "=")
            if (i <= 0) next
            key = substr(line, 1, i - 1)
            val = substr(line, i + 1)
            gsub(/^[ \t]+|[ \t]+$/, "", key)
            gsub(/^[ \t]+|[ \t]+$/, "", val)
            gsub(/^"|"$/, "", val)
            if (key == k) { print val; exit }
        }' "$f" 2>/dev/null
}

# java 可执行文件 -> JDK Home（处理 .../jre/bin/java 的旧布局）
java_root_of() {
    local p=${1:-} root
    root=$(dirname "$(dirname "$p")")
    if [ "${root##*/}" = "jre" ] && [ ! -f "$root/release" ]; then
        root=$(dirname "$root")
    fi
    printf '%s' "$root"
}

java_name() {
    case $(lower "${1##*/}") in
        java|javaw|java.exe|javaw.exe) return 0 ;;
        *) return 1 ;;
    esac
}

# 列出待盘点的 JDK Home
# 从 .../lib/server/libjvm.so 反推运行时根目录（不含 /proc 前缀）
root_of_lib() { jvm_root_from_lib "" "$1"; }

# --root：在给定目录里找嵌入式运行时的 libjvm.so，反推 Home
scan_root_dirs() {
    local r entry home relative separators
    [ ${#ROOT_ARGS[@]} -gt 0 ] || return 0
    for r in "${ROOT_ARGS[@]}"; do
        if ! have find || [ ! -d "$r" ]; then
            printf 'error\n' >> "$ROOT_COVERAGE_FILE"
            warn "无法搜索安装目录: $r"
            continue
        fi
        r=$(real_path "$r")
        if ! find "$r" -xdev -maxdepth "$ROOT_DEPTH" \
                \( -type d -o -name libjvm.so \( -type f -o -type l \) \) -print0 \
                > "$WORK/root-entries" 2>/dev/null; then
            printf 'error\n' >> "$ROOT_COVERAGE_FILE"
            warn "搜索安装目录时发生错误，结果可能不完整: $r"
        fi
        while IFS= read -r -d '' entry; do
            if [ -d "$entry" ] && [ ! -L "$entry" ]; then
                relative=${entry#"${r%/}/"}
                separators=${relative//[^\/]/}
                if { [ "$entry" = "$r" ] && [ "$ROOT_DEPTH" -eq 0 ]; } ||
                   { [ "$entry" != "$r" ] && [ "$((${#separators} + 1))" -eq "$ROOT_DEPTH" ]; }; then
                    printf 'boundary\n' >> "$ROOT_COVERAGE_FILE"
                fi
                continue
            fi
            home=$(root_of_lib "$entry")
            [ -n "$home" ] && [ -d "$home" ] || continue
            printf '%s\n' "$(real_path "$home")"
        done < "$WORK/root-entries"
    done
}

list_roots() {
    local d j pat f
    if [ ${#JDK_ARGS[@]} -gt 0 ]; then
        for d in ${JDK_ARGS[@]+"${JDK_ARGS[@]}"}; do
            [ -n "$d" ] || continue
            printf '%s\n' "$(real_path "$(resolve_symlinks "$d")")"
        done
        scan_root_dirs
        return
    fi

    if [ -n "${JAVA_HOME:-}" ] && [ -d "${JAVA_HOME:-}" ]; then
        printf '%s\n' "$(real_path "$(resolve_symlinks "$JAVA_HOME")")"
    fi

    if j=$(command -v java 2>/dev/null); then
        j=$(resolve_symlinks "$j")
        if [ "$OS" != "Darwin" ] || [ "$j" != "/usr/bin/java" ]; then
            printf '%s\n' "$(real_path "$(resolve_symlinks "$(java_root_of "$j")")")"
        fi
    fi

    case $OS in
        Darwin)
            pat="/Library/Java/JavaVirtualMachines/*/Contents/Home/release"
            [ -n "${HOME:-}" ] && pat="$pat $HOME/Library/Java/JavaVirtualMachines/*/Contents/Home/release"
            ;;
        Linux)
            pat="/usr/lib/jvm/*/release /usr/lib64/jvm/*/release /usr/java/*/release \
/opt/java/*/release /opt/jdk*/release /opt/*/release /usr/local/*/release /usr/local/java/*/release"
            ;;
        *)
            pat=""
            ;;
    esac

    for f in $pat; do
        [ -f "$f" ] || continue
        release_is_jdk "$f" || continue
        printf '%s\n' "$(real_path "$(resolve_symlinks "$(dirname "$f")")")"
    done

    scan_root_dirs
}

# ---------------------------------------------------------------------------
# 构建判定（版本 -> fixed|unfixed|outside_scope|candidate|unknown + 依据）
# ---------------------------------------------------------------------------
range_assess() {
    local v=$1 base major first last fixed fixed_note
    if [[ $v =~ ^[0-9]+$ ]]; then
        printf 'unknown\t仅有 Java 主版本号（%s），缺少可供范围判定的版本细节' "$v"
        return
    fi
    base=${v%%+*}
    major=${base%%.*}
    major=${major//[!0-9]/}
    case $major in
        17) first="17.0.6";    last="17.0.21.0.3";  fixed="17.0.21.1"
            fixed_note="17.0.21.1（Oracle）/ 17.0.21.1.2（Corretto）" ;;
        21) first="";          last="21.0.13.0.3";  fixed="21.0.13.1"
            fixed_note="21.0.13.1（Oracle）/ 21.0.13.1.2（Corretto）" ;;
        25) first="";          last="25.0.5.0.3";   fixed="25.0.5.1"
            fixed_note="25.0.5.1（Oracle）/ 25.0.5.1.2（Corretto）" ;;
        27) first="";          last="27.0.1.0.3";   fixed="27.0.1.1"
            fixed_note="27.0.1.1（Oracle）/ 27.0.1.1.4（Corretto）" ;;
        8|11)
            printf 'outside_scope\tJava %s 标准版本不在 Oracle 公布的受影响构建列表内' "$major"
            return ;;
        '')
            printf 'unknown\t无法从版本串中解析主版本号'
            return ;;
        *)
            printf 'unknown\tJava %s 不在已核对的受影响范围表（17/21/25/27）内，需按厂商公告确认' "$major"
            return ;;
    esac

    if [ "$major" = 17 ] && [ "$(vcmp "$base" "$first")" = 0 ]; then
        local build_number=""
        if [[ $v =~ \+([0-9]+) ]]; then build_number=${BASH_REMATCH[1]}; fi
        if [ -z "$build_number" ] || ! vge "$build_number" 10; then
            printf 'unknown\tJava 17.0.6 缺少已核实的受影响构建号（基线 +10）'
            return
        fi
    fi

    if vge "$base" "$fixed"; then
        printf 'candidate\t需核对厂商及完整修复构建（参考 %s）' "$fixed_note"
    elif [ -n "$first" ] && vlt "$base" "$first"; then
        printf 'outside_scope\t版本早于公开受影响范围（首受影响 %s）' "$first"
    elif vle "$base" "$last"; then
        printf 'unfixed\t版本落在公开受影响范围（至 %s），修复构建为 %s' "$last" "$fixed_note"
    else
        printf 'unknown\t版本位于"最后已知受影响构建 %s"与"首个已知修复构建 %s"之间，没有公开构建落在此处；请直接升级到 %s' \
            "$last" "$fixed" "$fixed_note"
    fi
}

recognized_jdk_vendor() {
    local v vm
    v=$(lower "${1:-}")
    vm=$(lower "${2:-}")
    if [ -n "$vm" ]; then
        case $vm in
            *hotspot*|*openjdk*) : ;;
            *) return 1 ;;
        esac
    fi
    case $v in
        openjdk|debian|ubuntu|canonical|"eclipse adoptium"|temurin|"amazon.com inc."|"amazon.com inc"|\
        microsoft|"azul systems, inc."|azul|"red hat, inc."|"red hat"|bellsoft|"sap se"|\
        "eclipse foundation"|"oracle corporation"|oracle)
            return 0 ;;
    esac
    case $vm in
        *openjdk*) return 0 ;;
    esac
    return 1
}

build_assess() {
    local version=${1:-} vendor=${2:-} product=${3:-} vm=${4:-}
    local v vl pl vml base major

    v=$(lower "$(trim "$version")")
    vl=$(lower "$(trim "$vendor")")
    pl=$(lower "$(trim "$product")")
    vml=$(lower "$(trim "$vm")")

    if [ -z "$v" ]; then
        printf 'unknown\t没有可用的 Java 版本元数据（release/version 输出缺失）'
        return
    fi

    case $vml in
        *openj9*)
            printf 'outside_scope\t识别到 OpenJ9 VM；该 CVE 属于 HotSpot intrinsic，不在影响范围'
            return ;;
    esac

    base=${v%%+*}
    major=${base%%.*}
    major=${major//[!0-9]/}

    # Oracle Java 8 Performance Pack boundaries come from the vendor advisory.
    if [[ $v =~ ^(1\.8\.0_[0-9]+(-[A-Za-z0-9.-]+)?|8u[0-9]+(b[0-9]+)?(-perf)?)$ ]]; then
        if [[ $vl == oracle || $vl == "oracle corporation" ]]; then
            case $v in
                8u511b33-perf|1.8.0_511-perf-b33)
                    printf 'unfixed\tOracle Java SE 8u511b33-perf 在受影响列表内'
                    return ;;
                8u513-perf|1.8.0_513-perf-b4|1.8.0_513-perf-b04)
                    printf 'fixed\tOracle Java SE 8u513-perf 修复构建'
                    return ;;
            esac
        fi
        printf 'unknown\tJava 8 构建缺少适用的厂商规则'
        return
    fi

    # ---- 精确规则：OpenJDK / Oracle OpenJDK 构建 ----
    if [[ ( $vl == openjdk && ( -z $pl || $pl == openjdk ) ) ||
          ( ( $vl == oracle || $vl == "oracle corporation" ) && $pl == openjdk ) ]]; then
        case $v in
            17.0.21.1+2|21.0.13.1+2|25.0.5.1+2|27.0.1.1+4)
                printf 'fixed\tOpenJDK 修复 GA 标签（%s）' "${base}"
                return ;;
            17.0.21|17.0.21.0.3|21.0.13|21.0.13.0.3|25.0.5|25.0.5.0.3|27.0.1|27.0.1.0.3)
                printf 'unfixed\tOpenJDK 受影响 GA 标签（%s），缺少变更 8393212 的尾块长度检查' "${base}"
                return ;;
        esac
    fi

    # ---- 精确规则：Oracle 产品线 ----
    if [ "$vl" = "oracle" ] || [ "$vl" = "oracle corporation" ]; then
        case $pl in
            "oracle java se")
                case $base in
                    8u511b33-perf|1.8.0_511-perf-b33|17.0.21.0.3|21.0.13.0.3|25.0.5.0.3|27.0.1.0.3)
                        printf 'unfixed\tOracle Java SE 受影响构建（%s）' "$base"
                        return ;;
                    17.0.21.1|21.0.13.1|25.0.5.1|27.0.1.1)
                        case $v in
                            "$base+4") printf 'fixed\tOracle Java SE 修复构建（%s+4）' "$base"; return ;;
                            "$base"+*)
                                if [[ ${v#"$base"} =~ ^\+4-lts(-[0-9]+)?$ ]]; then
                                    printf 'fixed\tOracle Java SE 修复构建（%s）' "$v"
                                    return
                                fi ;;
                        esac
                        printf 'unknown\tOracle Java SE 版本缺少已核实的完整修复构建号（%s）' "$v"
                        return
                        ;;
                esac ;;
            "oracle graalvm for jdk")
                case $base in
                    17.0.21.0.3|21.0.13.0.3)
                        printf 'unfixed\tOracle GraalVM for JDK 受影响构建（%s）' "$base"; return ;;
                esac ;;
            "oracle graalvm enterprise edition")
                case $base in
                    21.3.20.0.3)
                        printf 'unfixed\tOracle GraalVM Enterprise Edition 受影响构建（%s）' "$base"; return ;;
                esac ;;
        esac
    fi

    if [[ $vl == "amazon.com inc." || $vl == "amazon.com inc" ]]; then
        local distribution
        distribution=$(lower "${5:-}")
        distribution=${distribution#corretto-}
        case "$v:$distribution" in
            17.0.21.1.2:*|21.0.13.1.2:*|25.0.5.1.2:*|27.0.1.1.4:*|\
            17.0.21.1+2:17.0.21.1.2|17.0.21.1+2-lts:17.0.21.1.2|\
            21.0.13.1+2:21.0.13.1.2|21.0.13.1+2-lts:21.0.13.1.2|\
            25.0.5.1+2:25.0.5.1.2|25.0.5.1+2-lts:25.0.5.1.2|\
            27.0.1.1+4:27.0.1.1.4|27.0.1.1+4-fr:27.0.1.1.4)
                printf 'fixed\tAmazon Corretto 已核实的修复发行版本'
                return ;;
        esac
    fi

    # ---- 精确规则：Debian 构建 ----
    if [ "$vl" = "debian" ]; then
        case $v in
            17.0.19+10-1~deb12u2|17.0.21+9-1~deb12u1|17.0.21.0.3+1-1|\
21.0.12.1+1-1~deb13u1|21.0.13+9-1~deb13u2|21.0.13+9-1-deb13u2-debian|21.0.13.0.3+1-1|\
25.0.3+9-2~deb13u1|25.0.5+8-1~deb13u1|25.0.5+8-1|25.0.5.0.3+1-3|27.0.1.0.3+1-1)
                printf 'unfixed\tDebian 跟踪器所列受影响包版本（%s）' "$v"
                return ;;
        esac
    fi

    case $pl in
        *graalvm*)
            printf 'candidate\tGraalVM 需按其具体产品与构建确认补丁证据'
            return ;;
    esac

    # ---- 版本形态校验 ----
    if [[ ! $v =~ ^[0-9]{1,3}(\.[0-9]+){0,4}(\+[0-9]+([.-][A-Za-z0-9.~+_-]+)?)?$ ]]; then
        printf 'unknown\t没有可用的 Java 版本元数据（%s）' "$version"
        return
    fi
    if [ -z "$major" ] || [ "$major" -lt 8 ] || [ "$major" -gt 27 ]; then
        printf 'unknown\tJava %s 超出已核对覆盖范围（8–27）' "${major:-?}"
        return
    fi

    # ---- 范围兜底 ----
    local r assess evidence extra=""
    r=$(range_assess "$v")
    assess=${r%%	*}
    evidence=${r#*	}
    if ! recognized_jdk_vendor "$vendor" "$vm"; then
        extra="（厂商/产品未确认为 OpenJDK 系，按公开 OpenJDK 范围判定）"
        case $assess in
            fixed|unfixed) assess="candidate" ;;
        esac
    fi
    printf '%s\t%s%s' "$assess" "$evidence" "$extra"
}

# ---------------------------------------------------------------------------
# 缓解参数
#   多次出现按最后一个生效；-XX:UseAVX<=2 视为已缓解
# ---------------------------------------------------------------------------
flag_assessment() {
    local base64=$1 avx=$2
    if [[ $base64 == false || $avx =~ ^0*[0-2]$ ]]; then
        printf 'mitigated'
    elif [[ $base64 == true && $avx =~ ^0*3$ ]]; then
        printf 'unmitigated'
    else
        printf 'unknown'
    fi
}

launcher_flag_assessment() {
    local flags=${1:-} flag base64=unknown avx=unknown
    for flag in $flags; do
        case $flag in
            -XX:-UseBASE64Intrinsics) base64=false ;;
            -XX:+UseBASE64Intrinsics) base64=true ;;
            -XX:UseAVX=*) avx=${flag#-XX:UseAVX=} ;;
        esac
    done
    flag_assessment "$base64" "$avx"
}

mitigation_from_flags() {
    [[ $(launcher_flag_assessment "${1:-}") == mitigated ]]
}

# ---------------------------------------------------------------------------
# 状态合成
#   classify build cpu mitigated arch -> status
# ---------------------------------------------------------------------------
classify() {
    local build=$1 cpu=$2 mit=$3 feff=$4 arch=$5
    case $build in
        fixed|outside_scope) printf 'not_affected'; return ;;
    esac
    if [ "$cpu" = "absent" ]; then printf 'not_affected'; return; fi
    if [ "$build" = "unknown" ]; then printf 'unknown'; return; fi
    if [ "${6:-process}" != "process" ]; then printf 'potential'; return; fi
    if [ "$mit" -eq 1 ] && [ "$feff" -eq 1 ] && [ "$arch" = "amd64" ]; then printf 'mitigated'; return; fi
    if [ "$build" = "unfixed" ] && [ "$cpu" = "present" ] && [ "$mit" -eq 0 ] && [ "$feff" -eq 1 ]; then
        printf 'affected'; return
    fi
    if [ "$build" = "unfixed" ] && [ "$cpu" = "present" ]; then
        printf 'unknown'
    else
        printf 'potential'
    fi
}

# 生成判定依据
make_reason() {
    local status=$1 build=$2 bevid=$3 cpu=$4 mit=$5 arch=$6 hint=${7:-}
    local reason=""
    case $status in
        not_affected)
            case $build in
                fixed)        reason="已确认修复：版本已达到修复构建。" ;;
                outside_scope) reason="不在影响范围：$bevid" ;;
                *)            reason="CPU/架构不满足漏洞条件：需 x86-64 且运行环境可见 avx512f、avx512bw、avx512vbmi、bmi2。" ;;
            esac ;;
        unknown)
            reason="证据不足，无法判定。请核对构建、CPU 和 JVM 生效参数。$bevid" ;;
        mitigated)
            reason="已缓解：JVM 生效参数禁用了 Base64 intrinsic 或将 AVX 级别限制到 2 及以下。" ;;
        affected)
            reason="运行中 JVM 的构建与 CPU 符合受影响条件，生效参数显示相关指令路径未禁用。$bevid" ;;
        potential)
            reason="存在风险线索，需进一步确认：$bevid"
            [ "$mit" -eq 1 ] && reason="$reason 已观察到缓解参数，但未确认其为该 JVM 的有效参数。"
            [ "$cpu" = "mixed" ] && reason="$reason 可见逻辑 CPU 的 AVX-512 特性不一致。"
            [ "$build" = "unfixed" ] && [ "$cpu" = "unknown" ] && reason="$reason CPU 条件未知。"
            ;;
    esac
    [ -n "$hint" ] && reason="$reason $hint"
    printf '%s' "$reason"
}

# ---------------------------------------------------------------------------
# 资产记录：写入 FIND_FILE（以 ASCII 单元分隔符分隔）
#  1 id 2 kind 3 status 4 reason 5 build 6 build_evidence 7 cpu
#  8 version 9 java_home 10 vendor 11 product 12 vm 13 arch
#  14 flags 15 flags_effective 16 container 17 notes
#  18 identity_confidence 19 disk_version 20 disk_vendor 21 disk_product 22 disk_build
# ---------------------------------------------------------------------------
emit_finding() {
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes
    id=$(san_field "${1:-}")
    kind=$(san_field "${2:-}")
    status=$(san_field "${3:-}")
    reason=$(san_field "${4:-}")
    build=$(san_field "${5:-}")
    bevid=$(san_field "${6:-}")
    cpu=$(san_field "${7:-}")
    version=$(san_field "${8:-}")
    jhome=$(san_field "${9:-}")
    vendor=$(san_field "${10:-}")
    product=$(san_field "${11:-}")
    vm=$(san_field "${12:-}")
    arch=$(san_field "${13:-}")
    flags=$(san_field "${14:-}")
    feff=$(san_field "${15:-}")
    container=$(san_field "${16:-}")
    notes=$(san_field "${17:-}")
    local identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build
    identity_confidence=$(san_field "${18:-}")
    disk_hint_version=$(san_field "${19:-}")
    disk_hint_vendor=$(san_field "${20:-}")
    disk_hint_product=$(san_field "${21:-}")
    disk_hint_build=$(san_field "${22:-}")

    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
        "$id" "$kind" "$status" "$reason" "$build" "$bevid" "$cpu" "$version" \
        "$jhome" "$vendor" "$product" "$vm" "$arch" "$flags" "$feff" "$container" "$notes" \
        "$identity_confidence" "$disk_hint_version" "$disk_hint_vendor" "$disk_hint_product" "$disk_hint_build" \
        >> "$FIND_FILE"
}

add_note() { NOTES="${NOTES:+$NOTES | }$1"; }

# ---------------------------------------------------------------------------
# 采集：JDK 安装目录
# ---------------------------------------------------------------------------
file_id() {
  local raw device inode
  raw=$(stat -Lc '%d %i' -- "$1" 2>/dev/null) || return 1
  read -r device inode <<< "$raw"
  [[ $device =~ ^[0-9]+$ && $inode =~ ^[0-9]+$ ]] || return 1
  # Decode Linux st_dev. Keep inode as text to preserve all 64 bits.
  printf '%s %s %s' "$(( (device >> 8 & 0xfff) | (device >> 32 & 0xfffff000) ))" \
    "$(( (device & 0xff) | (device >> 12 & 0xffffff00) ))" "$inode"
}

jdk_product() {
    local home=$1 vendor=$2 label graal edition
    case $(lower "$vendor") in
        openjdk) printf 'OpenJDK' ;;
        oracle|"oracle corporation")
            graal=$(release_get "$home/release" GRAALVM_VERSION)
            edition=$(lower "$(release_get "$home/release" GRAALVM_EDITION)")
            label=$(lower "$(printf '%s %s %s' "$edition" \
                "$(release_get "$home/release" IMPLEMENTOR_VERSION)" \
                "$(release_get "$home/release" JAVA_RUNTIME_NAME)")")
            case "$label" in
                *"enterprise edition"*|*"graalvm enterprise"*)
                    printf 'Oracle GraalVM Enterprise Edition'
                    return ;;
            esac
            if [[ $edition == ee && $graal == 21.3.* ]]; then
                printf 'Oracle GraalVM Enterprise Edition'
                return
            fi
            case "$graal $label" in
                *graalvm*) printf 'Oracle GraalVM for JDK'; return ;;
            esac
            if [ -n "$graal" ]; then printf 'Oracle GraalVM for JDK'; return; fi
            case $label in
                *"java(tm)"*|*"java se"*) printf 'Oracle Java SE' ;;
                *openjdk*) printf 'OpenJDK' ;;
                *)
                    if [ -f "$home/README" ] &&
                       head -c 65536 "$home/README" 2>/dev/null | grep -q 'Thank you for using the Oracle JDK.'; then
                        printf 'Oracle Java SE'
                    fi ;;
            esac ;;
    esac
}

assess_jdk_build() {
    local home=$1 version=$2 vendor=$3 product=$4 vm=$5 distribution="" graal=""
    if [ -n "$home" ]; then
        distribution=$(release_get "$home/release" IMPLEMENTOR_VERSION)
        if [ "$product" = "Oracle GraalVM Enterprise Edition" ]; then
            graal=$(release_get "$home/release" GRAALVM_VERSION)
            if [[ $graal =~ ^[0-9]+(\.[0-9]+){1,4}$ ]]; then
                version=$graal
            fi
        fi
    fi
    build_assess "$version" "$vendor" "$product" "$vm" "$distribution"
}

scan_installations() {
    local root version vendor product vm arch notes build cpu status mit flags feff vmname vmtext openj9
    local bevid reason bevid_and_build lib lib_id matched

    while IFS= read -r root; do
        [ -n "$root" ] || continue
        matched=0
        for lib in "$root"/lib/libjvm.so "$root"/lib/*/libjvm.so                    "$root"/lib/*/*/libjvm.so "$root"/jre/lib/*/libjvm.so "$root"/jre/lib/*/*/libjvm.so; do
            [ -f "$lib" ] || continue
            lib_id=$(file_id "$lib") || continue
            if grep -Fxq -- "$lib_id" "$ACTIVE_FILE"; then matched=1; break; fi
        done
        [ "$matched" -eq 0 ] || continue
        NOTES=""
        version=""; vendor=""; product=""; vm=""; arch=""
        build="unknown"; bevid=""

        if [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            vmname=$(release_get "$root/release" JAVA_VM_NAME)
            arch=$(release_get "$root/release" OS_ARCH)
            [ -n "$version" ] || add_note "release 文件中没有 JAVA_VERSION/JAVA_RUNTIME_VERSION"
        else
            add_note "缺少 release 元数据（可能不是完整 JDK Home，或为嵌入式 JRE）"
        fi

        product=$(jdk_product "$root" "$vendor")

        if [ -z "$arch" ]; then
            arch=$ARCH_RAW
            add_note "release 缺少 OS_ARCH，按本机架构（$ARCH_RAW）判定"
        fi

        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(assess_jdk_build "$root" "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)

        flags=""
        feff="false"
        mit=0
        [ "$build" = "" ] && build="unknown"

        vmtext=$(lower "${vm:-} ${vmname:-}")
        case $vmtext in *openj9*) openj9=1 ;; *) openj9=0 ;; esac
        if [ "$openj9" -eq 1 ]; then
            build="outside_scope"
            bevid="运行在 Eclipse OpenJ9（自有 Base64 实现，不经过 HotSpot intrinsic）"
            status="not_affected"
            reason="OpenJ9 不使用 HotSpot 的 Base64 intrinsic，不在本次影响面"
            add_note "OpenJ9 走自有实现；公告未单列该实现，若厂商有相反说明以厂商为准"
        else
            status=$(classify "$build" "$cpu" "$mit" 0 "$(norm_arch "$arch")" installation)
            reason=$(make_reason "$status" "$build" "$bevid" "$cpu" "$mit" "$(norm_arch "$arch")")
        fi

        emit_finding "install:$root" "installation" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root" "$vendor" "$product" "$vm" "$arch" "$flags" "$feff" "" "$NOTES"
    done < <(list_roots | LC_ALL=C sort -u)
}

# ---------------------------------------------------------------------------
# 采集：进程
# ---------------------------------------------------------------------------
java_process_start() {
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

libjvm_meta() {
    awk '
        /\/libjvm\.so( \(deleted\))?$/ && $5 != "0" {
            dev = $4; inode = $5; path = $0
            for (i = 0; i < 5; i++) sub(/^[[:space:]]*[^[:space:]]+/, "", path)
            sub(/^[[:space:]]+/, "", path)
            if (path !~ /^\//) next
            row = dev "\037" inode "\037" path
            if (!seen[row]++) print row "\037" $1
        }
    ' "$1/maps" 2>/dev/null
}

mapping_identity() {
    local proc=$1 range=$2 expected=$3 disk=$4 mapped
    if [[ $disk == "$expected" ]]; then
        printf 'maps'
        return
    fi
    [[ ${disk##* } == "${expected##* }" && $range =~ ^[[:xdigit:]]+-[[:xdigit:]]+$ ]] || return 1
    mapped=$(file_id "$proc/map_files/$range") || return 2
    [[ $mapped == "$disk" ]] || return 1
    printf 'map_files'
}

jcmd_version() {
    local pid=$1 jc=$2 out
    have timeout || return 1
    out=$(timeout -k 1s 3s "$jc" "$pid" VM.version 2>/dev/null) || return 1
    printf '%s\n' "$out" | awk '
        / VM version / {
            for (i = 1; i < NF; ++i) {
                if ($i == "version" && $(i+1) ~ /^[0-9]+([._][0-9]+)*\+([0-9]+)([-.][A-Za-z0-9._~+-]+)?$/) {
                    full = $(i+1)
                    exit
                }
            }
        }
        $1 == "JDK" && $2 ~ /^[0-9]+([._][0-9]+)*$/ { short = $2 }
        END {
            if (full != "") print full
            else if (short != "") print short
            else exit 1
        }
    '
}

runtime_version_conflicts() {
    local runtime=$1 disk=$2
    [[ $runtime == *+* && -n $disk ]] || return 1
    if [[ $disk == *+* ]]; then
        [[ ${runtime,,} != "${disk,,}" ]]
    else
        [[ ${runtime%%+*} != "$disk" ]]
    fi
}

jcmd_bin() {
    type -P jcmd || :
}

# JVM 是否注册了 SIGQUIT 处理器（attach 监听器的前提）
handles_sigquit() {
    local f=$1/status mask
    [ -r "$f" ] || return 1
    mask=$(awk '$1 == "SigCgt:" { print $2; exit }' "$f" 2>/dev/null)
    [ -n "$mask" ] || return 1
    case ${mask: -1} in
        [0-9a-fA-F]) ;;
        *) return 1 ;;
    esac
    [ $(( 16#${mask: -1} & 4 )) -ne 0 ]
}

# 用 jcmd 读真实生效 flags，输出 "UseBASE64Intrinsics UseAVX"（未知为 unknown）
jcmd_flags() {
    local pid=$1 jc=$2 out="" b64="" avx=""
    have timeout || return 1
    out=$(timeout -k 1s 3s "$jc" "$pid" VM.flags -all 2>/dev/null) || return 1
    [ -n "$out" ] || return 1
    b64=$(printf '%s\n' "$out" | awk '$2 == "UseBASE64Intrinsics" && ($3 == "=" || $3 == ":=") { print $4; exit }')
    avx=$(printf '%s\n' "$out" | awk '$2 == "UseAVX" && ($3 == "=" || $3 == ":=") { print $4; exit }')
    [ -n "$b64" ] || [ -n "$avx" ] || return 1
    printf '%s %s\n' "${b64:-unknown}" "${avx:-unknown}"
}

jvm_root_from_lib() {
    local proc=$1 lib=$2 server libdir root
    server=${lib%/*}
    [ "${server##*/}" = "server" ] || { printf ''; return; }
    libdir=${server%/*}
    case ${libdir##*/} in
        amd64|i386) libdir=${libdir%/*} ;;
    esac
    [ "${libdir##*/}" = "lib" ] || { printf ''; return; }
    root="${libdir%/*}"
    if [ -n "$proc" ]; then root="$proc/root$root"; fi
    if [ "${root##*/}" = "jre" ] && [ ! -f "$root/release" ]; then
        root=${root%/*}
    fi
    printf '%s' "$root"
}

container_hint() {
    local proc=$1 line ns initns
    if [ -r "$proc/cgroup" ]; then
        while IFS= read -r line; do
            case $(lower "$line") in
                *kubepods*)   printf 'kubepods（cgroup 线索）'; return ;;
                *docker*)     printf 'docker（cgroup 线索）'; return ;;
                *libpod*)     printf 'libpod（cgroup 线索）'; return ;;
                *containerd*) printf 'containerd（cgroup 线索）'; return ;;
                */lxc*)       printf 'lxc（cgroup 线索）'; return ;;
                *cri-o*|*crio-*) printf 'cri-o（cgroup 线索）'; return ;;
            esac
        done < "$proc/cgroup"
    fi
    if [ -e "$proc/root/.dockerenv" ]; then printf 'docker（root 标记）'; return; fi
    if [ -e "$proc/root/run/.containerenv" ]; then printf 'container（root 标记）'; return; fi
    ns=$(readlink "$proc/ns/pid" 2>/dev/null || echo "")
    initns=$(readlink /proc/1/ns/pid 2>/dev/null || echo "")
    if [ -n "$ns" ] && [ -n "$initns" ] && [ "$ns" != "$initns" ]; then
        printf '独立 PID 命名空间'
        return
    fi
    printf ''
}

# 从 cmdline 提取启动参数（跳过 -cp/-jar 等及其值）
launcher_flags() {
    local f=$1 arg i=1 n out="" args=()
    [ -r "$f" ] || { printf ''; return; }
    while IFS= read -r -d '' arg; do
        args[${#args[@]}]="$arg"
    done < "$f" 2>/dev/null
    n=${#args[@]}
    while [ "$i" -lt "$n" ]; do
        arg=${args[$i]}
        case $arg in
            -cp|-classpath|--class-path|-p|--module-path|--upgrade-module-path|\
--add-modules|--limit-modules|--add-exports|--add-opens|--add-reads|\
--patch-module|--source|--enable-native-access)
                i=$((i + 2)); continue ;;
        esac
        case $arg in
            -jar|-m|--module|--module=*|--) break ;;
            -*)
                case $arg in
                    -XX:-UseBASE64Intrinsics|-XX:+UseBASE64Intrinsics) out="$out $arg" ;;
                    -XX:UseAVX=*) out="$out $arg" ;;
                esac ;;
            *) break ;;
        esac
        i=$((i + 1))
    done
    printf '%s' "${out# }"
}

scan_processes() {
    local pid proc exe exe_clean comm named has_jvm maps_ok explicit=0
    local libmeta libpath libdev libino st mhex nhex verified range expected identity_source identity_rc
    local root root_disp version vendor product vm arch build bevid cpu status reason
    local flags feff mit fn notes container start1 start2
    local measured_state assumed_state b64 eavx reported_version
    local bevid_and_build verify_problem libmeta2 libmeta3 jc jcf vmname vmtext
    local runtime_version disk_version version_conflict weak_identity
    local identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build

    local pidlist
    if [ ${#PID_ARGS[@]} -gt 0 ]; then
        explicit=1
        pidlist=$(printf '%s\n' ${PID_ARGS[@]+"${PID_ARGS[@]}"})
    elif [ "$OS" = "Linux" ]; then
        pidlist=$(for d in /proc/[0-9]*; do printf '%s\n' "${d#/proc/}"; done | LC_ALL=C sort -n)
    else
        return
    fi

    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        proc="/proc/$pid"
        NOTES=""

        if [ ! -d "$proc" ]; then
            if [ "$explicit" -eq 1 ]; then
                emit_finding "pid:$pid" "process" "unknown" \
                    "进程不存在或已退出，未采集到任何证据。" "unknown" "进程不存在" \
                    "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            fi
            continue
        fi

        start1=$(java_process_start "$pid")

        exe=$(readlink "$proc/exe" 2>/dev/null || echo "")
        exe_clean=${exe% (deleted)}
        named=0
        java_name "$exe_clean" && named=1
        if [ "$named" -eq 0 ] && [ -r "$proc/comm" ]; then
            comm=$(tr -d '\n' < "$proc/comm" 2>/dev/null)
            java_name "$comm" && named=1
        fi

        has_jvm=0
        maps_ok=1
        if libmeta=$(libjvm_meta "$proc"); then
            [ -z "$libmeta" ] || has_jvm=1
        else
            maps_ok=0
            if [ -d "$proc" ]; then LIMITED_PROCS=$((LIMITED_PROCS + 1)); fi
        fi
        if [ "$maps_ok" -eq 0 ] && { [ "$explicit" -eq 1 ] || [ "$named" -eq 1 ]; }; then
            emit_finding "pid:$pid" "process" "unknown" "无法读取进程映射，无法核实运行中 JVM。" \
                "unknown" "进程映射不可读" "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" \
                "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            continue
        fi

        if [ "$named" -eq 0 ] && [ "$has_jvm" -eq 0 ]; then
            if [ "$explicit" -eq 1 ]; then
                emit_finding "pid:$pid" "process" "unknown" \
                    "该 PID 既不是 Java 启动器，也未映射 HotSpot 库，无法判定。" "unknown" "非 Java 进程" \
                    "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            fi
            continue
        fi

        # File identity and JVM version evidence have independent lifetimes.
        verified=0
        weak_identity=0
        version_conflict=0
        identity_source=""
        runtime_version=""
        disk_version=""
        root=""
        libpath=""
        st=""
        verify_problem=""
        if [[ -n $libmeta && $libmeta != *$'\n'* ]]; then
            IFS=$'\037' read -r libdev libino libpath range <<< "$libmeta"
            mhex=${libdev%%:*}
            nhex=${libdev##*:}
            if [[ $libpath == *" (deleted)" ]]; then
                verify_problem="运行中的 HotSpot 库已被删除，无法核对磁盘文件"
            elif ! st=$(file_id "$proc/root$libpath"); then
                verify_problem="无法读取磁盘上对应的 libjvm.so 文件身份"
            elif [[ $mhex =~ ^[[:xdigit:]]+$ && $nhex =~ ^[[:xdigit:]]+$ ]]; then
                expected="$((16#$mhex)) $((16#$nhex)) $libino"
                identity_rc=0
                identity_source=$(mapping_identity "$proc" "$range" "$expected" "$st") || identity_rc=$?
                case $identity_rc in
                    0) verified=1 ;;
                    2) weak_identity=1 ;;
                    *) verify_problem="无法将运行中映射与磁盘文件关联" ;;
                esac
                if [ "$identity_source" = map_files ] || [ "$weak_identity" -eq 1 ] ||
                   [ "$identity_rc" -ne 0 ]; then
                    add_note "maps 设备号及 inode: $expected；磁盘 stat: $st"
                fi
                if [ "$weak_identity" -eq 1 ]; then
                    add_note "inode 相同但设备号不同，无法读取 map_files 进一步核实"
                fi
                if [ "$verified" -eq 1 ] || [ "$weak_identity" -eq 1 ]; then
                    root=$(jvm_root_from_lib "$proc" "$libpath")
                fi
            fi
        elif [[ -n $libmeta ]]; then
            verify_problem="进程内存在多个不同的 HotSpot 库映射，无法确定运行实体"
        fi

        version=""; vendor=""; product=""; vm=""; arch=""
        if [ -n "$root" ] && [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            vmname=$(release_get "$root/release" JAVA_VM_NAME)
            arch=$(release_get "$root/release" OS_ARCH)
            product=$(jdk_product "$root" "$vendor")
            disk_version=$version
            if [ "$weak_identity" -eq 1 ]; then
                add_note "未关联的磁盘 release 构建: ${disk_version:-未知}"
            fi
            case $identity_source in
                maps) add_note "已映射的 HotSpot 库与磁盘 JDK 的设备号和 inode 一致" ;;
                map_files) add_note "已通过 map_files 核实映射对象与磁盘文件的设备号和 inode" ;;
            esac
            root_disp=${root#"$proc/root"}
            [ -n "$root_disp" ] || root_disp=$root
            libmeta2=$(libjvm_meta "$proc")
            if [ "$libmeta2" != "$libmeta" ]; then
                verify_problem="采集期间进程映射发生变化（可能重启或重新映射）"
            fi
        else
            root_disp=""
            if [ -n "$verify_problem" ]; then
                add_note "$verify_problem；不采用磁盘启动器的版本，避免把已升级的磁盘版本当成运行版本"
            else
                add_note "无法核实 JVM 身份或 release 元数据（可能为不同用户/已删除文件/受限的 /proc）"
            fi
        fi
        [ -n "$arch" ] || arch=$ARCH_RAW

        if { [ "$verified" -ne 1 ] && [ "$weak_identity" -ne 1 ]; } || [ -n "$verify_problem" ]; then
            verify_problem=${verify_problem:-无法核实运行中 JVM 映像}
            container=$(container_hint "$proc")
            start2=$(java_process_start "$pid")
            [ "$start1" = "$start2" ] || verify_problem="采集期间进程已退出或身份发生变化"
            emit_finding "pid:$pid" "process" "unknown" "$verify_problem" "unknown" "$verify_problem" \
                "$(cpu_assess "$arch" "$CPU_STATE")" "$version" "$root_disp" "$vendor" "$product" "$vm" "$arch" \
                "" "false" "$container" "$NOTES"
            continue
        fi

        # --- 缓解参数 ---
        flags=""
        if [ "$named" -eq 1 ] || [ "$has_jvm" -eq 1 ]; then
            flags=$(launcher_flags "$proc/cmdline")
        fi
        feff="false"
        if [ -n "$flags" ]; then
            # 启动参数是可信的"启动证据"，但 JVM 有效值仍需按实际进程确认
            if [ "$ASSUME_FEFF" -eq 1 ]; then
                add_note "启动参数: $flags（已请求按启动参数估算，jcmd 实测优先）"
            else
                add_note "启动参数: $flags（启动证据，未确认该 JVM 的有效值）"
            fi
        fi

        # --- 生效参数（--jcmd，可选）：读 JVM 真实生效值，而不是启动器写法 ---
        measured_state=
        assumed_state=unknown
        if [ "$JCMD" -eq 1 ] && [ "$has_jvm" -eq 1 ]; then
            jc=$(jcmd_bin)
            if [ -z "$jc" ]; then
                add_note "未在 PATH 找到 jcmd，跳过生效参数探测"
            elif [ "$(stat -c %u "$proc" 2>/dev/null)" != "$(id -u)" ]; then
                add_note "目标 JVM 不属于当前用户，jcmd 无法 attach"
            elif ! handles_sigquit "$proc"; then
                add_note "目标 JVM 未注册 SIGQUIT 处理器（attach 监听器未启用），跳过 jcmd"
            elif [ -n "$start1" ] && [ "$(java_process_start "$pid")" = "$start1" ] &&
                 [ "$(libjvm_meta "$proc")" = "$libmeta" ]; then
                if jcf=$(jcmd_flags "$pid" "$jc"); then
                    read -r b64 eavx <<< "$jcf"
                    measured_state=$(flag_assessment "$b64" "$eavx")
                    if [ "$measured_state" != unknown ]; then feff=true; fi
                    add_note "jcmd 生效参数：UseBASE64Intrinsics=$b64 UseAVX=$eavx"
                    if [ "$measured_state" = unknown ]; then
                        add_note "实测参数不足以确认缓解状态"
                    fi
                else
                    add_note "jcmd 生效参数查询失败，启动参数仅作线索"
                fi
                if [ "$(java_process_start "$pid")" = "$start1" ] &&
                   [ "$(libjvm_meta "$proc")" = "$libmeta" ] &&
                   reported_version=$(jcmd_version "$pid" "$jc"); then
                    if [[ $reported_version == *+* ]]; then
                        runtime_version=$reported_version
                        add_note "jcmd 自报运行构建: $runtime_version；磁盘 release: ${disk_version:-未知}"
                        if runtime_version_conflicts "$runtime_version" "$disk_version"; then
                            version_conflict=1
                        fi
                    else
                        add_note "jcmd 仅报告短版本 $reported_version，无法核对运行构建号"
                    fi
                fi
            else
                add_note "jcmd 探测失败或超时（attach 未被响应），启动参数仅作线索"
            fi
        fi

        container=$(container_hint "$proc")

        # --- 采集期间身份是否变化 ---
        start2=$(java_process_start "$pid")
        libmeta3=$(libjvm_meta "$proc")
        if [ -z "$start1" ] || [ "$start1" != "$start2" ] || [ ! -d "$proc" ] ||
           [ "$libmeta3" != "$libmeta" ] || [ "$(file_id "$proc/root$libpath")" != "$st" ] ||
           { [ "$identity_source" = map_files ] && [ "$(file_id "$proc/map_files/$range")" != "$st" ]; }; then
            emit_finding "pid:$pid" "process" "unknown" "采集期间进程已退出或身份发生变化。" \
                "unknown" "进程已退出" "$(cpu_assess "$arch" "$CPU_STATE")" "" "" "" "" "" "$arch" "" "false" "" ""
            continue
        fi

        if [ "$verified" -eq 1 ] && [ "$version_conflict" -eq 0 ]; then
            printf '%s\n' "$st" >> "$ACTIVE_FILE"
        fi

        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(assess_jdk_build "$root" "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
        [ -n "$build" ] || build="unknown"

        vmtext=$(lower "${vm:-} ${vmname:-}")
        case $vmtext in *openj9*) openj9=1 ;; *) openj9=0 ;; esac

        fn=0
        mit=0
        case $measured_state in
            mitigated) fn=1; mit=1 ;;
            unmitigated) fn=1 ;;
            '')
                if [ "$ASSUME_FEFF" -eq 1 ]; then
                    assumed_state=$(launcher_flag_assessment "$flags")
                    case $assumed_state in
                        mitigated) fn=1; mit=1 ;;
                        unmitigated) fn=1 ;;
                    esac
                    if [ "$fn" -eq 1 ]; then
                        add_note "裁决采用显式信任的启动参数，未通过 jcmd 核实"
                    fi
                fi ;;
        esac
        identity_confidence=strong
        [ "$weak_identity" -eq 0 ] || identity_confidence=weak
        disk_hint_version="" disk_hint_vendor="" disk_hint_product="" disk_hint_build=""
        if [ "$weak_identity" -eq 1 ] || [ "$version_conflict" -eq 1 ]; then
            disk_hint_version=$disk_version
            disk_hint_vendor=$vendor
            disk_hint_product=$product
            disk_hint_build=$build
        fi

        if [ "$version_conflict" -eq 1 ]; then
            status=unknown
            reason="jcmd 自报运行构建与磁盘 release 不一致"
            build=unknown
            bevid=$reason
            version=$runtime_version
            vendor="" product="" vm=""
        elif [ "$weak_identity" -eq 1 ]; then
            status=potential
            reason="运行库身份未核实：inode 相同、设备号不同，磁盘构建仅供参考"
            if [ "$disk_hint_build" = unfixed ]; then
                reason="$reason；发现受影响的磁盘构建"
            fi
            build=candidate
            bevid=$reason
            version=$runtime_version
            vendor="" product="" vm=""
        elif [ "$openj9" -eq 1 ]; then
            build="outside_scope"
            bevid="运行在 Eclipse OpenJ9（自有 Base64 实现，不经过 HotSpot intrinsic）"
            status="not_affected"
            reason="OpenJ9 不使用 HotSpot 的 Base64 intrinsic，不在本次影响面"
            add_note "OpenJ9 走自有实现；公告未单列该实现，若厂商有相反说明以厂商为准"
        else
            status=$(classify "$build" "$cpu" "$mit" "$fn" "$(norm_arch "$arch")")
            reason=$(make_reason "$status" "$build" "$bevid" "$cpu" "$mit" "$(norm_arch "$arch")")
            case "$status:$assumed_state" in
                mitigated:mitigated) reason="按显式信任的 JVM 启动参数估算为已缓解，尚无 jcmd 实测。" ;;
                affected:unmitigated) reason="按显式信任的 JVM 启动参数估算为受影响，尚无 jcmd 实测。" ;;
            esac
        fi

        emit_finding "pid:$pid" "process" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root_disp" "$vendor" "$product" "$vm" "$arch" \
            "$flags" "$feff" "$container" "$NOTES" \
            "$identity_confidence" "$disk_hint_version" "$disk_hint_vendor" "$disk_hint_product" "$disk_hint_build"
    done <<< "$pidlist"
}

# 非 Linux 平台：仅能做启动器级别的线索（Go 版在 macOS 上同样不校验运行库）
scan_processes_other() {
    local pid exe root notes version vendor product vm arch cpu build bevid status reason bevid_and_build
    product=""
    command -v ps >/dev/null 2>&1 || return
    while read -r pid exe; do
        [ -n "$pid" ] || continue
        [ -n "$exe" ] || continue
        java_name "$exe" || continue
        NOTES=""
        root=$(java_root_of "$exe")
        version=""; vendor=""; vm=""; arch=""
        if [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            arch=$(release_get "$root/release" OS_ARCH)
            add_note "运行中加载的库未核实，版本取磁盘启动器"
        else
            add_note "无 release 元数据"
        fi
        [ -n "$arch" ] || arch=$ARCH_RAW
        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(build_assess "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
        [ -n "$build" ] || build="unknown"
        status=$(classify "$build" "$cpu" 0 0 "$(norm_arch "$arch")" installation)
        reason=$(make_reason "$status" "$build" "$bevid" "$cpu" 0 "$(norm_arch "$arch")")
        emit_finding "pid:$pid" "process" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root" "$vendor" "$product" "$vm" "$arch" "" "false" "" "$NOTES"
    done < <(ps -axww -o pid=,comm= 2>/dev/null)
}

# ---------------------------------------------------------------------------
# 采集：java -version 门禁
# ---------------------------------------------------------------------------
scan_java_binary() {
    local bin=$1 out version vendor vm arch product build bevid cpu status reason notes home full_version
    [ -f "$bin" ] || die "java 可执行文件不存在: $bin"
    [ -x "$bin" ] || die "java 不可执行: $bin"

    out=""
    if have timeout; then
        out=$(timeout 30 "$bin" -version 2>&1 || true)
    else
        out=$("$bin" -version 2>&1 || true)
    fi

    version=$(printf '%s\n' "$out" | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n 1)
    full_version=$(printf '%s\n' "$out" | sed -n 's/.*Runtime Environment.*(build \([^, )]*\).*/\1/p' | head -n 1)
    [ -z "$full_version" ] || version=$full_version
    home=$(java_root_of "$(resolve_symlinks "$bin")")
    vendor=""
    if [ -n "$home" ]; then
        vendor=$(release_get "$home/release" IMPLEMENTOR)
    fi

    notes=""
    vm=""
    case $(lower "$out") in
        *openj9*) vm="OpenJ9" ;;
        *hotspot*|*"server vm"*|*"client vm"*) vm="HotSpot" ;;
    esac
    product=""
    if [ -n "$home" ]; then product=$(jdk_product "$home" "$vendor"); fi
    if [ -z "$product" ]; then
        case $(lower "$out") in
            *"graalvm enterprise"*)
                vendor=${vendor:-Oracle}
                product="Oracle GraalVM Enterprise Edition" ;;
            *graalvm*) product="GraalVM"; notes="版本输出提示 GraalVM" ;;
            *"java(tm) se runtime environment"*)
                vendor=${vendor:-Oracle}
                product="Oracle Java SE" ;;
        esac
    fi
    arch=$ARCH_RAW

    cpu=$(cpu_assess "$arch" "$CPU_STATE")
    bevid_and_build=$(assess_jdk_build "$home" "$version" "$vendor" "$product" "$vm")
    build=$(printf '%s' "$bevid_and_build" | cut -f1)
    bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
    [ -n "$build" ] || build="unknown"

    # -version 门禁没有可信的启动参数证据，按未缓解处理
    status=$(classify "$build" "$cpu" 0 0 "$(norm_arch "$arch")" installation)
    reason=$(make_reason "$status" "$build" "$bevid" "$cpu" 0 "$(norm_arch "$arch")" \
        "（本项来自 java -version 门禁，未校验运行参数）")

    emit_finding "java:$bin" "java-binary" "$status" "$reason" "$build" "$bevid" \
        "$cpu" "$version" "$bin" "$vendor" "${product:-}" "${vm:-}" "$arch" "" "false" "" "$notes"
}

# ---------------------------------------------------------------------------
# 采集：已知受影响应用目录
# ---------------------------------------------------------------------------
scan_apps() {
    local root=$1 depth=$2 d name token label exposure
    [ -d "$root" ] || die "--apps 路径不是目录: $root"
    root=$(real_path "$root")

    while IFS= read -r d; do
        [ -n "$d" ] || continue
        [ "$d" = "$root" ] && continue
        name=${d##*/}
        case $name in .*) continue ;; esac
        token=$(printf '%s' "$name" | sed 's/[-_]//g' | tr '[:upper:]' '[:lower:]')
        label=""
        exposure=""
        case $token in
            *keycloak*)     label="Keycloak";     exposure="默认配置下无需认证即可触发 RCE" ;;
            *jira*)         label="Atlassian Jira"; exposure="默认配置下无需认证即可触发 RCE" ;;
            *confluence*)   label="Atlassian Confluence"; exposure="默认配置下无需认证即可触发 RCE" ;;
            *artifactory*)  label="JFrog Artifactory"; exposure="默认配置下无需认证即可触发 RCE" ;;
            *jenkins*)      label="Jenkins";      exposure="默认配置下无需认证即可触发 RCE" ;;
            *pingfederate*) label="PingFederate"; exposure="默认配置下无需认证即可触发 RCE" ;;
            *kafka*)        label="Apache Kafka Broker"; exposure="认证后可触发 RCE" ;;
            *solr*)         label="Apache Solr";  exposure="认证后可触发 RCE" ;;
            *elasticsearch*) label="Elasticsearch"; exposure="认证后可触发 RCE" ;;
            *gerrit*)       label="Gerrit";       exposure="认证后可触发 RCE" ;;
            *spinnaker*)    label="Spinnaker";    exposure="认证后可触发 RCE" ;;
        esac
        [ -n "$label" ] || continue
        printf '%s\037%s\037%s\n' "$label" "$exposure" "$d" >> "$APP_FILE"
    done < <(find "$root" -maxdepth "$depth" -type d -not -path '*/.*' 2>/dev/null | LC_ALL=C sort)
}

# ---------------------------------------------------------------------------
# 采集：演示样本（完全不采集本机数据）
# ---------------------------------------------------------------------------
demo_cpuinfo() {
    local extra=$1
    local f="fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc bmi1 avx2 $extra"
    printf 'processor\t: 0\nflags\t\t: %s\nprocessor\t: 1\nflags\t\t: %s\n' "$f" "$f"
}

run_demo() {
    local with="avx512f avx512bw avx512vbmi bmi2"
    local without="avx512f avx512bw bmi2"
    local i=0 case_n case_label version vendor product vm flags cpu build bevid status reason cpuraw
    local total=0 bad=0

    demo_case() {
        local label=$1 version=$2 vendor=$3 product=$4 vm=$5 flags=$6 cpuextra=$7 expect=$8
        local cpuraw cpu build bevid mit status
        cpuraw=$(demo_cpuinfo "$cpuextra" | cpu_from_text)
        cpu=$(cpu_assess "x86_64" "$(printf '%s' "$cpuraw" | cut -d' ' -f1)")
        bevid_and_build=$(build_assess "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
        mit=0
        mitigation_from_flags "$flags" && mit=1
        status=$(classify "$build" "$cpu" "$mit" 1 amd64)

        total=$((total + 1))
        if [ "$FORMAT" != txt ]; then
            emit_finding "demo:$total" demo "$status" "$label" "$build" "$bevid" "$cpu" "$version" "" "$vendor" "$product" "$vm" x86_64 "$flags" true "" ""
            [ "$status" = "$expect" ] || bad=$((bad + 1))
            return
        fi
        printf '[demo %d] %s\n' "$total" "$label"
        printf '  Java: %s（厂商/产品: %s / %s）\n' "${version:-未知}" "${vendor:-未知}" "${product:-未知}"
        printf '  CPU: x86_64，AVX-512 VBMI %s\n' "$(case $cpu in present) echo 存在;; absent) echo 不存在;; mixed) echo 不一致;; *) echo 未知;; esac)"
        printf '  构建判定: %s\n' "$build"
        printf '  判定: %s\n' "$(status_label "$status")"
        [ "$status" = "$expect" ] || { printf '  [x] 与预期(%s)不一致\n' "$expect"; bad=$((bad + 1)); }
        printf '\n'
    }

    [ "$FORMAT" != txt ] || printf '%s · %s 演示（固定样本，不采集本机数据）\n\n' "$NICKNAME" "$CVE"

    demo_case "受影响 — OpenJDK 17.0.21 + AVX-512 VBMI" \
        17.0.21 openjdk OpenJDK HotSpot "" "$with" affected

    demo_case "已修复 — OpenJDK 21.0.13.1 + AVX-512 VBMI" \
        21.0.13.1+2 openjdk OpenJDK HotSpot "" "$with" not_affected

    demo_case "受影响 — Debian 21.0.13+9-1~deb13u2" \
        21.0.13+9-1~deb13u2 debian "" HotSpot "" "$with" affected

    demo_case "已缓解 — 17.0.21 且禁用 Base64 intrinsic" \
        17.0.21 openjdk OpenJDK HotSpot "-XX:-UseBASE64Intrinsics" "$with" mitigated

    demo_case "不受影响 — 17.0.21 但 CPU 无 VBMI" \
        17.0.21 openjdk OpenJDK HotSpot "" "$without" not_affected

    demo_case "无法判断 — 17.0.21.0.4（已知受影响与已修复之间的空档）" \
        17.0.21.0.4 openjdk OpenJDK HotSpot "" "$with" unknown

    case $FORMAT in
        json) report_json ;;
        csv) report_csv ;;
        *) printf '合计 %d 个样本，异常 %d 个。\n' "$total" "$bad" ;;
    esac
    [ "$bad" -eq 0 ] || return 1
    return 0
}

status_label() {
    case $1 in
        affected)     printf '受影响' ;;
        potential)    printf '待确认' ;;
        mitigated)    printf '已缓解' ;;
        not_affected) printf '不受影响' ;;
        unknown)      printf '无法判断' ;;
        *)            printf '%s' "$1" ;;
    esac
}

build_label() {
    case $1 in
        fixed)        printf '已修复' ;;
        unfixed)      printf '未修复（受影响构建）' ;;
        outside_scope) printf '范围外' ;;
        candidate)    printf '需确认' ;;
        unknown)      printf '未知' ;;
        *)            printf '%s' "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
total_count() { wc -l < "$FIND_FILE" 2>/dev/null | tr -d ' '; }
status_count() { awk -F'\037' -v s="$1" '$3 == s { c++ } END { print c + 0 }' "$FIND_FILE"; }
apps_count() { wc -l < "$APP_FILE" 2>/dev/null | tr -d ' '; }

brief_name() {
    local id=$1 kind=$2 version=$3
    case $kind in
        installation) printf '%s · Java %s' "${id#install:}" "${version:-未知}" ;;
        *)            printf '%s · Java %s' "$id" "${version:-未知}" ;;
    esac
}

txt_header() {
    printf '%s · %s（规则 %s · 模式 %s · bash 单文件版）\n' "$NICKNAME" "$CVE" "$RULES_AS_OF" "$MODE_NAME"
    printf '主机: %s / %s    CPU: %s（%s）\n' "$(hostname 2>/dev/null || echo unknown)" "$ARCH_RAW" "$CPU_STATE" "$CPU_SOURCE"
}

report_txt() {
    local total affected potential mitigated notaffected unknown
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build

    total=$(total_count)
    affected=$(status_count affected)
    potential=$(status_count potential)
    mitigated=$(status_count mitigated)
    notaffected=$(status_count not_affected)
    unknown=$(status_count unknown)

    txt_header
    if [ "$total" -eq 0 ]; then
        printf '未找到可评估的 Java 资产。\n'
    else
        printf '已检查 %d 项 · 受影响 %d · 待确认 %d · 已缓解 %d · 不受影响 %d · 无法判断 %d\n' \
            "$total" "$affected" "$potential" "$mitigated" "$notaffected" "$unknown"
    fi

    if [ "$total" -gt 0 ]; then
        if [ "$affected" -gt 0 ]; then
            printf '结论: 存在受影响资产，请立即升级到修复构建，或加缓解参数后重启\n'
        elif [ "$potential" -gt 0 ]; then
            printf '结论: 无已确认受影响资产，但有需确认项，请核对构建来源与厂商补丁\n'
        elif [ "$unknown" -gt 0 ]; then
            printf '结论: 未命中失败级别，但存在证据不足的资产，建议补充 release/CPU 证据\n'
        else
            printf '结论: 未发现受影响资产\n'
        fi
    fi

    if [ "$DETAILS" -eq 0 ]; then
        while IFS=$'\037' read -r id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build; do
            case $status in
                affected|potential|unknown)
                    printf '  %s  %s\n' "$(status_label "$status")" "$(brief_name "$id" "$kind" "$version")" ;;
            esac
        done < "$FIND_FILE"

        local napps
        napps=$(apps_count)
        if [ "$napps" -gt 0 ]; then
            printf '  已发现 %s 个已知受影响应用的安装目录（--details 查看）\n' "$napps"
        fi
        local nwarn
        nwarn=$(wc -l < "$WARN_FILE" 2>/dev/null | tr -d ' ')
        [ "${nwarn:-0}" -gt 0 ] && printf '提示: %s 条采集提示（--details 查看）\n' "$nwarn"
        return
    fi

    # ---- 详细模式 ----
    while IFS=$'\037' read -r id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build; do
        printf '\n=== %s [%s]\n' "$id" "$kind"
        printf '  状态      : %s（构建判定: %s；CPU: %s）\n' "$(status_label "$status")" "$(build_label "$build")" "$cpu"
        printf '  版本      : %s\n' "${version:-未知}"
        printf '  厂商/产品 : %s / %s\n' "${vendor:-未知}" "${product:-未知}"
        printf '  VM/架构   : %s / %s\n' "${vm:-未知}" "${arch:-未知}"
        printf '  Java Home : %s\n' "${jhome:-—}"
        if [ -n "$disk_hint_build" ]; then
            printf '  磁盘证据  : %s · %s / %s · %s（仅供参考）\n' \
                "${disk_hint_version:-未知}" "${disk_hint_vendor:-未知}" "${disk_hint_product:-未知}" "$(build_label "$disk_hint_build")"
        fi
        [ -n "$flags" ] && printf '  启动参数  : %s（有效率: %s）\n' "$flags" "$feff"
        [ -n "$container" ] && printf '  容器线索  : %s\n' "$container"
        printf '  依据      : %s\n' "${reason:-—}"
        [ -n "$notes" ] && printf '  备注      : %s\n' "$notes"
    done < "$FIND_FILE"

    local napps nwarn
    napps=$(apps_count)
    printf '\n=== 已知受影响应用清点\n'
    if [ "${napps:-0}" -eq 0 ]; then
        printf '  未发现已知受影响应用的安装目录%s。\n' "${APPS_DIR:+（扫描 $APPS_DIR）}"
        printf '  注意：目录存在本身不等于可利用，仍需核查该应用实际使用的 JVM。\n'
    else
        while IFS=$'\037' read -r id kind path; do
            printf '  - %s（%s）— %s\n' "$id" "$kind" "$path"
        done < "$APP_FILE"
        printf '  注意：目录存在本身不等于可利用，仍需核查该应用实际使用的 JVM。\n'
    fi

    nwarn=$(wc -l < "$WARN_FILE" 2>/dev/null | tr -d ' ')
    if [ "${nwarn:-0}" -gt 0 ]; then
        printf '\n=== 采集提示\n'
        while IFS= read -r id; do printf '  - %s\n' "$id"; done < "$WARN_FILE"
    fi
}

json_escape() {
    printf '%s' "${1:-}" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

jstr() { printf '"%s"' "$(json_escape "${1:-}")"; }

json_notes() {
    local s=${1:-} item sep="" out=""
    printf '['
    [ -n "$s" ] || { printf ']'; return; }
    local oldifs=$IFS
    IFS='|'
    for item in $s; do
        item=$(trim "$item")
        [ -n "$item" ] || continue
        printf '%s%s' "$sep" "$(jstr "$item")"
        sep=","
    done
    IFS=$oldifs
    printf ']'
}

report_json() {
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build
    local first=1 total affected potential mitigated notaffected unknown apps

    total=$(total_count)
    affected=$(status_count affected)
    potential=$(status_count potential)
    mitigated=$(status_count mitigated)
    notaffected=$(status_count not_affected)
    unknown=$(status_count unknown)
    apps=$(apps_count)

    printf '{\n'
    printf '  "cve": %s,\n' "$(jstr "$CVE")"
    printf '  "nickname": %s,\n' "$(jstr "$NICKNAME")"
    printf '  "rules_as_of": %s,\n' "$(jstr "$RULES_AS_OF")"
    printf '  "mode": %s,\n' "$(jstr "$MODE_NAME")"
    printf '  "summary": {"total": %s, "by_status": {"affected": %s, "potential": %s, "mitigated": %s, "not_affected": %s, "unknown": %s}},\n' \
        "${total:-0}" "${affected:-0}" "${potential:-0}" "${mitigated:-0}" "${notaffected:-0}" "${unknown:-0}"
    printf '  "cpu": {"arch": %s, "state": %s, "required_features": %s, "counts": %s, "source": %s},\n' \
        "$(jstr "$ARCH_RAW")" "$(jstr "$CPU_STATE")" "$(jstr "$REQ_FEATURES")" "$(jstr "$CPU_COUNTS")" "$(jstr "$CPU_SOURCE")"

    printf '  "coverage": {"root_max_depth": %s, "root_depth_boundaries": %s, "root_scan_errors": %s, "unreadable_process_maps": %s},\n'         "$((10#$ROOT_DEPTH))" "$ROOT_DEPTH_BOUNDARIES" "$ROOT_SCAN_ERRORS" "$LIMITED_PROCS"

    printf '  "warnings": ['
    first=1
    while IFS= read -r id; do
        [ -n "$id" ] || continue
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '%s' "$(jstr "$id")"
    done < "$WARN_FILE"
    printf '],\n'

    printf '  "findings": [\n'
    first=1
    while IFS=$'\037' read -r id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build; do
        [ -n "$id" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"id": %s, "kind": %s, "status": %s, "reason": %s, ' \
            "$(jstr "$id")" "$(jstr "$kind")" "$(jstr "$status")" "$(jstr "$reason")"
        printf '"build_assessment": %s, "build_evidence": %s, "cpu_assessment": %s, ' \
            "$(jstr "$build")" "$(jstr "$bevid")" "$(jstr "$cpu")"
        printf '"version": %s, "java_home": %s, "vendor": %s, "product": %s, "vm": %s, "arch": %s, ' \
            "$(jstr "$version")" "$(jstr "$jhome")" "$(jstr "$vendor")" "$(jstr "$product")" "$(jstr "$vm")" "$(jstr "$arch")"
        printf '"flags": %s, "flags_effective": %s, "container": %s, "notes": %s' \
            "$(jstr "$flags")" "${feff:-false}" "$(jstr "$container")" "$(json_notes "$notes")"
        if [ -n "$identity_confidence" ]; then
            printf ', "identity_confidence": %s' "$(jstr "$identity_confidence")"
        fi
        if [ -n "$disk_hint_build" ]; then
            printf ', "disk_evidence": {"version": %s, "vendor": %s, "product": %s, "build_assessment": %s}' \
                "$(jstr "$disk_hint_version")" "$(jstr "$disk_hint_vendor")" \
                "$(jstr "$disk_hint_product")" "$(jstr "$disk_hint_build")"
        fi
        printf '}'
    done < "$FIND_FILE"
    printf '\n  ],\n'

    printf '  "apps": [\n'
    first=1
    while IFS=$'\037' read -r id kind path; do
        [ -n "$id" ] || continue
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        printf '    {"name": %s, "exposure": %s, "path": %s}' "$(jstr "$id")" "$(jstr "$kind")" "$(jstr "$path")"
    done < "$APP_FILE"
    printf '\n  ]\n'
    printf '}\n'
}

csv_field() {
    local v=${1:-}
    case $v in
        [=+@-]*) v="'$v" ;;
    esac
    v=${v//\"/\"\"}
    printf '"%s"' "$v"
}

csv_line() {
    local out="" sep="" f
    for f in "$@"; do
        out="$out$sep$(csv_field "$f")"
        sep=","
    done
    printf '%s' "$out"
}

report_csv() {
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build
    printf '%s\n' "cve,rules_as_of,mode,id,kind,status,reason,build_assessment,build_evidence,cpu_assessment,version,java_home,vendor,product,vm,arch,cpu_state,cpu_source,patch,patch_ref,flags,flags_effective,container,notes,identity_confidence,disk_version,disk_vendor,disk_product,disk_build_assessment"
    while IFS=$'\037' read -r id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build; do
        [ -n "$id" ] || continue
        csv_line "$CVE" "$RULES_AS_OF" "$MODE_NAME" "$id" "$kind" "$status" "$reason" \
            "$build" "$bevid" "$cpu" "$version" "$jhome" "$vendor" "$product" "$vm" "$arch" \
            "$CPU_STATE" "$CPU_SOURCE" "" "" "$flags" "$feff" "$container" "$notes" \
            "$identity_confidence" "$disk_hint_version" "$disk_hint_vendor" "$disk_hint_product" "$disk_hint_build"
        printf '\n'
    done < "$FIND_FILE"
}

report_apps_csv() {
    local id kind path
    while IFS=$'\037' read -r id kind path; do
        [ -n "$id" ] || continue
        csv_line "$CVE" "$RULES_AS_OF" "$MODE_NAME" "$path" "app" "inventory" "$kind" "-" "-" "-" "" "$path" "" "" "" "" "$CPU_STATE" "$CPU_SOURCE" "" "" "" "false" "" "$id" "" "" "" "" ""
        printf '\n'
    done < "$APP_FILE"
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            -h|--help)    usage; exit 0 ;;
            -V|--version) printf '%s %s\n' "$PROG" "$SCRIPT_VERSION"; exit 0 ;;
            --jdk)        [ $# -ge 2 ] || die "--jdk 需要一个路径"; JDK_ARGS[${#JDK_ARGS[@]}]=$2; shift 2 ;;
            --pid)        [ $# -ge 2 ] || die "--pid 需要一个进程号"
                          case $2 in ''|*[!0-9]*) die "--pid 需要正整数: $2" ;; esac
                          PID_ARGS[${#PID_ARGS[@]}]=$2; shift 2 ;;
            --java-path)  [ $# -ge 2 ] || die "--java-path 需要一个路径"; JAVA_BINS[${#JAVA_BINS[@]}]=$2; shift 2 ;;
            --cpuinfo)    [ $# -ge 2 ] || die "--cpuinfo 需要一个路径"; CPUINFO=$2; shift 2 ;;
            --apps)       [ $# -ge 2 ] || die "--apps 需要一个目录"; APPS_DIR=$2; shift 2 ;;
            --apps-depth) [ $# -ge 2 ] || die "--apps-depth 需要数字"
                          case $2 in ''|*[!0-9]*) die "--apps-depth 需要正整数: $2" ;; esac
                          APPS_DEPTH=$2; shift 2 ;;
            --format)     [ $# -ge 2 ] || die "--format 需要 txt/json/csv"
                          case $2 in txt|json|csv) FORMAT=$2 ;; *) die "未知格式: $2" ;; esac
                          shift 2 ;;
            --json)       FORMAT=json; shift ;;
            --csv)        FORMAT=csv; shift ;;
            --out)        [ $# -ge 2 ] || die "--out 需要一个文件路径"; OUT=$2; shift 2 ;;
            --fail-on)    [ $# -ge 2 ] || die "--fail-on 需要一个状态列表"; FAIL_ON=$2; shift 2 ;;
            --assume-flags-effective) ASSUME_FEFF=1; shift ;;
            --root)       [ $# -ge 2 ] || die "--root 需要一个目录"; ROOT_ARGS[${#ROOT_ARGS[@]}]=$2; shift 2 ;;
            --root-depth) [ $# -ge 2 ] || die "--root-depth 需要数字"
                          case $2 in ''|*[!0-9]*) die "--root-depth 需要正整数: $2" ;; esac
                          ROOT_DEPTH=$2; shift 2 ;;
            --jcmd)       JCMD=1; shift ;;
            --processes-only) PROC_ONLY=1; shift ;;
            --no-processes)   NO_PROC=1; shift ;;
            --details)    DETAILS=1; shift ;;
            --demo)       DEMO=1; shift ;;
            --quiet)      QUIET=1; shift ;;
            --)           shift; break ;;
            -*)           die "未知参数: $1（用 --help 查看用法）" ;;
            *)            die "多余的参数: $1" ;;
        esac
    done

    if [ "$PROC_ONLY" -eq 1 ] && [ "$NO_PROC" -eq 1 ]; then
        die "--processes-only 与 --no-processes 不能同时使用"
    fi
    if [ "$PROC_ONLY" -eq 1 ] && [ ${#JDK_ARGS[@]} -gt 0 ]; then
        die "--processes-only 与 --jdk 不能同时使用"
    fi
    if [ "$PROC_ONLY" -eq 1 ] && [ ${#ROOT_ARGS[@]} -gt 0 ]; then
        die "--processes-only 与 --root 不能同时使用"
    fi

    local status_pattern='(affected|potential|mitigated|not_affected|unknown)'
    [[ $FAIL_ON =~ ^$status_pattern(,$status_pattern)*$ ]] ||
        die "--fail-on 只接受 affected,potential,mitigated,not_affected,unknown"
}

cleanup() {
    [ -n "${WORK:-}" ] && [ -d "$WORK" ] && rm -rf "$WORK"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
# Nginx2Root mode reuses the report format helpers and only reads local files.
nginx2root_reference() {
    local raw=$1 cve minimum feature status comma=
    printf '['
    while read -r cve minimum feature; do
        status=unknown
        if { [[ $raw == 1.30.* ]] && vge "$raw" 1.30.7; } ||
           { [[ $raw == 1.31.* ]] && vge "$raw" 1.31.9; }; then
            status=meets_upstream_reference
        elif [ -n "$raw" ]; then
            if vlt "$raw" "$minimum"; then status=outside_upstream_range
            elif vle "$raw" 1.31.8; then status=potential
            fi
        fi
        printf '%s{"cve":"%s","status":"%s","feature":"%s"}' "$comma" "$cve" "$status" "$feature"
        comma=,
    done <<'RULES'
CVE-2026-123007 1.9.5 http2
CVE-2026-123633 1.19.7 http2_upstream
CVE-2026-123634 0.6.18 resolver_proxy_mirror
CVE-2026-121810 1.25.0 http3_upstream
CVE-2026-113425 0.5.33 mail_proxy_auth_http
RULES
    printf ']'
}

nginx2root_version() {
    local file=$1 size marks
    [ -f "$file" ] || return 0
    size=$(stat -Lc '%s' -- "$file" 2>/dev/null) || return 0
    [[ $size =~ ^[0-9]+$ ]] && [ "$size" -le 16777216 ] || return 0
    [[ $(head -c 4 -- "$file" 2>/dev/null) == $'\x7fELF' ]] || return 0
    marks=$(head -c 16777216 -- "$file" 2>/dev/null |
        LC_ALL=C grep -aEo 'nginx/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\b|nginx-plus|Tengine|openresty' | LC_ALL=C sort -u)
    if [[ $marks =~ ^nginx/([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

nginx2root_config() {
    local config size count=0
    local -a configs=()
    if [ "$#" -gt 0 ]; then
        configs=("$@")
    else
        configs=(/etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /usr/local/nginx/conf/nginx.conf)
    fi
    (
        for config in "${configs[@]}"; do
            [ -f "$config" ] || continue
            count=$((count + 1))
            [ "$count" -le 64 ] || { printf '@skipped\n'; break; }
            size=$(stat -Lc '%s' -- "$config" 2>/dev/null) || size=
            if [[ ! $size =~ ^[0-9]+$ ]] || [ "$size" -gt 65536 ] || [ ! -r "$config" ]; then
                printf '@skipped\n'; continue
            fi
            if ! head -c 65536 -- "$config" 2>/dev/null; then printf '@skipped\n'; continue; fi
            printf '\n@file\n'
        done
    ) | awk '
        /^@file$/ { files++; next }
        /^@skipped$/ { skipped++; next }
        {
            gsub(/"[^"]*"|\047[^\047]*\047/, "", $0)
            sub(/#.*/, "", $0)
            if ($0 ~ /(^|[;{}[:space:]])http2[[:space:]]+on([[:space:]]|;)/ ||
                $0 ~ /(^|[;{}[:space:]])listen[[:space:]]+[^;]*[[:space:]]http2([[:space:]]|;)/) h2=1
            if ($0 ~ /(^|[;{}[:space:]])http2[[:space:]]+off([[:space:]]|;)/) h2off=1
            if ($0 ~ /(^|[;{}[:space:]])http3[[:space:]]+on([[:space:]]|;)/ ||
                $0 ~ /(^|[;{}[:space:]])listen[[:space:]]+[^;]*[[:space:]]quic([[:space:]]|;)/) h3=1
            if ($0 ~ /(^|[;{}[:space:]])resolver[[:space:]]+/) resolver=1
            if ($0 ~ /(^|[;{}[:space:]])(proxy_pass|grpc_pass|fastcgi_pass|uwsgi_pass|scgi_pass)[[:space:]]+/) upstream=1
            if ($0 ~ /(^|[;{}[:space:]])proxy_pass[[:space:]]+[^;]*\$/) dynamic=1
            if ($0 ~ /(^|[;{}[:space:]])mirror[[:space:]]+/) mirror=1
            if ($0 ~ /(^|[;{}[:space:]])mirror_request_body[[:space:]]+off([[:space:]]|;)/) mirror_off=1
            if ($0 ~ /(^|[;{}[:space:]])ssi[[:space:]]+on([[:space:]]|;)/) ssi=1
            if ($0 ~ /(^|[;{}[:space:]])mail[[:space:]]*\{/) mail=1
            if ($0 ~ /(^|[;{}[:space:]])proxy[[:space:]]+on([[:space:]]|;)/) mail_proxy=1
            if ($0 ~ /(^|[;{}[:space:]])auth_http[[:space:]]+/) auth=1
        }
        function b(value) { return value ? "true" : "false" }
        END {
            printf "{\"scope\":\"disk_directive_hints\",\"files_examined\":%d,\"skipped\":%d,", files, skipped
            printf "\"http2_on\":%s,\"http2_off\":%s,\"http3_or_quic\":%s,", b(h2), b(h2off), b(h3)
            printf "\"upstream\":%s,\"resolver\":%s,\"dynamic_proxy_pass\":%s,", b(upstream), b(resolver), b(dynamic)
            printf "\"mirror\":%s,\"mirror_request_body_off\":%s,\"ssi\":%s,", b(mirror), b(mirror_off), b(ssi)
            printf "\"mail\":%s,\"mail_proxy\":%s,\"auth_http\":%s}", b(mail), b(mail_proxy), b(auth)
        }'
}

nginx2root_sctp() {
    local file loaded=false automatic_block_hint=false
    [ ! -d /sys/module/sctp ] || loaded=true
    for file in /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf /lib/modprobe.d/*.conf; do
        [ -f "$file" ] && [ -r "$file" ] || continue
        if grep -Eq '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+(/usr)?/bin/false([[:space:]]|$)' "$file" 2>/dev/null; then
            automatic_block_hint=true
            break
        fi
    done
    printf '{"kernel_release":%s,"module_visible":%s,"modprobe_install_block_hint":%s,"patch_status":"unknown"}' \
        "$(jstr "$(cat /proc/sys/kernel/osrelease 2>/dev/null || :)")" "$loaded" "$automatic_block_hint"
}

apache_reference() {
    local raw=$1 scope=${2:-httpd}
    if [ "$scope" = module ]; then
        [[ $raw =~ ^2\.0\.([0-9]+)$ ]] || { printf unknown; return; }
        if vlt "$raw" 2.0.8; then printf outside_upstream_range
        elif vle "$raw" 2.0.42; then printf potential
        else printf unknown
        fi
    else
        [[ $raw =~ ^2\.4\.([0-9]+)$ ]] || { printf unknown; return; }
        if vlt "$raw" 2.4.55; then printf outside_upstream_range
        elif vle "$raw" 2.4.70; then printf potential
        else printf meets_upstream_reference
        fi
    fi
}

apache_config_hints() {
    local file size count=0
    (
        for file in /etc/apache2/apache2.conf /etc/apache2/{mods,conf,sites}-enabled/*.conf \
                    /etc/apache2/mods-enabled/*.load /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf \
                    /etc/httpd/conf.modules.d/*.conf /usr/local/apache2/conf/httpd.conf; do
            [ -f "$file" ] || continue
            count=$((count + 1))
            [ "$count" -le 64 ] || { printf '@skipped\n'; break; }
            size=$(stat -Lc '%s' -- "$file" 2>/dev/null) || size=
            if ! [[ $size =~ ^[0-9]+$ ]] || [ "$size" -gt 65536 ] || ! head -c 65536 -- "$file" 2>/dev/null; then
                printf '\n@skipped\n'; continue
            fi
            printf '\n@file\n'
        done
    ) | awk '
        /^@file$/ {files++; next}
        /^@skipped$/ {skipped++; next}
        { sub(/#.*/, ""); gsub(/"/, ""); $0=tolower($0) }
        $1 == "loadmodule" && $2 == "http2_module" {mod=1}
        $1 == "protocols" {
            if (NF == 2 && $2 == "http/1.1") h1=1
            for (i=2; i<=NF; i++) {
                if ($i == "h2") h2=1
                if ($i == "h2c") h2c=1
            }
        }
        function b(v) { return v ? "true" : "false" }
        END {
            printf "{\"scope\":\"disk_directive_hints\",\"files_examined\":%d,\"skipped\":%d,", files, skipped
            printf "\"h2\":%s,\"h2c\":%s,\"http1_only_directive\":%s,\"load_module\":%s}", b(h2),b(h2c),b(h1),b(mod)
        }'
}

apache_mapped_http2() {
    local file=$1 data limit=1048576
    [ -r "$file" ] || { printf null; return; }
    if ! data=$(head -c "$((limit + 1))" -- "$file" 2>/dev/null); then printf null; return; fi
    if grep -Eq '/mod_http2\.so( \(deleted\))?$' <<< "$data"; then printf true
    elif [ "${#data}" -ge "$((limit - 1))" ]; then printf null
    else printf false
    fi
}

apache_inventory() {
    local format=$1 proc name pid path id start row= seen=' ' rows=0 disk=0 comma= version reference mapped config
    local gate=0 modules=0 unknown=0
    config=$(apache_config_hints)
    for proc in /proc/[0-9]*; do
        [ -r "$proc/comm" ] || continue
        IFS= read -r name < "$proc/comm" 2>/dev/null || continue
        case $name in apache2|httpd) ;; *) continue ;; esac
        ((rows < 24)) || break
        pid=${proc##*/}
        start=$(java_process_start "$pid")
        path=$(readlink "$proc/exe" 2>/dev/null || :)
        id=$(file_id "$proc/exe" || :)
        version=$(apache_version "$proc/exe" httpd)
        mapped=$(apache_mapped_http2 "$proc/maps")
        if [[ -z $id || -z $start || $(file_id "$proc/exe") != "$id" ||
              $(java_process_start "$pid") != "$start" ]]; then
            version=
            mapped=null
        elif [[ $path == /* && $(file_id "$proc/root$path") == "$id" ]]; then
            seen+="$id "
        fi
        reference=$(apache_reference "$version")
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        if [ "$format" = json ]; then
            row+="$comma{\"kind\":\"process\",\"pid\":$pid,\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"version_status\":$(jstr "$reference"),\"mod_http2_mapped\":$mapped}"
            comma=,
        else
            printf 'Apache PID %s · %q · %s · %s · mod_http2 映射 %s\n' "$pid" "$path" "${version:-版本未知}" "$reference" "$mapped"
        fi
        rows=$((rows + 1))
    done
    for path in "$(type -P apache2 || :)" "$(type -P httpd || :)" /usr/sbin/apache2 /usr/sbin/httpd /usr/local/apache2/bin/httpd; do
        [ -n "$path" ] && [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        seen+="$id "
        version=$(apache_version "$path" httpd)
        reference=$(apache_reference "$version")
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        if [ "$format" = json ]; then
            row+="$comma{\"kind\":\"installation\",\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"version_status\":$(jstr "$reference")}"
            comma=,
        else
            printf 'Apache 磁盘安装 · %q · %s · %s\n' "$path" "${version:-版本未知}" "$reference"
        fi
        disk=$((disk + 1))
    done
    for path in /usr/lib/apache2/modules/mod_http2.so /usr/lib64/httpd/modules/mod_http2.so /usr/lib/httpd/modules/mod_http2.so /usr/local/apache2/modules/mod_http2.so; do
        [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        seen+="$id "
        version=$(apache_version "$path" module)
        reference=$(apache_reference "$version" module)
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        if [ "$format" = json ]; then
            row+="$comma{\"kind\":\"module_installation\",\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"version_status\":$(jstr "$reference")}"
            comma=,
        else
            printf 'Apache 磁盘模块 · %q · %s · %s\n' "$path" "${version:-版本未知}" "$reference"
        fi
        modules=$((modules + 1))
    done
    local status=observed
    ((rows + disk + modules > 0)) || status=not_observed
    if [ "$format" = json ]; then
        printf '{"status":"%s","cve":"CVE-2026-119618","patch_verified":false,"configuration":%s,"proc_limit_reached":%s,"findings":[%s]}' \
            "$status" "$config" "$([ "$rows" -ge 24 ] && printf true || printf false)" "$row"
    else
        if [ "$status" = not_observed ]; then printf 'Apache · 当前范围未观察到安装或进程\n'; fi
        printf 'Apache CVE-2026-119618 · 磁盘配置线索: %s\n' "$config"
    fi
    if [ "$gate" -eq 1 ]; then return 1; fi
    if [ "$unknown" -eq 1 ] || [ "$rows" -ge 24 ]; then return 3; fi
    return 0
}

apache_version() {
    local file=$1 scope=$2 marks pattern='Apache/'
    [ -f "$file" ] || return 0
    [[ $(head -c 4 -- "$file" 2>/dev/null) == $'\x7fELF' ]] || return 0
    if [ "$scope" = module ]; then pattern='mod_http2(/| \(v)'; fi
    marks=$(head -c 16777216 -- "$file" 2>/dev/null |
        LC_ALL=C grep -aEo "$pattern"'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\b' | LC_ALL=C sort -u)
    if [[ $marks != *$'\n'* && $marks =~ ([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

audit_all() {
    local format=txt rc_java=0 rc_nginx=0 rc_apache=0 java_report nginx_report apache_report
    local -a java_args=(--quiet) nginx_args=()
    while (($#)); do
        case $1 in
            --json) format=json ;;
            --jcmd) java_args+=("$1") ;;
            --nginx-path|--nginx-config)
                (($# >= 2)) || die "$1 需要一个路径"
                nginx_args+=("$1" "$2"); shift ;;
            *) die "未知批量检查选项: $1" ;;
        esac
        shift
    done
    if [ "$format" = json ]; then
        java_report=$(java4shell_main "${java_args[@]}" --json) || rc_java=$?
        nginx_report=$(nginx2root_scan "${nginx_args[@]}" --json) || rc_nginx=$?
        apache_report=$(apache_inventory json) || rc_apache=$?
        printf '{"scope":"local_read_only_inventory","java4shell":%s,"nginx2root":%s,"apache":%s,"exit_codes":{"java4shell":%s,"nginx2root":%s,"apache2root":%s}}\n' \
            "${java_report:-null}" "${nginx_report:-null}" "${apache_report:-null}" "$rc_java" "$rc_nginx" "$rc_apache"
    else
        printf '=== Java4Shell ===\n'
        (java4shell_main "${java_args[@]}") || rc_java=$?
        printf '\n=== Nginx2Root ===\n'
        (nginx2root_scan "${nginx_args[@]}") || rc_nginx=$?
        printf '\n=== Apache HTTP Server ===\n'
        apache_inventory txt || rc_apache=$?
    fi
    if ((rc_java == 2 || rc_nginx == 2 || rc_apache == 2)); then return 2; fi
    if ((rc_java == 1 || rc_nginx == 1 || rc_apache == 1)); then return 1; fi
    if ((rc_java != 0 || rc_nginx != 0 || rc_apache != 0)); then return 3; fi
    return 0
}

nginx_package_hint() {
    local path=$1 owner manager result
    have timeout || return 0
    [[ $path == /* ]] || return 0
    if have dpkg-query; then
        owner=$(timeout 2 dpkg-query -S -- "$path" 2>/dev/null | awk -F ': ' -v target="$path" '$2 == target { print $1 }')
        [[ $owner =~ ^[[:alnum:].+:-]+$ ]] || return 0
        manager=dpkg
        result=$(timeout 2 dpkg-query -W -f='${binary:Package} ${Version} ${db:Status-Status}' -- "$owner" 2>/dev/null) || return 0
        [[ $result == *" installed" ]] || return 0
        result=${result% installed}
    elif have rpm; then
        manager=rpm
        result=$(timeout 2 rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}' -- "$path" 2>/dev/null) || return 0
    else
        return 0
    fi
    [ -n "$result" ] || return 0
    printf '{"manager":%s,"installed_package":%s,"patch_status":"unverified"}' "$(jstr "$manager")" "$(jstr "$(san_field "$result")")"
}

nginx2root_scan() {
    local format=txt explicit="" installed path proc pid id current raw matched
    local seen=' ' rows=0 comma= gate=0 unknown=0 total=0 config_report sctp_report package_hint
    local -A packages=()
    local -a config_paths=()
    while (($#)); do
        case $1 in
            --json|--format=json) format=json ;;
            --nginx-config)
                (($# > 1)) && [ -f "$2" ] || die "--nginx-config 需要存在的文件"
                config_paths+=("$2"); shift ;;
            --nginx-path)
                (($# > 1)) && [ -f "$2" ] || die "--nginx-path 需要存在的文件"
                explicit=$2
                shift ;;
            --help|-h)
                printf '用法: %s --nginx2root [--json] [--nginx-path PATH] [--nginx-config FILE]\n' "$PROG"
                return ;;
            *) die "未知 Nginx2Root 选项: $1" ;;
        esac
        shift
    done
    [ "$OS" = Linux ] || die "Nginx2Root 主机盘点需要 Linux /proc"
    config_report=$(nginx2root_config "${config_paths[@]}")
    sctp_report=$(nginx2root_sctp)
    if [ "$format" = json ]; then
        printf '{"status":"collected","source":"local_binary_inventory","patch_verified":false,"exploitability_confirmed":false,"sctp":%s,"configuration":%s,"sources":["https://nginx.org/en/security_advisories.html","https://cert.europa.eu/publications/security-advisories/2026-022/"],"findings":[' "$sctp_report" "$config_report"
    else
        printf 'NGINX 上游版本参考\n磁盘配置线索: %s\n内核 SCTP 线索: %s\n' "$config_report" "$sctp_report"
    fi

    nginx2root_row() {
        local kind=$1 pid=$2 path=$3 raw=$4 matched=$5 package_hint=${6:-null}
        local references
        references=$(nginx2root_reference "$raw")
        case $references in *'"status":"potential"'*) gate=1 ;; esac
        case $references in *'"status":"unknown"'*) unknown=1 ;; esac
        total=$((total + 1))
        if [ "$format" = json ]; then
            printf '%s{"kind":"%s","pid":%s,"path":%s,"version":%s,"disk_identity_matched":%s,"cves":' \
                "$comma" "$kind" "$(jstr "$pid")" "$(jstr "$(san_field "$path")")" "$(jstr "$raw")" "$matched"
            printf '%s,"package_evidence":%s}' "$references" "$package_hint"
            comma=,
        else
            printf '%s %s %q · NGINX %s · 磁盘身份匹配 %s\n' "$kind" "$pid" "$path" "${raw:-未知}" "$matched"
            printf '%s\n' "$references"
            [ "$package_hint" = null ] || printf '软件包线索: %s\n' "$package_hint"
        fi
    }

    for proc in /proc/[0-9]*; do
        [ -r "$proc/comm" ] || continue
        IFS= read -r current < "$proc/comm" 2>/dev/null || continue
        [ "$current" = nginx ] || continue
        ((rows < 24)) || break
        pid=${proc##*/}
        path=$(readlink "$proc/exe" 2>/dev/null || :)
        id=$(file_id "$proc/exe" || :)
        raw=$(nginx2root_version "$proc/exe")
        matched=false
        if [[ -z $id || $(file_id "$proc/exe") != "$id" ]]; then
            raw=
        elif [[ $path == /* && $(file_id "$proc/root$path") == "$id" ]]; then
            matched=true
            seen+="$id "
        fi
        package_hint=null
        if [[ $matched == true && $(file_id "$path") == "$id" ]]; then
            if [[ ! ${packages[$id]+found} ]]; then
                packages[$id]=$(nginx_package_hint "$path")
            fi
            package_hint=${packages[$id]:-null}
        fi
        nginx2root_row process "$pid" "$path" "$raw" "$matched" "$package_hint"
        rows=$((rows + 1))
    done
    installed=$(type -P nginx || :)
    for path in "$explicit" "$installed" /usr/sbin/nginx /usr/local/nginx/sbin/nginx; do
        [ -n "$path" ] && [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        raw=$(nginx2root_version "$path")
        seen+="$id "
        package_hint=$(nginx_package_hint "$path")
        nginx2root_row installation "" "$path" "$raw" null "${package_hint:-null}"
    done
    if [ "$format" = json ]; then
        printf '],"coverage":{"proc_limit_reached":%s}}\n' "$([ "$rows" -ge 24 ] && printf true || printf false)"
    fi
    if [ "$gate" -eq 1 ]; then return 1; fi
    if [ "$unknown" -eq 1 ] || [ "$total" -eq 0 ] || [ "$rows" -ge 24 ]; then return 3; fi
    return 0
}

java4shell_main() {
    parse_args "$@"

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/java4shell.XXXXXX") || die "无法创建临时目录"
    FIND_FILE="$WORK/findings.tsv"
    WARN_FILE="$WORK/warnings.txt"
    APP_FILE="$WORK/apps.tsv"
    ACTIVE_FILE="$WORK/active-ids"
    ROOT_COVERAGE_FILE="$WORK/root-coverage"
    : > "$ROOT_COVERAGE_FILE"
    : > "$FIND_FILE"; : > "$WARN_FILE"; : > "$APP_FILE"; : > "$ACTIVE_FILE"
    trap 'cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    if [ "$PROC_ONLY" -eq 1 ]; then MODE_NAME="processes-only"; else MODE_NAME="local"; fi

    # 输出格式推断
    if [ -z "$FORMAT" ]; then
        case ${OUT##*.} in
            json) FORMAT=json ;;
            csv)  FORMAT=csv ;;
            *)    FORMAT=txt ;;
        esac
    fi

    if [ "$DEMO" -eq 1 ]; then
        MODE_NAME=demo
        CPU_SOURCE="demo fixtures"
        if [ -n "$OUT" ]; then
            [ ! -e "$OUT" ] && [ ! -L "$OUT" ] || die "输出文件已存在: $OUT"
            local demo_rc=0
            (set -C; exec > "$OUT" || exit 2; run_demo) || demo_rc=$?
            [ "$demo_rc" -ne 2 ] || die "写入报告失败: $OUT"
            exit "$demo_rc"
        fi
        run_demo
        exit $?
    fi

    if [ -n "$OUT" ] && [ -e "$OUT" ]; then
        die "输出文件已存在，本工具不覆盖: $OUT"
    fi

    if [ ${#JDK_ARGS[@]} -gt 0 ]; then
        local d
        for d in ${JDK_ARGS[@]+"${JDK_ARGS[@]}"}; do
            [ -d "$d" ] || die "--jdk 不是目录: $d"
        done
    fi
    if [ ${#ROOT_ARGS[@]} -gt 0 ] && [ "$PROC_ONLY" -eq 0 ]; then
        local r
        for r in ${ROOT_ARGS[@]+"${ROOT_ARGS[@]}"}; do
            [ -d "$r" ] || die "--root 不是目录: $r"
        done
    fi

    cpu_probe
    note_progress "CPU 条件: $CPU_STATE（$CPU_SOURCE）"

    if [ "$EUID" -ne 0 ] 2>/dev/null; then
        warn "当前非 root 运行：部分其他用户的进程 /proc 可能不可读，进程发现可能不完整。"
    fi

    case $OS in
        Linux) : ;;
        Darwin) : ;;
        *) warn "当前平台 ($OS) 无 /proc，进程级校验降级为启动器线索。" ;;
    esac

    # --- 运行进程 ---
    if [ "$NO_PROC" -eq 0 ]; then
        if [ "$OS" = "Linux" ]; then
            note_progress "检查运行中的 JVM 进程..."
            scan_processes
        elif [ "$OS" = "Darwin" ]; then
            note_progress "检查 Java 进程（启动器线索）..."
            scan_processes_other
        else
            warn "当前平台不支持进程发现。"
        fi
    fi

    # --- 安装目录 ---
    if [ "$PROC_ONLY" -eq 0 ]; then
        note_progress "盘点 JDK 安装目录..."
        scan_installations
    fi

    # --- java -version 门禁 ---
    if [ ${#JAVA_BINS[@]} -gt 0 ]; then
        local b
        for b in ${JAVA_BINS[@]+"${JAVA_BINS[@]}"}; do
            scan_java_binary "$b"
        done
    fi

    # --- 应用清点 ---
    if [ -n "$APPS_DIR" ]; then
        note_progress "清点已知受影响应用: $APPS_DIR"
        scan_apps "$APPS_DIR" "$APPS_DEPTH"
    fi

    ROOT_DEPTH_BOUNDARIES=$(grep -cx boundary "$ROOT_COVERAGE_FILE")
    ROOT_SCAN_ERRORS=$(grep -cx error "$ROOT_COVERAGE_FILE")
    if [ "$ROOT_DEPTH_BOUNDARIES" -gt 0 ]; then
        warn "有 $ROOT_DEPTH_BOUNDARIES 个目录达到 --root-depth $ROOT_DEPTH，更深的目录未检查。"
    fi

    if [ "${LIMITED_PROCS:-0}" -gt 0 ]; then
        warn "有 $LIMITED_PROCS 个进程的映射无法读取，进程发现可能不完整。"
    fi

    if [ "$(total_count)" -eq 0 ] && [ "$(apps_count)" -eq 0 ]; then
        warn "在本次检查范围内没有找到可评估的 Java 资产。"
    fi

    # --- 输出 ---
    report_all() {
        case $FORMAT in
            json) report_json ;;
            csv)  report_csv; report_apps_csv ;;
            *)    report_txt ;;
        esac
    }

    if [ -n "$OUT" ]; then
        (set -C; report_all > "$OUT") || die "写入报告失败: $OUT"
        printf '报告已写入: %s\n' "$OUT" >&2
    else
        report_all
    fi

    # --- 退出码 ---
    local rc=0 s c oldifs
    oldifs=$IFS
    IFS=','
    for s in $FAIL_ON; do
        s=$(trim "$s")
        [ -n "$s" ] || continue
        c=$(status_count "$s")
        [ "${c:-0}" -gt 0 ] && rc=1
    done
    IFS=$oldifs
    if [ "$rc" -eq 0 ] && { [ "$(status_count unknown)" -gt 0 ] ||
                           [ "$(total_count)" -eq 0 ] || [ "$LIMITED_PROCS" -gt 0 ] ||
                           [ "$ROOT_DEPTH_BOUNDARIES" -gt 0 ] || [ "$ROOT_SCAN_ERRORS" -gt 0 ]; }; then
        rc=3
    fi
    exit "$rc"
}

main() {
    if [ "$#" -eq 0 ]; then audit_all; return; fi
    case $1 in
        --all) shift; audit_all "$@" ;;
        --nginx2root) shift; nginx2root_scan "$@" ;;
        --apache2root)
            shift
            case "${1:-}:$#" in
                :0) apache_inventory txt ;;
                --json:1) apache_inventory json ;;
                *) die "--apache2root 只接受 --json" ;;
            esac ;;
        --java4shell) shift; java4shell_main "$@" ;;
        *) java4shell_main "$@" ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
