#!/usr/bin/env bash
set -eu

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scanner=$repo/scripts/x2shell-check.sh
source "$scanner"

assert_build() {
    local expected=$1 result
    shift
    result=$(build_assess "$@")
    if [[ ${result%%$'\t'*} != "$expected" ]]; then
        printf 'build_assess (%s): expected %s, got %s\n' "$*" "$expected" "$result" >&2
        exit 1
    fi
}

assert_build unknown 17.0.6 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 17.0.6+9 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unfixed 17.0.6+10 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 21 OpenJDK OpenJDK HotSpot
assert_build unknown 25 OpenJDK OpenJDK HotSpot
assert_build unfixed 21+35 OpenJDK OpenJDK HotSpot
assert_build unfixed 21.0.13 OpenJDK OpenJDK HotSpot
assert_build unknown 21.0.13.1 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 21.0.13.1+3 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build fixed 21.0.13.1+4 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build fixed 21.0.13.1.2 'Amazon.com Inc.' '' HotSpot
assert_build fixed 21.0.13.1+2-LTS 'Amazon.com Inc.' '' HotSpot Corretto-21.0.13.1.2
assert_build candidate 21.0.13.1+1 'Amazon.com Inc.' '' HotSpot Corretto-21.0.13.1.2
assert_build fixed 17.0.21.1+2 OpenJDK '' HotSpot
assert_build candidate 17.0.21.1+2 'Unlisted vendor' '' HotSpot
assert_build candidate 17.0.21.1+2 OpenJDK GraalVM HotSpot
assert_build candidate 27.0.1.1+2 OpenJDK OpenJDK HotSpot
assert_build fixed 27.0.1.1+4 OpenJDK OpenJDK HotSpot
assert_build candidate 27.0.1.1+2 'Amazon.com Inc.' '' HotSpot Corretto-27.0.1.1.4
assert_build fixed 27.0.1.1+4-FR 'Amazon.com Inc.' '' HotSpot Corretto-27.0.1.1.4
assert_build candidate 21.0.13.1+2 'Eclipse Adoptium' '' HotSpot
assert_build candidate 21.1.3+9 OpenJDK OpenJDK HotSpot
assert_build outside_scope 1.8.0_441-b07 'Oracle Corporation' 'Oracle Java SE' HotSpot
for vendor in 'Red Hat, Inc.' 'Eclipse Adoptium' 'Amazon.com Inc.' 'Azul Systems, Inc.' Debian; do
    assert_build outside_scope 1.8.0_442-b06 "$vendor" "" HotSpot
done
assert_build unknown 1.8.0_442-b06 'Unknown vendor' '' HotSpot
assert_build outside_scope 8u441 OpenJDK OpenJDK HotSpot
assert_build unknown 8u511 'Oracle Corporation' 'Oracle Java SE' HotSpot
deb12_hotfix=1.22.1-9+deb12u10.1~hp3
backport=$(nginx_package_backport debian 12 nginx-core:amd64 "$deb12_hotfix" nginx "$deb12_hotfix" amd64)
[[ $backport == *'"provider":"hosted_power"'* && $backport == *'"binary_verified":false'* ]]
[[ $backport == *'CVE-2026-123007'* && $backport != *'CVE-2026-121810'* ]]
[[ -z $(nginx_package_backport debian 12 nginx "$deb12_hotfix" nginx "$deb12_hotfix" arm64) ]]
[[ -z $(nginx_package_backport debian 12 nginx "$deb12_hotfix" nginx 1.22.1-9+deb12u10 amd64) ]]
deb13_fixed=1.26.3-3+deb13u11
backport=$(nginx_package_backport debian 13 nginx "$deb13_fixed" nginx "$deb13_fixed" arm64)
[[ $backport == *'"provider":"debian"'* && $backport == *'CVE-2026-121810'* ]]
[[ $(nginx2root_reference 1.32.0) == *'"status":"meets_upstream_reference"'* ]]
[[ $(nginx2root_reference 2.0.0) == *'"status":"unknown"'* ]]
assert_build unfixed 8u511b33-perf 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 8u511b33-perf-b32 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 1.8.0_511-perf-b32 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unfixed 17.0.21.0.3 'Oracle Corporation' 'Oracle GraalVM for JDK' HotSpot
assert_build outside_scope 21.0.13+9 IBM '' OpenJ9
[[ $(classify candidate present 0 0 amd64 installation) == potential ]]
[[ $(classify unfixed present 0 0 amd64 installation) == potential ]]
[[ $(flag_assessment true unknown) == unknown ]]
[[ $(flag_assessment unknown 3) == unknown ]]
[[ $(flag_assessment true 3) == unmitigated ]]
[[ $(flag_assessment false unknown) == mitigated ]]
[[ $(flag_assessment true 2) == mitigated ]]
[[ $(launcher_flag_assessment '-XX:+UseBASE64Intrinsics') == unknown ]]
[[ $(launcher_flag_assessment '-XX:UseAVX=3') == unknown ]]
[[ $(launcher_flag_assessment '-XX:+UseBASE64Intrinsics -XX:UseAVX=3') == unmitigated ]]
[[ $(launcher_flag_assessment '-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics -XX:UseAVX=2') == mitigated ]]

fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/jdk" "$fixture/root/boundary/deeper" "$fixture/tools"
printf '%s\n' 'JAVA_RUNTIME_VERSION="21.0.13.1+4"' 'IMPLEMENTOR="Oracle Corporation"' \
    'JAVA_RUNTIME_NAME="Java(TM) SE Runtime Environment"' > "$fixture/jdk/release"

mkdir -p "$fixture/graal-ee" "$fixture/graal-jdk"
printf '%s\n' 'JAVA_RUNTIME_VERSION="17.0.18+8"' 'IMPLEMENTOR="Oracle Corporation"'     'GRAALVM_EDITION="Enterprise Edition"' 'GRAALVM_VERSION="21.3.20.0.3"' > "$fixture/graal-ee/release"
printf '%s\n' 'JAVA_RUNTIME_VERSION="17.0.21.0.3+1"' 'IMPLEMENTOR="Oracle Corporation"'     'GRAALVM_EDITION="ee"' 'GRAALVM_VERSION="23.0.12"' > "$fixture/graal-jdk/release"
[[ $(jdk_product "$fixture/graal-jdk" 'Oracle Corporation') == 'Oracle GraalVM for JDK' ]]
bash "$scanner" --quiet --no-processes --jdk "$fixture/graal-ee" --fail-on affected --json > "$fixture/ee.json"
grep -Fq '"product": "Oracle GraalVM Enterprise Edition"' "$fixture/ee.json"
grep -Fq '"build_assessment": "unfixed"' "$fixture/ee.json"
grep -Fq 'Oracle GraalVM Enterprise Edition 受影响构建（21.3.20.0.3）' "$fixture/ee.json"
grep -Fq '"version": "17.0.18+8"' "$fixture/ee.json"

mkdir -p "$fixture/entry-cap/jenkins" "$fixture/entry-cap/keycloak"
: > "$fixture/entry-cap/file"
rc=0
(
    DIRECTORY_ENTRY_LIMIT=1
    main --java4shell --quiet --no-processes --jdk "$fixture/jdk" \
        --root "$fixture/entry-cap" --apps "$fixture/entry-cap" --json
) > "$fixture/capped.json" || rc=$?
[[ $rc == 3 ]]
grep -Fq '"root_entry_limit_reached": true' "$fixture/capped.json"
grep -Fq '"apps_entry_limit_reached": true' "$fixture/capped.json"

mkdir -p "$fixture/jdk/bin"
rc=0
(
    OS=Darwin
    ps() {
        [[ $2 == -p ]] || return 2
        printf '123 %s\n' "$fixture/jdk/bin/java"
    }
    main --java4shell --quiet --pid 99999999 --jdk "$fixture/jdk" --json
) > "$fixture/darwin-missing-pid.json" || rc=$?
[[ $rc == 3 ]]
grep -Fq '"id": "pid:99999999", "kind": "process", "status": "unknown"' "$fixture/darwin-missing-pid.json"
if grep -Fq '"id": "pid:123"' "$fixture/darwin-missing-pid.json"; then exit 1; fi
rc=0
(
    OS=Darwin
    ps() {
        [[ $2 == -p && $3 == 123 ]] || return 2
        printf '123 %s\n' "$fixture/jdk/bin/java"
    }
    main --java4shell --quiet --pid 123 --jdk "$fixture/jdk" --json
) > "$fixture/darwin-selected-pid.json" || rc=$?
[[ $rc == 0 ]]
grep -Fq '"id": "pid:123", "kind": "process", "status": "not_affected"' "$fixture/darwin-selected-pid.json"

mkdir -p "$fixture/apps/jenkins-archive" "$fixture/apps/kafka-backup"
for format in json txt csv; do
    bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" --apps "$fixture/apps" \
        --details --format "$format" > "$fixture/apps.$format"
    grep -Fq '目录名匹配，应用身份和漏洞暴露待核验' "$fixture/apps.$format"
    if grep -Fq '可触发 RCE' "$fixture/apps.$format"; then exit 1; fi
done
grep -Fq '"name": "Jenkins"' "$fixture/apps.json"
grep -Fq '"path": "'"$fixture/apps/jenkins-archive"'", "evidence": "directory_name"' "$fixture/apps.json"
grep -Fq '应用目录线索' "$fixture/apps.txt"
grep -Fq ',"app","inventory",' "$fixture/apps.csv"
bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" --apps "$fixture/apps" > "$fixture/apps-brief.txt"
grep -Fq '已发现 2 条待核验的应用目录线索' "$fixture/apps-brief.txt"

mkdir -p "$fixture/apps/"$'jenkins-\xff'
bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" --apps "$fixture/apps" --json > "$fixture/apps-invalid-utf8.json"
grep -Fq '/jenkins-\ufffd", "evidence": "directory_name"' "$fixture/apps-invalid-utf8.json"

rc=0
bash "$scanner" --java4shell --no-processes --pid "$$" --jdk "$fixture/jdk" --json \
    > "$fixture/pid-conflict.out" 2> "$fixture/pid-conflict.err" || rc=$?
[[ $rc == 2 && ! -s $fixture/pid-conflict.out ]]
grep -Fq -- '--pid 与 --no-processes 不能同时使用' "$fixture/pid-conflict.err"

rc=0
(
    PROCESS_SCAN_LIMIT=0
    main --java4shell --quiet --jdk "$fixture/jdk" --pid "$$" --json
) > "$fixture/pid-capped.json" || rc=$?
if [[ $OS == Linux || $OS == Darwin ]]; then
    [[ $rc == 3 ]]
    grep -Fq '"process_limit_reached": true' "$fixture/pid-capped.json"
fi

: > "$fixture/find-coverage"
bounded_find 1 "$fixture/find-coverage" "$fixture/find-entries" "$fixture/entry-cap" -maxdepth 0
[[ ! -s $fixture/find-coverage ]]

rc=0
bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" --root "$fixture/root" \
    --root-depth 1 --json > "$fixture/report.json" || rc=$?
[[ $rc == 3 ]]
grep -Fq '"root_depth_boundaries": 1, "root_scan_errors": 0' "$fixture/report.json"

printf '%s\n' '#!/bin/sh' 'exit 1' > "$fixture/tools/find"
chmod +x "$fixture/tools/find"
rc=0
PATH="$fixture/tools:$PATH" bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" \
    --root "$fixture/root" --json > "$fixture/report.json" || rc=$?
[[ $rc == 3 ]]
grep -Fq '"root_depth_boundaries": 0, "root_scan_errors": 1' "$fixture/report.json"

rc=0
bash "$scanner" --demo --fail-on candidate >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]

if [[ $OS == Linux ]]; then
    (
        PID_ARGS=("$$")
        libjvm_meta() { return 2; }
        emit_finding() {
            [[ $3 == unknown && $6 == '进程映射不可读' ]]
        }
        scan_processes
        [[ $LIMITED_PROCS == 1 ]]
    )
fi

(
    stat() {
        [[ $1 == -Lc && $2 == '%d %i' ]] || return 1
        printf '%s %s\n' "$(( (23 << 20) | (259 << 8) | 7 ))" 9223372036855101503
    }
    [[ $(file_id anywhere) == '259 5895 9223372036855101503' ]]
)

for fixed in 17.0.21.1 21.0.13.1 25.0.5.1 27.0.1.1; do
    assert_build fixed "$fixed+4" 'Oracle Corporation' 'Oracle Java SE' HotSpot
    assert_build unknown "$fixed+3" 'Oracle Corporation' 'Oracle Java SE' HotSpot
done

mkdir -p "$fixture/launcher/bin"
cat > "$fixture/launcher/bin/java" <<'JAVA'
#!/bin/sh
printf '%s\n' 'java version "21.0.13.1"' \
    'Java(TM) SE Runtime Environment (build 21.0.13.1+4-LTS)' \
    'Java HotSpot(TM) 64-Bit Server VM (build 21.0.13.1+4-LTS, mixed mode)' >&2
JAVA
chmod +x "$fixture/launcher/bin/java"
if have timeout || have gtimeout; then
    bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" \
        --java-path "$fixture/launcher/bin/java" --json > "$fixture/report.json"
    grep -Fq '"version": "21.0.13.1+4-LTS"' "$fixture/report.json"
    grep -Fq '"kind": "java-binary", "status": "not_affected"' "$fixture/report.json"
fi

mkfifo "$fixture/cpu-fifo"
rc=0
bash "$scanner" --quiet --no-processes --cpuinfo "$fixture/cpu-fifo" \
    > "$fixture/cpu-fifo.out" 2> "$fixture/cpu-fifo.err" || rc=$?
[[ $rc == 2 ]]
grep -Fq '需要可读的普通文件' "$fixture/cpu-fifo.err"

printf 'processor: 0\nflags: avx512f\n' > "$fixture/cpuinfo"
rc=0
(
    CPUINFO_BYTE_LIMIT=4
    main --quiet --no-processes --cpuinfo "$fixture/cpuinfo"
) > "$fixture/cpu-limit.out" 2> "$fixture/cpu-limit.err" || rc=$?
[[ $rc == 2 ]]
grep -Fq '超过 4 字节' "$fixture/cpu-limit.err"

cat > "$fixture/never-launch" <<'JAVA'
#!/bin/sh
printf 'executed\n' > "$X2_LAUNCH_MARKER"
JAVA
chmod +x "$fixture/never-launch"
rc=0
(
    export X2_LAUNCH_MARKER="$fixture/launch-marker"
    type() { return 1; }
    scan_java_binary "$fixture/never-launch"
) > "$fixture/launch.out" 2> "$fixture/launch.err" || rc=$?
[[ $rc == 2 && ! -e $fixture/launch-marker ]]
grep -Fq '需要 timeout 或 gtimeout' "$fixture/launch.err"

(
    file_id() { printf '%s' "$mapped_identity"; }
    mapped_identity='0 49 860636'
    [[ $(mapping_identity /proc/1 'aa-bb' '0 46 860636' '0 49 860636') == map_files ]]
    mapped_identity='0 46 860636'
    if mapping_identity /proc/1 'aa-bb' '0 46 860636' '0 49 860636'; then
        exit 1
    fi
    runtime_version_conflicts '21.0.13.1+3' '21.0.13.1+4'
    ! runtime_version_conflicts '21.0.13.1+4' '21.0.13.1'
    ! runtime_version_conflicts '21.0.13.1' '21.0.13.1+4'
)

cat > "$fixture/tools/jcmd" <<'JCMD'
#!/bin/sh
printf '%s\n' '123:' 'OpenJDK 64-Bit Server VM version 21.0.13.1+3' 'JDK 21.0.13.1'
JCMD
chmod +x "$fixture/tools/jcmd"
if have timeout; then
    [[ $(jcmd_version 123 "$fixture/tools/jcmd") == '21.0.13.1+3' ]]
fi

if [[ $OS == Linux ]]; then
    (
        sleep 30 &
        second=$!
        trap 'kill "$second" 2>/dev/null || :; wait "$second" 2>/dev/null || :' EXIT
        PID_ARGS=("$$" "$second")
        ACTIVE_FILE="$fixture/active-ids"
        : > "$ACTIVE_FILE"
        CPU_STATE=present
        JCMD=1
        libjvm_meta() { printf '00:2e\037860636\037/test/lib/server/libjvm.so\037aa-bb'; }
        file_id() {
            case $1 in
                "/proc/$$/root/"*) printf '0 46 860636' ;;
                "/proc/$second/root/"*) printf '0 49 860636' ;;
                *) return 1 ;;
            esac
        }
        jvm_root_from_lib() { printf '%s' "$fixture/jdk"; }
        jcmd_bin() { printf 'fixture-jcmd'; }
        handles_sigquit() { return 0; }
        launcher_flags() { return 0; }
        jcmd_flags() { printf 'true 3'; }
        jcmd_version() { printf '%s' "${fixture_runtime_version:-21.0.13.1+4}"; }
        container_hint() { return 0; }
        declare -f emit_finding > "$fixture/emit-finding"
        emit_finding() { printf '%s %s %s\n' "$1" "$3" "$8"; }
        scan_processes > "$fixture/pid-report"
        grep -Fxq "pid:$$ not_affected 21.0.13.1+4" "$fixture/pid-report"
        grep -Fxq "pid:$second potential 21.0.13.1+4" "$fixture/pid-report"
        [[ $(cat "$ACTIVE_FILE") == '0 46 860636' ]]

        fixture_runtime_version=21.0.13.1+3
        : > "$ACTIVE_FILE"
        scan_processes > "$fixture/pid-report"
        grep -Fxq "pid:$second unknown 21.0.13.1+3" "$fixture/pid-report"
        [[ ! -s $ACTIVE_FILE ]]

        PID_ARGS=("$$")
        ASSUME_FEFF=1
        fixture_runtime_version=21.0.13
        jvm_root_from_lib() { printf '%s' "$fixture/affected-jdk"; }
        mkdir "$fixture/affected-jdk"
        printf '%s\n' 'JAVA_RUNTIME_VERSION="21.0.13+9"' 'IMPLEMENTOR="OpenJDK"' > "$fixture/affected-jdk/release"
        launcher_flags() { printf '%s' "$fixture_flags"; }
        jcmd_flags() { printf '%s' "$fixture_measured"; }
        emit_finding() { printf '%s %s %s\n' "$3" "${15}" "${17}"; }

        fixture_flags='-XX:+UseBASE64Intrinsics -XX:UseAVX=3'
        fixture_measured='true unknown'
        scan_processes > "$fixture/pid-report"
        grep -q '^unknown false .*仅报告短版本' "$fixture/pid-report"

        JCMD=0
        scan_processes > "$fixture/pid-report"
        grep -q '^affected false .*显式信任' "$fixture/pid-report"
        fixture_flags='-XX:+UseBASE64Intrinsics'
        scan_processes > "$fixture/pid-report"
        grep -q '^unknown false ' "$fixture/pid-report"
        fixture_flags='-XX:UseAVX=2'
        scan_processes > "$fixture/pid-report"
        grep -q '^mitigated false .*显式信任' "$fixture/pid-report"

        source "$fixture/emit-finding"
        PID_ARGS=("$second")
        FIND_FILE="$fixture/weak-findings"
        WARN_FILE="$fixture/weak-warnings"
        APP_FILE="$fixture/weak-apps"
        MODE_NAME=processes-only
        : > "$FIND_FILE"; : > "$WARN_FILE"; : > "$APP_FILE"; : > "$ACTIVE_FILE"
        scan_processes
        [[ ! -s $ACTIVE_FILE ]]
        report_json > "$fixture/weak.json"
        grep -Fq '"kind": "process", "status": "potential"' "$fixture/weak.json"
        grep -Fq '"version": "21.0.13+9", "java_home":' "$fixture/weak.json"
        grep -Fq '"identity_confidence": "weak"' "$fixture/weak.json"
        grep -Fq '"disk_evidence": {"version": "21.0.13+9", "vendor": "OpenJDK", "product": "OpenJDK", "build_assessment": "unfixed"}' "$fixture/weak.json"
        grep -Fq '发现受影响的磁盘构建' "$fixture/weak.json"
        report_csv > "$fixture/weak.csv"
        grep -Fq 'identity_confidence,disk_version,disk_vendor,disk_product,disk_build_assessment' "$fixture/weak.csv"
        grep -Fq '"weak","21.0.13+9","OpenJDK","OpenJDK","unfixed"' "$fixture/weak.csv"
        DETAILS=1
        report_txt > "$fixture/weak.txt"
        grep -Fq '21.0.13+9 · OpenJDK / OpenJDK' "$fixture/weak.txt"
    )
fi

if [[ $OS == Linux ]]; then
    cat > "$fixture/nginx.conf" <<'NGINX'
# listen 443 ssl http2;
server {
    http2 off;
    listen 443 quic;
    resolver 192.0.2.53;
    proxy_pass http://$upstream;
    proxy_http_version 2;
}
mail { proxy on; auth_http localhost; }
include /etc/nginx/another.conf;
NGINX
    flags=$(nginx2root_config "$fixture/nginx.conf")
    [[ $flags == *'"http2_on":false,"http2_off":true,"http3_or_quic":true'* ]]
    [[ $flags == *'"resolver":true,"dynamic_proxy_pass":true'* ]]
    [[ $flags == *'"mail_proxy":true,"auth_http":true'* ]]
    [[ $flags == *'"include_observed":true,"proxy_http_version_2":true,"grpc_upstream":false'* ]]
    printf '%s\n'  'Protocols http/1.1' '<VirtualHost *:443>' 'Protocols h2 http/1.1' '</VirtualHost>' 'H2Direct on' 'H2Upgrade on' 'IncludeOptional conf.d/*.conf' > "$fixture/apache.conf"
    flags=$(apache_config_hints "$fixture/apache.conf")
    [[ $flags == *'"h2":true'*'"h2_direct_on":true,"h2_upgrade_on":true,"include_observed":true,"h2_in_virtualhost":true,"h2_outside_virtualhost":false'* ]]
    [[ $(web_disk_identity /proc/self "$fixture/apache.conf" "$(file_id "$fixture/apache.conf")") == matched ]]
    [[ $(web_disk_identity /proc/self "$fixture/apache.conf" '0 1 2') == mismatch ]]
    [[ $(web_disk_identity /proc/self '/tmp/sample (deleted)' '0 1 2') == deleted ]]
    [[ $(web_disk_identity /proc/self "$fixture/missing" '0 1 2') == unverified ]]
    printf '\177ELF nginx/1.27.4 nginx-plus-r37.0.7.1 --with-http_v2_module ngx_http_v3_module' > "$fixture/nginx-elf"
    [[ $(nginx2root_binary_metadata "$fixture/nginx-elf") == '1.27.4|plus|37.0.7.1|["http_v2","http_v3"]|' ]]
    printf '\177ELF nginx/1.27.4 nginx/1.27.5 openresty' > "$fixture/nginx-elf"
    [[ $(nginx2root_binary_metadata "$fixture/nginx-elf") == '|openresty||[]|' ]]
    for plus_release in 36-p1 37-p1 37 37.0.7.1-p2 37.2.0.1; do
        [[ $(nginx_plus_reference "$plus_release") == potential ]]
    done
    [[ $(nginx_plus_reference 37.2.0.2-p1) == unknown ]]
    [[ $(nginx_plus_reference 37-pbad) == unknown ]]
    [[ $(nginx_plus_reference 37.2.0.2) == unknown ]]
    [[ $(nginx_plus_reference 37.2.0.1 CVE-2026-123633) == meets_vendor_reference ]]
    [[ $(nginx_plus_reference 37.2.0.1 CVE-2026-123007) == potential ]]
    [[ $(nginx_plus_reference 37.0.8.1 CVE-2026-123007) == meets_vendor_reference ]]
    printf '\177ELF nginx/1.31.5 Tengine/3.2.0' > "$fixture/nginx-elf"
    [[ $(nginx2root_binary_metadata "$fixture/nginx-elf") == '1.31.5|tengine||[]|3.2.0' ]]
    refs=$(nginx2root_reference 1.31.5 '' tengine)
    [[ $refs == *'"status":"potential"'*'"embedded_upstream_status":"potential"'* ]]
    refs=$(nginx2root_reference 1.31.9 '' openresty)
    [[ $refs == *'"status":"unknown"'*'"embedded_upstream_status":"meets_upstream_reference"'* ]]
    refs=$(nginx2root_reference 1.25.0 '{"http2_on":true}')
    [[ $refs == *'"feature":"http2","config_evidence":"disk_hints_present","missing_disk_hints":[]'* ]]
    [[ $refs == *'"feature":"http2_upstream","config_evidence":"condition_not_observed","missing_disk_hints":["upstream"]'* ]]
    printf '\177ELF nginx/1.27.4 nginx-plus' > "$fixture/nginx-elf"
    nginx_rc=0
    : > "$fixture/empty-nginx.conf"
    "$scanner" --nginx2root --nginx-path "$fixture/nginx-elf" --nginx-config "$fixture/empty-nginx.conf" --json \
        > "$fixture/nginx-plus.json" || nginx_rc=$?
    [[ $nginx_rc == 1 || $nginx_rc == 3 ]]
    grep -Fq '"flavor":"plus","plus_release":"","plus_release_unresolved":true' "$fixture/nginx-plus.json"
    grep -Eq '"unknown_condition_not_observed":([5-9]|[1-9][0-9]+),' "$fixture/nginx-plus.json"
    mkdir "$fixture/sites"
    printf '%s\n' 'include sites/*.conf;' 'include missing.conf;' > "$fixture/entry.conf"
    printf '%s\n' '# header' 'http2 on;' 'include entry.conf;' > "$fixture/sites/site.conf"
    flags=$(nginx2root_config "$fixture/entry.conf")
    [[ $flags == *'"files_examined":2,"skipped":1'* ]]
    [[ $flags == *'"hint":"http2_on","file":"'"$fixture/sites/site.conf"'","line":2'* ]]
    cat > "$fixture/multiline.conf" <<'CONF'
http {
    access_by_lua_block {
        local ignored = [=[http2 off; }]=]
    }
    http2
        on;
    proxy_pass "http://$backend/path";
}
CONF
    flags=$(nginx2root_config "$fixture/multiline.conf")
    [[ $flags == *'"skipped":0,'* && $flags == *'"http2_on":true'* &&
        $flags == *'"http2_off":false'* && $flags == *'"dynamic_proxy_host":true'* ]]

    printf '\177ELF nginx/1.25.3 --conf-path=/opt/NGINX/conf/nginx.conf' > "$fixture/nginx-elf"
    nginx_rc=0
    "$scanner" --nginx2root --nginx-path "$fixture/nginx-elf" --nginx-config "$fixture/empty-nginx.conf" --json \
        > "$fixture/nginx-static.json" || nginx_rc=$?
    [[ $nginx_rc == 1 ]]
    grep -Fq '"compiled_config_path":"/opt/NGINX/conf/nginx.conf"' "$fixture/nginx-static.json"
    grep -Fq '"status":"potential","feature":"http2","config_evidence":"condition_not_observed"' "$fixture/nginx-static.json"

    printf '\177ELF Apache/2.4.70' > "$fixture/httpd-elf"
    apache_rc=0
    "$scanner" --apache2root --apache-path "$fixture/httpd-elf" --json > "$fixture/apache-static.json" || apache_rc=$?
    [[ $apache_rc == 1 ]]
    grep -Fq '"path":"'"$fixture/httpd-elf"'","version":"2.4.70","version_status":"potential"' "$fixture/apache-static.json"

    printf 'nginx: master process nginx -c %s -g daemon off;\0' "$fixture/entry.conf" > "$fixture/cmdline"
    [[ $(nginx_process_config_entry "$fixture") == "$fixture/entry.conf" ]]
    printf 'nginx\0-g\0daemon off;\0-c\0%s\0' "$fixture/entry.conf" > "$fixture/cmdline"
    [[ $(nginx_process_config_entry "$fixture") == "$fixture/entry.conf" ]]
    [[ $(nginx_plus_reference 37.3.0.1-p2 CVE-2026-123007) == meets_vendor_reference ]]
    mkdir -p "$fixture/openresty/nginx/"{sbin,conf}
    printf '\177ELF openresty/1.31.8.1' > "$fixture/openresty/nginx/sbin/nginx"
    printf 'http2 on;\n' > "$fixture/openresty/nginx/conf/nginx.conf"
    nginx_rc=0
    (cd "$fixture" && "$scanner" --nginx2root --nginx-path ./openresty/nginx/sbin/nginx --json) > "$fixture/layout.json" || nginx_rc=$?
    [[ $nginx_rc == 1 ]]
    grep -Fq '"configuration_entry_source":"installation_layout"' "$fixture/layout.json"
    refs=$(nginx2root_reference 1.31.8 '' nginx)
    [[ $refs == *'"config_evidence":"configuration_not_attributed","missing_disk_hints":[]'* ]]
    refs=$(nginx2root_reference '' '' plus 37.3.0.1)
    [[ $refs == *'"vendor_reference":"https://docs.nginx.com/nginx/releases/"'* ]]
    nginx_rc=0
    "$scanner" --nginx2root --nginx-path "$fixture/openresty/nginx/sbin/nginx" --nginx-config "$fixture/missing" --json > "$fixture/incomplete.json" || nginx_rc=$?
    [[ $nginx_rc == 1 ]]
    grep -Fq '"evidence_incomplete":true,"configuration_evidence_incomplete":true,"configuration_incomplete":true},"summary":{"risk_gate_hit":true' "$fixture/incomplete.json"
    rc=0
    (
        scan_processes() { :; }
        linux_process_visibility_limited() { return 0; }
        java4shell_main --quiet --jdk "$fixture/jdk" --json
    ) > "$fixture/java-limited.json" || rc=$?
    [[ $rc == 3 ]]
    grep -Fq '"status": "not_affected"' "$fixture/java-limited.json"
    grep -Fq '"process_visibility_limited": true' "$fixture/java-limited.json"
    (
        linux_process_visibility_limited() { return 0; }
        java4shell_main --quiet --no-processes --jdk "$fixture/jdk" --json > "$fixture/java-static-only.json"
    )
    grep -Fq '"process_visibility_limited": false' "$fixture/java-static-only.json"

    if have timeout && timeout -k 1s 1s true >/dev/null 2>&1; then
        mkdir -p "$fixture/package-tools" "$fixture/rpm-jdk/bin"
        : > "$fixture/rpm-jdk/bin/java"
        cat > "$fixture/package-tools/rpm" <<'RPM'
#!/bin/sh
trap '' TERM
: > "$X2_RPM_STARTED"
sleep 4
: > "$X2_RPM_FINISHED"
RPM
        chmod +x "$fixture/package-tools/rpm"
        (
            export PATH="$fixture/package-tools:$PATH"
            export X2_RPM_STARTED="$fixture/rpm-started" X2_RPM_FINISHED="$fixture/rpm-finished"
            PACKAGE_QUERY_TIMEOUT=1
            ! installation_rpm_metadata "$fixture/rpm-jdk"
            [[ -e $X2_RPM_STARTED && ! -e $X2_RPM_FINISHED ]]
        ) 2> "$fixture/rpm-timeout.err"
    fi

    (
        mkdir -p "$fixture/shared-config-procs"
        printf '\177ELF nginx/1.31.8' > "$fixture/shared-nginx-image"
        : > "$fixture/shared-nginx.conf"
        for proc_id in 101 102 103 104; do
            proc="$fixture/shared-config-procs/$proc_id"
            mkdir -p "$proc/ns"
            printf 'nginx\n' > "$proc/comm"
            ln -s "$fixture/shared-nginx-image" "$proc/exe"
            ln -s / "$proc/root"
            ln -s "$(readlink /proc/self/ns/mnt)" "$proc/ns/mnt"
            case $proc_id in
                101) printf 'nginx: master process nginx -c %s\0' "$fixture/shared-nginx.conf" > "$proc/cmdline" ;;
                102|103)
                    printf 'nginx: worker process\0' > "$proc/cmdline"
                    printf 'PPid:\t101\n' > "$proc/status" ;;
                104) printf 'nginx\0-c\0%s\0' "$fixture/shared-nginx.conf" > "$proc/cmdline" ;;
            esac
        done
        web_process_paths() { printf '%s\n' "$fixture"/shared-config-procs/*; }
        linux_process_visibility_limited() { return 1; }
        java_process_start() { printf '123'; }
        web_package_hint() { :; }
        nginx2root_config() {
            printf '%s\n' "${1:-defaults}" >> "$fixture/nginx-config-reads"
            printf '{"files_examined":1,"skipped":0,"http2_on":true}'
        }
        rc=0
        nginx2root_scan --json > "$fixture/nginx-shared-config.json" || rc=$?
        [[ $rc == 1 ]]
        [[ $(grep -Fxc "$fixture/shared-nginx.conf" "$fixture/nginx-config-reads") == 1 ]]
        [[ $(grep -Fo '"configuration_entry_source":"parent_process_argument"' "$fixture/nginx-shared-config.json" | wc -l) -eq 2 ]]

        printf 'PPid:\t999\n' > "$fixture/shared-config-procs/103/status"
        : > "$fixture/nginx-config-reads"
        rc=0
        nginx2root_scan --json > "$fixture/nginx-unmatched-parent.json" || rc=$?
        [[ $rc == 1 ]]
        [[ $(grep -Fxc "$fixture/shared-nginx.conf" "$fixture/nginx-config-reads") == 1 ]]
        [[ $(grep -Fo '"configuration_entry_source":"parent_process_argument"' "$fixture/nginx-unmatched-parent.json" | wc -l) -eq 1 ]]
    )

    # Exercise the mount parser and the verdict when the process view is limited.
    mkdir -p "$fixture/proc-view/self" "$fixture/proc-view/1" "$fixture/proc-view/123"
    : > "$fixture/proc-view/self/stat"
    : > "$fixture/proc-view/1/comm"
    (
        container_hint() { :; }
        procview=$fixture/proc-view
        printf '%s\n' '31 23 0:4 / /proc rw,nosuid - proc proc rw,hidepid=off' > "$procview/self/mountinfo"
        ! linux_process_visibility_limited "$procview"
        printf '%s\n' '31 23 0:4 / /proc rw,nosuid - proc proc rw,hidepid=invisible' > "$procview/self/mountinfo"
        linux_process_visibility_limited "$procview"
        printf '%s\n' '31 23 0:4 /1 /proc rw,nosuid - proc proc rw' > "$procview/self/mountinfo"
        linux_process_visibility_limited "$procview"
        container_hint() { printf 'container'; }
        printf '%s\n' '31 23 0:4 / /proc rw,nosuid - proc proc rw' > "$procview/self/mountinfo"
        linux_process_visibility_limited "$procview"
    )
    (
        web_process_paths() { :; }
        linux_process_visibility_limited() { return 0; }
        web_package_hint() { :; }
        file_id() {
            case $1 in "$fixture/"*) printf '%s' "$1" ;; *) return 1 ;; esac
        }
        rc=0
        apache_inventory --apache-config "$fixture/apache.conf" --json > "$fixture/apache-limited.json" || rc=$?
        [[ $rc == 3 ]]
        grep -Fq '"status":"not_observed"' "$fixture/apache-limited.json"
        grep -Fq '"process_visibility_limited":true' "$fixture/apache-limited.json"

        printf '\177ELF nginx/1.31.9' > "$fixture/nginx-elf"
        rc=0
        nginx2root_scan --nginx-path "$fixture/nginx-elf" --nginx-config "$fixture/empty-nginx.conf" --json \
            > "$fixture/nginx-limited.json" || rc=$?
        [[ $rc == 3 ]]
        grep -Fq '"status":"meets_upstream_reference"' "$fixture/nginx-limited.json"
        grep -Fq '"process_visibility_limited":true,"evidence_incomplete":true' "$fixture/nginx-limited.json"

        java4shell_main() { printf '{"status":"fixture"}'; }
        rc=0
        audit_all --nginx-path "$fixture/nginx-elf" --nginx-config "$fixture/empty-nginx.conf" \
            --apache-config "$fixture/apache.conf" --json > "$fixture/all-limited.json" || rc=$?
        [[ $rc == 3 ]]
        grep -Fq '"exit_codes":{"java4shell":0,"nginx2root":3,"apache2root":3}' "$fixture/all-limited.json"

        printf '\177ELF nginx/1.31.8' > "$fixture/nginx-elf"
        rc=0
        nginx2root_scan --nginx-path "$fixture/nginx-elf" --nginx-config "$fixture/empty-nginx.conf" --json \
            > "$fixture/nginx-risk-limited.json" || rc=$?
        [[ $rc == 1 ]]
        grep -Fq '"process_visibility_limited":true' "$fixture/nginx-risk-limited.json"

        linux_process_visibility_limited() { return 1; }
        apache_inventory --apache-config "$fixture/apache.conf" --json > "$fixture/apache-visible.json"
        grep -Fq '"process_visibility_limited":false' "$fixture/apache-visible.json"

        web_process_paths() { printf '%s\n' "$fixture/proc-view/123"; }
        rc=0
        apache_inventory --apache-config "$fixture/apache.conf" > "$fixture/apache-unreadable.txt" || rc=$?
        [[ $rc == 3 ]]
        grep -Fq '进程视图受限' "$fixture/apache-unreadable.txt"
    )
    web_coverage_incomplete false 0 '{"skipped":1}'
    ! web_coverage_incomplete false 0 '{"skipped":0}'
    (
        java4shell_main() { printf '{"status":"fixture"}'; return 0; }
        nginx2root_scan() { printf '{"status":"fixture"}'; return 0; }
        apache_inventory() { printf '{"status":"fixture"}'; }
        [[ $(main --all --json) == *'"java4shell":{"status":"fixture"},"nginx2root":{"status":"fixture"},"apache":{"status":"fixture"}'* ]]
        [[ $(main) == *'=== Java4Shell ==='*'=== Nginx2Root ==='*'=== Apache HTTP Server ==='* ]]
    )
fi

[[ $(jstr $'path\twith\nnewline\n') == '"path\u0009with\nnewline\n"' ]]
[[ $(jstr '目录📁') == '"目录📁"' ]]
[[ $(jstr $'\x80\xc0\xaf') == '"\ufffd\ufffd\ufffd"' ]]
[[ $(jstr $'\xed\xa0\x80\xf4\x90\x80\x80') == '"\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd\ufffd"' ]]
[[ $(jstr $'\xe2\x82') == '"\ufffd\ufffd"' ]]
mkdir -p "$fixture/standalone/jre/bin" "$fixture/nested/jre/bin"
touch "$fixture/nested/release"
[[ $(java_root_of "$fixture/standalone/jre/bin/java") == "$fixture/standalone/jre" ]]
[[ $(java_root_of "$fixture/nested/jre/bin/java") == "$fixture/nested" ]]
[[ $(apache_reference 2.4.54) == outside_upstream_range ]]
[[ $(apache_reference 2.4.55) == potential ]]
[[ $(apache_reference 2.4.70) == potential ]]
[[ $(apache_reference 2.4.71) == meets_upstream_reference ]]
[[ $(apache_reference 2.0.42 module) == potential ]]
[[ $(apache_reference 2.0.43 module) == outside_upstream_range ]]
printf '%s\n' '7f000000-7f008000 r-xp 0 00:2e 123 /usr/lib/httpd/modules/mod_http2.so (deleted)' > "$fixture/apache-maps"
[[ $(apache_mapped_http2 "$fixture/apache-maps") == true ]]
[[ $(apache_mapped_http2 "$fixture/missing") == null ]]

# Full dispatch also needs to succeed on macOS, where /proc is unavailable.
darwin_rc=0
bash -c 'source "$1"; OS=Darwin; main --all --json' bash "$scanner" \
    > "$fixture/darwin.json" 2> "$fixture/darwin.stderr" || darwin_rc=$?
[[ $darwin_rc == 1 || $darwin_rc == 3 ]]
grep -Fq '"nginx2root":{"status":"unavailable","reason":"linux_proc_required","platform":"Darwin"' "$fixture/darwin.json"
grep -Fq '"apache":{"status":"unavailable","reason":"linux_proc_required","platform":"Darwin"' "$fixture/darwin.json"
! grep -Fq 'unbound variable' "$fixture/darwin.stderr"
