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
bash "$scanner" --quiet --no-processes --jdk "$fixture/jdk" \
    --java-path "$fixture/launcher/bin/java" --json > "$fixture/report.json"
grep -Fq '"version": "21.0.13.1+4-LTS"' "$fixture/report.json"
grep -Fq '"kind": "java-binary", "status": "not_affected"' "$fixture/report.json"

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
    grep -Eq '"unknown_condition_not_observed":([5-9]|[1-9][0-9]+)}' "$fixture/nginx-plus.json"
    mkdir "$fixture/sites"
    printf '%s\n' 'include sites/*.conf;' 'include missing.conf;' > "$fixture/entry.conf"
    printf '%s\n' '# header' 'http2 on;' 'include entry.conf;' > "$fixture/sites/site.conf"
    flags=$(nginx2root_config "$fixture/entry.conf")
    [[ $flags == *'"files_examined":2,"skipped":1'* ]]
    [[ $flags == *'"hint":"http2_on","file":"'"$fixture/sites/site.conf"'","line":2'* ]]
    printf 'nginx: master process nginx -c %s -g daemon off;\0' "$fixture/entry.conf" > "$fixture/cmdline"
    [[ $(nginx_process_config_entry "$fixture") == "$fixture/entry.conf" ]]
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

[[ $(apache_reference 2.4.54) == outside_upstream_range ]]
[[ $(apache_reference 2.4.55) == potential ]]
[[ $(apache_reference 2.4.70) == potential ]]
[[ $(apache_reference 2.4.71) == meets_upstream_reference ]]
[[ $(apache_reference 2.0.42 module) == potential ]]
[[ $(apache_reference 2.0.43 module) == unknown ]]
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
