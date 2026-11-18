#!/usr/bin/env bash
set -eu

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scanner=$repo/scripts/java4shell-scan.sh
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
assert_build unfixed 21+35 OpenJDK OpenJDK HotSpot
assert_build unknown 21.0.13.1 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 21.0.13.1+3 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build fixed 21.0.13.1+4 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build candidate 21.0.13.1.2 'Amazon.com Inc.' '' HotSpot
assert_build candidate 21.1.3+9 OpenJDK OpenJDK HotSpot
assert_build unfixed 8u511b33-perf 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 8u511b33-perf-b32 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unknown 1.8.0_511-perf-b32 'Oracle Corporation' 'Oracle Java SE' HotSpot
assert_build unfixed 17.0.21.0.3 'Oracle Corporation' 'Oracle GraalVM for JDK' HotSpot
assert_build outside_scope 21.0.13+9 IBM '' OpenJ9
[[ $(classify candidate present 0 0 amd64 installation) == potential ]]

fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/jdk" "$fixture/root/boundary/deeper" "$fixture/tools"
printf '%s\n' 'JAVA_RUNTIME_VERSION="21.0.13.1+4"' 'IMPLEMENTOR="Oracle Corporation"' \
    'JAVA_RUNTIME_NAME="Java(TM) SE Runtime Environment"' > "$fixture/jdk/release"

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
