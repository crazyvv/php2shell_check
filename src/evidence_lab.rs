//! Pure, offline evidence reasoning. This module never opens sockets or executes PHP.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub const SOURCES: [(&str, &str); 5] = [
    (
        "PHP GHSA-w8hw-w9fx-j79w",
        "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    ),
    (
        "PHP GHSA-6wmf-4rv5-p3rp",
        "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    ),
    (
        "ikow/php2shell-poc@caffb96",
        "https://github.com/ikow/php2shell-poc/tree/caffb96b0a165eb3796828a9a1dc7445ec7ff77d",
    ),
    (
        "murrez/php2shell@7de30d5",
        "https://github.com/murrez/php2shell/tree/7de30d56887d20e4bfc1b3f90b47f067917742c7",
    ),
    (
        "spcaeo/php2shell-check@78afcd9",
        "https://github.com/spcaeo/php2shell-check/tree/78afcd9b8d88e76549f5d2fc9d61e9f077fe081e",
    ),
];

fn runtime_array(report: &Value) -> Option<&Vec<Value>> {
    report["runtime_observations"]
        .as_array()
        .or_else(|| report["report"]["runtime_observations"].as_array())
        .or_else(|| report["assessment"]["runtime_observations"].as_array())
}

fn runtime_scope(sapi: &str) -> &'static str {
    match sapi.to_ascii_lowercase().as_str() {
        "cli" | "phpdbg" => "cli_only",
        "apache2handler" | "fpm-fcgi" | "cgi-fcgi" | "frankenphp" | "litespeed" | "cli-server" => {
            "web_runtime"
        }
        _ => "unknown",
    }
}

fn boolish(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "on" | "true" | "yes" | "enabled" => Some(true),
            "" | "0" | "off" | "false" | "no" | "disabled" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn version_status(version: &str) -> &'static str {
    let Some(parts) = crate::scanner::stable_version(version) else {
        return "unknown";
    };
    let fixed = match (parts[0], parts[1]) {
        (8, 2) => Some(35),
        (8, 3) => Some(36),
        (8, 4) => Some(27),
        (8, 5) => Some(12),
        _ => None,
    };
    match fixed {
        Some(fixed) if parts[2] < fixed => "below_upstream_fix",
        Some(_) => "meets_upstream_fix",
        None if (5..=7).contains(&parts[0]) || (parts[0] == 8 && parts[1] <= 1) => "eol",
        None => "unknown",
    }
}

fn normalized_runtime(runtime: &Value) -> Value {
    let sapi = runtime["sapi"].as_str().unwrap_or("unknown");
    let version = runtime["version"].as_str().unwrap_or("");
    let settings = runtime["settings"].as_object();
    let progress = runtime
        .get("upload_progress")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            settings
                .and_then(|s| s.get("session.upload_progress.enabled"))
                .and_then(boolish)
                .map(|enabled| if enabled { "enabled" } else { "disabled" }.to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    json!({
        "scope": runtime_scope(sapi),
        "sapi": sapi,
        "version": if version.is_empty() { Value::Null } else { json!(version) },
        "version_status": version_status(version),
        "upload_progress": progress,
        "serialize_handler": settings
            .and_then(|s| s.get("session.serialize_handler"))
            .cloned()
            .unwrap_or(Value::Null),
        "save_handler": settings
            .and_then(|s| s.get("session.save_handler"))
            .cloned()
            .unwrap_or(Value::Null),
        "source": runtime["source"],
        "confidence": "unverified"
    })
}

fn patch_evidence(report: &Value) -> Value {
    let raw = report
        .get("patch_evidence")
        .or_else(|| report.get("report").and_then(|v| v.get("patch_evidence")))
        .unwrap_or(&Value::Null);
    let review = report
        .get("review")
        .or_else(|| report.get("assessment").and_then(|v| v.get("review")))
        .unwrap_or(&Value::Null);
    let advisory = raw["vendor_advisory"]
        .as_str()
        .filter(|v| !v.is_empty())
        .is_some()
        || review["advisory_url"]
            .as_str()
            .filter(|v| !v.is_empty())
            .is_some();
    let revision = raw["package_revision"]
        .as_str()
        .filter(|v| !v.is_empty())
        .is_some()
        || review["package_revision"]
            .as_str()
            .filter(|v| !v.is_empty())
            .is_some();
    let running_image = raw["running_image_matches"]
        .as_bool()
        .or_else(|| raw["running_image_matches_claimed"].as_bool())
        .unwrap_or(false);
    let restarted = raw["workers_restarted"]
        .as_bool()
        .or_else(|| raw["workers_restarted_claimed"].as_bool())
        .unwrap_or(false);
    let backends = raw["all_backends_sampled"]
        .as_bool()
        .or_else(|| raw["all_backends_sampled_claimed"].as_bool())
        .unwrap_or(false);
    let complete_claimed = advisory && revision && running_image && restarted && backends;
    json!({
        "vendor_advisory_present": advisory,
        "package_revision_present": revision,
        "running_image_matches_claimed": running_image,
        "workers_restarted_claimed": restarted,
        "all_backends_sampled_claimed": backends,
        "complete_claimed": complete_claimed,
        "independently_verified": false
    })
}

/// Reduce a host report or imported assessment to scope-bound facts.
pub fn summarize_report(report: &Value) -> Result<Value> {
    let runtimes = runtime_array(report).context("报告缺少 runtime_observations 数组")?;
    ensure!(runtimes.len() <= 128, "运行时条目超过 128 条限制");
    let mut web = vec![];
    let mut cli = vec![];
    let mut unknown = vec![];
    for runtime in runtimes.iter().take(128).filter(|v| v.is_object()) {
        let normalized = normalized_runtime(runtime);
        match normalized["scope"].as_str() {
            Some("web_runtime") => web.push(normalized),
            Some("cli_only") => cli.push(normalized),
            _ => unknown.push(normalized),
        }
    }
    ensure!(
        !web.is_empty() || !cli.is_empty() || !unknown.is_empty(),
        "报告没有有效运行时条目"
    );
    Ok(json!({
        "web": web,
        "cli": cli,
        "unknown": unknown,
        "web_evidence_present": !web.is_empty(),
        "cli_is_not_web_evidence": true,
        "patch_evidence": patch_evidence(report),
        "limitations": [
            "CLI 版本和配置不能替代 Web/FPM 运行实例证据",
            "报告与手工声明未经独立核验，不自动确认漏洞或修复",
            "负载均衡环境需要逐个后端和运行 worker 复核"
        ]
    }))
}

fn first_text(summary: &Value, group: &str, key: &str) -> Value {
    summary[group]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn all_values(summary: &Value, group: &str, key: &str) -> Value {
    let mut values = vec![];
    for value in summary[group]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get(key))
        .filter(|value| !value.is_null())
    {
        if !values.contains(value) {
            values.push(value.clone());
        }
    }
    json!(values)
}

fn change(field: &str, before: Value, after: Value, meaning: &str) -> Value {
    json!({"field":field,"before":before,"after":after,"changed":before!=after,"meaning":meaning})
}

/// Compare two host reports without contacting either target.
pub fn compare_reports(before: &Value, after: &Value) -> Result<Value> {
    let before = summarize_report(before).context("修复前报告无效")?;
    let after = summarize_report(after).context("修复后报告无效")?;
    let changes = vec![
        change(
            "web.version",
            all_values(&before, "web", "version"),
            all_values(&after, "web", "version"),
            "只比较明确归属 Web SAPI 的版本；CLI 版本单独列出",
        ),
        change(
            "web.version_status",
            all_values(&before, "web", "version_status"),
            all_values(&after, "web", "version_status"),
            "达到上游版本基线仍需厂商、运行映像和 worker 证据",
        ),
        change(
            "web.sapi",
            all_values(&before, "web", "sapi"),
            all_values(&after, "web", "sapi"),
            "SAPI 变化会改变适用链路，不能用响应头推断",
        ),
        change(
            "web.upload_progress",
            all_values(&before, "web", "upload_progress"),
            all_values(&after, "web", "upload_progress"),
            "关闭上传进度只减少部分路径，不能替代完整修复",
        ),
        change(
            "web.serialize_handler",
            all_values(&before, "web", "serialize_handler"),
            all_values(&after, "web", "serialize_handler"),
            "需要跨目录、池和虚拟主机核对一致性",
        ),
        change(
            "cli.version",
            all_values(&before, "cli", "version"),
            all_values(&after, "cli", "version"),
            "仅记录 CLI 变化，不用于替代 Web 修复结论",
        ),
        change(
            "patch_evidence.complete_claimed",
            before["patch_evidence"]["complete_claimed"].clone(),
            after["patch_evidence"]["complete_claimed"].clone(),
            "完整声明仍是提交材料，不是独立验证",
        ),
    ];
    let before_web = before["web"].as_array().cloned().unwrap_or_default();
    let after_web = after["web"].as_array().cloned().unwrap_or_default();
    let web_improved = before_web
        .iter()
        .any(|runtime| runtime["version_status"] == "below_upstream_fix")
        && !after_web.is_empty()
        && after_web
            .iter()
            .all(|runtime| runtime["version_status"] == "meets_upstream_fix");
    let evidence_improved = web_improved && after["patch_evidence"]["complete_claimed"] == true;
    Ok(json!({
        "schema":"php-selfcheck-report-comparison/v1",
        "mode":"offline",
        "before":before,
        "after":after,
        "changes":changes,
        "conclusion":if evidence_improved{"remediation_evidence_improved"}else{"requires_review"},
        "remediation_evidence_complete_claimed":after["patch_evidence"]["complete_claimed"],
        "patch_independently_verified":false,
        "exploitability_confirmed":false
    }))
}

fn missing_if(missing: &mut Vec<Value>, condition: bool, text: &str) {
    if !condition {
        missing.push(json!(text));
    }
}

/// Build the five-chain prerequisite and missing-evidence matrix for one report.
pub fn chain_matrix(report: &Value) -> Result<Value> {
    let summary = summarize_report(report)?;
    let web = summary["web"].as_array().cloned().unwrap_or_default();
    let web_present = !web.is_empty();
    let progress_enabled = web
        .iter()
        .any(|runtime| runtime["upload_progress"] == "enabled");
    let has_sapi = |expected: &[&str]| {
        web.iter().any(|runtime| {
            runtime["sapi"]
                .as_str()
                .is_some_and(|sapi| expected.contains(&sapi))
        })
    };
    let mut rows = vec![];

    let definitions = [
        (
            "A",
            "会话写入 + 应用 LFI",
            vec![
                "Web 实例存在会话上传进度写入路径",
                "应用存在可达的本地文件包含缺陷",
                "会话存储可被该包含点读取",
            ],
            "上传元数据进入会话存储，随后由应用包含路径读取",
            vec![
                "修复 LFI",
                "隔离会话存储与可包含路径",
                "关闭不需要的上传进度并安装完整补丁",
            ],
        ),
        (
            "B",
            "反序列化清理重入",
            vec![
                "实际 Web 构建处于相关影响范围",
                "不可信数据可到达反序列化边界",
                "存在可触发的对象生命周期行为",
            ],
            "异常清理期间发生对象生命周期重入并接触失效状态",
            vec!["更新 PHP", "消除不可信反序列化", "用崩溃栈或内存检测器复核"],
        ),
        (
            "C",
            "会话序列化处理器不一致",
            vec![
                "同一会话可经过不同处理器配置",
                "会话存储在这些路径之间共享",
                "存在受控的对象生命周期证据",
            ],
            "一种格式写入的会话数据被另一处理器解释并进入失败清理",
            vec![
                "统一全部池、目录和虚拟主机配置",
                "更新并重启全部 worker",
                "隔离会话存储",
            ],
        ),
        (
            "D",
            "mod_php 解析期异常与陈旧状态",
            vec![
                "实际 Web SAPI 是 apache2handler",
                "运行映像处于相关影响范围",
                "服务端崩溃栈对应解析和关闭路径",
            ],
            "请求解析异常中断后，关闭阶段接触不完整的执行状态",
            vec![
                "安装完整补丁",
                "重启 Apache worker",
                "关联请求、进程和崩溃日志",
            ],
        ),
        (
            "E",
            "FPM 跨请求陈旧状态",
            vec![
                "实际 Web SAPI 是 FPM/兼容复用 worker",
                "前后请求命中同一 worker",
                "服务端证据显示前一请求异常中止并留下相关状态",
            ],
            "复用 worker 的后一请求在正常初始化前接触前一请求残留状态",
            vec![
                "安装完整补丁",
                "重启全部 FPM 池",
                "按 worker PID 关联连续请求与崩溃日志",
            ],
        ),
    ];
    for (id, name, prerequisites, propagation, defenses) in definitions {
        let mut missing = vec![];
        missing_if(&mut missing, web_present, "缺少实际 Web/FPM 运行时材料");
        match id {
            "A" => {
                missing_if(
                    &mut missing,
                    progress_enabled,
                    "缺少 Web 实例上传进度写入证据",
                );
                missing.push(json!("缺少应用 LFI 代码审计或安全复核证据"));
                missing.push(json!("缺少会话存储与包含路径隔离证据"));
            }
            "B" => {
                missing.push(json!("缺少不可信反序列化调用点审计"));
                missing.push(json!("缺少受控测试环境的崩溃栈或内存检测报告"));
            }
            "C" => {
                missing.push(json!("缺少跨目录、池或虚拟主机的处理器配置对照"));
                missing.push(json!("缺少共享会话存储范围证据"));
            }
            "D" => {
                missing_if(
                    &mut missing,
                    has_sapi(&["apache2handler"]),
                    "Web SAPI 不是已核实的 apache2handler",
                );
                missing.push(json!("缺少服务端解析/关闭路径崩溃栈"));
            }
            "E" => {
                missing_if(
                    &mut missing,
                    has_sapi(&["fpm-fcgi", "frankenphp"]),
                    "Web SAPI 不是已核实的复用 worker 类型",
                );
                missing.push(json!("缺少同一 worker PID 的前后请求关联证据"));
                missing.push(json!("缺少服务端异常中止与残留状态证据"));
            }
            _ => unreachable!(),
        }
        rows.push(json!({
            "id":id,
            "name":name,
            "prerequisites":prerequisites,
            "propagation":propagation,
            "defenses":defenses,
            "missing_evidence":missing,
            "status":"incomplete",
            "exploitation_verified":false
        }));
    }
    Ok(json!({
        "schema":"php-selfcheck-chain-matrix/v1",
        "runtime_summary":summary,
        "chains":rows,
        "rule":"任何单项版本、响应、配置或错误文本都不能补齐整条漏洞链"
    }))
}

fn synthetic_before() -> Value {
    json!({
        "schema":"php-selfcheck-host/v1",
        "source":"synthetic_fixture",
        "runtime_observations":[
            {"scope":"cli_only","sapi":"cli","version":"8.5.12","settings":{"session.upload_progress.enabled":"Off","session.serialize_handler":"php_serialize"}},
            {"scope":"web_runtime","sapi":"fpm-fcgi","version":"8.4.26","settings":{"session.upload_progress.enabled":"On","session.serialize_handler":"php","session.save_handler":"files"}}
        ],
        "patch_evidence":{"vendor_advisory":"","package_revision":"","running_image_matches":false,"workers_restarted":false,"all_backends_sampled":false}
    })
}

fn synthetic_after() -> Value {
    json!({
        "schema":"php-selfcheck-host/v1",
        "source":"synthetic_fixture",
        "runtime_observations":[
            {"scope":"cli_only","sapi":"cli","version":"8.5.12","settings":{"session.upload_progress.enabled":"Off","session.serialize_handler":"php_serialize"}},
            {"scope":"web_runtime","sapi":"fpm-fcgi","version":"8.4.27","settings":{"session.upload_progress.enabled":"Off","session.serialize_handler":"php_serialize","session.save_handler":"files"}}
        ],
        "patch_evidence":{"vendor_advisory":"https://vendor.invalid/advisory","package_revision":"8.4.27-synthetic1","running_image_matches":true,"workers_restarted":true,"all_backends_sampled":true}
    })
}

fn rule(id: &str, title: &str, passed: bool, evidence: Value) -> Value {
    json!({"id":id,"title":title,"passed":passed,"evidence":evidence})
}

/// Deterministic, synthetic and non-operational PoC for the evidence engine.
pub fn offline_poc() -> Result<Value> {
    let before_report = synthetic_before();
    let after_report = synthetic_after();
    let before = summarize_report(&before_report)?;
    let after = summarize_report(&after_report)?;
    let comparison = compare_reports(&before_report, &after_report)?;
    let matrix = chain_matrix(&after_report)?;
    let chains = matrix["chains"].as_array().context("合成矩阵无效")?;
    let rules = vec![
        rule(
            "E1",
            "CLI 与 Web 运行时严格分离",
            first_text(&before, "cli", "version") == "8.5.12"
                && first_text(&before, "web", "version") == "8.4.26",
            json!({"cli":before["cli"],"web":before["web"]}),
        ),
        rule(
            "E2",
            "版本只产生基线线索，不确认修复",
            first_text(&before, "web", "version_status") == "below_upstream_fix"
                && first_text(&after, "web", "version_status") == "meets_upstream_fix"
                && after["patch_evidence"]["independently_verified"] == false,
            json!({"before":first_text(&before,"web","version_status"),"after":first_text(&after,"web","version_status"),"verified":false}),
        ),
        rule(
            "E3",
            "配置证据绑定其运行时范围",
            first_text(&before, "cli", "upload_progress") == "disabled"
                && first_text(&before, "web", "upload_progress") == "enabled",
            json!({"cli":first_text(&before,"cli","upload_progress"),"web":first_text(&before,"web","upload_progress")}),
        ),
        rule(
            "E4",
            "SAPI 只决定链路适用面，不证明链路成立",
            first_text(&before, "web", "sapi") == "fpm-fcgi"
                && chains.iter().all(|chain| chain["status"] == "incomplete"),
            json!({"web_sapi":first_text(&before,"web","sapi"),"chain_statuses":chains.iter().map(|v|v["status"].clone()).collect::<Vec<_>>()}),
        ),
        rule(
            "E5",
            "五类链路均要求缺失证据矩阵",
            chains.len() == 5
                && chains.iter().all(|chain| {
                    chain["missing_evidence"]
                        .as_array()
                        .is_some_and(|missing| !missing.is_empty())
                        && chain["exploitation_verified"] == false
                }),
            json!({"chain_count":chains.len(),"all_incomplete":true}),
        ),
        rule(
            "E6",
            "修复前后对比不升级为独立验证",
            comparison["conclusion"] == "remediation_evidence_improved"
                && comparison["patch_independently_verified"] == false
                && comparison["exploitability_confirmed"] == false,
            json!({"conclusion":comparison["conclusion"],"patch_verified":comparison["patch_independently_verified"],"exploitability_confirmed":comparison["exploitability_confirmed"]}),
        ),
    ];
    let passed = rules.iter().filter(|rule| rule["passed"] == true).count();
    let sources = SOURCES
        .iter()
        .map(|(name, url)| json!({"name":name,"url":url}))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema":"php-selfcheck-offline-poc/v1",
        "mode":"offline_synthetic",
        "guarantees":{"network_requests":0,"target_connections":0,"php_commands":0,"exploit_payloads":0,"vulnerability_triggers":0},
        "synthetic_reports":{"before":before_report,"after":after_report},
        "comparison":comparison,
        "chain_matrix":matrix,
        "rules":rules,
        "summary":{"passed":passed,"total":6,"all_passed":passed==6},
        "sources":sources
    }))
}

pub fn human_poc(result: &Value) -> String {
    let mut lines = vec![format!(
        "离线无害 PoC：{}/{} 项证据规则通过",
        result["summary"]["passed"].as_u64().unwrap_or(0),
        result["summary"]["total"].as_u64().unwrap_or(0)
    )];
    lines.push("网络请求 0 · 目标连接 0 · PHP 命令 0 · 漏洞载荷 0 · 漏洞触发 0".into());
    for item in result["rules"].as_array().into_iter().flatten() {
        lines.push(format!(
            "{} {} · {}",
            if item["passed"] == true {
                "通过"
            } else {
                "失败"
            },
            item["id"].as_str().unwrap_or("?"),
            item["title"].as_str().unwrap_or("")
        ));
    }
    lines.push(format!(
        "报告对比：{}（不等于独立确认修复）",
        result["comparison"]["conclusion"]
            .as_str()
            .unwrap_or("requires_review")
    ));
    lines.join("\n")
}

pub fn human_comparison(result: &Value) -> String {
    let mut lines = vec!["修复前后运行时报告对比（离线）".to_owned()];
    for item in result["changes"].as_array().into_iter().flatten() {
        let show = |value: &Value| match value {
            Value::Null => "未知".to_owned(),
            Value::String(value) => value.clone(),
            Value::Array(values) if values.is_empty() => "未知".to_owned(),
            Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .collect::<Vec<_>>()
                .join("、"),
            other => other.to_string(),
        };
        lines.push(format!(
            "{}: {} -> {}{}",
            item["field"].as_str().unwrap_or("unknown"),
            show(&item["before"]),
            show(&item["after"]),
            if item["changed"] == true {
                "（变化）"
            } else {
                ""
            }
        ));
    }
    lines.push(format!(
        "结论：{}；材料未经独立核验。",
        result["conclusion"].as_str().unwrap_or("requires_review")
    ));
    lines.join("\n")
}

/// Read bounded JSON for the offline comparison CLI.
pub fn read_report(path: &std::path::Path) -> Result<Value> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("无法读取报告 {}", path.display()))?;
    ensure!(metadata.len() <= 1_048_576, "报告超过 1 MiB 限制");
    let bytes = std::fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("报告不是有效 JSON: {}", path.display()))?;
    ensure!(value.is_object(), "报告根节点必须是对象");
    Ok(value)
}
