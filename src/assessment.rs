//! Evidence describes observations, not exploitability. Imported assertions never become verified facts.
use regex::Regex;
use serde_json::{Value, json};
use std::sync::LazyLock;
pub const SOURCES: [&str; 2] = [
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
];
static MULTIPART: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<form\b[^>]{0,4096}\benctype\s*=\s*["']multipart/form-data["']"#).unwrap()
});
static PROGRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bname\s*=\s*["']PHP_SESSION_UPLOAD_PROGRESS["']"#).unwrap()
});
pub fn observation(status: &str, source: &str, confidence: &str, detail: &str) -> Value {
    json!({"status":status,"source":source,"confidence":confidence,"detail":detail})
}
pub fn remote(headers: &[(String, String)], body: &[u8], versions: &[String]) -> Value {
    let page = String::from_utf8_lossy(body);
    let server = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.chars().take(300).collect::<String>())
        .collect::<Vec<_>>()
        .join("; ");
    let mut patch = observation(
        "unknown",
        "not_observed",
        "none",
        "实际 Web 实例与厂商补丁尚未核实",
    );
    let mut lifecycle = observation(
        "unknown",
        "not_observed",
        "none",
        "缺少唯一且可识别的版本声明",
    );
    if versions.len() == 1 {
        let parts = versions[0]
            .split('.')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>();
        if let Ok(p) = parts
            && p.len() == 3
        {
            let fixed = match (p[0], p[1]) {
                (8, 2) => Some(35),
                (8, 3) => Some(36),
                (8, 4) => Some(27),
                (8, 5) => Some(12),
                _ => None,
            };
            if let Some(f) = fixed {
                patch = if p[2] < f {
                    observation(
                        "below_upstream_fix",
                        "response_header",
                        "low",
                        "声明版本低于官方修复基线；回补补丁状态未知",
                    )
                } else {
                    observation(
                        "meets_upstream_fix",
                        "response_header",
                        "low",
                        "声明版本达到上游基线，不证明实际实例已修复",
                    )
                };
                lifecycle = observation(
                    "supported_branch",
                    "response_header",
                    "low",
                    "截至 2026-10-23 的上游支持分支，仍须检查补丁",
                );
            } else if (5..=7).contains(&p[0]) || (p[0] == 8 && p[1] <= 1) {
                lifecycle = observation(
                    "eol",
                    "response_header",
                    "low",
                    "已停止上游维护；发行版、商业 LTS 或源码回补状态未知",
                );
            }
        }
    }
    let priority = if patch["status"] == "below_upstream_fix" || lifecycle["status"] == "eol" {
        "high"
    } else {
        "review"
    };
    json!({
        "web_server":observation(if server.is_empty(){"unknown"}else{"header_claim"},"response_header",if server.is_empty(){"none"}else{"low"},&server),
        "sapi":observation("unknown","not_observed","none","Server 头不能确认 mod_php、FPM 或其他 SAPI"),
        "multipart":if MULTIPART.is_match(&page){observation("form_hint","page_reference","low","页面含 multipart 表单，不证明请求进入 PHP 解析器")}else{observation("unknown","not_tested","none","未执行 multipart POST；未发现表单不代表不支持")},
        "upload_progress":if PROGRESS.is_match(&page){observation("field_hint","page_reference","low","发现默认上传进度字段名，仅为线索，不证明配置开启")}else{observation("unknown","not_observed","none","HTTP GET 无法确认配置；无标记不代表关闭")},
        "patch":patch,"lifecycle":lifecycle,
        "review_priority":priority,"confidence":"low","sources":SOURCES,
        "review_hints":["核实实际 Web/FPM SAPI、运行版本和软件包修订号","确认厂商公告或源码回补记录，并核查全部后端 worker","upload_progress 关闭仅阻断部分路径，不能代替完整修复","multipart 响应、空白 500 和内存耗尽均不能单独确认 RCE"]
    })
}
/// User-entered review fields are an allowlisted assertion, never an authority override.
pub fn review(raw: &Value) -> anyhow::Result<Value> {
    if raw.is_null() {
        return Ok(json!({}));
    }
    anyhow::ensure!(raw.is_object(), "复核信息必须是对象");
    let mut out = json!({});
    for (key, allowed) in [
        (
            "sapi",
            vec![
                "unknown",
                "apache2handler",
                "fpm-fcgi",
                "cgi-fcgi",
                "frankenphp",
                "litespeed",
                "cli",
            ],
        ),
        ("upload_progress", vec!["unknown", "enabled", "disabled"]),
        (
            "patch_status",
            vec!["unknown", "fixed_claimed", "missing_claimed"],
        ),
    ] {
        if let Some(value) = raw.get(key) {
            let v = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("复核字段格式错误"))?;
            anyhow::ensure!(allowed.contains(&v), "复核字段值不支持: {key}");
            out[key] = json!(v);
        }
    }
    for key in ["patch_vendor", "package_revision", "advisory_url", "notes"] {
        if let Some(value) = raw.get(key) {
            let v = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("复核字段格式错误"))?;
            anyhow::ensure!(v.len() <= 2000, "复核信息过长");
            if key == "advisory_url" && !v.is_empty() {
                let url = url::Url::parse(v)?;
                anyhow::ensure!(
                    matches!(url.scheme(), "http" | "https")
                        && url.username().is_empty()
                        && url.password().is_none(),
                    "公告链接须为不含凭据的 HTTP/HTTPS URL"
                );
            }
            out[key] = json!(v);
        }
    }
    Ok(out)
}
pub fn host(payload: &Value) -> Value {
    let runtimes = payload["report"]["runtime_observations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut observations = vec![];
    for runtime in runtimes.iter().take(32) {
        let sapi = runtime["sapi"].as_str().unwrap_or("unknown");
        let scope = match sapi {
            "cli" | "phpdbg" => "cli_only",
            "apache2handler" | "fpm-fcgi" | "cgi-fcgi" | "frankenphp" | "litespeed"
            | "cli-server" => "web_runtime_claimed",
            _ => "unknown",
        };
        let setting = &runtime["settings"]["session.upload_progress.enabled"];
        let enabled = match setting {
            Value::Bool(b) => Some(*b),
            Value::String(s) => match s.to_ascii_lowercase().as_str() {
                "1" | "on" | "true" => Some(true),
                "" | "0" | "off" | "false" => Some(false),
                _ => None,
            },
            _ => None,
        };
        observations.push(json!({"scope":scope,"sapi":sapi,"version":runtime["version"],"upload_progress":enabled.map(|b|if b{"enabled"}else{"disabled"}).unwrap_or("unknown"),"settings":runtime["settings"],"confidence":"unverified","source":"developer_supplied_runtime_report"}));
    }
    let raw = &payload["report"]["middleware"];
    let entries = |key: &str, limit: usize| {
        raw[key]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|v| v.is_object())
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let middleware = json!({"status":raw["status"].as_str().unwrap_or("not_collected"),"instances":entries("instances",128),"web_probes":entries("web_probes",64),"source":"developer_supplied_host_report","confidence":"unverified"});
    json!({"middleware":middleware,"trust":"开发者提交，未经独立核验","association":"用户指定关联目标，未验证实例归属","runtime_observations":observations,"review":payload["review"],"patch_status":"unverified","confidence":"unverified","verdict_promoted":false})
}
