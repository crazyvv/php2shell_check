//! Bounded HTTP observations. Every request is scoped before connecting to a pinned IP.
use crate::config::Config;
use anyhow::{Result, bail, ensure};
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};
use url::Url;
pub const RULE_DATE: &str = "2026-10-23";
pub const SOURCE: &str = "https://www.php.net/archive/2026.php#2026-10-21-5";
pub const MAX_BODY: usize = 131072;
static PHP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bPHP\b").unwrap());
static VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bPHP[/\s]+([^\s,;)]+)").unwrap());
static WEAK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:href|src|action)\s*=\s*["'][^"']{0,500}\.php(?:[?"'/])"#).unwrap()
});
pub fn normalize(value: &str) -> Result<Url> {
    let value = value.trim();
    ensure!(
        !value.is_empty()
            && value.len() <= 2048
            && !value
                .chars()
                .any(|c| c <= ' ' || c == '\u{7f}' || c == '\\'),
        "目标为空、过长或包含控制字符"
    );
    let value = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let mut u = Url::parse(&value)?;
    ensure!(
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && !value
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .contains('@'),
        "仅支持不含账号密码的 HTTP/HTTPS URL"
    );
    ensure!(u.fragment().is_none(), "请去掉 URL 中的 # 片段");
    if let Some(url::Host::Domain(host)) = u.host() {
        let host = host.trim_end_matches('.').to_owned();
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "域名格式错误"
        );
        u.set_host(Some(&host))?;
    }
    Ok(u)
}
pub fn forbidden(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    match ip {
        IpAddr::V4(a) => {
            let b = a.octets();
            a.is_link_local()
                || a.is_broadcast()
                || b[0] >= 240
                || b[0] == 0
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || ["100.100.100.200", "168.63.129.16"].contains(&a.to_string().as_str())
        }
        IpAddr::V6(a) => {
            // Conservatively allow only global unicast and private ULA. No mapped IPv4.
            let n = u128::from(a);
            a.to_ipv4_mapped().is_some()
                || a.is_unicast_link_local()
                || !((n >> 125 == 1) || (n >> 121 == 0x7e))
                || a.to_string() == "fd00:ec2::254"
        }
    }
}
pub fn validate_addresses(u: &Url, cfg: &Config, ips: &[IpAddr]) -> Result<()> {
    ensure!(
        (cfg.allow_without_whitelist && cfg.allowed_ports.is_empty())
            || cfg
                .allowed_ports
                .contains(&u.port_or_known_default().unwrap_or(0)),
        "端口不在管理员允许范围"
    );
    if let Some(url::Host::Domain(host)) = u.host() {
        ensure!(
            cfg.allowed_domains.is_empty()
                || cfg
                    .allowed_domains
                    .iter()
                    .any(|d| host == d || host.ends_with(&format!(".{d}"))),
            "域名不在允许范围"
        );
    }
    ensure!(
        cfg.allow_without_whitelist || !cfg.allowed_networks.is_empty(),
        "未配置资产网段；默认禁止扫描"
    );
    let nets = cfg
        .allowed_networks
        .iter()
        .map(|n| n.parse::<ipnet::IpNet>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!ips.is_empty(), "DNS 没有返回地址");
    for ip in ips {
        ensure!(!forbidden(*ip), "目标包含禁止访问的特殊地址");
        ensure!(
            (cfg.allow_without_whitelist && nets.is_empty()) || nets.iter().any(|n| n.contains(ip)),
            "目标或 DNS 地址不在资产网段白名单"
        );
    }
    Ok(())
}
async fn resolve(u: &Url, cfg: &Config) -> Result<Vec<IpAddr>> {
    // Check non-DNS scope before resolving; empty scope is denied unless explicitly allowed.
    ensure!(
        cfg.allow_without_whitelist || !cfg.allowed_networks.is_empty(),
        "未配置资产网段；默认禁止扫描"
    );
    ensure!(
        (cfg.allow_without_whitelist && cfg.allowed_ports.is_empty())
            || cfg
                .allowed_ports
                .contains(&u.port_or_known_default().unwrap_or(0)),
        "端口不在管理员允许范围"
    );
    let host = match u.host().unwrap() {
        url::Host::Domain(h) => h.to_owned(),
        url::Host::Ipv4(a) => a.to_string(),
        url::Host::Ipv6(a) => a.to_string(),
    };
    if matches!(u.host(), Some(url::Host::Domain(_))) && !cfg.allowed_domains.is_empty() {
        ensure!(
            cfg.allowed_domains
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}"))),
            "域名不在允许范围"
        );
    }
    let ips: Vec<_> = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), u.port_or_known_default().unwrap())),
    )
    .await??
    .map(|s| s.ip())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    validate_addresses(u, cfg, &ips)?;
    Ok(ips)
}
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}
async fn request_pinned(u: &Url, ip: IpAddr) -> Result<Reply> {
    request_method(u, ip, RequestKind::Get).await
}
#[derive(Clone, Copy)]
enum RequestKind {
    Get,
    Head,
    GetHeaders,
    Multipart,
    Progress,
}
fn progress_control_body() -> String {
    // Ordinary text only. No PHP bytes, serializer syntax, supplied SID, or stress fields.
    format!(
        "--PHPSELFCheckProgress\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nselfcheck_{}\r\n--PHPSELFCheckProgress\r\nContent-Disposition: form-data; name=\"selfcheck_text\"; filename=\"php-selfcheck.txt\"\r\nContent-Type: text/plain\r\n\r\nselfcheck\r\n--PHPSELFCheckProgress--\r\n",
        crate::config::token(8)
    )
}
fn progress_observation(reply: &Reply, baseline_cookie: bool) -> Value {
    let cookie = reply.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("set-cookie")
            && value
                .split_once('=')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("PHPSESSID"))
    });
    // This observation omits session fixation/readback, LFI and fault requests.
    // See docs/ikow-detection-review.md for the defensive verification workflow.
    // Application session_start(), proxies and normal business logic can all set this cookie.
    // Neither a cookie nor a reflected marker proves parser reachability, a session write or CVE.
    let mut out = crate::assessment::observation(
        if cookie {
            "session_cookie_hint"
        } else {
            "unknown"
        },
        "minimal_upload_progress_observation",
        "low",
        "小型普通文本文件 POST；Cookie、反射或 HTTP 状态均不能确认 upload_progress 配置、会话写入、漏洞或修复。未指定会话 ID、不回读文件、不跟随跳转。",
    );
    out["http_status"] = json!(reply.status);
    out["session_cookie_observed"] = json!(cookie);
    out["baseline_session_cookie_observed"] = json!(baseline_cookie);
    out["exploitation_verified"] = json!(false);
    out
}
async fn request_method(u: &Url, ip: IpAddr, kind: RequestKind) -> Result<Reply> {
    let host = u.host_str().unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(13))
        .resolve(
            host,
            SocketAddr::new(ip, u.port_or_known_default().unwrap()),
        )
        .build()?;
    let request = if matches!(kind, RequestKind::Multipart) {
        client.post(u.clone()).header("Content-Type","multipart/form-data; boundary=PHPSELFCheckControl")
            .body("--PHPSELFCheckControl\r\nContent-Disposition: form-data; name=\"selfcheck_control\"\r\n\r\n1\r\n--PHPSELFCheckControl--\r\n")
    } else if matches!(kind, RequestKind::Progress) {
        client
            .post(u.clone())
            .header(
                "Content-Type",
                "multipart/form-data; boundary=PHPSELFCheckProgress",
            )
            .body(progress_control_body())
    } else if matches!(kind, RequestKind::Head) {
        client.head(u.clone())
    } else {
        client.get(u.clone())
    };
    let mut response = request
        .header(
            "User-Agent",
            format!("Company-PHP-SelfCheck/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Accept", "text/html,application/json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .send()
        .await?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    if matches!(kind, RequestKind::Head | RequestKind::GetHeaders) {
        return Ok(Reply {
            status,
            headers,
            body: vec![],
            truncated: false,
        });
    }
    let body = tokio::time::timeout(Duration::from_secs(8), async {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let take = chunk.len().min(MAX_BODY + 1 - body.len());
            body.extend_from_slice(&chunk[..take]);
            if body.len() > MAX_BODY {
                break;
            }
        }
        Ok::<_, reqwest::Error>(body)
    })
    .await??;
    let truncated = body.len() > MAX_BODY;
    Ok(Reply {
        status,
        headers,
        body: body.into_iter().take(MAX_BODY).collect(),
        truncated,
    })
}
/// Preserve the raw banner; distro revisions are not evidence of a vendor backport.
pub fn stable_version(value: &str) -> Option<[u32; 3]> {
    static STABLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(\d+)\.(\d+)\.(\d+)([-+~][A-Za-z0-9.+~:_-]+)?$").unwrap());
    static PRE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)(?:^|[-+~._])(?:dev|alpha|beta|rc)").unwrap());
    let c = STABLE.captures(value)?;
    if c.get(4).is_some_and(|s| PRE.is_match(s.as_str())) {
        return None;
    }
    Some([c[1].parse().ok()?, c[2].parse().ok()?, c[3].parse().ok()?])
}
pub fn check_exit_code(result: &Value) -> u8 {
    match result["verdict"].as_str() {
        Some("版本达到修复基线（待核验）") => 0,
        Some("疑似受影响") => 1,
        _ => 3,
    }
}
pub fn version_risk(v: &str) -> (&'static str, &'static str) {
    let Some(p) = stable_version(v) else {
        return (
            "无法判断",
            "预发布、格式不明或未识别的版本声明，不按正式修复版判断",
        );
    };
    let fix = match (p[0], p[1]) {
        (8, 2) => Some(35),
        (8, 3) => Some(36),
        (8, 4) => Some(27),
        (8, 5) => Some(12),
        _ => None,
    };
    if let Some(fix) = fix {
        if p[2] < fix {
            return (
                "疑似受影响",
                "披露版本低于官方修复基线；需排除发行版回补补丁",
            );
        }
        return (
            "版本达到修复基线（待核验）",
            "仅为远程版本声明；需核验实际 Web 实例与厂商补丁",
        );
    }
    if matches!((p[0], p[1]), (5, 4..=6) | (7, 0..=4) | (8, 0..=1)) {
        return (
            "疑似受影响",
            "已停止上游维护的 PHP；补丁状态未知，需核验厂商或源码回补",
        );
    }
    ("无法判断", "规则未覆盖此版本，不推断安全状态")
}
pub fn inspect(headers: &[(String, String)], body: &[u8]) -> Value {
    inspect_with_library(headers, body, None, &crate::fingerprints::builtin())
}
pub fn inspect_with_library(
    headers: &[(String, String)],
    body: &[u8],
    url: Option<&Url>,
    library: &crate::fingerprints::Library,
) -> Value {
    let fingerprints = library.detect(url, headers, body);
    let mut evidence = vec![];
    let mut versions = BTreeSet::new();
    let mut strong = false;
    for (name, value) in headers {
        let low = name.to_ascii_lowercase();
        if matches!(low.as_str(), "x-powered-by" | "server") && PHP.is_match(value) {
            strong = true;
            evidence.push(json!({"kind":"response_header","detail":format!("{name}: {}",value.chars().take(300).collect::<String>())}));
            for c in VERSION.captures_iter(value) {
                versions.insert(c[1].to_owned());
            }
        }
        if low == "set-cookie"
            && value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("phpsessid=")
        {
            strong = true;
            evidence.push(
                json!({"kind":"cookie_name","detail":"PHPSESSID（值已省略，可自定义或伪造）"}),
            );
        }
    }
    let weak = WEAK.is_match(&String::from_utf8_lossy(body));
    if weak {
        evidence.push(json!({"kind":"page_reference","detail":"页面引用 .php 路径，仅为弱线索"}));
    }
    let versions: Vec<_> = versions.into_iter().collect();
    let (mut verdict, mut reason) = if versions.len() > 1 {
        ("无法判断", "检测到多个版本声明，请核查代理头与后端实例")
    } else if let Some(v) = versions.first() {
        version_risk(v)
    } else if strong {
        (
            "已识别 PHP 特征，版本未知",
            "需主机侧核验；特征可被隐藏或伪造",
        )
    } else if weak || fingerprints["php_hint"] == true {
        (
            "疑似使用 PHP",
            "页面路径或 CMS/框架特征仅为线索；PHP 版本及实际实例仍需核实",
        )
    } else {
        ("未发现 PHP 特征", "不代表未使用 PHP，也不代表无漏洞")
    };
    let mut assessment = crate::assessment::remote(headers, body, &versions);
    assessment["surfaces"] = crate::surfaces::inspect(url, body);
    let warnings: Vec<_> = versions
        .iter()
        .filter(|v| version_risk(v).0 == "疑似受影响")
        .cloned()
        .collect();
    if !warnings.is_empty() {
        assessment["review_priority"] = json!("high");
    }

    if fingerprints["blocked_hint"] == true {
        verdict = "无法完成检测";
        reason = "命中挑战页特征，响应可能来自防护层；不能据此判断业务实例，不自动绕过";
        assessment["patch"] = crate::assessment::observation(
            "unknown",
            "intermediary_response",
            "none",
            "挑战页响应不能确认业务实例的补丁状态；版本声明仅作为原始线索保留",
        );
    }
    json!({"fingerprints":fingerprints,"version_warnings":warnings,"assessment":assessment,"verdict":verdict,"reason":reason,"versions":versions,"evidence":evidence,"cves":["CVE-2026-109618","CVE-2026-109619"],"rule_date":RULE_DATE,"source":SOURCE,"rule_provenance":"2026-10-23 已核对 PHP 官方 GHSA 与 php-src NEWS","exploitation_verified":false})
}
async fn headers_using<F, Fut>(mut fetch: F) -> Result<(Reply, IpAddr, Vec<Value>)>
where
    F: FnMut(RequestKind) -> Fut,
    Fut: std::future::Future<Output = Result<(Reply, IpAddr)>>,
{
    let (mut reply, mut ip) = fetch(RequestKind::Head).await?;
    let mut trace = vec![
        json!({"method":"HEAD","http_status":reply.status,"ip":ip.to_string(),"body_read":false}),
    ];
    if matches!(reply.status, 405 | 501) {
        let (mut fallback, next_ip) = fetch(RequestKind::GetHeaders).await?;
        trace.push(json!({"method":"GET","http_status":fallback.status,"ip":next_ip.to_string(),"body_read":false}));
        fallback.headers.extend(reply.headers);
        reply = fallback;
        ip = next_ip;
    }
    Ok((reply, ip, trace))
}
pub async fn scan(target: &str, cfg: &Config) -> Value {
    let library = cfg
        .fingerprint_library
        .clone()
        .unwrap_or_else(crate::fingerprints::builtin);
    let trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let mut result = if cfg.headers_only {
        let trace = trace.clone();
        scan_using_library(
            target,
            move |u: Url| {
                let trace = trace.clone();
                async move {
                    let (reply, ip, requests) = headers_using(|kind| {
                        let u = u.clone();
                        async move {
                            let ips = resolve(&u, cfg).await?;
                            Ok((request_method(&u, ips[0], kind).await?, ips[0]))
                        }
                    })
                    .await?;
                    *trace.lock().unwrap() = requests;
                    Ok((reply, ip))
                }
            },
            false,
            library,
        )
        .await
    } else {
        scan_using_library(
            target,
            |u: Url| async move {
                let ips = resolve(&u, cfg).await?;
                Ok((request_pinned(&u, ips[0]).await?, ips[0]))
            },
            true,
            library,
        )
        .await
    };
    if cfg.headers_only {
        result["requests"] = json!(*trace.lock().unwrap());
    }
    result["scan_mode"] = json!(if cfg.headers_only {
        "headers_only"
    } else {
        "full"
    });
    if cfg.headers_only {
        result["assessment"]["multipart"] = crate::assessment::observation(
            "unknown",
            "not_tested",
            "none",
            "仅响应头模式，不读取页面或发送 multipart POST",
        );
    }
    if cfg.probe_multipart
        && !cfg.headers_only
        && result["http_status"]
            .as_u64()
            .is_some_and(|s| (200..300).contains(&s))
        && result["verdict"] != "无法完成检测"
    {
        let probe: Result<(Reply, IpAddr, Url)> = async {
            let u = normalize(
                result["final_url"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("缺少目标"))?,
            )?;
            let ips = resolve(&u, cfg).await?;
            Ok((
                request_method(&u, ips[0], RequestKind::Multipart).await?,
                ips[0],
                u,
            ))
        }
        .await;
        result["assessment"]["multipart"] = match probe {
            Ok((reply, ip, u)) => {
                let status = if (200..300).contains(&reply.status) {
                    "responded"
                } else if matches!(reply.status, 405 | 415) {
                    "rejected"
                } else {
                    "unknown"
                };
                let mut observation = crate::assessment::observation(
                    status,
                    "minimal_multipart_control",
                    "low",
                    "一次小型普通表单 POST；响应不证明 PHP 解析、upload_progress 开启或漏洞存在；不跟随 POST 跳转",
                );
                observation["http_status"] = json!(reply.status);
                observation["connected_ip"] = json!(ip.to_string());
                observation["url"] = json!(u.as_str());
                observation["checked_at"] = json!(chrono::Utc::now().to_rfc3339());
                observation
            }
            Err(_) => crate::assessment::observation(
                "unknown",
                "minimal_multipart_control",
                "none",
                "范围、TLS、DNS 或传输失败，不能据此认定不支持 multipart",
            ),
        };
    }
    if cfg.probe_upload_progress {
        let mut observation = crate::assessment::observation(
            "unknown",
            "not_tested",
            "none",
            "未执行：需要完整 GET 成功、无挑战/拦截且未强制仅响应头模式",
        );
        if !cfg.headers_only
            && result["http_status"]
                .as_u64()
                .is_some_and(|s| (200..300).contains(&s))
            && result["verdict"] != "无法完成检测"
        {
            let probe: Result<(Reply, IpAddr, Url)> = async {
                let u = normalize(
                    result["final_url"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("缺少目标"))?,
                )?;
                let ips = resolve(&u, cfg).await?;
                Ok((
                    request_method(&u, ips[0], RequestKind::Progress).await?,
                    ips[0],
                    u,
                ))
            }
            .await;
            observation = match probe {
                Ok((reply, ip, u)) => {
                    let baseline_cookie = result["evidence"]
                        .as_array()
                        .is_some_and(|v| v.iter().any(|e| e["kind"] == "cookie_name"));
                    let mut o = progress_observation(&reply, baseline_cookie);
                    o["connected_ip"] = json!(ip.to_string());
                    o["url"] = json!(u.as_str());
                    o["checked_at"] = json!(chrono::Utc::now().to_rfc3339());
                    o
                }
                Err(_) => crate::assessment::observation(
                    "unknown",
                    "minimal_upload_progress_observation",
                    "none",
                    "范围、TLS、DNS 或传输失败；不能据此判断是否开启、存在漏洞或已修复",
                ),
            };
        }
        result["assessment"]["upload_progress_probe"] = observation;
    }
    result
}
#[cfg(test)]
async fn scan_using<F, Fut>(target: &str, fetch: F) -> Value
where
    F: FnMut(Url) -> Fut,
    Fut: std::future::Future<Output = Result<(Reply, IpAddr)>>,
{
    scan_using_mode(target, fetch, true).await
}
#[cfg(test)]
async fn scan_using_mode<F, Fut>(target: &str, fetch: F, follow_redirects: bool) -> Value
where
    F: FnMut(Url) -> Fut,
    Fut: std::future::Future<Output = Result<(Reply, IpAddr)>>,
{
    scan_using_library(
        target,
        fetch,
        follow_redirects,
        crate::fingerprints::builtin(),
    )
    .await
}
async fn scan_using_library<F, Fut>(
    target: &str,
    mut fetch: F,
    follow_redirects: bool,
    library: std::sync::Arc<crate::fingerprints::Library>,
) -> Value
where
    F: FnMut(Url) -> Fut,
    Fut: std::future::Future<Output = Result<(Reply, IpAddr)>>,
{
    let mut result = json!({"target":target,"checked_at":chrono::Utc::now().to_rfc3339(),"hops":[],"fingerprints":library.detect(None,&[],&[]),"assessment":crate::assessment::remote(&[],&[],&[])});
    let outcome: Result<()> = async {
        let mut u = normalize(target)?;
        for hop in 0..4 {
            let (r, ip) = fetch(u.clone()).await?;
            let findings = inspect_with_library(&r.headers, &r.body, Some(&u), &library);
            result["hops"].as_array_mut().unwrap().push(
                json!({"url":u.as_str(),"ip":ip.to_string(),"status":r.status,"findings":findings}),
            );
            for (k, v) in findings.as_object().unwrap() {
                result[k] = v.clone();
            }
            result["final_url"] = json!(u.as_str());
            result["connected_ip"] = json!(ip.to_string());
            result["http_status"] = json!(r.status);
            result["body_truncated"] = json!(r.truncated);
            if result["fingerprints"]["blocked_hint"] == true {
                result["verdict"] = json!("无法完成检测");
                result["reason"] =
                    json!("命中挑战页特征，响应可能来自防护层；不能据此判断业务实例，不自动绕过");
                result["assessment"]["patch"] = crate::assessment::observation(
                    "unknown",
                    "intermediary_response",
                    "none",
                    "挑战页响应不能确认业务实例的补丁状态；版本声明仅作为原始线索保留",
                );
                break;
            }
            let location = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"));
            if follow_redirects
                && matches!(r.status, 301 | 302 | 303 | 307 | 308)
                && let Some((_, loc)) = location
            {
                if hop == 3 {
                    bail!("重定向次数超过限制")
                }
                u = normalize(u.join(loc)?.as_str())?;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            if matches!(r.status, 401 | 403 | 407 | 429) || r.status >= 500 {
                result["verdict"] = json!("无法完成检测");
                result["reason"] = json!("HTTP 状态提示认证、拦截、限流或服务异常；已保留可见特征");
            }
            break;
        }
        Ok(())
    }
    .await;
    if let Err(e) = outcome {
        result["verdict"] = json!("无法完成检测");
        result["reason"] = json!(e.to_string().chars().take(300).collect::<String>());
        result["exploitation_verified"] = json!(false);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn configured_fingerprints_use_only_fetched_responses_and_stop_at_challenges() {
        let library=crate::fingerprints::Library::from_json(r#"{"schema":"php-selfcheck-fingerprints/v1","version":"custom","mode":"extend","rules":[{"id":"own","name":"Our PHP app","category":"framework","runtime":"php","any":[{"source":"header","header":"x-app","pattern":"^our-app$"}]}]}"#).unwrap();
        let mut calls = 0;
        let r = scan_using_library(
            "https://example.com",
            |_| {
                calls += 1;
                async {
                    Ok((
                        Reply {
                            status: 200,
                            headers: vec![("x-app".into(), "our-app".into())],
                            body: vec![],
                            truncated: false,
                        },
                        "10.0.0.1".parse().unwrap(),
                    ))
                }
            },
            true,
            library,
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(r["verdict"], "疑似使用 PHP");
        assert_eq!(r["fingerprints"]["library"]["version"], "custom");
        assert_eq!(
            r["hops"][0]["findings"]["fingerprints"]["matches"][0]["evidence"][0]["url"],
            "https://example.com/"
        );
        let mut calls = 0;
        let r = scan_using_library(
            "https://example.com",
            |_| {
                calls += 1;
                async {
                    Ok((
                        Reply {
                            status: 302,
                            headers: vec![
                                ("cf-mitigated".into(), "challenge".into()),
                                ("location".into(), "https://elsewhere.invalid/".into()),
                            ],
                            body: vec![],
                            truncated: false,
                        },
                        "10.0.0.1".parse().unwrap(),
                    ))
                }
            },
            true,
            crate::fingerprints::builtin(),
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(r["verdict"], "无法完成检测");
    }
    #[tokio::test]
    async fn headers_mode_falls_back_only_on_405_501_and_never_reads_body() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        for fallback_status in [405, 501] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                for method in ["HEAD", "GET"] {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut bytes = [0; 4096];
                    let n = socket.read(&mut bytes).await.unwrap();
                    let text = String::from_utf8_lossy(&bytes[..n]);
                    assert!(text.starts_with(&format!("{method} / ")));
                    assert!(!text.to_lowercase().contains("authorization:"));
                    if method == "HEAD" {
                        socket.write_all(format!("HTTP/1.1 {fallback_status} Unsupported\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
                    } else {
                        socket.write_all(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.27\r\nContent-Length: 999999\r\n\r\nPHP/8.2.34").await.unwrap();
                    }
                }
            });
            let u = Url::parse(&format!("http://headers.invalid:{port}/")).unwrap();
            let (reply, _, trace) = tokio::time::timeout(
                Duration::from_secs(2),
                headers_using(|kind| {
                    let u = u.clone();
                    async move {
                        Ok((
                            request_method(&u, "127.0.0.1".parse().unwrap(), kind).await?,
                            "127.0.0.1".parse().unwrap(),
                        ))
                    }
                }),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(reply.body.is_empty());
            assert_eq!(trace.len(), 2);
            assert_eq!(trace[1]["method"], "GET");
            let finding = inspect(&reply.headers, &reply.body);
            assert_eq!(finding["verdict"], "无法判断");
            assert_eq!(finding["version_warnings"][0], "8.4.26");
            server.await.unwrap();
        }
        for status in [200, 302, 403, 500] {
            let mut calls = 0;
            let (reply, _, trace) = headers_using(|kind| {
                calls += 1;
                assert!(matches!(kind, RequestKind::Head));
                async move {
                    Ok((
                        Reply {
                            status,
                            headers: vec![],
                            body: vec![],
                            truncated: false,
                        },
                        "10.0.0.1".parse().unwrap(),
                    ))
                }
            })
            .await
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(trace.len(), 1);
            assert_eq!(reply.status, status);
        }
    }
    #[tokio::test]
    async fn headers_mode_does_not_follow_redirects() {
        let mut calls = 0;
        let result = scan_using_mode(
            "https://example.com",
            |_| {
                calls += 1;
                async {
                    Ok((
                        Reply {
                            status: 302,
                            headers: vec![("Location".into(), "https://elsewhere.invalid/".into())],
                            body: vec![],
                            truncated: false,
                        },
                        "10.0.0.1".parse().unwrap(),
                    ))
                }
            },
            false,
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(result["hops"].as_array().unwrap().len(), 1);
        assert_eq!(result["final_url"], "https://example.com/");
    }
    #[tokio::test]
    async fn redirect_revalidates_scope() {
        let cfg = Config {
            collection_defaults: Default::default(),
            public_origin: "http://localhost".into(),
            admins: Default::default(),
            allow_anonymous: false,
            probe_multipart: false,
            probe_upload_progress: false,
            headers_only: false,
            fingerprint_file: None,
            fingerprint_library: None,
            allow_without_whitelist: false,
            allowed_networks: vec!["10.0.0.0/8".into()],
            allowed_domains: vec![],
            allowed_ports: vec![80],
            database: String::new(),
            users: Default::default(),
        };
        let result = scan_using("http://example.com", |u: Url| {
            let cfg = cfg.clone();
            async move {
                if u.host_str() == Some("example.com") {
                    Ok((
                        Reply {
                            status: 302,
                            headers: vec![(
                                "Location".into(),
                                "http://169.254.169.254/latest".into(),
                            )],
                            body: vec![],
                            truncated: false,
                        },
                        "10.1.1.1".parse().unwrap(),
                    ))
                } else {
                    validate_addresses(&u, &cfg, &["169.254.169.254".parse().unwrap()])?;
                    panic!("metadata address must be rejected before transport")
                }
            }
        })
        .await;
        assert_eq!(result["verdict"], "无法完成检测");
        assert_eq!(result["hops"].as_array().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn blocked_http_status_and_redirect_limit() {
        for status in [401, 403, 407, 429, 503] {
            let result = scan_using("https://example.com", move |_| async move {
                Ok((
                    Reply {
                        status,
                        headers: vec![],
                        body: vec![],
                        truncated: false,
                    },
                    "10.1.1.1".parse().unwrap(),
                ))
            })
            .await;
            assert_eq!(result["verdict"], "无法完成检测");
        }
        let result = scan_using("https://example.com", |_| async {
            Ok((
                Reply {
                    status: 302,
                    headers: vec![("location".into(), "/again".into())],
                    body: vec![],
                    truncated: false,
                },
                "10.1.1.1".parse().unwrap(),
            ))
        })
        .await;
        assert_eq!(result["hops"].as_array().unwrap().len(), 4);
        assert_eq!(result["reason"], "重定向次数超过限制");
    }
    #[tokio::test]
    async fn tls_does_not_accept_plaintext_endpoint() {
        use tokio::{io::AsyncWriteExt, net::TcpListener};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        assert!(
            request_pinned(
                &Url::parse(&format!("https://test.invalid:{port}/")).unwrap(),
                "127.0.0.1".parse().unwrap()
            )
            .await
            .is_err()
        );
        server.await.unwrap();
    }
    #[test]
    fn progress_cookie_and_reflection_never_confirm_configuration_or_cve() {
        let reply = Reply {
            status: 200,
            headers: vec![("set-cookie".into(), "PHPSESSID=SECRET; HttpOnly".into())],
            body: b"selfcheck marker reflected".to_vec(),
            truncated: false,
        };
        let o = progress_observation(&reply, true);
        assert_eq!(o["status"], "session_cookie_hint");
        assert_eq!(o["confidence"], "low");
        assert_eq!(o["baseline_session_cookie_observed"], true);
        assert_eq!(o["exploitation_verified"], false);
        assert!(!o.to_string().contains("SECRET"));
        assert!(!o.to_string().contains("marker reflected"));
        let empty = Reply {
            headers: vec![],
            ..reply
        };
        assert_eq!(progress_observation(&empty, false)["status"], "unknown");
    }
    #[tokio::test]
    async fn progress_probe_is_bounded_plain_text_without_session_fixation_or_redirects() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = vec![];
            loop {
                let mut buf = [0; 2048];
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.ends_with(b"--PHPSELFCheckProgress--\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(data).unwrap();
            assert!(text.len() < 2048);
            assert!(text.starts_with("POST /check "));
            assert!(text.contains("PHP_SESSION_UPLOAD_PROGRESS"));
            assert!(text.contains("filename=\"php-selfcheck.txt\""));
            assert!(!text.contains("<?"));
            assert!(!text.contains("PHPSESSID"));
            assert!(!text.to_lowercase().contains("\r\ncookie:"));
            assert!(!text.to_lowercase().contains("\r\nauthorization:"));
            assert!(!text.contains("serialize_handler"));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let reply = request_method(
            &Url::parse(&format!("http://progress.invalid:{port}/check")).unwrap(),
            "127.0.0.1".parse().unwrap(),
            RequestKind::Progress,
        )
        .await
        .unwrap();
        assert_eq!(reply.status, 302);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn multipart_control_is_small_and_does_not_follow_redirect() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = vec![];
            loop {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if data.ends_with(b"--PHPSELFCheckControl--\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(data).unwrap();
            assert!(text.starts_with("POST /check "));
            assert!(text.len() < 1024);
            assert!(text.contains("selfcheck_control"));
            assert!(!text.contains("PHP_SESSION_UPLOAD_PROGRESS"));
            assert!(!text.contains("filename="));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let reply = request_method(
            &Url::parse(&format!("http://control.invalid:{port}/check")).unwrap(),
            "127.0.0.1".parse().unwrap(),
            RequestKind::Multipart,
        )
        .await
        .unwrap();
        assert_eq!(reply.status, 302);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn pinned_transport_keeps_host_and_limits_body() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let n = s.read(&mut request).await.unwrap();
            assert!(
                String::from_utf8_lossy(&request[..n])
                    .to_lowercase()
                    .contains(&format!("host: test.invalid:{port}"))
            );
            let body = vec![b'x'; MAX_BODY + 100];
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.34\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let _ = s.write_all(&body).await;
        });
        // Injection is private to this unit test. Production always runs scope checks.
        let r = request_pinned(
            &Url::parse(&format!("http://test.invalid:{port}/")).unwrap(),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert!(r.truncated);
        assert_eq!(r.body.len(), MAX_BODY);
        assert_eq!(inspect(&r.headers, &r.body)["verdict"], "疑似受影响");
        server.await.unwrap();
    }
}
