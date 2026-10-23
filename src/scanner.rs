//! Read-only HTTP fingerprints. Every hop is scoped before connecting to a pinned IP.
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
    LazyLock::new(|| Regex::new(r"(?i)\bPHP[/\s]+(\d+\.\d+\.\d+)\b").unwrap());
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
                    .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c)),
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
        cfg.allowed_ports
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
        !cfg.allowed_networks.is_empty(),
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
            nets.iter().any(|n| n.contains(ip)),
            "目标或 DNS 地址不在资产网段白名单"
        );
    }
    Ok(())
}
async fn resolve(u: &Url, cfg: &Config) -> Result<Vec<IpAddr>> {
    // Check non-DNS scope first, so empty scope never performs DNS lookups.
    ensure!(
        !cfg.allowed_networks.is_empty(),
        "未配置资产网段；默认禁止扫描"
    );
    ensure!(
        cfg.allowed_ports
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
    let mut response = client
        .get(u.clone())
        .header("User-Agent", "Company-PHP-SelfCheck/0.2")
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
pub fn version_risk(v: &str) -> (&'static str, &'static str) {
    let p = v
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(p) = p else {
        return ("无法判断", "版本格式错误");
    };
    if p.len() != 3 {
        return ("无法判断", "版本格式错误");
    }
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
                "披露版本低于原版修复基线；需排除发行版回补补丁",
            );
        }
        return (
            "版本达到修复基线（待核验）",
            "仅为远程版本声明；需核验实际 Web 实例与厂商补丁",
        );
    }
    if p.as_slice() >= [5, 4, 0].as_slice() && p.as_slice() < [8, 2, 0].as_slice() {
        return (
            "疑似受影响",
            "旧版 PHP；需核验厂商回补补丁或升级至受支持版本",
        );
    }
    ("无法判断", "规则未覆盖此版本，不推断安全状态")
}
pub fn inspect(headers: &[(String, String)], body: &[u8]) -> Value {
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
    let (verdict, reason) = if versions.len() > 1 {
        ("无法判断", "检测到多个版本声明，请核查代理头与后端实例")
    } else if let Some(v) = versions.first() {
        version_risk(v)
    } else if strong {
        (
            "已识别 PHP 特征，版本未知",
            "需主机侧核验；特征可被隐藏或伪造",
        )
    } else if weak {
        ("疑似使用 PHP", "页面路径不足以确认运行 PHP")
    } else {
        ("未发现 PHP 特征", "不代表未使用 PHP，也不代表无漏洞")
    };
    json!({"verdict":verdict,"reason":reason,"versions":versions,"evidence":evidence,"cves":["CVE-2026-109618","CVE-2026-109619"],"rule_date":RULE_DATE,"source":SOURCE,"rule_provenance":"原 Python v0.1 规则，迁移时未重新核实公告","exploitation_verified":false})
}
pub async fn scan(target: &str, cfg: &Config) -> Value {
    scan_using(target, |u: Url| async move {
        let ips = resolve(&u, cfg).await?;
        Ok((request_pinned(&u, ips[0]).await?, ips[0]))
    })
    .await
}
async fn scan_using<F, Fut>(target: &str, mut fetch: F) -> Value
where
    F: FnMut(Url) -> Fut,
    Fut: std::future::Future<Output = Result<(Reply, IpAddr)>>,
{
    let mut result =
        json!({"target":target,"checked_at":chrono::Utc::now().to_rfc3339(),"hops":[]});
    let outcome: Result<()> = async {
        let mut u = normalize(target)?;
        for hop in 0..4 {
            let (r, ip) = fetch(u.clone()).await?;
            let findings = inspect(&r.headers, &r.body);
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
            let location = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"));
            if matches!(r.status, 301 | 302 | 303 | 307 | 308)
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
    async fn redirect_revalidates_scope() {
        let cfg = Config {
            public_origin: "http://localhost".into(),
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
