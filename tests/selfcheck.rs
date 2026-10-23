use php_selfcheck::{
    config::{self, Config},
    portal, scanner,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
fn cfg() -> Config {
    Config {
        public_origin: "http://127.0.0.1:8080".into(),
        admins: BTreeMap::new(),
        allow_anonymous: false,
        probe_multipart: false,
        headers_only: false,
        allow_without_whitelist: false,
        allowed_networks: vec!["10.0.0.0/8".into()],
        allowed_domains: vec![],
        allowed_ports: vec![80, 443],
        database: ":memory:".into(),
        users: BTreeMap::from([("alice".into(), "unused".into())]),
    }
}
#[test]
fn fix_boundaries_and_unknown() {
    for (branch, fix) in [("8.2", 35), ("8.3", 36), ("8.4", 27), ("8.5", 12)] {
        assert_eq!(
            scanner::version_risk(&format!("{branch}.{}", fix - 1)).0,
            "疑似受影响"
        );
        assert!(
            scanner::version_risk(&format!("{branch}.{fix}"))
                .0
                .contains("待核验")
        );
    }
    assert_eq!(scanner::version_risk("7.4.33").0, "疑似受影响");
    assert_eq!(scanner::version_risk("9.0.0").0, "无法判断");
    assert_eq!(scanner::version_risk("8.2.99999999999999999").0, "无法判断");
}
#[test]
fn fingerprints_are_php_specific() {
    let h = vec![
        ("Server".into(), "Apache/8.2.34".into()),
        ("X-Powered-By".into(), "ASP.NET/8.2.34".into()),
    ];
    assert_eq!(scanner::inspect(&h, b"")["verdict"], "未发现 PHP 特征");
    assert_eq!(
        scanner::inspect(&[], b"<a href='index.php'>")["verdict"],
        "疑似使用 PHP"
    );
    let cookie = scanner::inspect(
        &[("Set-Cookie".into(), "PHPSESSID=SECRET; Secure".into())],
        b"",
    );
    assert_eq!(cookie["verdict"], "已识别 PHP 特征，版本未知");
    assert!(!cookie.to_string().contains("SECRET"));
    assert_eq!(
        scanner::inspect(
            &[
                ("Server".into(), "PHP/8.2.34".into()),
                ("X-Powered-By".into(), "PHP/8.3.36".into())
            ],
            b""
        )["verdict"],
        "无法判断"
    );
}
#[test]
fn normalize_and_reject_unsafe_urls() {
    assert_eq!(
        scanner::normalize("example.com").unwrap().as_str(),
        "https://example.com/"
    );
    assert_eq!(
        scanner::normalize("http://[2001:4860::1]:8080/a")
            .unwrap()
            .as_str(),
        "http://[2001:4860::1]:8080/a"
    );
    for u in [
        "file:///etc/passwd",
        "gopher://example.com",
        "https://a:b@example.com",
        "https://@example.com",
        "http://example.com/\r\nX:x",
        "http://[fe80::1%25eth0]/",
        "https://example.com/#secret",
        "http://example.com/\\evil",
    ] {
        assert!(scanner::normalize(u).is_err(), "{u}");
    }
}
#[test]
fn scope_mixed_dns_domains_and_ports() {
    let mut c = cfg();
    c.allowed_domains = vec!["example.com".into()];
    let u = scanner::normalize("a.example.com").unwrap();
    assert!(scanner::validate_addresses(&u, &c, &["10.1.2.3".parse().unwrap()]).is_ok());
    assert!(
        scanner::validate_addresses(
            &u,
            &c,
            &["10.1.2.3".parse().unwrap(), "8.8.8.8".parse().unwrap()]
        )
        .is_err()
    );
    assert!(
        scanner::validate_addresses(
            &scanner::normalize("evilexample.com").unwrap(),
            &c,
            &["10.1.2.3".parse().unwrap()]
        )
        .is_err()
    );
    assert!(
        scanner::validate_addresses(
            &scanner::normalize("example.com:9000").unwrap(),
            &c,
            &["10.1.2.3".parse().unwrap()]
        )
        .is_err()
    );
    c.allowed_networks.clear();
    assert!(scanner::validate_addresses(&u, &c, &["10.1.2.3".parse().unwrap()]).is_err());
}
#[test]
fn special_addresses_never_allowed() {
    for ip in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "::ffff:10.1.2.3",
        "100.100.100.200",
        "192.0.0.192",
        "168.63.129.16",
        "fd00:ec2::254",
        "fe80::1234",
        "255.255.255.255",
        "240.0.0.1",
    ] {
        assert!(scanner::forbidden(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    assert!(!scanner::forbidden("10.20.1.25".parse().unwrap()));
    assert!(!scanner::forbidden("fd00:1234::1".parse().unwrap()));
}
#[test]
fn csv_formulas_neutralized() {
    for v in ["=HYPERLINK(\"x\")", "  @SUM(1)", "+1", "-1", "\r=1", "\t1"] {
        assert!(portal::csv_safe(v).starts_with('\''));
    }
}
#[test]
fn python_password_hash_compatibility() {
    // Python hashlib.pbkdf2_hmac('sha256', b'password', bytes.fromhex('00'*16), 260000).
    let hash = config::password_hash("password", Some("00000000000000000000000000000000")).unwrap();
    assert_eq!(
        hash,
        "00000000000000000000000000000000:c9b5bcfd561d622e86edbd370f115716a2414cf9afbcb108182be135f7cc35ea"
    );
    assert!(config::verify("password", &hash));
    assert!(!config::verify("bad", &hash));
    assert!(!config::verify("x", "bad"));
}
#[test]
fn config_permissions_validation_and_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let mut c = cfg();
    config::write_config(&path, &c, true).unwrap();
    assert!(config::write_config(&path, &c, true).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
    c.allowed_networks = vec!["10.1.2.3/8".into()];
    assert!(c.validate(&path, "127.0.0.1".parse().unwrap()).is_err());
    let mut c = cfg();
    c.public_origin.push('/');
    assert!(c.validate(&path, "127.0.0.1".parse().unwrap()).is_err());
    let mut c = cfg();
    assert!(c.validate(&path, "0.0.0.0".parse().unwrap()).is_err());
}
struct Portal {
    base: String,
    state: Arc<portal::State>,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Portal {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Portal {
    async fn new() -> Self {
        Self::with_options(false).await
    }
    async fn with_options(anonymous: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut c = cfg();
        c.public_origin = base.clone();
        c.database = dir.path().join("test.sqlite3").to_string_lossy().into();
        c.allowed_networks.clear();
        c.users = BTreeMap::from([
            ("alice".into(), config::password_hash("a", None).unwrap()),
            ("bob".into(), config::password_hash("b", None).unwrap()),
        ]);
        if anonymous {
            c.allow_anonymous = true;
            c.allow_without_whitelist = true;
            c.users.clear();
            c.allowed_ports.clear();
        }
        c.admins.insert(
            "admin".into(),
            c.users
                .get("alice")
                .cloned()
                .unwrap_or_else(|| config::password_hash("a", None).unwrap()),
        );
        let state = portal::State::new(c).unwrap();
        let router = portal::router(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        Self {
            base,
            state,
            _dir: dir,
            task,
        }
    }
    fn request(&self, path: &str, user: &str) -> reqwest::RequestBuilder {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("{}{path}", self.base))
            .basic_auth(user, Some(if user == "alice" { "a" } else { "b" }))
    }
    fn post(&self, path: &str, body: Value) -> reqwest::RequestBuilder {
        let mut r = self.request(path, "alice").build().unwrap();
        *r.method_mut() = reqwest::Method::POST;
        r.headers_mut().insert("origin", self.base.parse().unwrap());
        r.headers_mut()
            .insert("x-requested-with", "PHP-SelfCheck".parse().unwrap());
        r.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        *r.body_mut() = Some(body.to_string().into());
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .request(reqwest::Method::POST, r.url().clone())
            .headers(r.headers().clone())
            .body(r.body().unwrap().as_bytes().unwrap().to_vec())
    }
}
#[tokio::test]
async fn portal_auth_isolation_exports_and_imports() {
    let p = Portal::new().await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(client.get(&p.base).send().await.unwrap().status(), 401);
    for path in ["/", "/ui.js", "/style.css"] {
        let r = p.request(path, "alice").send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert!(
            r.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        assert!(!r.bytes().await.unwrap().is_empty());
    }
    assert_eq!(
        p.request("/", "alice")
            .header("host", "evil.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        p.request("/api/scan", "alice").build().unwrap().method(),
        reqwest::Method::GET
    );
    let no_origin = client
        .post(format!("{}/api/scan", p.base))
        .basic_auth("alice", Some("a"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(no_origin.status(), 403);
    for body in [
        json!({"targets":vec!["a";51]}),
        json!({"targets":["file:///etc/passwd"]}),
        json!({"targets":[42]}),
    ] {
        assert_eq!(
            p.post("/api/scan", body).send().await.unwrap().status(),
            400
        );
    }
    let r = p
        .post(
            "/api/scan",
            json!({"targets":["example.com","example.com"]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let id = r.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut done = Value::Null;
    for _ in 0..15 {
        done = p
            .request(&format!("/api/jobs/{id}"), "alice")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        if done["state"] == "done" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(done["state"], "done");
    assert_eq!(done["results"].as_array().unwrap().len(), 1);
    assert_eq!(done["results"][0]["verdict"], "无法完成检测");
    assert!(
        done["results"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("未配置")
    );
    assert_eq!(
        p.request(&format!("/api/jobs/{id}"), "bob")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let csv = p
        .request(&format!("/api/jobs/{id}?format=csv"), "alice")
        .send()
        .await
        .unwrap();
    assert_eq!(csv.status(), 200);
    assert!(csv.text().await.unwrap().contains("https://example.com/"));
    let report = json!({"target":"example.com","report":{"schema":"php-selfcheck-host/v1","verdict":"已确认修复","runtime_observations":[{"sapi":"cli","scope":"web_runtime","version":"8.2.34","settings":{"session.upload_progress.enabled":"1"}}]},"review":{"sapi":"fpm-fcgi","upload_progress":"disabled","patch_status":"fixed_claimed","patch_vendor":"Test LTS","package_revision":"8.2.34-vendor1","advisory_url":"https://vendor.example/security"}});
    assert_eq!(
        p.post("/api/reports", report)
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let reports = p
        .request("/api/reports", "alice")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(reports[0]["payload"]["trust"], "开发者提交，未经独立核验");
    assert_eq!(
        p.request("/api/reports", "bob")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!([])
    );
    // The arbitrary imported verdict never changes a scan result.
    assert_eq!(
        p.request(&format!("/api/jobs/{id}"), "alice")
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["results"][0]["verdict"],
        "无法完成检测"
    );
    let linked = p
        .request(&format!("/api/jobs/{id}"), "alice")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        linked["results"][0]["host_evidence"][0]["assessment"]["runtime_observations"][0]["scope"],
        "cli_only"
    );
    assert_eq!(
        linked["results"][0]["host_evidence"][0]["assessment"]["review"]["patch_vendor"],
        "Test LTS"
    );
    assert_eq!(
        linked["results"][0]["host_evidence"][0]["assessment"]["verdict_promoted"],
        false
    );
    assert!(
        p.request(&format!("/api/jobs/{id}?format=csv"), "alice")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("Test LTS")
    );
    assert_eq!(p.post("/api/reports",json!({"target":"example.com","report":{"schema":"php-selfcheck-host/v1"},"review":{"patch_status":"verified_safe"}})).send().await.unwrap().status(),400);
    let db = rusqlite::Connection::open(&p.state.config.database).unwrap();
    let audits: i64 = db
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap();
    assert!(audits >= 3);
    db.execute(
        "INSERT INTO jobs VALUES('old','alice',0,'running','[]')",
        [],
    )
    .unwrap();
    let _restarted = portal::State::new(p.state.config.clone()).unwrap();
    let state: String = db
        .query_row("SELECT state FROM jobs WHERE id='old'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "interrupted");
}

#[test]
fn optional_whitelist_and_legacy_defaults() {
    let mut c = cfg();
    c.allow_without_whitelist = true;
    c.allowed_networks.clear();
    c.allowed_ports.clear();
    let u = scanner::normalize("https://example.com:9000/").unwrap();
    assert!(scanner::validate_addresses(&u, &c, &["8.8.8.8".parse().unwrap()]).is_ok());
    assert!(scanner::validate_addresses(&u, &c, &["169.254.169.254".parse().unwrap()]).is_err());
    c.allowed_networks = vec!["10.0.0.0/8".into()];
    assert!(scanner::validate_addresses(&u, &c, &["8.8.8.8".parse().unwrap()]).is_err());
    c.allowed_ports = vec![443];
    assert!(scanner::validate_addresses(&u, &c, &["10.1.1.1".parse().unwrap()]).is_err());
    c.allowed_ports.clear();
    c.allowed_domains = vec!["company.example".into()];
    assert!(scanner::validate_addresses(&u, &c, &["10.1.1.1".parse().unwrap()]).is_err());
    let mut legacy = serde_json::to_value(cfg()).unwrap();
    legacy.as_object_mut().unwrap().remove("allow_anonymous");
    legacy
        .as_object_mut()
        .unwrap()
        .remove("allow_without_whitelist");
    let legacy: Config = serde_json::from_value(legacy).unwrap();
    assert!(!legacy.allow_anonymous && !legacy.allow_without_whitelist);
    let mut anonymous:Config=serde_json::from_value(json!({"public_origin":"http://127.0.0.1:8080","allow_anonymous":true,"allow_without_whitelist":true,"database":"data/test.sqlite3"})).unwrap();
    let dir = tempfile::tempdir().unwrap();
    assert!(
        anonymous
            .validate(
                &dir.path().join("config.json"),
                "127.0.0.1".parse().unwrap()
            )
            .is_ok()
    );
}
#[tokio::test]
async fn anonymous_http_isolated_workspace_and_scope_options() {
    let p = Portal::with_options(true).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let r = client.get(&p.base).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(!r.headers().contains_key("www-authenticate"));
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("cookie", cookie.parse().unwrap());
    let client = reqwest::Client::builder()
        .no_proxy()
        .default_headers(headers)
        .build()
        .unwrap();
    let me = client
        .get(format!("{}/api/me", p.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(me["user"].as_str().unwrap().starts_with("visitor:"));
    assert_eq!(me["scope_configured"], true);
    assert_eq!(me["allow_anonymous"], true);
    let invalid = client
        .post(format!("{}/api/scan", p.base))
        .header("origin", &p.base)
        .header("x-requested-with", "PHP-SelfCheck")
        .json(&json!({"targets":["https://example.com"],"headers_only":"true"}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 400);
    let r = client
        .post(format!("{}/api/scan", p.base))
        .header("origin", &p.base)
        .header("x-requested-with", "PHP-SelfCheck")
        .json(&json!({"targets":["http://169.254.169.254/"],"headers_only":true}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let id = r.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut record = Value::Null;
    for _ in 0..30 {
        record = client
            .get(format!("{}/api/jobs/{id}", p.base))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        if record["state"] == "done" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(record["owner"], me["user"]);
    assert_eq!(record["state"], "done");
    assert_eq!(record["results"][0]["scan_mode"], "headers_only");
    assert_eq!(
        record["results"][0]["assessment"]["multipart"]["source"],
        "not_tested"
    );
    assert!(
        record["results"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("特殊地址")
    );
    let other = reqwest::Client::builder().no_proxy().build().unwrap();
    for suffix in ["", "?format=csv"] {
        assert_eq!(
            other
                .get(format!("{}/api/jobs/{id}{suffix}", p.base))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    assert_eq!(
        other
            .get(format!(
                "{}/api/jobs?owner={}",
                p.base,
                me["user"].as_str().unwrap()
            ))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!([])
    );
    let invalid = client
        .post(format!("{}/api/scan", p.base))
        .json(&json!({"targets":["example.com"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 403);
}

#[test]
fn underscore_hosts_are_accepted_without_changing_authority() {
    for (input, expected) in [
        ("http://erp_api.xxxx.com", "http://erp_api.xxxx.com/"),
        ("erp_api.xxxx.com", "https://erp_api.xxxx.com/"),
        (
            "http://erp_api.xxxx.com:8080/login?next=index.php",
            "http://erp_api.xxxx.com:8080/login?next=index.php",
        ),
        ("http://ERP_API.xxxx.com.\u{a0}", "http://erp_api.xxxx.com/"),
    ] {
        let u = scanner::normalize(input).unwrap();
        assert_eq!(u.as_str(), expected);
        assert_eq!(u.host_str(), Some("erp_api.xxxx.com"));
    }
    for input in [
        "http://user:password@erp_api.xxxx.com",
        "http://erp_api.xxxx.com/\r\nX:x",
        "http://erp_api.xxxx.com/\\evil",
    ] {
        assert!(scanner::normalize(input).is_err());
    }
    let mut c = cfg();
    c.allowed_domains = vec!["xxxx.com".into()];
    let u = scanner::normalize("http://erp_api.xxxx.com").unwrap();
    assert!(scanner::validate_addresses(&u, &c, &["10.1.2.3".parse().unwrap()]).is_ok());
    c.allowed_domains = vec!["other.example".into()];
    assert!(scanner::validate_addresses(&u, &c, &["10.1.2.3".parse().unwrap()]).is_err());
}

fn cookie_client(cookie: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("cookie", cookie.split(';').next().unwrap().parse().unwrap());
    reqwest::Client::builder()
        .no_proxy()
        .default_headers(headers)
        .build()
        .unwrap()
}
async fn admin_post(
    client: &reqwest::Client,
    p: &Portal,
    path: &str,
    body: Value,
) -> reqwest::Response {
    client
        .post(format!("{}{path}", p.base))
        .header("origin", &p.base)
        .header("x-requested-with", "PHP-SelfCheck")
        .json(&body)
        .send()
        .await
        .unwrap()
}
#[tokio::test]
async fn admin_history_requires_separate_login_and_supports_logout() {
    let p = Portal::with_options(true).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    {
        let db = rusqlite::Connection::open(&p.state.config.database).unwrap();
        db.execute(
            "INSERT INTO jobs VALUES('legacy','anonymous',0,'done','[]')",
            [],
        )
        .unwrap();
    }
    let first = client.get(&p.base).send().await.unwrap();
    let visitor = cookie_client(first.headers()["set-cookie"].to_str().unwrap());
    let other = client.get(&p.base).send().await.unwrap();
    let second = cookie_client(other.headers()["set-cookie"].to_str().unwrap());
    let mut ids = vec![];
    for browser in [&visitor, &second] {
        let r = admin_post(
            browser,
            &p,
            "/api/scan",
            json!({"targets":["http://169.254.169.254/"]}),
        )
        .await;
        assert_eq!(r.status(), 202);
        ids.push(
            r.json::<Value>().await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(
        visitor
            .get(format!("{}/api/jobs/{}", p.base, ids[1]))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        visitor
            .get(format!("{}/api/jobs/legacy", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(admin_post(&visitor,&p,"/api/reports",json!({"target":"http://169.254.169.254/","report":{"schema":"php-selfcheck-host/v1"},"review":{"patch_vendor":"visitor-A-only"}})).await.status(),201);
    assert_eq!(
        second
            .get(format!("{}/api/reports", p.base))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap(),
        json!([])
    );
    // A new scan replaces the developer API's current record; all rows remain in SQLite.
    let newer = admin_post(
        &visitor,
        &p,
        "/api/scan",
        json!({"targets":["http://169.254.169.254/"]}),
    )
    .await;
    assert_eq!(newer.status(), 202);
    let newer = newer.json::<Value>().await.unwrap();
    let current = visitor
        .get(format!("{}/api/jobs", p.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(current.as_array().unwrap().len(), 1);
    assert_eq!(current[0]["id"], newer["id"]);
    for path in ["/api/admin/jobs", "/api/admin/me"] {
        assert_eq!(
            visitor
                .get(format!("{}{path}", p.base))
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
    }
    assert_eq!(
        visitor
            .get(format!("{}/api/admin/jobs/{}?format=csv", p.base, ids[1]))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{}/admin", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        admin_post(
            &client,
            &p,
            "/api/admin/login",
            json!({"user":"alice","password":"a"})
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        admin_post(
            &client,
            &p,
            "/api/admin/login",
            json!({"user":"admin","password":"wrong"})
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        client
            .post(format!("{}/api/admin/login", p.base))
            .json(&json!({"user":"admin","password":"a"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let login = admin_post(
        &client,
        &p,
        "/api/admin/login",
        json!({"user":"admin","password":"a"}),
    )
    .await;
    assert_eq!(login.status(), 200);
    let admin = cookie_client(login.headers()["set-cookie"].to_str().unwrap());
    let history = admin
        .get(format!("{}/api/admin/jobs?limit=1", p.base))
        .send()
        .await
        .unwrap();
    assert_eq!(history.status(), 200);
    let history = history.json::<Value>().await.unwrap();
    assert_eq!(history["total"], 4);
    assert_eq!(history["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(history["summary"]["jobs"], 4);
    let page = admin
        .get(format!("{}/api/admin/jobs?limit=1&offset=1", p.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_ne!(history["jobs"][0]["id"], page["jobs"][0]["id"]);
    for id in &ids {
        assert_eq!(
            admin
                .get(format!("{}/api/admin/jobs/{id}?format=csv", p.base))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    let own = admin
        .get(format!("{}/api/admin/jobs/{}", p.base, ids[0]))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let foreign = admin
        .get(format!("{}/api/admin/jobs/{}", p.base, ids[1]))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(own.contains("visitor-A-only"));
    assert!(!foreign.contains("visitor-A-only"));
    assert_eq!(
        admin
            .get(format!("{}/api/admin/jobs/legacy", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let filtered = admin
        .get(format!("{}/api/admin/jobs?search={}", p.base, ids[0]))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(filtered["total"], 1);
    let hidden = admin
        .get(format!("{}/api/admin/jobs?search=%25", p.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(hidden["total"], 0);
    // Logout invalidates the server token, even if an attacker replays the old cookie.
    assert_eq!(
        admin_post(&admin, &p, "/api/admin/logout", json!({}))
            .await
            .status(),
        200
    );
    assert_eq!(
        admin
            .get(format!("{}/api/admin/jobs", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let db = rusqlite::Connection::open(&p.state.config.database).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM audit WHERE owner='admin:admin'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(count >= 5);
}

#[tokio::test]
async fn admin_result_filters_sort_and_confirmed_deletion() {
    let p = Portal::with_options(true).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    {
        let db = rusqlite::Connection::open(&p.state.config.database).unwrap();
        for (id, created, state, results) in [
            (
                "mixed",
                1,
                "done",
                json!([{"target":"https://risk.example/","verdict":"疑似受影响"},{"target":"https://patched.example/","verdict":"版本达到修复基线（待核验）"}]),
            ),
            (
                "low",
                1000,
                "done",
                json!([{"target":"https://low.example/","verdict":"未发现 PHP 特征"}]),
            ),
            (
                "blocked",
                2,
                "failed",
                json!([{"target":"https://blocked.example/","verdict":"无法完成检测"}]),
            ),
            ("active", 3, "running", json!([])),
        ] {
            db.execute(
                "INSERT INTO jobs VALUES(?, 'visitor:test', ?, ?, ?)",
                rusqlite::params![id, created, state, results.to_string()],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO reports VALUES('material','visitor:test',0,'https://risk.example/','{}')",
            [],
        )
        .unwrap();
    }
    let login = admin_post(
        &client,
        &p,
        "/api/admin/login",
        json!({"user":"admin","password":"a"}),
    )
    .await;
    let admin = cookie_client(login.headers()["set-cookie"].to_str().unwrap());
    let history = admin
        .get(format!("{}/api/admin/jobs", p.base))
        .query(&[("verdict", "疑似受影响"), ("sort", "risk_desc")])
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(history["total"], 1);
    assert_eq!(history["jobs"][0]["id"], "mixed");
    assert_eq!(history["jobs"][0]["total_results"], 2);
    assert_eq!(history["jobs"][0]["results"].as_array().unwrap().len(), 1);
    let exported = admin
        .get(format!("{}/api/admin/jobs/mixed", p.base))
        .query(&[("format", "csv"), ("verdict", "疑似受影响")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(exported.contains("risk.example"));
    assert!(!exported.contains("patched.example"));
    for (sort, first) in [
        ("risk_desc", "mixed"),
        ("risk_asc", "low"),
        ("newest", "low"),
        ("oldest", "mixed"),
    ] {
        let r = admin
            .get(format!("{}/api/admin/jobs", p.base))
            .query(&[("sort", sort)])
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(r["jobs"][0]["id"], first);
    }
    let empty = admin
        .get(format!("{}/api/admin/jobs", p.base))
        .query(&[("verdict", "疑似受影响"), ("search", "low.example")])
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(empty["total"], 0);
    let unrelated = admin
        .get(format!("{}/api/admin/jobs", p.base))
        .query(&[("verdict", "疑似受影响"), ("search", "patched.example")])
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(unrelated["total"], 0);
    assert_eq!(
        admin
            .get(format!("{}/api/admin/jobs?sort=untrusted", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        admin_post(
            &client,
            &p,
            "/api/admin/jobs/mixed/delete",
            json!({"confirm":true})
        )
        .await
        .status(),
        401
    );
    assert_eq!(
        admin
            .post(format!("{}/api/admin/jobs/mixed/delete", p.base))
            .json(&json!({"confirm":true}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        admin_post(&admin, &p, "/api/admin/jobs/mixed/delete", json!({}))
            .await
            .status(),
        400
    );
    assert_eq!(
        admin_post(
            &admin,
            &p,
            "/api/admin/jobs/active/delete",
            json!({"confirm":true})
        )
        .await
        .status(),
        409
    );
    assert_eq!(
        admin_post(
            &admin,
            &p,
            "/api/admin/jobs/mixed/delete",
            json!({"confirm":true})
        )
        .await
        .status(),
        200
    );
    assert_eq!(
        admin
            .get(format!("{}/api/admin/jobs/mixed?format=csv", p.base))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        admin_post(
            &admin,
            &p,
            "/api/admin/jobs/mixed/delete",
            json!({"confirm":true})
        )
        .await
        .status(),
        404
    );
    let summary = admin
        .get(format!("{}/api/admin/jobs", p.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(summary["total"], 3);
    assert_eq!(summary["summary"]["jobs"], 3);
    assert!(summary["summary"]["verdicts"].get("疑似受影响").is_none());
    let db = rusqlite::Connection::open(&p.state.config.database).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM reports", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM audit WHERE action='admin_scan_delete' AND owner='admin:admin'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
