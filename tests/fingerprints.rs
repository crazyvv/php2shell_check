use php_selfcheck::{
    fingerprints::{self, Library},
    scanner,
};
use serde_json::{Value, json};
use url::Url;
fn detect(headers: &[(&str, &str)], body: &str) -> Value {
    let url = Url::parse("https://app.example.com/").unwrap();
    fingerprints::builtin().detect(
        Some(&url),
        &headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>(),
        body.as_bytes(),
    )
}
fn has(v: &Value, id: &str) -> bool {
    v["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == id)
}
fn custom(rules: Value) -> std::sync::Arc<Library> {
    Library::from_json(
        &json!({"schema":fingerprints::SCHEMA,"version":"test-1","mode":"replace","rules":rules})
            .to_string(),
    )
    .unwrap()
}
#[test]
fn builtin_coverage_cms_node_static_and_servers_are_evidence_hints() {
    let r = detect(
        &[("Server", "nginx/1.28.0"), ("CF-Ray", "opaque-request-id")],
        r#"<meta CONTENT='WordPress 6.6.2' NAME=generator><script src='/wp-includes/js/core.js?ver=6.6.2'></script>"#,
    );
    assert!(has(&r, "wordpress") && has(&r, "nginx") && has(&r, "cloudflare"));
    assert_eq!(r["php_hint"], true);
    assert_eq!(r["blocked_hint"], false);
    let wordpress = r["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "wordpress")
        .unwrap();
    assert_eq!(wordpress["versions"][0], "6.6.2");
    assert_eq!(wordpress["patch_verified"], false);
    let r = detect(
        &[],
        r#"<script src='/_next/static/app.js'></script><meta name=generator content='Astro 5.0'>"#,
    );
    assert!(has(&r, "nextjs") && has(&r, "astro"));
    assert_eq!(r["php_hint"], false);
    assert_eq!(r["library"]["rule_count"], 51);
    assert_eq!(r["library"]["sha256"].as_str().unwrap().len(), 64);
    assert!(!r.to_string().contains("opaque-request-id"));
}
#[test]
fn external_resource_and_plain_mentions_do_not_identify_target_php() {
    let r = detect(
        &[],
        r#"<script src='https://cdn.other.example/wp-content/plugins/woocommerce/app.js?token=SECRET'></script>"#,
    );
    assert!(has(&r, "wordpress") && has(&r, "woocommerce"));
    assert_eq!(r["php_hint"], false);
    assert!(
        r["matches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["relation"] == "external_reference")
    );
    assert!(!r.to_string().contains("SECRET"));
    let r = detect(
        &[],
        r#"A tutorial about WordPress, Drupal and /wp-content/. <!-- <script src='/wp-content/comment.js'></script> --><script>const example="<img src='/wp-content/fake.png'>";</script>"#,
    );
    assert!(!has(&r, "wordpress"));
    assert_eq!(r["php_hint"], false);
}
#[test]
fn cookie_values_are_never_matched_or_exported() {
    let r = detect(
        &[
            ("Set-Cookie", "laravel_session=TOP-SECRET; HttpOnly; Path=/"),
            ("Set-Cookie", "other=WordPress; Secure"),
        ],
        "",
    );
    assert!(has(&r, "laravel"));
    assert!(!has(&r, "wordpress"));
    assert!(!r.to_string().contains("TOP-SECRET"));
    let file = json!({"schema":fingerprints::SCHEMA,"version":"test","rules":[{"id":"bad","name":"bad","category":"cms","any":[{"source":"header","header":"Set-Cookie","pattern":"TOP-SECRET"}]}]});
    assert!(Library::from_json(&file.to_string()).is_err());
}
#[test]
fn all_any_overrides_disable_replace_and_empty_body_semantics() {
    let library = custom(
        json!([{"id":"own","name":"Company app","category":"framework","runtime":"php","all":[{"source":"header","header":"X_App","pattern":"^erp$"},{"source":"cookie_name","pattern":"^own_session$"}],"any":[{"source":"meta_generator","pattern":"Company"},{"source":"title","pattern":"ERP"}]}]),
    );
    let u = Url::parse("https://app.example.com").unwrap();
    let headers = vec![
        ("X_App".into(), "erp".into()),
        ("Set-Cookie".into(), "own_session=private".into()),
    ];
    assert!(has(
        &library.detect(Some(&u), &headers, b"<title>ERP</title>"),
        "own"
    ));
    assert!(!has(&library.detect(Some(&u), &headers, b"plain"), "own"));
    assert!(!has(
        &library.detect(Some(&u), &headers[..1], b"<title>ERP</title>"),
        "own"
    ));
    let body_only = custom(
        json!([{"id":"empty","name":"No fetched body","category":"cms","any":[{"source":"body","pattern":".*"}]}]),
    );
    assert!(
        body_only.detect(Some(&u), &[], &[])["matches"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let extension = json!({"schema":fingerprints::SCHEMA,"version":"my-2","mode":"extend","disabled_rules":["wordpress"],"rules":[{"id":"nginx","name":"Custom Nginx","category":"web_server","any":[{"source":"header","header":"x-custom-server","pattern":"nginx"}]}]});
    let lib = Library::from_json(&extension.to_string()).unwrap();
    let r = lib.detect(
        Some(&u),
        &[("Server".into(), "nginx/1.2".into())],
        b"<meta name=generator content=WordPress>",
    );
    assert!(!has(&r, "wordpress") && !has(&r, "nginx"));
    assert_eq!(r["library"]["source"], "custom_extend");
    let empty = custom(json!([]));
    assert_eq!(empty.metadata()["rule_count"], 0);
    let core = scanner::inspect_with_library(
        &[("X-Powered-By".into(), "PHP/8.4.26".into())],
        b"",
        Some(&u),
        &empty,
    );
    assert_eq!(core["verdict"], "疑似受影响");
}
#[test]
fn reject_invalid_regex_unknown_fields_duplicate_ids_and_unsafe_version_sources() {
    let base = json!({"schema":fingerprints::SCHEMA,"version":"test","mode":"replace","rules":[{"id":"one","name":"One","category":"cms","any":[{"source":"body","pattern":"WordPress"}]}]});
    let mut cases = vec![];
    let mut v = base.clone();
    v["rules"][0]["any"][0]["pattern"] = json!("(");
    cases.push(v);
    let mut v = base.clone();
    v["rules"][0]["any"][0]["pattern"] = json!(r"(?P<version>8.4.27)");
    cases.push(v);
    let mut v = base.clone();
    v["rules"][0]["probe_url"] = json!("/wp-login.php");
    cases.push(v);
    let mut v = base.clone();
    v["rules"][0]["runtime"] = json!("fixed");
    cases.push(v);
    let mut v = base.clone();
    v["rules"][0]["id"] = json!("../bad");
    cases.push(v);
    let mut v = base.clone();
    v["rules"]
        .as_array_mut()
        .unwrap()
        .push(base["rules"][0].clone());
    cases.push(v);
    let mut v = base.clone();
    v["mode"] = json!("extend");
    v["disabled_rules"] = json!(["typo-does-not-exist"]);
    cases.push(v);
    let mut v = base.clone();
    v["schema"] = json!("different/v1");
    cases.push(v);
    let mut v = base.clone();
    v["rules"][0]["any"] = json!([]);
    cases.push(v);
    for value in cases {
        assert!(Library::from_json(&value.to_string()).is_err(), "{value}");
    }
    assert!(Library::from_json(&" ".repeat(524289)).is_err());
}
#[test]
fn cms_version_is_never_php_version_and_managed_sites_are_not_marked_fixed() {
    let u = Url::parse("https://app.example.com").unwrap();
    let r = scanner::inspect_with_library(
        &[],
        b"<meta name=generator content='WordPress 8.4.27'>",
        Some(&u),
        &fingerprints::builtin(),
    );
    assert!(r["versions"].as_array().unwrap().is_empty());
    assert_eq!(r["verdict"], "疑似使用 PHP");
    assert_eq!(r["assessment"]["patch"]["status"], "unknown");
    let r = detect(&[("x-shopid", "123"), ("Server", "Vercel")], "");
    assert!(has(&r, "shopify") && has(&r, "vercel"));
    assert_eq!(r["php_hint"], false);
    assert!(
        r["matches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["patch_verified"] == false)
    );
}
#[test]
fn explicit_challenge_is_blocked_but_cdn_alone_is_not() {
    let u = Url::parse("https://app.example.com").unwrap();
    let challenge = scanner::inspect_with_library(
        &[
            ("CF-Mitigated".into(), "challenge".into()),
            ("X-Powered-By".into(), "PHP/8.4.27".into()),
        ],
        b"",
        Some(&u),
        &fingerprints::builtin(),
    );
    assert_eq!(challenge["verdict"], "无法完成检测");
    assert_eq!(challenge["assessment"]["patch"]["status"], "unknown");
    let normal = scanner::inspect_with_library(
        &[
            ("CF-Ray".into(), "request-id".into()),
            ("X-Powered-By".into(), "PHP/8.4.27".into()),
        ],
        b"",
        Some(&u),
        &fingerprints::builtin(),
    );
    assert_eq!(normal["verdict"], "版本达到修复基线（待核验）");
    let blocked = detect(
        &[("CF-Ray", "request-id")],
        "<title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/run.js'></script>",
    );
    assert_eq!(blocked["blocked_hint"], true);
}
#[test]
fn match_limits_and_version_conflicts_are_explicit() {
    let rules:Vec<_>=(0..70).map(|i|json!({"id":format!("rule-{i}"),"name":"Match","category":"cms","any":[{"source":"header","header":"server","pattern":"App"}]})).collect();
    let lib = custom(json!(rules));
    let u = Url::parse("https://app.example.com").unwrap();
    let r = lib.detect(Some(&u), &[("Server".into(), "App".into())], b"");
    assert_eq!(r["matches"].as_array().unwrap().len(), 64);
    assert_eq!(r["matches_truncated"], true);
    let r = detect(&[("Server", "PHP/8.4.26 PHP/8.4.27")], "");
    let php = r["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "php")
        .unwrap();
    assert_eq!(php["version_conflict"], true);
}

#[test]
fn configuration_resolves_custom_files_and_rejects_invalid_rules_at_startup() {
    use php_selfcheck::config::{self, Config};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let file = dir.path().join("fingerprints.json");
    std::fs::write(&file, include_str!("../fingerprints.example.json")).unwrap();
    let mut cfg: Config =
        serde_json::from_str(include_str!("../config.open.example.json")).unwrap();
    cfg.fingerprint_file = Some("fingerprints.json".into());
    config::write_config(&path, &cfg, true).unwrap();
    let mut loaded = config::load(&path).unwrap();
    loaded
        .validate(&path, "127.0.0.1".parse().unwrap())
        .unwrap();
    assert_eq!(
        loaded.fingerprint_library.as_ref().unwrap().metadata()["version"],
        "company-1"
    );
    assert!(
        serde_json::to_value(&loaded)
            .unwrap()
            .get("fingerprint_library")
            .is_none()
    );
    std::fs::write(&file, "not JSON").unwrap();
    assert!(
        config::load(&path)
            .unwrap()
            .validate(&path, "127.0.0.1".parse().unwrap())
            .is_err()
    );
}
