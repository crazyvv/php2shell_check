use php_selfcheck::assessment::{self, remote};
use serde_json::json;
#[test]
fn no_remote_sapi_or_progress_claim_from_generic_headers() {
    let a = remote(&[("Server".into(), "nginx/1.26".into())], b"", &[]);
    assert_eq!(a["sapi"]["status"], "unknown");
    assert_eq!(a["upload_progress"]["status"], "unknown");
    assert_eq!(a["multipart"]["status"], "unknown");
    assert_eq!(a["web_server"]["detail"], "nginx/1.26");
}
#[test]
fn page_features_are_hints_not_runtime_configuration() {
    let a=remote(&[],br#"<form method='post' enctype="multipart/form-data"><input name="PHP_SESSION_UPLOAD_PROGRESS"></form>"#,&[]);
    assert_eq!(a["multipart"]["status"], "form_hint");
    assert_eq!(a["upload_progress"]["status"], "field_hint");
    assert_eq!(a["upload_progress"]["confidence"], "low");
}
#[test]
fn eol_does_not_mean_missing_patch_and_fixed_header_is_not_verified() {
    let a = remote(&[], b"", &["7.4.33".into()]);
    assert_eq!(a["lifecycle"]["status"], "eol");
    assert_eq!(a["patch"]["status"], "unknown");
    assert_eq!(a["review_priority"], "high");
    let a = remote(&[], b"", &["8.2.35".into()]);
    assert_eq!(a["patch"]["status"], "meets_upstream_fix");
    assert_eq!(a["patch"]["confidence"], "low");
    assert_eq!(
        remote(&[], b"", &["8.2.34".into(), "8.2.35".into()])["patch"]["status"],
        "unknown"
    );
}
#[test]
fn runtime_scope_and_untrusted_claims_are_preserved() {
    let a = assessment::host(&json!({"report":{"runtime_observations":[
        {"sapi":"cli","scope":"web_runtime","binary":"/opt/php/bin/php","loaded_ini":"/etc/php/cli/php.ini","settings":{"session.upload_progress.enabled":"1"}},
        {"sapi":"fpm-fcgi","settings":{"session.upload_progress.enabled":"0"}},
        {"sapi":"apache2handler","settings":{"session.upload_progress.enabled":null}}
    ]},"review":{"patch_status":"fixed_claimed"}}));
    assert_eq!(a["runtime_observations"][0]["scope"], "cli_only");
    assert_eq!(a["runtime_observations"][0]["binary"], "/opt/php/bin/php");
    assert_eq!(
        a["runtime_observations"][0]["loaded_ini"],
        "/etc/php/cli/php.ini"
    );
    assert_eq!(a["runtime_observations"][0]["upload_progress"], "enabled");
    assert_eq!(a["runtime_observations"][1]["upload_progress"], "disabled");
    assert_eq!(a["runtime_observations"][2]["upload_progress"], "unknown");
    assert_eq!(a["patch_status"], "unverified");
    assert_eq!(a["verdict_promoted"], false);
    assert!(assessment::review(&json!({"advisory_url":"javascript:alert(1)"})).is_err());
    assert!(assessment::review(&json!({"upload_progress":"confirmed_exploitable"})).is_err());
    assert!(assessment::review(&json!({"notes":"x".repeat(2001)})).is_err());
    assert_eq!(
        assessment::review(&json!({"sapi":"fpm-fcgi","verdict":"safe"})).unwrap(),
        json!({"sapi":"fpm-fcgi"})
    );
}

#[test]
fn middleware_import_is_scoped_unverified_and_bounded() {
    let value = assessment::host(
        &json!({"report":{"middleware":{"status":"completed","instances":[{"pid":"100","family":"nginx"},"invalid"],"web_probes":[{"status":"responded","response":{"http_status":200}}]}}}),
    );
    assert_eq!(
        value["middleware"]["instances"].as_array().unwrap().len(),
        1
    );
    assert_eq!(value["middleware"]["confidence"], "unverified");
    assert_eq!(value["verdict_promoted"], false);
    let malformed =
        assessment::host(&json!({"report":{"middleware":{"instances":"invalid","web_probes":{}}}}));
    assert!(
        malformed["middleware"]["instances"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn vendor_reference_import_never_becomes_verified_or_promotes_verdict() {
    let a = assessment::host(
        &json!({"report":{"package_audit":{"status":"completed","rules_independently_verified":true,"instances":[{"pid":"123","artifacts":[{"running_patch_status":"meets_vendor_reference","package":{"patch_status":"meets_vendor_reference"}}]}]}}}),
    );
    assert_eq!(a["package_audit"]["rules_independently_verified"], false);
    assert_eq!(a["package_audit"]["confidence"], "unverified");
    assert_eq!(a["patch_status"], "unverified");
    assert_eq!(a["verdict_promoted"], false);
    assert_eq!(
        a["package_audit"]["instances"][0]["artifacts"][0]["running_patch_status"],
        "meets_vendor_reference"
    );
}

#[test]
fn passive_surfaces_do_not_promote_version_or_confirm_new_cve() {
    let url = url::Url::parse("https://example.com/path").unwrap();
    let r = php_selfcheck::scanner::inspect_with_library(
        &[],
        br#"<form action="/upload?secret=hidden" enctype="multipart/form-data"><input name="f" type="file"></form>Failed to decode session object; Allowed memory size of 123 bytes exhausted"#,
        Some(&url),
        &php_selfcheck::fingerprints::builtin(),
    );
    assert_eq!(r["verdict"], "未发现 PHP 特征");
    assert_eq!(r["exploitation_verified"], false);
    assert_eq!(
        r["assessment"]["surfaces"]["forms"][0]["endpoint"]["path"],
        "/upload"
    );
    assert_eq!(
        r["assessment"]["surfaces"]["errors"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!r["assessment"]["surfaces"].to_string().contains("hidden"));
    assert!(!r["cves"].to_string().contains("115560"));
}
