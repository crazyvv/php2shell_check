use serde_json::Value;
use std::process::Command;
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_php-selfcheck"))
}
#[test]
fn cli_check_exit_codes_invalid_config_and_special_address_denial() {
    let invalid = bin()
        .args(["check", "file:///etc/passwd", "--json"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let missing = bin()
        .args([
            "check",
            "https://example.com",
            "--config",
            "/does-not-exist/config.json",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.json");
    std::fs::write(&config, include_str!("../config.open.example.json")).unwrap();
    let denied = bin()
        .args([
            "check",
            "http://127.0.0.1",
            "--headers-only",
            "--json",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(3));
    let r: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(r["patch_status"], "unknown");
    assert_eq!(r["exit_code"], 3);
    assert_eq!(r["scan_mode"], "headers_only");
    assert_eq!(r["verdict"], "无法完成检测");
    assert!(r["requests"].as_array().unwrap().is_empty());
}
#[cfg(unix)]
#[test]
fn php_command_collection_is_explicit_and_json_override_can_disable_it() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let php = dir.path().join("php");
    let marker = dir.path().join("called");
    fs::write(&php,format!("#!/bin/sh\nprintf x >> '{}'\nif [ \"$1\" = '-r' ]; then printf '%s\\n' '{{\"sapi\":\"cli\",\"version\":\"8.4.27\",\"settings\":{{\"session.upload_progress.enabled\":\"1\"}}}}'; else printf 'PHP 8.4.27 (cli)\\n'; fi\n",marker.display())).unwrap();
    fs::set_permissions(&php, fs::Permissions::from_mode(0o700)).unwrap();
    let default = bin()
        .arg("collect")
        .env("PATH", dir.path())
        .output()
        .unwrap();
    assert!(default.status.success());
    assert!(!marker.exists());
    let r: Value = serde_json::from_slice(&default.stdout).unwrap();
    assert_eq!(r["php_command"]["status"], "disabled");
    assert!(r["runtime_observations"].as_array().unwrap().is_empty());
    let enabled = bin()
        .args([
            "collect",
            "--php-command",
            "--php-binary",
            php.to_str().unwrap(),
        ])
        .env("PATH", dir.path())
        .output()
        .unwrap();
    assert!(
        enabled.status.success(),
        "{}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert!(marker.exists());
    let r: Value = serde_json::from_slice(&enabled.stdout).unwrap();
    assert_eq!(r["runtime_observations"][0]["scope"], "cli_only");
    assert_eq!(r["runtime_observations"][0]["version"], "8.4.27");
    fs::remove_file(&marker).unwrap();
    let options = dir.path().join("options.json");
    fs::write(&options, r#"{"php_command":true}"#).unwrap();
    let disabled = bin()
        .args([
            "collect",
            "--options",
            options.to_str().unwrap(),
            "--php-command=false",
        ])
        .env("PATH", dir.path())
        .output()
        .unwrap();
    assert!(disabled.status.success());
    assert!(!marker.exists());
}
