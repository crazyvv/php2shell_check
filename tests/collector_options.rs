use clap::Parser;
use x2shell_check::collector::{CollectArgs, CollectOptions};
#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    collect: CollectArgs,
}
#[test]
fn cli_and_json_options_override_and_dependencies() {
    let options = Cli::parse_from([
        "collect",
        "--middleware",
        "--php-modules=true",
        "--ports",
        "--web-probe",
        "--web-host",
        "app.example",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(options.middleware && options.php_modules && options.ports && options.web_probe);
    assert!(
        Cli::parse_from(["collect", "--web-probe"])
            .collect
            .resolve()
            .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("options.json");
    std::fs::write(
        &file,
        r#"{"middleware":true,"ports":true,"web_probe":true}"#,
    )
    .unwrap();
    let options = Cli::parse_from([
        "collect",
        "--options",
        file.to_str().unwrap(),
        "--web-probe=false",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(options.ports && !options.web_probe);
    let default = Cli::parse_from(["collect"]).collect.resolve().unwrap();
    assert!(
        !default.middleware
            && !default.web_probe
            && !default.php_command
            && !default.java_command
            && !default.package_audit
    );
    let enabled = Cli::parse_from([
        "collect",
        "--php-command",
        "--java-command",
        "--package-audit",
    ])
    .collect
    .resolve()
    .unwrap();
    assert!(
        enabled.php_command && enabled.java_command && enabled.package_audit && !enabled.middleware
    );
}
#[test]
fn invalid_host_path_protocol_and_limits_are_rejected() {
    for host in [
        "user:secret@example.com",
        "example.com/path",
        "example.com:8080",
    ] {
        let c = CollectOptions {
            web_host: Some(host.into()),
            ..Default::default()
        };
        assert!(c.validate().is_err(), "{host}");
    }
    for path in ["//example.com/", "/\r\nX:1", "/#fragment", "/\\other"] {
        assert!(
            CollectOptions {
                web_path: path.into(),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        CollectOptions {
            max_web_probes: 65,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        CollectOptions {
            web_schemes: vec!["file".into()],
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn custom_web_fingerprints_resolve_relative_to_options_file() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("fingerprints.json");
    std::fs::write(&rules, include_str!("../fingerprints.example.json")).unwrap();
    let options = dir.path().join("options.json");
    std::fs::write(&options, r#"{"fingerprint_file":"fingerprints.json"}"#).unwrap();
    let cfg = Cli::parse_from(["collect", "--options", options.to_str().unwrap()])
        .collect
        .resolve()
        .unwrap();
    assert_eq!(cfg.fingerprint_file.as_ref(), Some(&rules));
    assert!(!cfg.web_probe);
    std::fs::write(&rules, "invalid JSON").unwrap();
    assert!(
        Cli::parse_from(["collect", "--options", options.to_str().unwrap()])
            .collect
            .resolve()
            .is_err()
    );
}

#[test]
fn java_demo_uses_synthetic_cases_in_all_formats() {
    let executable = env!("CARGO_BIN_EXE_x2shell-check");
    let output = std::process::Command::new(executable)
        .args(["collect", "--demo"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["scope"], "synthetic_java_demo");
    assert_eq!(report["audit"]["passed"], 6);
    for format in ["txt", "csv"] {
        let output = std::process::Command::new(executable)
            .args(["collect", "--demo", "--format", format])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("build_gap")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_java_launcher_checks_build_and_rejects_conflicting_metadata() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};

    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let launcher = bin.join("java");
    fs::create_dir(&bin).unwrap();
    fs::write(&launcher, concat!(
        "#!/bin/sh\n",
        "test \"$#\" = 1 && test \"$1\" = -version || exit 2\n",
        "printf '%s\\n' 'openjdk version \"17.0.21\"' 'OpenJDK Runtime Environment (build 17.0.21+9)' >&2\n",
    )).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    for (disk, code, status) in [("17.0.21+9", 1, "potential"), ("17.0.21+8", 3, "unknown")] {
        fs::write(dir.path().join("release"), format!(
            "JAVA_VERSION=\"17.0.21\"\nJAVA_RUNTIME_VERSION=\"{disk}\"\nIMPLEMENTOR=\"OpenJDK\"\n"
        )).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_x2shell-check"))
            .current_dir(dir.path())
            .args(["collect", "--java-path", "./bin/java", "--fail-on-risk"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{:?}", output);
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["java4shell"]["runtimes"][0]["status"], status);
        assert!(report["java4shell"]["runtime_audit"].is_null());
    }
}
