use clap::Parser;
use php_selfcheck::collector::{CollectArgs, CollectOptions};
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
        !default.middleware && !default.web_probe && !default.php_command && !default.package_audit
    );
    let enabled = Cli::parse_from(["collect", "--php-command", "--package-audit"])
        .collect
        .resolve()
        .unwrap();
    assert!(enabled.php_command && enabled.package_audit && !enabled.middleware);
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
