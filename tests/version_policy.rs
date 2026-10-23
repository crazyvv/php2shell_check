use php_selfcheck::scanner::{self, inspect, stable_version};
#[test]
fn raw_prerelease_unknown_and_distro_versions_are_not_truncated() {
    for raw in [
        "8.4.27-rc1",
        "8.4.27RC1",
        "8.4.27~beta1",
        "8.4.27-dev",
        "8.4.27+alpha2",
        "8.4.27.1",
        "8.4",
        "not-a-version",
    ] {
        let r = inspect(&[("X-Powered-By".into(), format!("PHP/{raw}"))], b"");
        assert_eq!(r["versions"][0], raw);
        assert_eq!(r["verdict"], "无法判断", "{raw}");
        assert_eq!(r["assessment"]["patch"]["status"], "unknown");
        assert_eq!(scanner::check_exit_code(&r), 3);
    }
    for raw in ["8.4.27", "8.4.27-1ubuntu1", "8.4.27+deb13u1"] {
        assert_eq!(stable_version(raw), Some([8, 4, 27]));
        let r = inspect(&[("Server".into(), format!("Apache PHP/{raw}"))], b"");
        assert_eq!(r["versions"][0], raw);
        assert_eq!(scanner::check_exit_code(&r), 0);
        assert_eq!(r["exploitation_verified"], false);
    }
}
#[test]
fn conflicting_headers_retain_all_banners_and_risk_warnings() {
    for versions in [
        ["8.4.26", "8.4.27"],
        ["8.4.27", "8.1.99"],
        ["8.4.27", "9.0.0"],
        ["8.4.27", "not-a-version"],
    ] {
        let r = inspect(
            &[
                ("Server".into(), format!("PHP/{}", versions[0])),
                ("X-Powered-By".into(), format!("PHP/{}", versions[1])),
            ],
            b"",
        );
        assert_eq!(r["verdict"], "无法判断");
        assert_eq!(r["versions"].as_array().unwrap().len(), 2);
        assert_eq!(scanner::check_exit_code(&r), 3);
        if versions.contains(&"8.4.26") || versions.contains(&"8.1.99") {
            assert_eq!(r["assessment"]["review_priority"], "high");
            assert!(!r["version_warnings"].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn only_known_affected_older_branches_warn() {
    for raw in [
        "5.4.45", "5.5.38", "5.6.40", "7.0.33", "7.4.33", "8.0.30", "8.1.99",
    ] {
        let r = inspect(&[("X-Powered-By".into(), format!("PHP/{raw}"))], b"");
        assert_eq!(scanner::check_exit_code(&r), 1, "{raw}");
    }
    for raw in ["5.7.0", "6.0.0", "7.5.0", "8.6.0", "9.0.0"] {
        assert_eq!(scanner::version_risk(raw).0, "无法判断", "{raw}");
    }
}
