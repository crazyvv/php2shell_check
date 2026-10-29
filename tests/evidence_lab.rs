use php_selfcheck::evidence_lab;
use serde_json::{Value, json};
use std::process::Command;

fn report(sapi: &str, version: &str, progress: &str, patched: bool) -> Value {
    json!({
        "schema":"php-selfcheck-host/v1",
        "runtime_observations":[{
            "scope":"web_runtime",
            "sapi":sapi,
            "version":version,
            "settings":{
                "session.upload_progress.enabled":progress,
                "session.serialize_handler":"php_serialize",
                "session.save_handler":"files"
            }
        }],
        "patch_evidence":if patched {json!({
            "vendor_advisory":"https://vendor.invalid/advisory",
            "package_revision":"synthetic-package",
            "running_image_matches":true,
            "workers_restarted":true,
            "all_backends_sampled":true
        })} else {json!({})}
    })
}

#[test]
fn offline_poc_validates_six_rules_without_operational_actions() {
    let result = evidence_lab::offline_poc().unwrap();
    assert_eq!(result["schema"], "php-selfcheck-offline-poc/v1");
    assert_eq!(
        result["summary"],
        json!({"passed":6,"total":6,"all_passed":true})
    );
    assert_eq!(result["guarantees"]["network_requests"], 0);
    assert_eq!(result["guarantees"]["target_connections"], 0);
    assert_eq!(result["guarantees"]["exploit_payloads"], 0);
    assert_eq!(result["guarantees"]["vulnerability_triggers"], 0);
    assert!(
        result["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|rule| rule["passed"] == true)
    );
}

#[test]
fn sapi_controls_scope_and_cli_claim_cannot_become_web_evidence() {
    let claimed = report("cli", "8.4.27", "Off", true);
    let summary = evidence_lab::summarize_report(&claimed).unwrap();
    assert!(summary["web"].as_array().unwrap().is_empty());
    assert_eq!(summary["cli"][0]["scope"], "cli_only");
    assert_eq!(summary["cli"][0]["version_status"], "meets_upstream_fix");
    assert_eq!(summary["web_evidence_present"], false);
}

#[test]
fn comparison_and_chain_matrix_keep_claims_unverified() {
    let before = report("fpm-fcgi", "8.4.26", "On", false);
    let after = report("fpm-fcgi", "8.4.27", "Off", true);
    let comparison = evidence_lab::compare_reports(&before, &after).unwrap();
    assert_eq!(comparison["conclusion"], "remediation_evidence_improved");
    assert_eq!(comparison["patch_independently_verified"], false);
    assert_eq!(comparison["exploitability_confirmed"], false);
    assert_eq!(
        comparison["before"]["web"][0]["version_status"],
        "below_upstream_fix"
    );
    assert_eq!(
        comparison["after"]["web"][0]["version_status"],
        "meets_upstream_fix"
    );
    let matrix = evidence_lab::chain_matrix(&after).unwrap();
    let chains = matrix["chains"].as_array().unwrap();
    assert_eq!(chains.len(), 5);
    assert!(chains.iter().all(|chain| {
        chain["status"] == "incomplete"
            && chain["exploitation_verified"] == false
            && !chain["missing_evidence"].as_array().unwrap().is_empty()
    }));
}

#[test]
fn every_observed_web_backend_must_reach_the_fix_baseline() {
    let before = report("fpm-fcgi", "8.4.26", "On", false);
    let mut after = report("fpm-fcgi", "8.4.27", "Off", true);
    after["runtime_observations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"sapi":"apache2handler","version":"8.3.35","settings":{"session.upload_progress.enabled":"Off"}}));
    let comparison = evidence_lab::compare_reports(&before, &after).unwrap();
    assert_eq!(comparison["conclusion"], "requires_review");
    assert_eq!(
        comparison["changes"][0]["after"],
        json!(["8.4.27", "8.3.35"])
    );
    let matrix = evidence_lab::chain_matrix(&after).unwrap();
    let chain_d = matrix["chains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|chain| chain["id"] == "D")
        .unwrap();
    assert!(
        !chain_d["missing_evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "Web SAPI 不是已核实的 apache2handler")
    );
}

#[test]
fn cli_offline_poc_and_bounded_report_comparison_are_machine_readable() {
    let binary = env!("CARGO_BIN_EXE_php-selfcheck");
    let output = Command::new(binary)
        .args(["offline-poc", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["summary"]["all_passed"], true);

    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(
        &before,
        serde_json::to_vec(&report("fpm-fcgi", "8.4.26", "On", false)).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &after,
        serde_json::to_vec(&report("fpm-fcgi", "8.4.27", "Off", true)).unwrap(),
    )
    .unwrap();
    let output = Command::new(binary)
        .args([
            "compare-reports",
            "--before",
            before.to_str().unwrap(),
            "--after",
            after.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "php-selfcheck-report-comparison/v1");
    assert_eq!(result["before"]["web"][0]["version"], "8.4.26");
    assert_eq!(result["after"]["web"][0]["version"], "8.4.27");
}
