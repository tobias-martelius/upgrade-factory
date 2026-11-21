use super::*;

fn example() -> Value {
    serde_json::to_value(Factory::parse(include_bytes!("../../factory.yaml")).unwrap()).unwrap()
}
fn parse(value: &Value) -> Result<Factory> {
    Factory::parse(serde_yaml_ng::to_string(value).unwrap().as_bytes())
}

#[test]
fn example_resolves_defaults_overrides_and_workflows() {
    let config = Factory::parse(include_bytes!("../../factory.yaml")).unwrap();
    assert_eq!(config.repositories.len(), 20);
    let plan = config.plan(Path::new("/factory-root")).unwrap();
    assert_eq!(plan["repositories"][0]["agent"]["runner"], "codex");
    assert_eq!(plan["repositories"][3]["agent"]["runner"], "pi");
    assert_eq!(
        plan["repositories"][3]["agent"]["model"]["provider"],
        "anthropic"
    );
    assert_eq!(
        plan["repositories"][0]["normal_route"],
        json!(["upgrade/<branch_id>", "develop", "stage"])
    );
    assert_eq!(
        plan["repositories"][0]["critical_route"]["isolated_stage"],
        "stage/hotfix-<branch_id>"
    );
    assert_eq!(plan["execution_started"], false);
    assert_eq!(plan["credentials_resolved"], false);
    assert_eq!(plan["repositories"][0]["agent"]["runtime_available"], false);
    assert_eq!(plan["configuration_digest"].as_str().unwrap().len(), 64);
}

#[test]
fn unknown_fields_and_duplicate_keys_are_not_silently_ignored() {
    let mut value = example();
    value["unknown_override"] = json!(true);
    assert!(parse(&value).is_err());
    let mut value = example();
    value["agents"]["java-upgrader"]["permissions"]["disable_tests"] = json!(true);
    assert!(parse(&value).is_err());
    let duplicate = format!("{}\nname: duplicate\n", include_str!("../../factory.yaml"));
    assert!(Factory::parse(duplicate.as_bytes())
        .unwrap_err()
        .to_ascii_lowercase()
        .contains("duplicate"));
    let duplicate = include_str!("../../factory.yaml")
        .replace("models:\n  primary:", "models:\n  primary: {}\n  primary:");
    assert!(Factory::parse(duplicate.as_bytes())
        .unwrap_err()
        .to_ascii_lowercase()
        .contains("duplicate"));
}

#[test]
fn references_and_repository_names_are_checked() {
    for field in ["toolchain", "agent", "model"] {
        let mut value = example();
        value["repositories"][0][field] = json!("missing");
        assert!(parse(&value).is_err());
    }
    let mut value = example();
    value["repositories"][1]["name"] = value["repositories"][0]["name"].clone();
    assert!(parse(&value).is_err());
    let mut value = example();
    value["agents"]["java-upgrader"]["model"] = json!("missing");
    assert!(parse(&value).is_err());
}

#[test]
fn unsafe_policy_shortcuts_and_premature_jira_handover_are_rejected() {
    for change in ["sandbox", "final_approval", "hotfix", "jira"] {
        let mut value = example();
        match change {
            "sandbox" => value["sandbox"]["required"] = json!(false),
            "final_approval" => value["approvals"]["final_result"] = json!("automatic"),
            "hotfix" => {
                value["workflow"]["critical"]["stage_strategy"] = json!("merge_shared_stage")
            }
            _ => value["jira"]["transition_gate"] = json!("first_repository_ready"),
        }
        assert!(parse(&value).is_err(), "{change}");
    }
    let mut value = example();
    value["workflow"]["normal"]["promote"] = json!(["develop", "main"]);
    assert!(parse(&value).is_err());
}

#[test]
fn credentials_are_references_not_values() {
    for credential in [
        "sk-live-secret",
        "${OPENAI_API_KEY}",
        "/home/user/secret",
        "",
    ] {
        let mut value = example();
        value["models"]["primary"]["credential_ref"] = json!(credential);
        assert!(parse(&value).is_err());
    }
    let mut value = example();
    value["gitlab"]["url"] = json!("https://user:password@gitlab.example.invalid");
    assert!(parse(&value).is_err());
    let mut value = example();
    value["gitlab"]["api_key"] = json!("not-permitted");
    assert!(parse(&value).is_err());
    let plan = parse(&example())
        .unwrap()
        .plan(Path::new("/factory-root"))
        .unwrap();
    assert_eq!(
        plan["repositories"][0]["agent"]["model"]["credential_ref"],
        "OPENAI_API_KEY"
    );
    assert_eq!(plan["credentials_resolved"], false);
}

#[test]
fn enabling_a_profile_does_not_claim_agent_runtime_support() {
    let mut value = example();
    value["agents"]["java-upgrader"]["enabled"] = json!(true);
    assert!(parse(&value).is_err());
    value["models"]["primary"]["model_id"] = json!("operator-selected-model");
    let plan = parse(&value)
        .unwrap()
        .plan(Path::new("/factory-root"))
        .unwrap();
    assert_eq!(plan["repositories"][0]["agent"]["configured_enabled"], true);
    assert_eq!(plan["repositories"][0]["agent"]["runtime_available"], false);
    assert_eq!(plan["execution_started"], false);
}

#[test]
fn budgets_paths_versions_and_queue_limits_are_validated() {
    let mut value = example();
    value["queue"]["scan_workers"] = json!(99);
    assert!(parse(&value).is_err());
    let mut value = example();
    value["queue"]["transient_retries"] = json!(9);
    assert!(parse(&value).is_err());
    let mut value = example();
    value["agents"]["java-upgrader"]["limits"]["max_cost_usd"] = json!(-1);
    assert!(parse(&value).is_err());
    let mut value = example();
    value["agents"]["java-upgrader"]["permissions"]["preserve_checks"] = json!(false);
    assert!(parse(&value).is_err());
    let mut value = example();
    value["repositories"][0]["path"] = json!("../outside");
    assert!(parse(&value).is_err());
    let mut value = example();
    value["branches"]["development"] = json!("bad.lock/branch");
    assert!(parse(&value).is_err());
    let mut value = example();
    value["api_version"] = json!("future/v9");
    assert!(parse(&value).is_err());
    assert!(Factory::parse(&vec![b' '; 1_048_577]).is_err());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn scanner_resolves_factory_relative_paths_and_rejects_unsupported_tool_overrides() {
    let config = parse(&example()).unwrap();
    let rows = config
        .scan_repositories(Path::new("/factory-root"))
        .unwrap();
    assert_eq!(rows.len(), 40);
    assert_eq!(rows[0].1, "develop");
    assert_eq!(
        rows[0].2,
        Path::new("/factory-root/.lab/rust-repos/order-service")
    );
    let mut value = example();
    value["toolchains"]["java21"]["jdk"] = json!("99");
    assert!(parse(&value)
        .unwrap()
        .scan_repositories(Path::new("/factory-root"))
        .unwrap_err()
        .contains("unsupported jdk"));
}
