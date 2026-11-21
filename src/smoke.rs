//! Reproducible real-tool baseline scan, deliberately separate from approved upgrades.
use crate::tools;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn step(
    root: &Path,
    repo: &Path,
    kind: &str,
    args: &[&str],
    network: bool,
    log: &str,
) -> Result<(), String> {
    eprintln!("Smoke: {log}...");
    let version = tools::pinned_version(kind)?;
    let jdk = tools::pinned_version("jdk")?;
    let output = tools::run_tool(
        root,
        kind,
        &version,
        Some(&jdk),
        Some(repo),
        network,
        args.iter().map(|s| s.to_string()).collect(),
    )?;
    let mut text = output.stdout;
    text.extend_from_slice(&output.stderr);
    fs::write(repo.join(log), text).map_err(|e| e.to_string())?;
    if output.timed_out || output.code != Some(0) {
        return Err(format!(
            "{kind} failed; see {} (timeout={})",
            repo.join(log).display(),
            output.timed_out
        ));
    }
    Ok(())
}

fn json_file(path: &Path) -> Result<Value, String> {
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

pub fn run(network: bool) -> Result<i32, String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let root = cwd.join(".lab/tools");
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let repo = cwd
        .join(".lab/smoke-runs")
        .join(format!("{id}-{}", std::process::id()));
    fs::create_dir_all(&repo).map_err(|e| e.to_string())?;
    fixture(&repo)?;
    let mut report = json!({"kind": "baseline-smoke", "status": "failed", "repo": repo,
                           "upgrades_applied": false, "network_enabled": network});
    let result = (|| {
        let offline = if network { "-ntp" } else { "-o" };
        step(
            &root,
            &repo,
            "maven",
            &[
                "-B",
                offline,
                "clean",
                "verify",
                "-DfailIfNoTests=true",
                "-DskipTests=false",
                "-Dmaven.test.skip=false",
                "-Dmaven.test.failure.ignore=false",
            ],
            network,
            "build.log",
        )?;
        step(
            &root,
            &repo,
            "maven",
            &[
                "-B",
                // CycloneDX declares requiresOnline even with a warm cache.
                // Seatbelt still enforces network denial when --network is absent.
                "-ntp",
                "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
                "-DoutputFormat=json",
                "-DoutputName=sbom",
                "-DincludeTestScope=false",
            ],
            network,
            "sbom.log",
        )?;
        let bom = json_file(&repo.join("target/sbom.json"))?;
        if bom["bomFormat"] != "CycloneDX"
            || !bom["components"]
                .as_array()
                .ok_or("Missing SBOM components")?
                .iter()
                .any(|c| {
                    c["group"] == "org.apache.commons"
                        && c["name"] == "commons-lang3"
                        && c["version"] == "3.12.0"
                })
        {
            return Err("SBOM is missing the expected baseline dependency".to_string());
        }
        let mut scan_args = vec![
            "sbom",
            "--scanners",
            "vuln",
            "--quiet",
            "--format",
            "json",
            "--output",
            "target/trivy.json",
        ];
        if !network {
            scan_args.extend(["--skip-db-update", "--offline-scan"]);
        }
        scan_args.push("target/sbom.json");
        step(&root, &repo, "trivy", &scan_args, network, "scan.log")?;
        let scan = json_file(&repo.join("target/trivy.json"))?;
        if scan["SchemaVersion"] != 2 {
            return Err("Unexpected Trivy schema".to_string());
        }
        let findings: Vec<Value> = scan["Results"].as_array().ok_or("No Trivy scan results")?.iter()
            .flat_map(|r| r["Vulnerabilities"].as_array().into_iter().flatten())
            .map(|v| json!({"id": v["VulnerabilityID"], "package": v["PkgName"],
                           "version": v["InstalledVersion"], "fixed_version": v["FixedVersion"], "severity": v["Severity"]})).collect();
        if !findings.iter().any(|v| {
            v["id"] == "CVE-2025-48924" && v["package"] == "org.apache.commons:commons-lang3"
        }) {
            return Err("Known fixture CVE not detected; inspect scanner/database coverage".into());
        }
        report["status"] = json!("completed_with_findings");
        report["findings"] = json!(findings);
        report["sbom"] = json!(repo.join("target/sbom.json"));
        report["scan"] = json!(repo.join("target/trivy.json"));
        report["test_report"] = json!(repo.join("target/surefire-reports/TEST-lab.AppTest.xml"));
        report["tools"] = tools::catalog()?;
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        report["error"] = json!(error);
    }
    let serialized = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    fs::write(repo.join("report.json"), &serialized).map_err(|e| e.to_string())?;
    println!("{serialized}");
    Ok(if report["status"] == "completed_with_findings" {
        0
    } else {
        1
    })
}

fn fixture(repo: &Path) -> Result<(), String> {
    let files = [
        ("pom.xml", include_str!("../examples/java-smoke/pom.xml")),
        (
            "src/main/java/lab/App.java",
            include_str!("../examples/java-smoke/src/main/java/lab/App.java"),
        ),
        (
            "src/test/java/lab/AppTest.java",
            include_str!("../examples/java-smoke/src/test/java/lab/AppTest.java"),
        ),
    ];
    for (name, content) in files {
        let path: PathBuf = repo.join(name);
        fs::create_dir_all(path.parent().ok_or("No fixture parent")?).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())?;
    }
    Ok(())
}
