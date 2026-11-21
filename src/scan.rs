//! Local Git branch scanning with bounded concurrency and no unsandboxed tools.
use crate::failure::{self, Failure};
use crate::sandbox::{self, Access, Job, Network};
use crate::store::{self, Store};
use crate::tools;
use serde_json::{json, Value};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HELP: &str = "Scan/status:\n\
  upgrade-lab repos init-examples\n\
  upgrade-lab scan --config PATH [--network] [--workers 4] [--retries 2]\n\
  upgrade-lab status [--repo NAME] [--cve CVE-ID] [--max-age-seconds 86400] [--json]\n\
  upgrade-lab inventory\n\
Database: .lab/scans.sqlite. Technical incidents are local, not GitLab issues yet.\n";

#[derive(Clone, Debug)]
struct Repository {
    name: String,
    branch: String,
    path: PathBuf,
}

fn is_factory_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|v| v.to_str()),
        Some("yaml" | "yml")
    )
}

fn parse_config(path: &Path) -> Result<Vec<Repository>, String> {
    if is_factory_file(path) {
        let (config, base) = crate::config::load(path)?;
        return Ok(config
            .scan_repositories(&base)?
            .into_iter()
            .map(|(name, branch, path)| Repository { name, branch, path })
            .collect());
    }
    let document: Value =
        serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let rows = document["repositories"]
        .as_array()
        .ok_or("Expected repositories array")?;
    let mut entries = vec![];
    let mut seen = HashSet::new();
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    for row in rows {
        let name = row["name"].as_str().ok_or("Repository needs name")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        {
            return Err("Invalid repository name".into());
        }
        let path = Path::new(row["path"].as_str().ok_or("Repository needs path")?);
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err("Repository paths must not contain ..".into());
        }
        let path = cwd.join(path);
        let path = fs::canonicalize(&path).unwrap_or(path);
        for branch in row["branches"]
            .as_array()
            .ok_or("Repository needs branches array")?
        {
            let branch = branch.as_str().ok_or("Branch must be a string")?;
            if !matches!(branch, "main" | "develop") {
                return Err("Only main/develop branches are supported".into());
            }
            if !seen.insert((name.to_string(), branch.to_string())) {
                return Err("Duplicate repo/branch".into());
            }
            entries.push(Repository {
                name: name.into(),
                branch: branch.into(),
                path: path.clone(),
            });
        }
    }
    if entries.is_empty() {
        return Err("Select at least one repository/branch".into());
    }
    Ok(entries)
}

fn git(repo: &Path, output: Option<&Path>, args: Vec<String>) -> Result<sandbox::Output, String> {
    let mut access = vec![Access::Read(repo.to_path_buf())];
    if let Some(path) = output {
        access.push(Access::Write(path.to_path_buf()));
    }
    // Apple git uses the selected Xcode/CommandLineTools installation. No user config is inherited.
    for path in [
        "/Library/Developer/CommandLineTools",
        "/Applications/Xcode.app",
    ] {
        if Path::new(path).exists() {
            access.push(Access::Read(path.into()));
        }
    }
    sandbox::execute(&Job {
        program: "/usr/bin/git".into(),
        args,
        access,
        network: Network::Denied,
        timeout: Duration::from_secs(60),
        environment: vec![],
        workdir: Some(repo.into()),
    })
}

fn output_failure(
    stage: &str,
    output: sandbox::Output,
    network: bool,
    log: &Path,
) -> Result<String, Failure> {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if output.truncated {
        text.push_str("\n[log truncated by sandbox capture]\n");
    }
    fs::write(log, &text).map_err(|e| Failure::new(stage, "local_io", e.to_string()))?;
    if output.code == Some(0) && !output.timed_out {
        return Ok(text);
    }
    let mut error = failure::classify(stage, &text, network, output.timed_out);
    error.message = format!(
        "{}; see {}",
        text.chars()
            .rev()
            .take(2000)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>(),
        log.display()
    );
    Err(error)
}

fn snapshot(repo: &Repository, run: &Path) -> Result<(String, PathBuf), Failure> {
    let path = fs::canonicalize(&repo.path)
        .map_err(|e| Failure::new("source", "source_configuration", e.to_string()))?;
    let head = git(
        &path,
        None,
        vec![
            "rev-parse".into(),
            "--verify".into(),
            format!("refs/heads/{}^{{commit}}", repo.branch),
        ],
    )
    .map_err(|e| failure::classify("source", &e, false, false))?;
    let commit = output_failure("source", head, false, &run.join("source-ref.log"))?
        .trim()
        .to_string();
    if !matches!(commit.len(), 40 | 64) || !commit.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Failure::new(
            "source",
            "source_configuration",
            "Invalid Git commit ID",
        ));
    }
    let archive = run.join("source.tar");
    let output = git(
        &path,
        Some(run),
        vec![
            "archive".into(),
            "--format=tar".into(),
            format!("--output={}", archive.display()),
            commit.clone(),
        ],
    )
    .map_err(|e| failure::classify("source", &e, false, false))?;
    output_failure("source", output, false, &run.join("source-archive.log"))?;
    let worktree = run.join("worktree");
    fs::create_dir(&worktree).map_err(|e| Failure::new("source", "local_io", e.to_string()))?;
    let output = sandbox::execute(&Job {
        program: "/usr/bin/tar".into(),
        args: vec![
            "--no-same-owner".into(),
            "--no-same-permissions".into(),
            "-xf".into(),
            archive.display().to_string(),
            "-C".into(),
            worktree.display().to_string(),
        ],
        access: vec![Access::Read(archive), Access::Write(worktree.clone())],
        network: Network::Denied,
        timeout: Duration::from_secs(60),
        environment: vec![],
        workdir: None,
    })
    .map_err(|e| failure::classify("source", &e, false, false))?;
    output_failure("source", output, false, &run.join("source-extract.log"))?;
    Ok((commit, worktree))
}

pub(crate) fn artifact(repo: &Path, relative: &str, stage: &str) -> Result<Value, Failure> {
    let path = fs::canonicalize(repo.join(relative))
        .map_err(|e| Failure::new(stage, "invalid_output", e.to_string()))?;
    if !path.starts_with(repo) {
        return Err(Failure::new(
            stage,
            "invalid_output",
            "Artifact symlink escapes job directory",
        ));
    }
    let metadata =
        fs::metadata(&path).map_err(|e| Failure::new(stage, "local_io", e.to_string()))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err(Failure::new(
            stage,
            "invalid_output",
            "Artifact missing, special or larger than 64 MiB",
        ));
    }
    let bytes = fs::read(path).map_err(|e| Failure::new(stage, "local_io", e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| Failure::new(stage, "invalid_output", e.to_string()))
}

pub(crate) fn findings(scan: &Value) -> Result<Vec<Value>, Failure> {
    if scan["SchemaVersion"] != 2 {
        return Err(Failure::new(
            "vulnerability_scan",
            "invalid_output",
            "Unsupported Trivy schema",
        ));
    }
    let results = scan["Results"].as_array().ok_or_else(|| {
        Failure::new(
            "vulnerability_scan",
            "invalid_output",
            "Missing Trivy Results",
        )
    })?;
    let mut findings = vec![];
    for result in results {
        let vulnerabilities = match result.get("Vulnerabilities") {
            None | Some(Value::Null) => continue,
            Some(value) => value.as_array().ok_or_else(|| {
                Failure::new(
                    "vulnerability_scan",
                    "invalid_output",
                    "Invalid vulnerability array",
                )
            })?,
        };
        for item in vulnerabilities {
            let field = |key: &str| {
                item[key].as_str().ok_or_else(|| {
                    Failure::new(
                        "vulnerability_scan",
                        "invalid_output",
                        format!("Missing {key}"),
                    )
                })
            };
            findings.push(
                json!({"id":field("VulnerabilityID")?,"package":field("PkgName")?,
                "version":field("InstalledVersion")?,"severity":field("Severity")?,
                "fixed_version":item["FixedVersion"].as_str().unwrap_or("")}),
            );
        }
    }
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
fn tool_step(
    root: &Path,
    worktree: &Path,
    run: &Path,
    kind: &str,
    stage: &str,
    args: Vec<String>,
    network: bool,
    retries: usize,
    attempts: &mut Value,
) -> Result<(), Failure> {
    failure::retry(
        retries,
        |attempt| {
            attempts[stage] = json!(attempt + 1);
            eprintln!(
                "{}: {stage} attempt {}",
                run.file_name().unwrap_or_default().to_string_lossy(),
                attempt + 1
            );
            let version = tools::pinned_version(kind)
                .map_err(|e| failure::classify(stage, &e, network, false))?;
            let jdk = tools::pinned_version("jdk")
                .map_err(|e| failure::classify(stage, &e, network, false))?;
            let output = tools::run_tool(
                root,
                kind,
                &version,
                Some(&jdk),
                Some(worktree),
                network,
                args.clone(),
            )
            .map_err(|e| failure::classify(stage, &e, network, false))?;
            output_failure(
                stage,
                output,
                network,
                &run.join(format!("{stage}-attempt-{}.log", attempt + 1)),
            )?;
            Ok(())
        },
        |seconds| std::thread::sleep(Duration::from_secs(seconds)),
    )
}

fn scan_one(
    repo: &Repository,
    cwd: &Path,
    database: &Path,
    network: bool,
    retries: usize,
) -> Result<Value, String> {
    let started = store::now_ms();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let id = format!(
        "{nonce}-{}-{}-{}",
        std::process::id(),
        repo.name,
        repo.branch
    );
    let run = cwd.join(".lab/scans").join(&id);
    fs::create_dir_all(&run).map_err(|e| e.to_string())?;
    let mut db = Store::open(database)?;
    db.begin(&id, &repo.name, &repo.branch, started)?;
    let mut report = json!({"id":id,"repo":repo.name,"branch":repo.branch,"started_at_ms":started,
                           "status":"failed","run_directory":run,"network_enabled":network,"attempts":{}});
    let result = (|| {
        let (commit, worktree) = snapshot(repo, &run)?;
        report["commit"] = json!(commit);
        let root = cwd.join(".lab/tools");
        let mut attempts = json!({});
        let result = (|| {
            let offline = if network { "-ntp" } else { "-o" };
            tool_step(
                &root,
                &worktree,
                &run,
                "maven",
                "build",
                [
                    "-B",
                    offline,
                    "clean",
                    "verify",
                    "-DfailIfNoTests=true",
                    "-DskipTests=false",
                    "-Dmaven.test.skip=false",
                    "-Dmaven.test.failure.ignore=false",
                ]
                .map(String::from)
                .to_vec(),
                network,
                retries,
                &mut attempts,
            )?;
            tool_step(
                &root,
                &worktree,
                &run,
                "maven",
                "sbom",
                [
                    "-B",
                    "-ntp",
                    "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
                    "-DoutputFormat=json",
                    "-DoutputName=sbom",
                    "-DincludeTestScope=false",
                ]
                .map(String::from)
                .to_vec(),
                network,
                retries,
                &mut attempts,
            )?;
            let bom = artifact(&worktree, "target/sbom.json", "sbom")?;
            if bom["bomFormat"] != "CycloneDX"
                || bom["specVersion"].as_str().is_none()
                || bom["components"].as_array().is_none()
            {
                return Err(Failure::new(
                    "sbom",
                    "invalid_output",
                    "Expected CycloneDX components",
                ));
            }
            let mut args = [
                "sbom",
                "--scanners",
                "vuln",
                "--quiet",
                "--format",
                "json",
                "--output",
                "target/trivy.json",
            ]
            .map(String::from)
            .to_vec();
            if !network {
                args.extend(["--skip-db-update".into(), "--offline-scan".into()]);
            }
            args.push("target/sbom.json".into());
            tool_step(
                &root,
                &worktree,
                &run,
                "trivy",
                "vulnerability_scan",
                args,
                network,
                retries,
                &mut attempts,
            )?;
            let scan = artifact(&worktree, "target/trivy.json", "vulnerability_scan")?;
            report["scanner_version"] = scan["Trivy"]["Version"].clone();
            let cache = cwd.join(".lab/cache/trivy");
            if let Ok(cache) = fs::canonicalize(cache) {
                if let Ok(metadata) = artifact(&cache, "db/metadata.json", "vulnerability_scan") {
                    report["scanner_database_metadata"] = metadata;
                }
            }
            let values = findings(&scan)?;
            // Require evidence of language analysis for nonempty Maven BOMs.
            if !bom["components"].as_array().unwrap().is_empty()
                && !scan["Results"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["Type"] == "jar")
            {
                return Err(Failure::new(
                    "vulnerability_scan",
                    "incomplete_scan",
                    "No Java analysis result for nonempty SBOM",
                ));
            }
            Ok((bom, values))
        })();
        report["attempts"] = attempts;
        let (bom, values) = result?;
        report["findings"] = json!(values);
        report["sbom"] = json!(worktree.join("target/sbom.json"));
        report["status"] = json!("succeeded");
        Ok::<_, Failure>((commit, bom))
    })();
    match result {
        Ok((commit, bom)) => {
            db.success(&id, &repo.name, &repo.branch, &commit, &report, &bom)?;
            crate::queue::refresh(database)
                .map_err(|e| format!("Scan saved, but decision queue/alarm update failed: {e}"))?;
        }
        Err(error) => {
            report["failure"] = error.json();
            db.failure(&id, &repo.name, &repo.branch, &report, &error)?;
        }
    }
    fs::write(
        run.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(report)
}

fn execute(config: &Path, workers: usize, retries: usize, network: bool) -> Result<i32, String> {
    let repos = parse_config(config)?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let database = cwd.join(".lab/scans.sqlite");
    let db = Store::open(&database)?;
    for repo in &repos {
        db.register(&repo.name, &repo.branch, &repo.path.display().to_string())?;
    }
    // Failure is persisted per job if no backend/tool is available; never run unsandboxed.
    let queue = Arc::new(Mutex::new(VecDeque::from(repos)));
    let reports = Arc::new(Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        for _ in 0..workers.clamp(1, 8) {
            let queue = Arc::clone(&queue);
            let reports = Arc::clone(&reports);
            let cwd = &cwd;
            let database = &database;
            scope.spawn(move || loop {
                let repo = queue.lock().unwrap().pop_front();
                let Some(repo) = repo else {
                    break;
                };
                let result = scan_one(&repo, cwd, database, network, retries);
                reports.lock().unwrap().push(result);
            });
        }
    });
    let reports = reports.lock().map_err(|e| e.to_string())?;
    let mut failed = false;
    let mut runs = vec![];
    let mut infrastructure_errors = vec![];
    for report in reports.iter() {
        match report {
            Ok(value) => {
                failed |= value["status"] != "succeeded";
                runs.push(value.clone());
            }
            Err(error) => {
                failed = true;
                infrastructure_errors.push(error.clone());
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"runs":runs,"infrastructure_errors":infrastructure_errors})
        )
        .map_err(|e| e.to_string())?
    );
    Ok(i32::from(failed))
}

fn display_status(status: &Value) {
    println!(
        "{:<25} {:<9} {:<14} {:<7} {:>5} {:>5} {:>5}  COMMIT",
        "REPO", "BRANCH", "SCAN", "DATA", "CRIT", "HIGH", "MED"
    );
    for repo in status["repositories"].as_array().into_iter().flatten() {
        let count = |key: &str| {
            repo["counts"][key]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or("—".into())
        };
        let commit = repo["last_success"]["commit"].as_str().unwrap_or("—");
        let commit: String = commit.chars().take(10).collect();
        println!(
            "{:<25} {:<9} {:<14} {:<7} {:>5} {:>5} {:>5}  {}",
            repo["repo"].as_str().unwrap_or("?"),
            repo["branch"].as_str().unwrap_or("?"),
            repo["scan_status"].as_str().unwrap_or("?"),
            if repo["data_stale"] == true {
                "STALE"
            } else {
                "recent"
            },
            count("CRITICAL"),
            count("HIGH"),
            count("MEDIUM"),
            commit
        );
    }
    let mut cves = std::collections::BTreeMap::<String, usize>::new();
    for finding in status["findings"].as_array().into_iter().flatten() {
        *cves
            .entry(finding["id"].as_str().unwrap_or("?").into())
            .or_default() += 1;
    }
    println!("\nCVE findings from last successful scans (may be stale):");
    for (cve, count) in cves {
        println!("  {cve}: {count} findings across selected repo/branches");
    }
    for incident in status["open_incidents"].as_array().into_iter().flatten() {
        println!(
            "  INCIDENT {}/{}: {} at {}",
            incident["repo"].as_str().unwrap_or("?"),
            incident["branch"].as_str().unwrap_or("?"),
            incident["category"].as_str().unwrap_or("?"),
            incident["failure"]["stage"].as_str().unwrap_or("?")
        );
    }
    println!("Use status --json for findings, timestamps, incidents and log paths. Scan success is not a clean security verdict.");
}

pub fn cli(args: &[String]) -> Result<i32, String> {
    let action = args.first().map(String::as_str).ok_or(HELP)?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    if action == "inventory" && args.len() == 1 {
        let result = Store::open(&cwd.join(".lab/scans.sqlite"))?.inventory()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
        );
        return Ok(0);
    }
    let mut config = None;
    let mut workers = None;
    let mut retries = None;
    let mut network = false;
    let mut repo = None;
    let mut cve = None;
    let mut age = 86400;
    let mut json_output = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--json" && action == "status" {
            json_output = true;
            i += 1;
            continue;
        }
        if args[i] == "--network" && action == "scan" {
            network = true;
            i += 1;
            continue;
        }
        let option = args[i].as_str();
        i += 1;
        let value = args.get(i).ok_or("Missing option value")?;
        match (action, option) {
            ("scan", "--config") => config = Some(Path::new(value)),
            ("scan", "--workers") => {
                workers = Some(value.parse::<usize>().map_err(|e| e.to_string())?)
            }
            ("scan", "--retries") => {
                retries = Some(value.parse::<usize>().map_err(|e| e.to_string())?)
            }
            ("status", "--repo") => repo = Some(value.as_str()),
            ("status", "--cve") => cve = Some(value.as_str()),
            ("status", "--max-age-seconds") => {
                age = value.parse::<u64>().map_err(|e| e.to_string())?
            }
            _ => return Err(HELP.into()),
        }
        i += 1;
    }
    match action {
        "scan" => {
            let path = config.ok_or("--config required")?;
            if is_factory_file(path) {
                let path = fs::canonicalize(path).map_err(|e| e.to_string())?;
                let (factory, base) = crate::config::load(&path)?;
                factory.scan_repositories(&base)?;
                std::env::set_current_dir(&base).map_err(|e| e.to_string())?;
                eprintln!("Factory configuration loaded. Applying scan repositories, branches, workers and retries only; agent, promotion and integration settings are declarative, not executable yet.");
                execute(
                    &path,
                    workers.unwrap_or(factory.queue.scan_workers),
                    retries.unwrap_or(factory.queue.transient_retries),
                    network,
                )
            } else {
                execute(path, workers.unwrap_or(4), retries.unwrap_or(2), network)
            }
        }
        "status" => {
            let result = Store::open(&cwd.join(".lab/scans.sqlite"))?.status(repo, cve, age)?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
                );
            } else {
                display_status(&result);
            }
            Ok(0)
        }
        _ => Err(HELP.into()),
    }
}

pub fn init_examples() -> Result<(), String> {
    sandbox::doctor()?;
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let names = [
        "order",
        "customer",
        "inventory",
        "payment",
        "shipping",
        "notification",
        "catalog",
        "pricing",
        "discount",
        "invoice",
        "report",
        "search",
        "auth",
        "audit",
        "booking",
        "subscription",
        "document",
        "integration",
        "batch",
        "health",
    ];
    let mut rows = vec![];
    for name in names {
        let name = format!("{name}-service");
        let repo = cwd.join(".lab/rust-repos").join(&name);
        if !repo.exists() {
            fs::create_dir_all(&repo).map_err(|e| e.to_string())?;
            for (path, text) in [
                ("pom.xml", include_str!("../examples/java-smoke/pom.xml")),
                (
                    "src/main/java/lab/App.java",
                    include_str!("../examples/java-smoke/src/main/java/lab/App.java"),
                ),
                (
                    "src/test/java/lab/AppTest.java",
                    include_str!("../examples/java-smoke/src/test/java/lab/AppTest.java"),
                ),
            ] {
                let path = repo.join(path);
                fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
                fs::write(path, text.replace("sandbox-smoke", &name)).map_err(|e| e.to_string())?;
            }
            fs::write(repo.join(".gitignore"), "target/\n").map_err(|e| e.to_string())?;
            let commands = vec![
                vec!["init", "-b", "main"],
                vec!["add", "."],
                vec![
                    "-c",
                    "user.name=Upgrade Lab",
                    "-c",
                    "user.email=lab@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-m",
                    "Initial Java scan fixture",
                ],
                vec!["branch", "develop"],
            ];
            for command in commands {
                let output = git(
                    &repo,
                    Some(&repo),
                    command.into_iter().map(String::from).collect(),
                )?;
                if output.code != Some(0) {
                    return Err(String::from_utf8_lossy(&output.stderr).into());
                }
            }
        }
        rows.push(json!({"name":name,"path":repo,"branches":["main"]}));
    }
    let path = cwd.join(".lab/repositories.json");
    if path.exists() {
        return Err(
            "Examples retained; .lab/repositories.json already exists, refusing overwrite".into(),
        );
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({"repositories":rows})).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("Created example config: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn factory_yaml_is_accepted_as_scan_input() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repositories = parse_config(&root.join("factory.yaml")).unwrap();
        assert_eq!(repositories.len(), 40);
        assert_eq!(repositories[0].name, "order-service");
        assert_eq!(repositories[0].branch, "develop");
        assert_eq!(
            repositories[0].path,
            root.join(".lab/rust-repos/order-service")
        );
    }
    #[test]
    fn malformed_scanner_output_is_not_clean() {
        assert!(findings(&json!({"SchemaVersion":2})).is_err());
        assert!(
            findings(&json!({"SchemaVersion":2,"Results":[{"Vulnerabilities":"bad"}]})).is_err()
        );
        assert!(
            findings(&json!({"SchemaVersion":2,"Results":[{"Type":"jar"}]}))
                .unwrap()
                .is_empty()
        );
    }
}
