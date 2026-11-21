use super::*;
use crate::store::Store;
use std::sync::atomic::{AtomicU64, Ordering};
static SEQ: AtomicU64 = AtomicU64::new(0);
const POM: &str = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion><groupId>lab</groupId><artifactId>demo</artifactId><version>1.0</version>
<!-- preserve formatting and comments -->
<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies>
</project>"#;
fn action(package: &str) -> Value {
    json!({"repo":"orders","branch":"main","base_commit":"base1","cve":format!("CVE-{package}"),"package":package,"installed_version":"1.0","severity":"HIGH","kind":"upgrade","target_version":"1.1","code_changes":false,"hotfix_exception":false,"mandate":"Only change approved dependency version","verification":["build","tests","sbom","security_scan"]})
}
struct Fixture {
    root: PathBuf,
    database: PathBuf,
    repo: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "upgrade-executor-{}-{}-{}",
            std::process::id(),
            store::now_ms(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let repo = root.join("source");
        fs::create_dir(&repo).unwrap();
        let database = root.join("db.sqlite");
        Self {
            root,
            database,
            repo,
        }
    }
    fn seed(&self, now: i64) -> (Queue, Value, Value) {
        let mut db = Store::open(&self.database).unwrap();
        db.register("orders", "main", self.repo.to_str().unwrap())
            .unwrap();
        db.begin("seed", "orders", "main", now).unwrap();
        let a = action("g:a");
        let b = action("g:b");
        let findings:Vec<_>=[&a,&b].into_iter().map(|a|json!({"id":a["cve"],"package":a["package"],"version":"1.0","severity":"HIGH","fixed_version":"1.1"})).collect();
        db.success(
            "seed",
            "orders",
            "main",
            "base1",
            &json!({"findings":findings}),
            &json!({"bomFormat":"CycloneDX","components":[]}),
        )
        .unwrap();
        (Queue::open(&self.database).unwrap(), a, b)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn patches_only_literal_direct_dependency_and_preserves_bytes() {
    let patched = patch_pom(POM, &[action("g:a")]).unwrap();
    assert_eq!(
        patched,
        POM.replace(
            "<artifactId>a</artifactId><version>1.0</version>",
            "<artifactId>a</artifactId><version>1.1</version>"
        )
    );
}
#[test]
fn property_bom_transitive_and_multimodule_require_manual_handling() {
    for pom in [
        POM.replace(
            "<artifactId>a</artifactId><version>1.0</version>",
            "<artifactId>a</artifactId><version>${v}</version>",
        ),
        POM.replace("</dependency>", "<type>pom</type></dependency>"),
        POM.replace(
            "</project>",
            "<modules><module>x</module></modules></project>",
        ),
    ] {
        assert!(patch_pom(&pom, &[action("g:a")]).is_err());
    }
    assert!(patch_pom(POM, &[action("g:transitive")]).is_err());
    let mut changed = action("g:a");
    changed["target_version"] = json!("2.0");
    assert!(patch_pom(POM, &[action("g:a"), changed]).is_err());
}
#[test]
fn security_gate_blocks_remaining_and_new_high_or_critical() {
    let existing = json!({"id":"CVE-old","package":"g:a","severity":"MEDIUM"});
    assert!(security(&[], std::slice::from_ref(&existing), &[action("g:a")]).is_err());
    let escalated = json!({"id":"CVE-old","package":"g:b","severity":"HIGH"});
    assert!(security(&[], std::slice::from_ref(&escalated), &[action("g:a")]).is_err());
    assert!(security(
        std::slice::from_ref(&escalated),
        std::slice::from_ref(&escalated),
        &[action("g:a")]
    )
    .is_ok());
}
#[test]
fn claim_is_single_use_and_repository_lock_is_atomic() {
    let fixture = Fixture::new();
    let now = store::now_ms();
    let (mut queue, a, b) = fixture.seed(now);
    let (first, _) = queue.propose(&a, "test", now).unwrap();
    let (second, _) = queue.propose(&b, "test", now).unwrap();
    let first = queue
        .approve(&[first], "test", now, now + 60_000, false, now)
        .unwrap();
    let second = queue
        .approve(&[second], "test", now, now + 60_000, false, now)
        .unwrap();
    let (_token, groups) = claim(&mut queue, &first, now).unwrap();
    assert_eq!(groups.len(), 1);
    assert!(claim(&mut queue, &first, now).is_err());
    assert!(claim(&mut queue, &second, now).is_err());
    let count: i64 = queue
        .connection
        .query_row("SELECT count(*) FROM executions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        queue
            .ready(now)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["batch_id"] == first)
            .unwrap()["execution_started"],
        true
    );
}
#[test]
fn code_action_is_not_silently_downgraded_to_version_update() {
    let fixture = Fixture::new();
    let now = store::now_ms();
    let (mut queue, mut a, _) = fixture.seed(now);
    // Use a separately scanned develop branch so the code mandate is valid for approval.
    let mut db = Store::open(&fixture.database).unwrap();
    db.register("orders", "develop", fixture.repo.to_str().unwrap())
        .unwrap();
    db.begin("dev", "orders", "develop", now).unwrap();
    db.success("dev","orders","develop","base1",&json!({"findings":[{"id":a["cve"],"package":"g:a","version":"1.0","severity":"HIGH","fixed_version":"1.1"}]}),&json!({})).unwrap();
    a["branch"] = json!("develop");
    a["code_changes"] = json!(true);
    a["verification"]
        .as_array_mut()
        .unwrap()
        .push(json!("code_review"));
    let (id, _) = queue.propose(&a, "test", now).unwrap();
    let batch = queue
        .approve(&[id], "test", now, now + 60_000, false, now)
        .unwrap();
    assert!(claim(&mut queue, &batch, now)
        .unwrap_err()
        .contains("Manual handling"));
    let count: i64 = queue
        .connection
        .query_row("SELECT count(*) FROM executions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
#[test]
fn revoked_window_and_changed_evidence_prevent_claim() {
    let fixture = Fixture::new();
    let now = store::now_ms();
    let (mut queue, a, _) = fixture.seed(now);
    let (id, _) = queue.propose(&a, "test", now).unwrap();
    let batch = queue
        .approve(&[id], "test", now + 10_000, now + 60_000, false, now)
        .unwrap();
    assert!(claim(&mut queue, &batch, now).is_err());
    queue.revoke(&batch, "test", "stop", now + 1).unwrap();
    assert!(claim(&mut queue, &batch, now + 20_000).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn actual_git_head_is_checked_not_only_cached_scan_evidence() {
    let fixture = Fixture::new();
    fs::write(fixture.repo.join("pom.xml"), POM).unwrap();
    for args in [
        vec!["init", "-b", "main"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
    ] {
        git(
            &fixture.repo,
            &[],
            std::slice::from_ref(&fixture.repo),
            args.into_iter().map(String::from).collect(),
            &fixture.root.join("init.log"),
        )
        .unwrap();
    }
    let base = String::from_utf8(
        git(
            &fixture.repo,
            &[],
            &[],
            vec!["rev-parse".into(), "HEAD".into()],
            &fixture.root.join("head.log"),
        )
        .unwrap(),
    )
    .unwrap()
    .trim()
    .to_string();
    let group = Group {
        repo: "test".into(),
        branch: "main".into(),
        source: fixture.repo.clone(),
        base,
        actions: vec![],
        baseline_findings: vec![],
        baseline_bom: json!({}),
    };
    source_head(&group, &fixture.root, "unchanged").unwrap();
    fs::write(fixture.repo.join("new.txt"), "new commit").unwrap();
    for args in [
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "new head",
        ],
    ] {
        git(
            &fixture.repo,
            &[],
            std::slice::from_ref(&fixture.repo),
            args.into_iter().map(String::from).collect(),
            &fixture.root.join("change.log"),
        )
        .unwrap();
    }
    assert!(source_head(&group, &fixture.root, "moved")
        .unwrap_err()
        .contains("moved"));
}

#[cfg(target_os = "macos")]
#[test]
fn protected_git_directory_cannot_be_written_by_build_process() {
    let fixture = Fixture::new();
    let git = fixture.repo.join(".git");
    fs::create_dir(&git).unwrap();
    fs::write(git.join("guard"), "original").unwrap();
    let output = sandbox::execute(&Job {
        program: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            "printf nope > \"$1/.git/guard\"".into(),
            "guard".into(),
            fixture.repo.display().to_string(),
        ],
        access: vec![
            Access::Write(fixture.repo.clone()),
            Access::Protected(git.clone()),
        ],
        network: Network::Denied,
        timeout: Duration::from_secs(2),
        environment: vec![],
        workdir: None,
    })
    .unwrap();
    assert_ne!(output.code, Some(0));
    assert_eq!(fs::read_to_string(git.join("guard")).unwrap(), "original");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires bootstrapped real JDK/Maven/Trivy and cached DB; downloads the fixed dependency over the network into managed cache. Uses only a temporary repo/database."]
fn real_approved_upgrade_does_not_modify_original_or_close_main_finding() {
    let fixture = Fixture::new();
    let cwd = std::env::current_dir().unwrap();
    let tools_root = cwd.join(".lab/tools");
    for (name, content) in [
        ("pom.xml", include_str!("../../examples/java-smoke/pom.xml")),
        (
            "src/main/java/lab/App.java",
            include_str!("../../examples/java-smoke/src/main/java/lab/App.java"),
        ),
        (
            "src/test/java/lab/AppTest.java",
            include_str!("../../examples/java-smoke/src/test/java/lab/AppTest.java"),
        ),
        (".gitignore", "target/\n"),
    ] {
        let path = fixture.repo.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    for args in [
        vec!["init", "-b", "main"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "fixture",
        ],
    ] {
        git(
            &fixture.repo,
            &[],
            std::slice::from_ref(&fixture.repo),
            args.into_iter().map(String::from).collect(),
            &fixture.root.join("init.log"),
        )
        .unwrap();
    }
    let base = String::from_utf8(
        git(
            &fixture.repo,
            &[],
            &[],
            vec!["rev-parse".into(), "HEAD".into()],
            &fixture.root.join("base.log"),
        )
        .unwrap(),
    )
    .unwrap()
    .trim()
    .to_string();
    let mvn = tools::pinned_version("maven").unwrap();
    let jdk = tools::pinned_version("jdk").unwrap();
    let trivy = tools::pinned_version("trivy").unwrap();
    for args in [
        vec!["-B", "-ntp", "clean", "verify", "-DfailIfNoTests=true"],
        vec![
            "-B",
            "-ntp",
            "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
            "-DoutputFormat=json",
            "-DoutputName=sbom",
        ],
    ] {
        let result = tools::run_tool(
            &tools_root,
            "maven",
            &mvn,
            Some(&jdk),
            Some(&fixture.repo),
            false,
            args.into_iter().map(String::from).collect(),
        )
        .unwrap();
        assert_eq!(
            result.code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let result = tools::run_tool(
        &tools_root,
        "trivy",
        &trivy,
        None,
        Some(&fixture.repo),
        false,
        [
            "sbom",
            "--scanners",
            "vuln",
            "--quiet",
            "--skip-db-update",
            "--offline-scan",
            "--format",
            "json",
            "--output",
            "target/trivy.json",
            "target/sbom.json",
        ]
        .map(String::from)
        .to_vec(),
    )
    .unwrap();
    assert_eq!(result.code, Some(0));
    let scan = scan::artifact(&fixture.repo, "target/trivy.json", "scan").unwrap();
    let findings = scan::findings(&scan).unwrap();
    let bom = scan::artifact(&fixture.repo, "target/sbom.json", "sbom").unwrap();
    let finding = findings
        .iter()
        .find(|f| f["id"] == "CVE-2025-48924")
        .unwrap();
    assert_eq!(finding["fixed_version"], "3.18.0");
    let now = store::now_ms();
    let mut db = Store::open(&fixture.database).unwrap();
    db.register("orders", "main", fixture.repo.to_str().unwrap())
        .unwrap();
    db.begin("baseline", "orders", "main", now).unwrap();
    db.success(
        "baseline",
        "orders",
        "main",
        &base,
        &json!({"findings":findings}),
        &bom,
    )
    .unwrap();
    let mut proposal = action("org.apache.commons:commons-lang3");
    proposal["base_commit"] = json!(base);
    proposal["cve"] = json!("CVE-2025-48924");
    proposal["severity"] = json!("MEDIUM");
    proposal["installed_version"] = json!("3.12.0");
    proposal["target_version"] = json!("3.18.0");
    let mut queue = Queue::open(&fixture.database).unwrap();
    let (id, _) = queue
        .propose(&proposal, "integration-test-only", now)
        .unwrap();
    let batch = queue
        .approve(
            &[id],
            "integration-test-only",
            now,
            now + 600_000,
            false,
            now,
        )
        .unwrap();
    let report = run(
        &fixture.database,
        &tools_root,
        &fixture.root.join("executions"),
        &batch,
        true,
        1,
    )
    .unwrap();
    assert_eq!(report["status"], "completed", "{report}");
    assert_eq!(
        report["groups"][0]["status"], "verified_candidate",
        "{report}"
    );
    assert!(fs::read_to_string(fixture.repo.join("pom.xml"))
        .unwrap()
        .contains("3.12.0"));
    let after = String::from_utf8(
        git(
            &fixture.repo,
            &[],
            &[],
            vec!["rev-parse".into(), "main".into()],
            &fixture.root.join("after.log"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(after.trim(), base);
    assert_eq!(
        db.status(None, None, 86400).unwrap()["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.inventory().unwrap()["candidate_snapshots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(run(
        &fixture.database,
        &tools_root,
        &fixture.root.join("executions"),
        &batch,
        false,
        1
    )
    .is_err());
}
