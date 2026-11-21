//! Version-only executor. Approval claim is durable; original repositories stay read-only.
use crate::{
    queue::{self, Queue},
    sandbox::{self, Access, Job, Network},
    scan, store, tools,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

type Result<T> = std::result::Result<T, String>;
pub const HELP:&str="Factory (version-only executor, no push/MR/merge):\n\
  upgrade-lab factory run --batch FULL_ID [--network] [--workers 2]\n\
  upgrade-lab factory status\n\
Only approved upgrade actions without code changes are supported. Other actions require manual handling.\n";

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| format!("Missing {key}"))
}

fn validate_batch(connection: &Connection, id: &str, now: i64) -> Result<Value> {
    let payload: String = connection
        .query_row(
            "SELECT payload FROM approval_batches WHERE id=?",
            [id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let batch: Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
    if queue::digest(&batch) != id {
        return Err("Approval digest mismatch".into());
    }
    if batch["mandate_policy"] != "approved-actions-v1"
        || batch["tool_catalog_sha256"].as_str() != Some(tools::catalog_pin_digest()?.as_str())
    {
        return Err(
            "Approval policy/tool catalog changed or is unbound; obtain a new approval".into(),
        );
    }
    let revoked: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM batch_revocations WHERE batch_id=?)",
            [id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if revoked {
        return Err("Approval revoked".into());
    }
    if now
        < batch["not_before_ms"]
            .as_i64()
            .ok_or("Invalid approval start")?
        || now
            >= batch["not_after_ms"]
                .as_i64()
                .ok_or("Invalid approval end")?
    {
        return Err("Outside approved execution window".into());
    }
    let ids = batch["ids"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("Empty approval")?;
    for id in ids {
        let id = id.as_str().ok_or("Invalid proposal ID")?;
        let action = Queue::action(connection, id)?;
        Queue::evidence(connection, &action, now)?;
        if Queue::superseded(connection, id)? {
            return Err("Proposal superseded; new approval required".into());
        }
    }
    Ok(batch)
}

#[derive(Clone, Debug)]
struct Group {
    repo: String,
    branch: String,
    source: PathBuf,
    base: String,
    actions: Vec<Value>,
    baseline_findings: Vec<Value>,
    baseline_bom: Value,
}

fn claim(queue: &mut Queue, batch_id: &str, now: i64) -> Result<(String, Vec<Group>)> {
    let transaction = queue
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let batch = validate_batch(&transaction, batch_id, now)?;
    let claimed: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE batch_id=?)",
            [batch_id],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if claimed {
        return Err("Batch already claimed; no automatic replay or duplicate execution".into());
    }
    let mut groups = BTreeMap::<(String, String), Group>::new();
    let mut aliases = BTreeMap::new();
    for id in batch["ids"].as_array().unwrap() {
        let action = Queue::action(&transaction, id.as_str().unwrap())?;
        if action["kind"] != "upgrade" || action["code_changes"] != false {
            return Err("Manual handling required: this executor only supports version-only upgrades. No agent or alternate action will be chosen automatically.".into());
        }
        let repo = string(&action, "repo")?;
        let branch = string(&action, "branch")?;
        let path: String = transaction
            .query_row(
                "SELECT path FROM repositories WHERE repo=? AND branch=?",
                params![repo, branch],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if let Some(previous) = aliases.insert((path.clone(), branch.to_string()), repo.to_string())
        {
            if previous != repo {
                return Err("Repository aliases in the same batch are not supported".into());
            }
        }
        let key = (repo.to_string(), branch.to_string());
        if !groups.contains_key(&key) {
            let (report,bom):(String,String)=transaction.query_row("SELECT r.report,s.document FROM runs r JOIN sboms s ON s.run_id=r.id WHERE r.repo=? AND r.branch=? AND r.status='succeeded' ORDER BY r.started_at DESC,r.rowid DESC LIMIT 1",params![repo,branch],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
            let report: Value = serde_json::from_str(&report).map_err(|e| e.to_string())?;
            groups.insert(
                key.clone(),
                Group {
                    repo: repo.into(),
                    branch: branch.into(),
                    source: path.into(),
                    base: string(&action, "base_commit")?.into(),
                    actions: vec![],
                    baseline_findings: report["findings"]
                        .as_array()
                        .ok_or("Missing baseline findings")?
                        .clone(),
                    baseline_bom: serde_json::from_str(&bom).map_err(|e| e.to_string())?,
                },
            );
        }
        groups.get_mut(&key).unwrap().actions.push(action);
    }
    let token = queue::digest(&json!([
        batch_id,
        now,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
            .to_string()
    ]));
    let groups: Vec<_> = groups.into_values().collect();
    for path in groups
        .iter()
        .map(|g| g.source.display().to_string())
        .collect::<BTreeSet<_>>()
    {
        transaction
            .execute(
                "INSERT INTO execution_locks VALUES (?,?)",
                params![path, token],
            )
            .map_err(|_| format!("Repository is locked by another execution: {path}"))?;
    }
    transaction
        .execute(
            "INSERT INTO executions VALUES (?,?,?,'running',?)",
            params![
                token,
                batch_id,
                now,
                json!({"batch_id":batch_id,"status":"running"}).to_string()
            ],
        )
        .map_err(|e| e.to_string())?;
    Queue::audit(
        &transaction,
        now,
        "factory",
        "execution_claimed",
        &token,
        &json!({"batch_id":batch_id,"merge_authorized":false}),
    )?;
    transaction.commit().map_err(|e| e.to_string())?;
    Ok((token, groups))
}

fn gate(database: &Path, execution: &str, batch: &str, group: &Group) -> Result<()> {
    let queue = Queue::open(database)?;
    validate_batch(&queue.connection, batch, store::now_ms())?;
    let owner: Option<String> = queue
        .connection
        .query_row(
            "SELECT execution_id FROM execution_locks WHERE path=?",
            [group.source.display().to_string()],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if owner.as_deref() != Some(execution) {
        return Err("Execution no longer owns repository lock".into());
    }
    let status: String = queue
        .connection
        .query_row(
            "SELECT status FROM executions WHERE id=?",
            [execution],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if status != "running" {
        return Err("Execution is no longer running".into());
    }
    Ok(())
}

fn git(
    cwd: &Path,
    read: &[PathBuf],
    write: &[PathBuf],
    args: Vec<String>,
    log: &Path,
) -> Result<Vec<u8>> {
    let mut access = vec![Access::Read(cwd.into())];
    access.extend(read.iter().cloned().map(Access::Read));
    access.extend(write.iter().cloned().map(Access::Write));
    for path in [
        "/Library/Developer/CommandLineTools",
        "/Applications/Xcode.app",
    ] {
        if Path::new(path).exists() {
            access.push(Access::Read(path.into()));
        }
    }
    let mut arguments = [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "core.pager=cat",
    ]
    .map(String::from)
    .to_vec();
    arguments.extend(args);
    let result = sandbox::execute(&Job {
        program: "/usr/bin/git".into(),
        args: arguments,
        access,
        network: Network::Denied,
        timeout: Duration::from_secs(120),
        environment: vec![("GIT_CONFIG_NOSYSTEM".into(), "1".into())],
        workdir: Some(cwd.into()),
    })?;
    let mut bytes = result.stdout.clone();
    bytes.extend_from_slice(&result.stderr);
    fs::write(log, bytes).map_err(|e| e.to_string())?;
    if result.code != Some(0) || result.timed_out || result.truncated {
        return Err(format!(
            "Git failed, timed out or output was truncated; see {}",
            log.display()
        ));
    }
    Ok(result.stdout)
}

fn source_head(group: &Group, logs: &Path, label: &str) -> Result<()> {
    let source = fs::canonicalize(&group.source).map_err(|e| e.to_string())?;
    if source != group.source {
        return Err("Repository path changed since registration".into());
    }
    let bytes = git(
        &source,
        &[],
        &[],
        vec![
            "rev-parse".into(),
            "--verify".into(),
            format!("refs/heads/{}^{{commit}}", group.branch),
        ],
        &logs.join(format!("source-{label}.log")),
    )?;
    if String::from_utf8_lossy(&bytes).trim() != group.base {
        return Err("Actual Git target branch moved; rescan and obtain a new approval".into());
    }
    Ok(())
}

fn children<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Vec<roxmltree::Node<'a, 'input>> {
    node.children()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == name
                && n.tag_name().namespace() == Some("http://maven.apache.org/POM/4.0.0")
        })
        .collect()
}
fn element_text<'a, 'input: 'a>(node: roxmltree::Node<'a, 'input>, name: &str) -> Result<&'a str> {
    let values = children(node, name);
    if values.len() != 1 {
        return Err(format!("Expected one {name}"));
    }
    values[0]
        .text()
        .ok_or_else(|| format!("Missing {name} text"))
}

fn patch_pom(before: &str, actions: &[Value]) -> Result<String> {
    let document = roxmltree::Document::parse(before).map_err(|e| e.to_string())?;
    let root = document.root_element();
    if root.tag_name().name() != "project"
        || root.tag_name().namespace() != Some("http://maven.apache.org/POM/4.0.0")
    {
        return Err("Expected namespaced Maven project".into());
    }
    if !children(root, "modules").is_empty() {
        return Err("Manual handling required: multimodule upgrades not supported yet".into());
    }
    let mut requested = BTreeMap::new();
    for action in actions {
        let package = string(action, "package")?;
        let coordinates: Vec<_> = package.split(':').collect();
        if coordinates.len() != 2 {
            return Err("Expected Maven group:artifact".into());
        }
        let from = string(action, "installed_version")?;
        let to = string(action, "target_version")?;
        if from == to
            || !to
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-+".contains(&c))
        {
            return Err("Manual handling required: unsupported target version".into());
        }
        if let Some(previous) = requested.insert((coordinates[0], coordinates[1]), (from, to)) {
            if previous != (from, to) {
                return Err("Conflicting approved versions".into());
            }
        }
    }
    let containers = children(root, "dependencies");
    if containers.len() != 1 {
        return Err("Manual handling required: no single direct dependency block".into());
    }
    let mut edits = vec![];
    for ((group, artifact), (from, to)) in requested {
        let nodes: Vec<_> = children(containers[0], "dependency")
            .into_iter()
            .filter(|n| {
                element_text(*n, "groupId").ok() == Some(group)
                    && element_text(*n, "artifactId").ok() == Some(artifact)
            })
            .collect();
        if nodes.len() != 1 {
            return Err(format!(
                "Manual handling required: {group}:{artifact} is not a unique direct dependency"
            ));
        }
        if element_text(nodes[0], "type").ok() == Some("pom")
            || element_text(nodes[0], "scope").ok() == Some("import")
        {
            return Err("Manual handling required: parent/BOM upgrade".into());
        }
        let versions = children(nodes[0], "version");
        if versions.len() != 1 {
            return Err("Manual handling required: missing direct version".into());
        }
        let text: Vec<_> = versions[0].children().collect();
        if text.len() != 1
            || !text[0].is_text()
            || text[0].text() != Some(from)
            || &before[text[0].range()] != from
        {
            return Err(
                "Manual handling required: property, managed version or unexpected baseline".into(),
            );
        }
        edits.push((text[0].range(), to));
    }
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut result = before.to_string();
    for (range, value) in edits {
        result.replace_range(range, value);
    }
    Ok(result)
}

fn assert_diff(
    candidate: &Path,
    group: &Group,
    expected: &str,
    logs: &Path,
    label: &str,
) -> Result<()> {
    let head = git(
        candidate,
        &[],
        &[],
        vec!["rev-parse".into(), "HEAD".into()],
        &logs.join(format!("head-{label}.log")),
    )?;
    if String::from_utf8_lossy(&head).trim() != group.base {
        return Err("Candidate HEAD changed during verification".into());
    }
    let changes = git(
        candidate,
        &[],
        &[],
        vec![
            "diff".into(),
            "--no-ext-diff".into(),
            "--no-renames".into(),
            "--name-only".into(),
            "-z".into(),
            group.base.clone(),
            "--".into(),
        ],
        &logs.join(format!("diff-{label}.log")),
    )?;
    if changes != b"pom.xml\0" {
        return Err("Changes outside approved pom.xml scope".into());
    }
    let pom = candidate.join("pom.xml");
    if fs::symlink_metadata(&pom)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
        || fs::read_to_string(&pom).map_err(|e| e.to_string())? != expected
    {
        return Err("POM differs from exact approved version substitutions".into());
    }
    let modes = git(
        candidate,
        &[],
        &[],
        vec![
            "diff".into(),
            "--no-ext-diff".into(),
            "--summary".into(),
            group.base.clone(),
            "--".into(),
        ],
        &logs.join(format!("modes-{label}.log")),
    )?;
    if !modes.is_empty() {
        return Err("File mode/type changes outside mandate".into());
    }
    Ok(())
}

fn component_set(bom: &Value) -> Result<BTreeSet<(String, String)>> {
    fn walk(items: &[Value], values: &mut BTreeSet<(String, String)>) -> Result<()> {
        for item in items {
            let name = format!(
                "{}:{}",
                item["group"].as_str().unwrap_or(""),
                string(item, "name")?
            );
            values.insert((name, string(item, "version")?.into()));
            if let Some(nested) = item.get("components") {
                walk(nested.as_array().ok_or("Invalid nested SBOM")?, values)?;
            }
        }
        Ok(())
    }
    if bom["bomFormat"] != "CycloneDX" {
        return Err("Invalid CycloneDX BOM".into());
    }
    let mut values = BTreeSet::new();
    walk(
        bom["components"].as_array().ok_or("Missing components")?,
        &mut values,
    )?;
    Ok(values)
}

fn security(baseline: &[Value], candidate: &[Value], actions: &[Value]) -> Result<()> {
    for finding in candidate {
        if actions.iter().any(|a| a["package"] == finding["package"]) {
            return Err(format!(
                "Vulnerability remains on upgraded package: {}",
                finding["id"]
            ));
        }
        if matches!(finding["severity"].as_str(), Some("HIGH" | "CRITICAL"))
            && !baseline.iter().any(|old| {
                old["id"] == finding["id"]
                    && old["package"] == finding["package"]
                    && matches!(old["severity"].as_str(), Some("HIGH" | "CRITICAL"))
            })
        {
            return Err("New/escalated HIGH or CRITICAL finding".into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn tool(
    database: &Path,
    execution: &str,
    batch: &str,
    group: &Group,
    root: &Path,
    candidate: &Path,
    logs: &Path,
    kind: &str,
    args: Vec<String>,
    network: bool,
    label: &str,
) -> Result<()> {
    gate(database, execution, batch, group)?;
    source_head(group, logs, label)?;
    let version = tools::pinned_version(kind)?;
    let jdk = tools::pinned_version("jdk")?;
    let output = tools::run_tool(
        root,
        kind,
        &version,
        Some(&jdk),
        Some(candidate),
        network,
        args,
    )?;
    let mut text = output.stdout;
    text.extend_from_slice(&output.stderr);
    if output.truncated {
        text.extend_from_slice(b"\n[truncated]\n");
    }
    fs::write(logs.join(format!("{label}.log")), text).map_err(|e| e.to_string())?;
    if output.code != Some(0) || output.timed_out {
        return Err(format!("{label} failed; see {}", logs.display()));
    }
    Ok(())
}

fn run_group(
    database: &Path,
    root: &Path,
    run: &Path,
    execution: &str,
    batch: &str,
    group: &Group,
    network: bool,
) -> Value {
    let key = queue::digest(&json!([group.repo, group.branch]));
    let logs = run.join(&key[..16]);
    let mut report = json!({"repo":group.repo,"target_branch":group.branch,"base_commit":group.base,"status":"failed","logs":logs,"original_branch_modified":false,"mr_created":false});
    let result = (|| {
        fs::create_dir(&logs).map_err(|e| e.to_string())?;
        gate(database, execution, batch, group)?;
        source_head(group, &logs, "before")?;
        let candidate = logs.join("candidate");
        git(
            &logs,
            std::slice::from_ref(&group.source),
            std::slice::from_ref(&logs),
            vec![
                "clone".into(),
                "--no-hardlinks".into(),
                "--no-checkout".into(),
                "--".into(),
                group.source.display().to_string(),
                candidate.display().to_string(),
            ],
            &logs.join("clone.log"),
        )?;
        let branch = format!("upgrade/{}/{}", &batch[..16], &key[..12]);
        git(
            &candidate,
            &[],
            std::slice::from_ref(&candidate),
            vec![
                "checkout".into(),
                "-b".into(),
                branch.clone(),
                group.base.clone(),
            ],
            &logs.join("checkout.log"),
        )?;
        let pom = candidate.join("pom.xml");
        if fs::symlink_metadata(&pom)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("Manual handling required: symlink POM".into());
        }
        let expected = patch_pom(
            &fs::read_to_string(&pom).map_err(|e| e.to_string())?,
            &group.actions,
        )?;
        fs::write(&pom, &expected).map_err(|e| e.to_string())?;
        assert_diff(&candidate, group, &expected, &logs, "before")?;
        let offline = if network { "-ntp" } else { "-o" };
        tool(
            database,
            execution,
            batch,
            group,
            root,
            &candidate,
            &logs,
            "maven",
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
            "build",
        )?;
        assert_diff(&candidate, group, &expected, &logs, "after-build")?;
        tool(
            database,
            execution,
            batch,
            group,
            root,
            &candidate,
            &logs,
            "maven",
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
            "sbom",
        )?;
        let bom = scan::artifact(&candidate, "target/sbom.json", "sbom").map_err(|e| e.message)?;
        let components = component_set(&bom)?;
        for action in &group.actions {
            if !components.contains(&(
                string(action, "package")?.into(),
                string(action, "target_version")?.into(),
            )) {
                return Err("Resolved SBOM version differs from approved target".into());
            }
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
        tool(
            database,
            execution,
            batch,
            group,
            root,
            &candidate,
            &logs,
            "trivy",
            args,
            network,
            "security-scan",
        )?;
        let scan = scan::artifact(&candidate, "target/trivy.json", "vulnerability_scan")
            .map_err(|e| e.message)?;
        let findings = scan::findings(&scan).map_err(|e| e.message)?;
        if !scan["Results"]
            .as_array()
            .ok_or("Missing scan results")?
            .iter()
            .any(|r| r["Type"] == "jar")
        {
            return Err("No Java vulnerability analysis result".into());
        }
        security(&group.baseline_findings, &findings, &group.actions)?;
        let baseline = component_set(&group.baseline_bom)?;
        let added: Vec<_> = components.difference(&baseline).cloned().collect();
        let removed: Vec<_> = baseline.difference(&components).cloned().collect();
        let extra = added.iter().chain(&removed).any(|(package, _)| {
            !group
                .actions
                .iter()
                .any(|a| a["package"].as_str() == Some(package))
        });
        report["dependency_delta"] = json!({"added":added,"removed":removed});
        report["findings"] = json!(findings);
        gate(database, execution, batch, group)?;
        source_head(group, &logs, "before-commit")?;
        assert_diff(&candidate, group, &expected, &logs, "final")?;
        git(
            &candidate,
            &[],
            std::slice::from_ref(&candidate),
            vec!["add".into(), "--".into(), "pom.xml".into()],
            &logs.join("add.log"),
        )?;
        git(
            &candidate,
            &[],
            std::slice::from_ref(&candidate),
            vec![
                "-c".into(),
                "user.name=Upgrade Lab".into(),
                "-c".into(),
                "user.email=lab@example.invalid".into(),
                "commit".into(),
                "--no-verify".into(),
                "-m".into(),
                format!("Approved dependency batch {batch}"),
            ],
            &logs.join("commit.log"),
        )?;
        let commit = String::from_utf8(git(
            &candidate,
            &[],
            &[],
            vec!["rev-parse".into(), "HEAD".into()],
            &logs.join("commit-id.log"),
        )?)
        .map_err(|e| e.to_string())?
        .trim()
        .to_string();
        let paths = git(
            &candidate,
            &[],
            &[],
            vec![
                "diff".into(),
                "--no-ext-diff".into(),
                "--name-only".into(),
                "-z".into(),
                group.base.clone(),
                commit.clone(),
                "--".into(),
            ],
            &logs.join("committed-diff.log"),
        )?;
        if paths != b"pom.xml\0" {
            return Err("Committed changes exceed approval".into());
        }
        let committed = git(
            &candidate,
            &[],
            &[],
            vec!["show".into(), format!("{commit}:pom.xml")],
            &logs.join("committed-pom.log"),
        )?;
        if committed != expected.as_bytes() {
            return Err("Committed POM differs from exact approved substitutions".into());
        }
        let modes = git(
            &candidate,
            &[],
            &[],
            vec![
                "diff".into(),
                "--no-ext-diff".into(),
                "--summary".into(),
                group.base.clone(),
                commit.clone(),
                "--".into(),
            ],
            &logs.join("committed-modes.log"),
        )?;
        let dirty = git(
            &candidate,
            &[],
            &[],
            vec![
                "diff".into(),
                "--no-ext-diff".into(),
                "--name-only".into(),
                "-z".into(),
                "HEAD".into(),
                "--".into(),
            ],
            &logs.join("post-commit-dirty.log"),
        )?;
        if !modes.is_empty() || !dirty.is_empty() {
            return Err(
                "Candidate file modes or tracked files changed outside verification".into(),
            );
        }
        gate(database, execution, batch, group)?;
        source_head(group, &logs, "after")?;
        let queue = Queue::open(database)?;
        queue
            .connection
            .execute(
                "INSERT INTO candidate_sboms VALUES (?,?,?,?,?)",
                params![execution, group.repo, group.branch, commit, bom.to_string()],
            )
            .map_err(|e| e.to_string())?;
        report["status"] = json!(if extra {
            "awaiting_dependency_review"
        } else {
            "verified_candidate"
        });
        report["candidate_repository"] = json!(candidate);
        report["candidate_branch"] = json!(branch);
        report["candidate_commit"] = json!(commit);
        report["sbom"] = json!(pom.parent().unwrap().join("target/sbom.json"));
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        report["status"] = json!(if error.starts_with("Manual handling required") {
            "manual_required"
        } else {
            "failed"
        });
        report["error"] = json!(error);
    }
    if logs.is_dir() {
        if let Err(error) = fs::write(
            logs.join("report.json"),
            serde_json::to_vec_pretty(&report).unwrap_or_default(),
        ) {
            report["status"] = json!("failed");
            report["error"] = json!(format!("Cannot persist group report: {error}"));
        }
    }
    report
}

pub fn run(
    database: &Path,
    tools_root: &Path,
    run_root: &Path,
    batch: &str,
    network: bool,
    workers: usize,
) -> Result<Value> {
    sandbox::doctor()?;
    let mut queue = Queue::open(database)?;
    let (execution, groups) = claim(&mut queue, batch, store::now_ms())?;
    let run = run_root.join(&execution);
    // A failure after claim deliberately leaves a durable record/lock; never silently replay.
    fs::create_dir_all(&run)
        .map_err(|e| format!("Claim {execution} retained; cannot create run directory: {e}"))?;
    let tasks = std::sync::Mutex::new(std::collections::VecDeque::from(groups));
    let results = std::sync::Mutex::new(vec![]);
    std::thread::scope(|scope| {
        for _ in 0..workers.clamp(1, 4) {
            let tasks = &tasks;
            let results = &results;
            let run = &run;
            let execution = &execution;
            scope.spawn(move || loop {
                let group = tasks.lock().unwrap().pop_front();
                let Some(group) = group else {
                    break;
                };
                let report =
                    run_group(database, tools_root, run, execution, batch, &group, network);
                results.lock().unwrap().push(report);
            });
        }
    });
    let results = results.into_inner().map_err(|e| e.to_string())?;
    let failed = results.iter().any(|r| {
        !matches!(
            r["status"].as_str(),
            Some("verified_candidate" | "awaiting_dependency_review")
        )
    });
    let report = json!({"execution_id":execution,"batch_id":batch,"status":if failed{"completed_with_failures"}else{"completed"},"groups":results,"network_enabled":network,"tool_catalog":tools::catalog()?,"merge_authorized":false,"mr_created":false});
    fs::write(
        run.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let transaction = queue
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    transaction
        .execute(
            "UPDATE executions SET status=?,report=? WHERE id=? AND status='running'",
            params![
                if failed {
                    "completed_with_failures"
                } else {
                    "completed"
                },
                report.to_string(),
                execution
            ],
        )
        .map_err(|e| e.to_string())?;
    transaction
        .execute(
            "DELETE FROM execution_locks WHERE execution_id=?",
            [&execution],
        )
        .map_err(|e| e.to_string())?;
    Queue::audit(
        &transaction,
        store::now_ms(),
        "factory",
        "execution_finished",
        &execution,
        &report,
    )?;
    transaction.commit().map_err(|e| e.to_string())?;
    Ok(report)
}

pub fn cli(args: &[String]) -> Result<i32> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let database = cwd.join(".lab/scans.sqlite");
    if args == ["status"] {
        let queue = Queue::open(&database)?;
        let mut statement = queue
            .connection
            .prepare("SELECT id,batch_id,status,report FROM executions ORDER BY started_at")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut reports = vec![];
        for row in rows {
            let (id, batch, status, payload) = row.map_err(|e| e.to_string())?;
            reports.push(json!({"execution_id":id,"batch_id":batch,"status":status,"report":serde_json::from_str::<Value>(&payload).map_err(|e|e.to_string())?}));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&reports).map_err(|e| e.to_string())?
        );
        return Ok(0);
    }
    if args.first().map(String::as_str) != Some("run") {
        return Err(HELP.into());
    }
    let mut batch = None;
    let mut network = false;
    let mut workers = 2;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--batch" if batch.is_none() => {
                i += 1;
                batch = Some(args.get(i).ok_or("Missing batch ID")?.as_str());
            }
            "--network" if !network => network = true,
            "--workers" => {
                i += 1;
                workers = args
                    .get(i)
                    .ok_or("Missing workers")?
                    .parse::<usize>()
                    .map_err(|e| e.to_string())?;
            }
            _ => return Err(HELP.into()),
        }
        i += 1;
    }
    let report = run(
        &database,
        &cwd.join(".lab/tools"),
        &cwd.join(".lab/executions"),
        batch.ok_or("--batch required")?,
        network,
        workers,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(i32::from(report["status"] != "completed"))
}

#[cfg(test)]
mod tests;
