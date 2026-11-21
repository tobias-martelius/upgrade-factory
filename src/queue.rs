//! Immutable remediation proposals, batch decisions and evidence gates. No executor.
#[cfg(test)]
mod tests;
use crate::store::{self, Store};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

type Result<T> = std::result::Result<T, String>;
pub const HELP: &str = "Remediation decisions (no execution yet):\n\
  upgrade-lab queue refresh\n\
  upgrade-lab queue list [--json]\n\
  upgrade-lab queue alerts\n\
  upgrade-lab queue propose --file PATH --by NAME\n\
  upgrade-lab queue approve (--ids ID,ID | --all) --by NAME (--now | --from UNIX_SECONDS --until UNIX_SECONDS)\n\
  upgrade-lab queue revoke --batch ID --by NAME --reason TEXT\n\
  upgrade-lab queue ready\n\
  upgrade-lab queue audit\n\
Use full proposal IDs. --now is reserved for Critical; merge is never authorized.\n";

pub(crate) fn digest(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("Missing nonempty {key}"))
}

fn validate(action: &Value) -> Result<()> {
    let object = action.as_object().ok_or("Proposal must be an object")?;
    let allowed = [
        "repo",
        "branch",
        "base_commit",
        "cve",
        "package",
        "installed_version",
        "severity",
        "kind",
        "target_version",
        "evidence_fixed_version",
        "replacement",
        "code_changes",
        "mandate",
        "verification",
        "hotfix_exception",
        "supersedes",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("Unknown proposal field".into());
    }
    for key in [
        "repo",
        "branch",
        "base_commit",
        "cve",
        "package",
        "installed_version",
        "severity",
        "kind",
        "mandate",
    ] {
        text(action, key)?;
    }
    if !matches!(text(action, "branch")?, "main" | "develop") {
        return Err("Only main/develop targets supported".into());
    }
    let kind = text(action, "kind")?;
    if !matches!(
        kind,
        "upgrade" | "adapt_code" | "replace" | "remove" | "mitigate" | "risk_accept"
    ) {
        return Err("Unknown remediation kind".into());
    }
    if !matches!(
        text(action, "severity")?,
        "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"
    ) {
        return Err("Unsupported severity".into());
    }
    if action
        .get("evidence_fixed_version")
        .is_some_and(|v| !v.is_string())
        || (kind != "upgrade" && action["evidence_fixed_version"].as_str().is_none())
    {
        return Err("evidence_fixed_version must contain the scanner's fix-version string (or empty string)".into());
    }
    let code = action["code_changes"]
        .as_bool()
        .ok_or("code_changes must be boolean")?;
    let exception = action["hotfix_exception"]
        .as_bool()
        .ok_or("hotfix_exception must be boolean")?;
    let checks = action["verification"]
        .as_array()
        .ok_or("verification must be an array")?;
    if checks.is_empty()
        || checks
            .iter()
            .any(|v| v.as_str().map_or(true, |s| s.trim().is_empty()))
    {
        return Err("Specify verification requirements".into());
    }
    if kind == "upgrade" {
        let version = text(action, "target_version")?;
        if version == text(action, "installed_version")?
            || version.contains(|c: char| c.is_whitespace() || ",[]()<>$".contains(c))
        {
            return Err("Select one explicit new target version".into());
        }
    }
    if kind == "replace" {
        text(action, "replacement")?;
    }
    if matches!(kind, "adapt_code" | "replace" | "remove") && !code {
        return Err("Code-impacting action requires explicit code_changes=true".into());
    }
    if kind == "risk_accept" {
        return Err("Risk acceptance needs expiry/owner controls; not implemented yet".into());
    }
    if action["branch"] == "main"
        && (code || kind != "upgrade")
        && !(exception && action["severity"] == "CRITICAL")
    {
        return Err("main allows version-only upgrades; code/other changes require a Critical hotfix exception or a separately scanned develop proposal".into());
    }
    if exception && action["severity"] != "CRITICAL" {
        return Err("Hotfix exceptions are only for Critical".into());
    }
    if code && !checks.iter().any(|v| v == "code_review") {
        return Err("Code changes require code_review verification".into());
    }
    for required in ["build", "tests", "sbom", "security_scan"] {
        if !checks.iter().any(|v| v == required) {
            return Err(format!("Missing verification: {required}"));
        }
    }
    Ok(())
}

pub struct Queue {
    pub(crate) connection: Connection,
}
impl Queue {
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure the scan schema exists even before a first scan.
        Store::open(path)?;
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .busy_timeout(Duration::from_secs(30))
            .map_err(|e| e.to_string())?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS proposals (
            id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approval_batches (
            id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, actor TEXT NOT NULL,
            not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS approval_members (
            batch_id TEXT NOT NULL, proposal_id TEXT NOT NULL, PRIMARY KEY(batch_id,proposal_id));
            CREATE TABLE IF NOT EXISTS batch_revocations (
            batch_id TEXT PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY, batch_id TEXT NOT NULL UNIQUE, started_at INTEGER NOT NULL,
            status TEXT NOT NULL, report TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS execution_locks (
            path TEXT PRIMARY KEY, execution_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS candidate_sboms (
            execution_id TEXT NOT NULL, repo TEXT NOT NULL, branch TEXT NOT NULL,
            commit_sha TEXT NOT NULL, document TEXT NOT NULL,
            PRIMARY KEY(execution_id,repo,branch));
            CREATE TABLE IF NOT EXISTS critical_observations (
            id TEXT PRIMARY KEY, at INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decision_audit (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL,
            event TEXT NOT NULL, subject TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS proposal_no_update BEFORE UPDATE ON proposals BEGIN SELECT RAISE(ABORT,'immutable proposal'); END;
            CREATE TRIGGER IF NOT EXISTS proposal_no_delete BEFORE DELETE ON proposals BEGIN SELECT RAISE(ABORT,'immutable proposal'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON decision_audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON decision_audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;").map_err(|e|e.to_string())?;
        for table in [
            "approval_batches",
            "approval_members",
            "batch_revocations",
            "critical_observations",
        ] {
            for operation in ["UPDATE", "DELETE"] {
                connection.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS immutable_{table}_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'immutable decision record'); END;")).map_err(|e|e.to_string())?;
            }
        }
        Ok(Self { connection })
    }
    pub(crate) fn evidence(connection: &Connection, action: &Value, now: i64) -> Result<()> {
        let row=connection.query_row("SELECT status,started_at,commit_sha,report FROM runs WHERE repo=? AND branch=? ORDER BY started_at DESC,rowid DESC LIMIT 1",
            params![text(action,"repo")?,text(action,"branch")?],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,String>(3)?)))
            .optional().map_err(|e|e.to_string())?.ok_or("No scan evidence")?;
        if row.0 != "succeeded" || now.saturating_sub(row.1) > 86_400_000 || row.1 > now {
            return Err("Latest scan failed, is running, or is stale (24h)".into());
        }
        if row.2.as_deref() != action["base_commit"].as_str() {
            return Err("Scanned base commit changed; create and approve a new proposal".into());
        }
        let report: Value = serde_json::from_str(&row.3).map_err(|e| e.to_string())?;
        if !report["findings"]
            .as_array()
            .ok_or("Missing finding evidence")?
            .iter()
            .any(|f| {
                f["id"] == action["cve"]
                    && f["package"] == action["package"]
                    && f["version"] == action["installed_version"]
                    && f["severity"] == action["severity"]
                    && f["fixed_version"].as_str().unwrap_or("")
                        == action["evidence_fixed_version"]
                            .as_str()
                            .or_else(|| action["target_version"].as_str())
                            .unwrap_or("")
            })
        {
            return Err("Finding or severity no longer matches evidence".into());
        }
        Ok(())
    }
    pub(crate) fn action(connection: &Connection, id: &str) -> Result<Value> {
        let payload: String = connection
            .query_row("SELECT payload FROM proposals WHERE id=?", [id], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        if digest(&value) != id {
            return Err("Proposal digest mismatch".into());
        }
        validate(&value)?;
        Ok(value)
    }
    pub(crate) fn superseded(connection: &Connection, id: &str) -> Result<bool> {
        let mut statement = connection
            .prepare("SELECT payload FROM proposals")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let value: Value = serde_json::from_str(&row.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            if value["supersedes"].as_str() == Some(id) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(crate) fn audit(
        connection: &Connection,
        now: i64,
        actor: &str,
        event: &str,
        subject: &str,
        details: &Value,
    ) -> Result<()> {
        connection
            .execute(
                "INSERT INTO decision_audit(at,actor,event,subject,details) VALUES (?,?,?,?,?)",
                params![now, actor, event, subject, details.to_string()],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn propose(&mut self, action: &Value, actor: &str, now: i64) -> Result<(String, bool)> {
        if actor.trim().is_empty() {
            return Err("Actor required".into());
        }
        validate(action)?;
        let id = digest(action);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        Self::evidence(&transaction, action, now)?;
        if let Some(old) = action.get("supersedes") {
            let old = old.as_str().ok_or("supersedes must be an ID")?;
            let previous = Self::action(&transaction, old)?;
            for key in ["repo", "branch", "cve", "package"] {
                if previous[key] != action[key] {
                    return Err("Supersession must identify the same repo/branch/finding".into());
                }
            }
            if old == id {
                return Err("Cannot supersede self".into());
            }
        }
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO proposals VALUES (?,?,?)",
                params![id, now, action.to_string()],
            )
            .map_err(|e| e.to_string())?
            == 1;
        if inserted {
            Self::audit(&transaction, now, actor, "proposal_created", &id, action)?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        Ok((id, inserted))
    }
    fn alarm(&mut self, finding: &Value, now: i64) -> Result<bool> {
        let key = json!([
            finding["repo"],
            finding["branch"],
            finding["commit"],
            finding["id"],
            finding["package"],
            finding["version"],
            finding["severity"]
        ]);
        let id = digest(&key);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO critical_observations VALUES (?,?,?)",
                params![id, now, finding.to_string()],
            )
            .map_err(|e| e.to_string())?
            == 1;
        if inserted {
            Self::audit(&transaction, now, "scanner", "critical_alarm", &id, finding)?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(inserted)
    }
    pub fn approve(
        &mut self,
        ids: &[String],
        actor: &str,
        from: i64,
        until: i64,
        immediate: bool,
        now: i64,
    ) -> Result<String> {
        if ids.is_empty()
            || actor.trim().is_empty()
            || from >= until
            || until <= now
            || (!immediate && from < now)
            || (immediate && from != now)
        {
            return Err("Invalid approval identity or time window".into());
        }
        let mut ids = ids.to_vec();
        ids.sort();
        if ids.windows(2).any(|p| p[0] == p[1]) {
            return Err("Duplicate proposal IDs".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let mut conflicts = HashSet::new();
        let mut remediations = HashMap::new();
        for id in &ids {
            let action = Self::action(&transaction, id)?;
            Self::evidence(&transaction, &action, now)?;
            if Self::superseded(&transaction, id)? {
                return Err("Proposal has been superseded".into());
            }
            if immediate && action["severity"] != "CRITICAL" {
                return Err("Immediate approval is reserved for Critical; select a planned window for other findings".into());
            }
            let key = format!(
                "{}/{}/{}/{}",
                text(&action, "repo")?,
                text(&action, "branch")?,
                text(&action, "cve")?,
                text(&action, "package")?
            );
            if !conflicts.insert(key) {
                return Err("Select one alternative per finding".into());
            }
            let package_key = format!(
                "{}/{}/{}",
                text(&action, "repo")?,
                text(&action, "branch")?,
                text(&action, "package")?
            );
            let remediation = json!([
                action["kind"],
                action["target_version"],
                action["replacement"],
                action["code_changes"],
                action["mandate"],
                action["hotfix_exception"]
            ]);
            if let Some(previous) = remediations.insert(package_key, remediation.clone()) {
                if previous != remediation {
                    return Err("Conflicting actions for the same package".into());
                }
            }
            let mut statement=transaction.prepare("SELECT p.payload FROM approval_members m JOIN approval_batches b ON b.id=m.batch_id JOIN proposals p ON p.id=m.proposal_id LEFT JOIN batch_revocations r ON r.batch_id=b.id WHERE b.not_after>? AND r.batch_id IS NULL").map_err(|e|e.to_string())?;
            let active = statement
                .query_map([now], |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            for payload in active {
                let previous: Value = serde_json::from_str(&payload.map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                if ["repo", "branch", "package"]
                    .iter()
                    .all(|key| previous[key] == action[key])
                {
                    return Err("This package already has an unexpired approval; revoke it before changing action or schedule".into());
                }
            }
        }
        let batch = json!({"ids":ids,"actor":actor,"approved_at_ms":now,"not_before_ms":from,"not_after_ms":until,"mode":if immediate {"critical_immediate"}else{"planned"},"merge_authorized":false,"mandate_policy":"approved-actions-v1","tool_catalog_sha256":crate::tools::catalog_pin_digest()?});
        let id = digest(&batch);
        transaction
            .execute(
                "INSERT INTO approval_batches VALUES (?,?,?,?,?,?)",
                params![id, now, actor, from, until, batch.to_string()],
            )
            .map_err(|e| e.to_string())?;
        for proposal in &ids {
            transaction
                .execute(
                    "INSERT INTO approval_members VALUES (?,?)",
                    params![id, proposal],
                )
                .map_err(|e| e.to_string())?;
        }
        Self::audit(&transaction, now, actor, "batch_approved", &id, &batch)?;
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(id)
    }
    pub fn revoke(&mut self, id: &str, actor: &str, reason: &str, now: i64) -> Result<()> {
        if actor.trim().is_empty() || reason.trim().is_empty() {
            return Err("Actor and reason required".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM approval_batches WHERE id=?)",
                [id],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !exists {
            return Err("Unknown batch".into());
        }
        transaction
            .execute(
                "INSERT INTO batch_revocations VALUES (?,?,?,?)",
                params![id, now, actor, reason],
            )
            .map_err(|e| e.to_string())?;
        Self::audit(
            &transaction,
            now,
            actor,
            "batch_revoked",
            id,
            &json!({"reason":reason}),
        )?;
        transaction.commit().map_err(|e| e.to_string())
    }
    pub fn list(&self, now: i64) -> Result<Value> {
        let mut statement = self
            .connection
            .prepare("SELECT id,created_at FROM proposals ORDER BY created_at,id")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| e.to_string())?;
        let mut values = vec![];
        for row in rows {
            let (id, created) = row.map_err(|e| e.to_string())?;
            let action = Self::action(&self.connection, &id)?;
            let blocked = if Self::superseded(&self.connection, &id)? {
                Some("superseded".into())
            } else {
                Self::evidence(&self.connection, &action, now).err()
            };
            let active: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM approval_members m JOIN approval_batches b ON b.id=m.batch_id LEFT JOIN batch_revocations r ON r.batch_id=b.id WHERE m.proposal_id=? AND b.not_after>? AND r.batch_id IS NULL)",params![id,now],|r|r.get(0)).map_err(|e|e.to_string())?;
            let state = if blocked.is_some() {
                "blocked"
            } else if active {
                "approved"
            } else {
                "awaiting_decision"
            };
            values.push(json!({"id":id,"created_at_ms":created,"proposal":action,"state":state,"evidence_blocker":blocked}));
        }
        Ok(Value::Array(values))
    }
    pub fn ready(&self, now: i64) -> Result<Value> {
        let mut statement = self
            .connection
            .prepare("SELECT id,payload FROM approval_batches ORDER BY created_at,id")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        let mut result = vec![];
        for row in rows {
            let (id, payload) = row.map_err(|e| e.to_string())?;
            let batch: Value = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
            if digest(&batch) != id {
                return Err("Approval digest mismatch".into());
            }
            let revoked: bool = self
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM batch_revocations WHERE batch_id=?)",
                    [&id],
                    |r| r.get(0),
                )
                .map_err(|e| e.to_string())?;
            let mut blockers = vec![];
            if revoked {
                blockers.push("revoked".into());
            }
            if now
                < batch["not_before_ms"]
                    .as_i64()
                    .ok_or("Invalid approval start")?
            {
                blockers.push("scheduled_for_later".into());
            }
            if now
                >= batch["not_after_ms"]
                    .as_i64()
                    .ok_or("Invalid approval end")?
            {
                blockers.push("approval_expired".into());
            }
            for proposal in batch["ids"].as_array().ok_or("Invalid approval IDs")? {
                let proposal = proposal.as_str().ok_or("Invalid proposal ID")?;
                let action = Self::action(&self.connection, proposal)?;
                if Self::superseded(&self.connection, proposal)? {
                    blockers.push(format!("{proposal}: superseded"));
                }
                if let Err(error) = Self::evidence(&self.connection, &action, now) {
                    blockers.push(format!("{proposal}: {error}"));
                }
            }
            let execution: Option<(String, String)> = self
                .connection
                .query_row(
                    "SELECT id,status FROM executions WHERE batch_id=?",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if execution.is_some() {
                blockers.push("batch_already_claimed".into());
            }
            result.push(json!({"batch_id":id,"approval":batch,"eligible_by_scan_evidence":blockers.is_empty(),"blockers":blockers,"execution_started":execution.is_some(),"execution":execution}));
        }
        Ok(Value::Array(result))
    }
    pub fn audit_log(&self) -> Result<Value> {
        let mut statement = self
            .connection
            .prepare("SELECT seq,at,actor,event,subject,details FROM decision_audit ORDER BY seq")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut result = vec![];
        for row in rows {
            let r = row.map_err(|e| e.to_string())?;
            result.push(json!({"sequence":r.0,"at_ms":r.1,"actor":r.2,"event":r.3,"subject":r.4,"details":serde_json::from_str::<Value>(&r.5).map_err(|e|e.to_string())?}));
        }
        Ok(Value::Array(result))
    }
}

pub fn refresh(path: &Path) -> Result<usize> {
    let now = store::now_ms();
    let status = Store::open(path)?.status(None, None, 86400)?;
    let mut queue = Queue::open(path)?;
    let mut alarms = 0;
    for finding in status["findings"]
        .as_array()
        .ok_or("Invalid status findings")?
    {
        if finding["data_stale"] == true {
            continue;
        }
        if finding["severity"] == "CRITICAL" && queue.alarm(finding, now)? {
            alarms += 1;
            eprintln!(
                "CRITICAL ALARM: {}/{} {} — approval required before any fix",
                finding["repo"], finding["branch"], finding["id"]
            );
        }
        let fixed = finding["fixed_version"].as_str().unwrap_or("");
        // No guessing if the scanner offers several versions or no fix.
        if fixed.is_empty() || fixed.contains(|c: char| c.is_whitespace() || ",[]()<>$".contains(c))
        {
            continue;
        }
        let action = json!({"repo":finding["repo"],"branch":finding["branch"],"base_commit":finding["commit"],
            "cve":finding["id"],"package":finding["package"],"installed_version":finding["version"],"severity":finding["severity"],
            "kind":"upgrade","target_version":fixed,"code_changes":false,"hotfix_exception":false,
            "mandate":"Change only the selected dependency version. Stop if source, parent/BOM or unrelated changes are needed.",
            "verification":["build","tests","sbom","security_scan"]});
        queue.propose(&action, "scanner", now)?;
    }
    Ok(alarms)
}

pub fn cli(args: &[String]) -> Result<i32> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let path = cwd.join(".lab/scans.sqlite");
    let action = args.first().map(String::as_str).ok_or(HELP)?;
    let now = store::now_ms();
    let mut queue = Queue::open(&path)?;
    let mut options = HashMap::new();
    let mut flags = HashSet::new();
    let mut i = 1;
    while i < args.len() {
        let key = args[i].as_str();
        if !matches!(
            key,
            "--json"
                | "--all"
                | "--now"
                | "--file"
                | "--by"
                | "--ids"
                | "--from"
                | "--until"
                | "--batch"
                | "--reason"
        ) {
            return Err(HELP.into());
        }
        if !flags.insert(key) {
            return Err("Duplicate option".into());
        }
        if !matches!(key, "--json" | "--all" | "--now") {
            i += 1;
            options.insert(key, args.get(i).ok_or("Missing option value")?.as_str());
        }
        i += 1;
    }
    let opt = |key: &str| {
        options
            .get(key)
            .copied()
            .ok_or_else(|| format!("Missing {key}"))
    };
    let allowed = match action {
        "refresh" | "alerts" | "ready" | "audit" => vec![],
        "list" => vec!["--json"],
        "propose" => vec!["--file", "--by"],
        "approve" => vec!["--ids", "--all", "--by", "--now", "--from", "--until"],
        "revoke" => vec!["--batch", "--by", "--reason"],
        _ => return Err(HELP.into()),
    };
    if flags.iter().any(|key| !allowed.contains(key)) {
        return Err("Option is not valid for this action".into());
    }
    let result = match action {
        "refresh" => json!({"new_critical_alarms":refresh(&path)?}),
        "alerts" => {
            let status = Store::open(&path)?.status(None, None, 86400)?;
            json!({"critical_alerts":status["findings"].as_array().ok_or("Invalid findings")?.iter().filter(|f|f["severity"]=="CRITICAL").collect::<Vec<_>>()})
        }
        "list" => {
            let values = queue.list(now)?;
            if !flags.contains("--json") {
                for row in values.as_array().unwrap() {
                    println!(
                        "{}  {} {}/{} {} -> {} [{}]",
                        row["id"].as_str().unwrap_or("?"),
                        row["proposal"]["severity"].as_str().unwrap_or("?"),
                        row["proposal"]["repo"].as_str().unwrap_or("?"),
                        row["proposal"]["branch"].as_str().unwrap_or("?"),
                        row["proposal"]["cve"].as_str().unwrap_or("?"),
                        row["proposal"]["kind"].as_str().unwrap_or("?"),
                        row["evidence_blocker"]
                            .as_str()
                            .unwrap_or_else(|| row["state"].as_str().unwrap_or("unknown"))
                    );
                }
                return Ok(0);
            }
            values
        }
        "propose" => {
            let proposal: Value = serde_json::from_str(
                &std::fs::read_to_string(opt("--file")?).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let (id, created) = queue.propose(&proposal, opt("--by")?, now)?;
            json!({"proposal_id":id,"created":created})
        }
        "approve" => {
            if flags.contains("--all") == options.contains_key("--ids") {
                return Err("Choose exactly one of --all or --ids".into());
            }
            let ids: Vec<String> = if flags.contains("--all") {
                queue
                    .list(now)?
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|v| v["state"] == "awaiting_decision")
                    .filter_map(|v| v["id"].as_str().map(String::from))
                    .collect()
            } else {
                opt("--ids")?.split(',').map(String::from).collect()
            };
            let immediate = flags.contains("--now");
            if immediate && (options.contains_key("--from") || options.contains_key("--until")) {
                return Err("--now and planned window are mutually exclusive".into());
            }
            let seconds = |key| -> Result<i64> {
                opt(key)?
                    .parse::<i64>()
                    .map_err(|e| e.to_string())?
                    .checked_mul(1000)
                    .ok_or("Timestamp overflow".into())
            };
            let (from, until) = if immediate {
                (now, now + 3_600_000)
            } else {
                (seconds("--from")?, seconds("--until")?)
            };
            let id = queue.approve(&ids, opt("--by")?, from, until, immediate, now)?;
            json!({"batch_id":id,"execution_started":false})
        }
        "revoke" => {
            queue.revoke(opt("--batch")?, opt("--by")?, opt("--reason")?, now)?;
            json!({"revoked":opt("--batch")?})
        }
        "ready" => queue.ready(now)?,
        "audit" => queue.audit_log()?,
        _ => unreachable!(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?
    );
    Ok(0)
}
