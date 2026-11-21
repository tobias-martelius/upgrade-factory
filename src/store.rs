//! Central scan history. Failure never deletes/replaces the last successful findings.
use crate::failure::Failure;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, String>;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub struct Store {
    connection: Connection,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let connection = Connection::open(path).map_err(|e| e.to_string())?;
        connection
            .busy_timeout(Duration::from_secs(30))
            .map_err(|e| e.to_string())?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS repositories (
                repo TEXT NOT NULL, branch TEXT NOT NULL, path TEXT NOT NULL,
                PRIMARY KEY(repo, branch));
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, repo TEXT NOT NULL, branch TEXT NOT NULL,
                started_at INTEGER NOT NULL, finished_at INTEGER, status TEXT NOT NULL,
                commit_sha TEXT, report TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS runs_lookup ON runs(repo,branch,started_at);
            CREATE TABLE IF NOT EXISTS sboms (
                run_id TEXT PRIMARY KEY, repo TEXT NOT NULL, branch TEXT NOT NULL,
                commit_sha TEXT NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incidents (
                repo TEXT NOT NULL, branch TEXT NOT NULL, category TEXT NOT NULL,
                state TEXT NOT NULL, occurrences INTEGER NOT NULL, last_run TEXT NOT NULL,
                failure TEXT NOT NULL, PRIMARY KEY(repo,branch,category));",
            )
            .map_err(|e| e.to_string())?;
        Ok(Self { connection })
    }
    pub fn register(&self, repo: &str, branch: &str, path: &str) -> Result<()> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT path FROM repositories WHERE repo=? AND branch=?",
                params![repo, branch],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if existing.as_deref().is_some_and(|old| old != path) {
            return Err(format!(
                "{repo}/{branch} already identifies another path; use a new repository name"
            ));
        }
        self.connection
            .execute(
                "INSERT OR IGNORE INTO repositories VALUES (?,?,?)",
                params![repo, branch, path],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn begin(&self, id: &str, repo: &str, branch: &str, started: i64) -> Result<()> {
        self.connection.execute("INSERT INTO runs(id,repo,branch,started_at,status,report) VALUES (?,?,?,?,'running','{}')",
                                params![id, repo, branch, started]).map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn success(
        &mut self,
        id: &str,
        repo: &str,
        branch: &str,
        commit: &str,
        report: &Value,
        bom: &Value,
    ) -> Result<()> {
        let transaction = self.connection.transaction().map_err(|e| e.to_string())?;
        let changed = transaction.execute("UPDATE runs SET finished_at=?,status='succeeded',commit_sha=?,report=? WHERE id=? AND repo=? AND branch=? AND status='running'",
            params![now_ms(), commit, report.to_string(), id, repo, branch]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("Scan is not running or identity differs".into());
        }
        transaction
            .execute(
                "INSERT INTO sboms VALUES (?,?,?,?,?)",
                params![id, repo, branch, commit, bom.to_string()],
            )
            .map_err(|e| e.to_string())?;
        let latest: String = transaction.query_row("SELECT id FROM runs WHERE repo=? AND branch=? AND status!='running' ORDER BY started_at DESC,rowid DESC LIMIT 1",params![repo,branch],|r|r.get(0)).map_err(|e|e.to_string())?;
        if latest == id {
            transaction.execute("UPDATE incidents SET state='resolved' WHERE repo=? AND branch=? AND state='open'", params![repo,branch]).map_err(|e|e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())
    }
    pub fn failure(
        &mut self,
        id: &str,
        repo: &str,
        branch: &str,
        report: &Value,
        error: &Failure,
    ) -> Result<()> {
        let transaction = self.connection.transaction().map_err(|e| e.to_string())?;
        let changed = transaction.execute("UPDATE runs SET finished_at=?,status='failed',report=? WHERE id=? AND repo=? AND branch=? AND status='running'",
            params![now_ms(), report.to_string(), id, repo, branch]).map_err(|e| e.to_string())?;
        if changed != 1 {
            return Err("Scan is not running or identity differs".into());
        }
        let latest: String = transaction.query_row("SELECT id FROM runs WHERE repo=? AND branch=? AND status!='running' ORDER BY started_at DESC,rowid DESC LIMIT 1",params![repo,branch],|r|r.get(0)).map_err(|e|e.to_string())?;
        if latest == id {
            transaction.execute("INSERT INTO incidents VALUES (?,?,?,'open',1,?,?)
                ON CONFLICT(repo,branch,category) DO UPDATE SET state='open',occurrences=occurrences+1,last_run=excluded.last_run,failure=excluded.failure",
                params![repo, branch, error.category, id, error.json().to_string()]).map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())
    }
    fn latest(&self, repo: &str, branch: &str, success_only: bool) -> Result<Option<Value>> {
        let query = if success_only {
            "SELECT id,started_at,finished_at,status,commit_sha,report FROM runs WHERE repo=? AND branch=? AND status='succeeded' ORDER BY started_at DESC,rowid DESC LIMIT 1"
        } else {
            "SELECT id,started_at,finished_at,status,commit_sha,report FROM runs WHERE repo=? AND branch=? ORDER BY started_at DESC,rowid DESC LIMIT 1"
        };
        let row = self
            .connection
            .query_row(query, params![repo, branch], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .optional()
            .map_err(|e| e.to_string())?;
        row.map(|(id, started, finished, status, commit, report)| {
            let report: Value = serde_json::from_str(&report).map_err(|e| e.to_string())?;
            Ok(json!({"id": id,"started_at_ms": started,"finished_at_ms": finished,"status":status,"commit":commit,"report":report}))
        }).transpose()
    }
    pub fn status(
        &self,
        repo_filter: Option<&str>,
        cve_filter: Option<&str>,
        max_age: u64,
    ) -> Result<Value> {
        let mut statement = self
            .connection
            .prepare("SELECT repo,branch,path FROM repositories ORDER BY repo,branch")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut repositories = vec![];
        let mut findings = vec![];
        for row in rows {
            let (repo, branch, path) = row.map_err(|e| e.to_string())?;
            if repo_filter.is_some_and(|filter| filter != repo) {
                continue;
            }
            let latest = self.latest(&repo, &branch, false)?;
            let success = self.latest(&repo, &branch, true)?;
            let status = latest
                .as_ref()
                .and_then(|v| v["status"].as_str())
                .unwrap_or("never_scanned");
            let age = success
                .as_ref()
                .and_then(|v| v["started_at_ms"].as_i64())
                .map(|t| now_ms().saturating_sub(t).max(0) as u64 / 1000);
            let stale = status != "succeeded" || age.map_or(true, |age| age > max_age);
            let mut counts = if success.is_some() {
                json!({"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0})
            } else {
                Value::Null
            };
            if let Some(success) = &success {
                for finding in success["report"]["findings"]
                    .as_array()
                    .ok_or("Stored success is missing findings")?
                {
                    let severity = finding["severity"].as_str().unwrap_or("UNKNOWN");
                    let severity = if counts.get(severity).is_some() {
                        severity
                    } else {
                        "UNKNOWN"
                    };
                    counts[severity] = json!(counts[severity].as_u64().unwrap_or(0) + 1);
                    if cve_filter.map_or(true, |cve| finding["id"].as_str() == Some(cve)) {
                        let mut finding = finding.clone();
                        finding["repo"] = json!(repo);
                        finding["branch"] = json!(branch);
                        finding["commit"] = success["commit"].clone();
                        finding["data_stale"] = json!(stale);
                        findings.push(finding);
                    }
                }
            }
            repositories.push(
                json!({"repo":repo,"branch":branch,"path":path,"scan_status":status,
                "data_stale":stale,"age_seconds":age,"counts":counts,"latest_run":latest,
                "last_success":success}),
            );
        }
        let mut statement = self.connection.prepare("SELECT repo,branch,category,state,occurrences,last_run,failure FROM incidents WHERE state='open' ORDER BY repo,branch").map_err(|e| e.to_string())?;
        let incidents = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let incidents: Vec<_> = incidents.into_iter().filter(|r| repo_filter.map_or(true, |repo| repo == r.0)).map(|r| {
            Ok(json!({"repo":r.0,"branch":r.1,"category":r.2,"state":r.3,"occurrences":r.4,"last_run":r.5,
                      "failure":serde_json::from_str::<Value>(&r.6).map_err(|e| e.to_string())?}))
        }).collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"repositories":repositories,"findings":findings,"open_incidents":incidents,"max_age_seconds":max_age}),
        )
    }
    pub fn inventory(&self) -> Result<Value> {
        let mut statement = self
            .connection
            .prepare("SELECT run_id,repo,branch,commit_sha,document FROM sboms ORDER BY rowid")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let values: Vec<_> = rows
            .into_iter()
            .map(|r| {
                Ok(json!({"run_id":r.0,"repo":r.1,"branch":r.2,"commit":r.3,
            "sbom":serde_json::from_str::<Value>(&r.4).map_err(|e| e.to_string())?}))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut candidates = vec![];
        let exists:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='candidate_sboms')",[],|r|r.get(0)).map_err(|e|e.to_string())?;
        if exists {
            let mut statement=self.connection.prepare("SELECT c.execution_id,c.repo,c.branch,c.commit_sha,c.document,e.status,e.report FROM candidate_sboms c JOIN executions e ON e.id=c.execution_id ORDER BY e.started_at,c.repo,c.branch").map_err(|e|e.to_string())?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let r = row.map_err(|e| e.to_string())?;
                let report: Value = serde_json::from_str(&r.6).map_err(|e| e.to_string())?;
                let verification = report["groups"]
                    .as_array()
                    .and_then(|groups| {
                        groups
                            .iter()
                            .find(|g| g["repo"] == r.1 && g["target_branch"] == r.2)
                    })
                    .map(|g| g["status"].clone())
                    .unwrap_or(json!("pending"));
                candidates.push(json!({"role":"candidate","execution_id":r.0,"repo":r.1,"target_branch":r.2,"commit":r.3,"execution_status":r.5,"verification_status":verification,"sbom":serde_json::from_str::<Value>(&r.4).map_err(|e|e.to_string())?}));
            }
        }
        Ok(
            json!({"format":"upgrade-lab-inventory-v1","snapshots":values,"candidate_snapshots":candidates}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_preserves_findings_and_recovery_closes_incident() {
        let mut db = Store::open(Path::new(":memory:")).unwrap();
        db.register("orders", "main", "/test").unwrap();
        db.begin("ok", "orders", "main", now_ms()).unwrap();
        let result = json!({"findings":[{"id":"CVE-TEST","severity":"HIGH"}]});
        db.success(
            "ok",
            "orders",
            "main",
            "sha1",
            &result,
            &json!({"bomFormat":"CycloneDX"}),
        )
        .unwrap();
        db.begin("failed", "orders", "main", now_ms()).unwrap();
        let error = Failure::new("build", "existing_build_failure", "compile error");
        db.failure(
            "failed",
            "orders",
            "main",
            &json!({"failure":error.json()}),
            &error,
        )
        .unwrap();
        let status = db.status(None, None, 86400).unwrap();
        assert_eq!(status["repositories"][0]["scan_status"], "failed");
        assert_eq!(status["repositories"][0]["counts"]["HIGH"], 1);
        assert_eq!(status["findings"][0]["data_stale"], true);
        assert_eq!(status["open_incidents"].as_array().unwrap().len(), 1);
        db.begin("recovery", "orders", "main", now_ms()).unwrap();
        db.success(
            "recovery",
            "orders",
            "main",
            "sha2",
            &json!({"findings":[]}),
            &json!({"bomFormat":"CycloneDX"}),
        )
        .unwrap();
        let status = db.status(None, None, 86400).unwrap();
        assert_eq!(status["repositories"][0]["data_stale"], false);
        assert_eq!(status["repositories"][0]["counts"]["HIGH"], 0);
        assert_eq!(status["open_incidents"].as_array().unwrap().len(), 0);
        assert_eq!(
            db.inventory().unwrap()["snapshots"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn late_old_success_does_not_close_a_newer_failure() {
        let mut db = Store::open(Path::new(":memory:")).unwrap();
        db.register("orders", "main", "/test").unwrap();
        db.begin("old", "orders", "main", 1).unwrap();
        db.begin("new", "orders", "main", 2).unwrap();
        let failure = Failure::new("build", "build_failure", "error");
        db.failure("new", "orders", "main", &json!({}), &failure)
            .unwrap();
        db.success(
            "old",
            "orders",
            "main",
            "old-sha",
            &json!({"findings":[]}),
            &json!({}),
        )
        .unwrap();
        let status = db.status(None, None, 86400).unwrap();
        assert_eq!(status["repositories"][0]["scan_status"], "failed");
        assert_eq!(status["open_incidents"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn late_old_failure_does_not_reopen_a_recovered_incident() {
        let mut db = Store::open(Path::new(":memory:")).unwrap();
        db.register("orders", "main", "/test").unwrap();
        db.begin("old", "orders", "main", 1).unwrap();
        db.begin("new", "orders", "main", 2).unwrap();
        db.success(
            "new",
            "orders",
            "main",
            "new-sha",
            &json!({"findings":[]}),
            &json!({}),
        )
        .unwrap();
        db.failure(
            "old",
            "orders",
            "main",
            &json!({}),
            &Failure::new("build", "build_failure", "error"),
        )
        .unwrap();
        assert_eq!(
            db.status(None, None, 86400).unwrap()["open_incidents"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn never_scanned_and_failed_without_success_are_not_clean() {
        let mut db = Store::open(Path::new(":memory:")).unwrap();
        db.register("new", "main", "/test").unwrap();
        let status = db.status(None, None, 1).unwrap();
        assert!(status["repositories"][0]["counts"].is_null());
        db.begin("failure", "new", "main", now_ms()).unwrap();
        db.failure(
            "failure",
            "new",
            "main",
            &json!({}),
            &Failure::new("source", "configuration", "bad ref"),
        )
        .unwrap();
        assert!(db.status(None, None, 1).unwrap()["repositories"][0]["counts"].is_null());
    }
}
