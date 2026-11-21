use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static ID: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "upgrade-decisions-{}-{}-{}",
            std::process::id(),
            store::now_ms(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("test.sqlite");
        Self { root, path }
    }
    fn connections(&self, severity: &str, now: i64) -> (Store, Queue, Value) {
        let mut store = Store::open(&self.path).unwrap();
        store.register("orders", "main", "/fixture").unwrap();
        store.begin("initial", "orders", "main", now).unwrap();
        let finding = json!({"id":"CVE-TEST","package":"group:library","version":"1.0","severity":severity,"fixed_version":"1.1"});
        store
            .success(
                "initial",
                "orders",
                "main",
                "base1",
                &json!({"findings":[finding]}),
                &json!({"bomFormat":"CycloneDX"}),
            )
            .unwrap();
        let action = json!({"repo":"orders","branch":"main","base_commit":"base1","cve":"CVE-TEST","package":"group:library","installed_version":"1.0","severity":severity,"kind":"upgrade","target_version":"1.1","evidence_fixed_version":"1.1","code_changes":false,"hotfix_exception":false,"mandate":"Only update selected dependency version","verification":["build","tests","sbom","security_scan"]});
        (store, Queue::open(&self.path).unwrap(), action)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn planned_window_revocation_and_expiry_are_gates() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, action) = fixture.connections("HIGH", now);
    let (id, _) = queue.propose(&action, "operator", now).unwrap();
    assert!(queue
        .approve(
            std::slice::from_ref(&id),
            "operator",
            now,
            now + 60_000,
            true,
            now
        )
        .is_err());
    let batch = queue
        .approve(&[id], "operator", now + 10_000, now + 60_000, false, now)
        .unwrap();
    assert_eq!(
        queue.ready(now).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
    assert_eq!(
        queue.ready(now + 20_000).unwrap()[0]["eligible_by_scan_evidence"],
        true
    );
    assert_eq!(
        queue.ready(now + 60_000).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
    queue
        .revoke(&batch, "operator", "Changed maintenance plan", now + 21_000)
        .unwrap();
    assert_eq!(
        queue.ready(now + 22_000).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
}

#[test]
fn critical_is_immediate_only_after_explicit_approval() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, action) = fixture.connections("CRITICAL", now);
    let (id, created) = queue.propose(&action, "scanner", now).unwrap();
    assert!(created);
    assert!(queue.ready(now).unwrap().as_array().unwrap().is_empty());
    queue
        .approve(&[id], "operator", now, now + 60_000, true, now)
        .unwrap();
    let ready = queue.ready(now).unwrap();
    assert_eq!(ready[0]["eligible_by_scan_evidence"], true);
    assert_eq!(ready[0]["execution_started"], false);
    assert_eq!(ready[0]["approval"]["merge_authorized"], false);
}

#[test]
fn code_change_requires_explicit_hotfix_and_review_on_main() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, mut action) = fixture.connections("CRITICAL", now);
    action["code_changes"] = json!(true);
    assert!(queue.propose(&action, "operator", now).is_err());
    action["hotfix_exception"] = json!(true);
    assert!(queue.propose(&action, "operator", now).is_err());
    action["verification"]
        .as_array_mut()
        .unwrap()
        .push(json!("code_review"));
    assert!(queue.propose(&action, "operator", now).is_ok());
    action["severity"] = json!("HIGH");
    assert!(validate(&action).is_err());
}

#[test]
fn superseding_mandate_invalidates_previous_batch() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, mut action) = fixture.connections("CRITICAL", now);
    let (id, _) = queue.propose(&action, "scanner", now).unwrap();
    queue
        .approve(
            std::slice::from_ref(&id),
            "operator",
            now,
            now + 60_000,
            true,
            now,
        )
        .unwrap();
    action["supersedes"] = json!(id);
    action["mandate"] = json!("Replace library with explicit reviewed changes");
    action["kind"] = json!("replace");
    action["replacement"] = json!("group:alternative:2.0");
    action["code_changes"] = json!(true);
    action["hotfix_exception"] = json!(true);
    action["verification"]
        .as_array_mut()
        .unwrap()
        .push(json!("code_review"));
    queue.propose(&action, "operator", now + 1).unwrap();
    assert_eq!(
        queue.ready(now + 2).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
}

#[test]
fn failed_or_changed_scan_blocks_previously_approved_work() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (mut store, mut queue, action) = fixture.connections("CRITICAL", now);
    let (id, _) = queue.propose(&action, "scanner", now).unwrap();
    queue
        .approve(
            std::slice::from_ref(&id),
            "operator",
            now,
            now + 60_000,
            true,
            now,
        )
        .unwrap();
    store.begin("failed", "orders", "main", now + 1).unwrap();
    store
        .failure(
            "failed",
            "orders",
            "main",
            &json!({}),
            &crate::failure::Failure::new("build", "build_failure", "broken"),
        )
        .unwrap();
    assert_eq!(
        queue.ready(now + 2).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
    assert!(queue
        .approve(&[id], "operator", now + 2, now + 50_000, true, now + 2)
        .is_err());
    store.begin("changed", "orders", "main", now + 3).unwrap();
    store.success("changed","orders","main","base2",&json!({"findings":[{"id":"CVE-TEST","package":"group:library","version":"1.0","severity":"CRITICAL"}]}),&json!({})).unwrap();
    assert_eq!(
        queue.ready(now + 4).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
}

#[test]
fn conflicting_choices_are_atomic_and_audit_is_append_only() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, mut action) = fixture.connections("CRITICAL", now);
    let (first, _) = queue.propose(&action, "scanner", now).unwrap();
    action["target_version"] = json!("1.2");
    let (second, _) = queue.propose(&action, "operator", now).unwrap();
    assert!(queue
        .approve(
            &[first.clone(), second],
            "operator",
            now,
            now + 60_000,
            true,
            now
        )
        .is_err());
    assert!(queue.ready(now).unwrap().as_array().unwrap().is_empty());
    assert!(queue
        .connection
        .execute("UPDATE proposals SET payload='{}' WHERE id=?", [first])
        .is_err());
    assert!(queue
        .connection
        .execute("DELETE FROM decision_audit", [])
        .is_err());
    assert!(queue
        .audit_log()
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["event"] != "batch_approved"));
}

#[test]
fn critical_without_fix_still_alarms_and_refresh_is_idempotent() {
    let fixture = Fixture::new();
    let now = store::now_ms();
    let (mut store, _queue, _action) = fixture.connections("CRITICAL", now);
    store.begin("no-fix", "orders", "main", now + 1).unwrap();
    store.success("no-fix","orders","main","base1",&json!({"findings":[{"id":"CVE-TEST","package":"group:library","version":"1.0","severity":"CRITICAL","fixed_version":""}]}),&json!({})).unwrap();
    // Use a start time no later than refresh's clock.
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(refresh(&fixture.path).unwrap(), 1);
    assert_eq!(refresh(&fixture.path).unwrap(), 0);
    let queue = Queue::open(&fixture.path).unwrap();
    assert!(queue
        .list(store::now_ms())
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(queue.audit_log().unwrap()[0]["event"], "critical_alarm");
}

#[test]
fn new_fix_guidance_blocks_old_approval_even_on_same_commit() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (mut store, mut queue, action) = fixture.connections("CRITICAL", now);
    let (id, _) = queue.propose(&action, "scanner", now).unwrap();
    queue
        .approve(&[id], "operator", now, now + 60_000, true, now)
        .unwrap();
    store
        .begin("updated-advisory", "orders", "main", now + 1)
        .unwrap();
    store.success("updated-advisory","orders","main","base1",&json!({"findings":[{"id":"CVE-TEST","package":"group:library","version":"1.0","severity":"CRITICAL","fixed_version":"1.2"}]}),&json!({})).unwrap();
    assert_eq!(
        queue.ready(now + 2).unwrap()[0]["eligible_by_scan_evidence"],
        false
    );
}

#[test]
fn alternative_cannot_get_a_second_active_package_approval() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, mut action) = fixture.connections("CRITICAL", now);
    let (first, _) = queue.propose(&action, "scanner", now).unwrap();
    queue
        .approve(&[first], "operator", now, now + 60_000, true, now)
        .unwrap();
    action["target_version"] = json!("1.2");
    let (second, _) = queue.propose(&action, "operator", now + 1).unwrap();
    assert!(queue
        .approve(&[second], "operator", now + 2, now + 60_000, true, now + 2)
        .is_err());
    assert_eq!(queue.ready(now + 2).unwrap().as_array().unwrap().len(), 1);
}

#[test]
fn stale_evidence_and_unknown_fields_are_rejected() {
    let fixture = Fixture::new();
    let now = 1_000_000;
    let (_store, mut queue, mut action) = fixture.connections("HIGH", now);
    assert!(queue
        .propose(&action, "operator", now + 86_400_001)
        .is_err());
    action["merge_automatically"] = json!(true);
    assert!(queue.propose(&action, "operator", now).is_err());
}
