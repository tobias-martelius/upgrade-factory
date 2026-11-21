//! Conservative, explainable classification. Text matching is advisory, not proof.
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct Failure {
    pub stage: String,
    pub category: String,
    pub message: String,
    pub retryable: bool,
}

impl Failure {
    pub fn new(stage: &str, category: &str, message: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            category: category.into(),
            message: message.into(),
            retryable: false,
        }
    }
    pub fn json(&self) -> Value {
        json!({"stage": self.stage, "category": self.category,
               "message": self.message, "retryable": self.retryable})
    }
}

pub fn classify(stage: &str, message: &str, network_enabled: bool, timed_out: bool) -> Failure {
    let text = message.to_ascii_lowercase();
    let has = |patterns: &[&str]| patterns.iter().any(|p| text.contains(p));
    // Policy/auth failures always win over generic network errors in the same log.
    let category = if has(&[
        "sandbox self-test",
        "cannot start seatbelt",
        "sandbox_apply",
        "operation not permitted",
        "sandbox denial",
        "no supported native sandbox",
        "native sandbox not implemented",
    ]) {
        "sandbox"
    } else if has(&[
        "401 unauthorized",
        "403 forbidden",
        "status code: 401",
        "status code: 403",
        "authentication failed",
        "permission denied (publickey)",
    ]) {
        "authentication"
    } else if timed_out {
        "timeout"
    } else if has(&[
        "tool not installed",
        "no pinned tool catalog",
        "maven requires --jdk",
        "java_home environment variable",
    ]) {
        "tool_configuration"
    } else if has(&[
        "currently offline",
        "has not been downloaded",
        "--skip-db-update cannot",
        "db error: database does not exist",
        "first run cannot skip",
    ]) {
        "missing_cache"
    } else if has(&[
        "connection reset",
        "connection timed out",
        "temporary failure in name resolution",
        "remote host terminated the handshake",
        "status code: 429",
        "status code: 503",
        "503 service unavailable",
        "429 too many requests",
    ]) {
        "transient_network"
    } else if has(&[
        "no tests were executed",
        "there are test failures",
        "compilation failure",
        "failed to compile",
    ]) {
        "existing_build_failure"
    } else if stage == "build" {
        "build_failure"
    } else if stage == "sbom" {
        "sbom_failure"
    } else if stage == "vulnerability_scan" {
        "scanner_failure"
    } else if stage == "source" {
        "source_configuration"
    } else {
        "unknown"
    };
    Failure {
        stage: stage.into(),
        category: category.into(),
        message: message.into(),
        retryable: category == "transient_network" && network_enabled,
    }
}

/// Maximum two retries, with short exponential delays. No autonomous policy edits.
pub fn retry<T>(
    limit: usize,
    mut operation: impl FnMut(usize) -> Result<T, Failure>,
    mut wait: impl FnMut(u64),
) -> Result<T, Failure> {
    let limit = limit.min(2);
    for attempt in 0..=limit {
        match operation(attempt) {
            Ok(value) => return Ok(value),
            Err(error) if error.retryable && attempt < limit => wait(1 << attempt),
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_retry_for_auth_policy_build_or_offline() {
        for (message, expected) in [
            ("403 Forbidden connection reset", "authentication"),
            ("Operation not permitted connection timed out", "sandbox"),
            ("There are test failures", "existing_build_failure"),
        ] {
            let error = classify("build", message, true, false);
            assert_eq!(error.category, expected);
            assert!(!error.retryable);
        }
        assert!(!classify("sbom", "connection reset", false, false).retryable);
        assert!(!classify("build", "timeout", true, true).retryable);
    }
    #[test]
    fn bounded_retries_and_backoff() {
        let mut calls = 0;
        let mut delays = vec![];
        let result: Result<(), Failure> = retry(
            99,
            |_| {
                calls += 1;
                Err(classify(
                    "vulnerability_scan",
                    "503 Service Unavailable",
                    true,
                    false,
                ))
            },
            |seconds| delays.push(seconds),
        );
        assert!(result.is_err());
        assert_eq!(calls, 3);
        assert_eq!(delays, [1, 2]);
    }
    #[test]
    fn succeeds_on_second_attempt() {
        let value = retry(
            2,
            |n| {
                if n == 0 {
                    Err(classify("sbom", "connection reset", true, false))
                } else {
                    Ok(7)
                }
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(value, 7);
    }
}
