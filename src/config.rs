//! Operator-owned factory configuration, not executable instructions from a repository.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, String>;
pub const HELP: &str = "Factory configuration:\n\
  upgrade-lab config validate [--file factory.yaml]\n\
  upgrade-lab config plan [--file factory.yaml]\n\
  upgrade-lab scan --config factory.yaml [--network]\n\
Validation does not start agents, resolve credentials, promote branches or contact integrations.\n";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Factory {
    pub api_version: String,
    pub name: String,
    pub storage: Storage,
    pub queue: Queue,
    pub sandbox: Sandbox,
    pub branches: Branches,
    pub approvals: Approvals,
    pub workflow: Workflow,
    pub defaults: Defaults,
    pub toolchains: BTreeMap<String, Toolchain>,
    pub models: BTreeMap<String, Model>,
    pub agents: BTreeMap<String, Agent>,
    pub gitlab: Integration,
    pub jira: Jira,
    pub repositories: Vec<Repository>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub root: PathBuf,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Queue {
    pub backend: String,
    pub scan_workers: usize,
    pub execution_workers: usize,
    pub per_repository: usize,
    pub transient_retries: usize,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub required: bool,
    pub backend: String,
    pub network: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Branches {
    pub development: String,
    pub staging: String,
    pub production: String,
    pub work_prefix: String,
    pub hotfix_stage_prefix: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Approvals {
    pub work: String,
    pub final_result: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workflow {
    pub request_sources: Vec<String>,
    pub feedback: String,
    pub normal: Normal,
    pub critical: Critical,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Normal {
    pub base: String,
    pub promote: Vec<String>,
    pub stage_gate: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Critical {
    pub base: String,
    pub stage_strategy: String,
    pub promote_to: String,
    pub backmerge_to: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub toolchain: String,
    pub agent: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub jdk: String,
    pub maven: String,
    pub trivy: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub provider: String,
    pub model_id: String,
    pub credential_ref: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub enabled: bool,
    pub runner: String,
    pub model: String,
    pub mode: String,
    pub limits: Limits,
    pub permissions: Permissions,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_attempts: usize,
    pub timeout_seconds: u64,
    pub max_cost_usd: f64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub writes: String,
    pub changes: Vec<String>,
    pub preserve_checks: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Integration {
    pub enabled: bool,
    pub url: String,
    pub credential_ref: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Jira {
    pub enabled: bool,
    pub url: String,
    pub project: String,
    pub credential_ref: Option<String>,
    pub ready_for_test_status: String,
    pub transition_gate: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub name: String,
    pub path: Option<PathBuf>,
    pub gitlab_project: Option<String>,
    pub scan_branches: Vec<String>,
    pub toolchain: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
}

fn nonempty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        && !matches!(value, "." | "..")
}
fn env_reference(value: Option<&str>, required: bool) -> Result<()> {
    match value {
        Some(name)
            if !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && !name.as_bytes()[0].is_ascii_digit() =>
        {
            Ok(())
        }
        None if !required => Ok(()),
        _ => Err(
            "credential_ref must be an environment-variable name, not a secret or interpolation"
                .into(),
        ),
    }
}
fn branch(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with(['-', '/', '.'])
        || value.ends_with(['/', '.'])
        || value.contains("..")
        || value.contains("//")
        || value.contains("@{")
        || value.ends_with(".lock")
        || value == "@"
        || value
            .split('/')
            .any(|p| p.starts_with('.') || p.ends_with(".lock"))
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "~^:?*[\\".contains(c))
    {
        return Err(format!("Invalid Git branch name: {value}"));
    }
    Ok(())
}
fn prefix(value: &str) -> Result<()> {
    if !value.ends_with('/') && !value.ends_with('-') {
        return Err("Branch prefixes must end with / or -".into());
    }
    branch(&format!("{value}example"))
}
fn base_url(value: &str) -> Result<()> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or("Integration URLs must use HTTPS")?;
    let authority = remainder.split('/').next().unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || value.contains(['?', '#'])
        || value.chars().any(char::is_whitespace)
    {
        return Err(
            "Use a base URL without embedded credentials, query strings or fragments".into(),
        );
    }
    Ok(())
}

impl Factory {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1_048_576 {
            return Err("Factory file exceeds 1 MiB".into());
        }
        // Parse through Value first so duplicate mapping keys are rejected, including registries.
        let value: serde_yaml_ng::Value =
            serde_yaml_ng::from_slice(bytes).map_err(|e| e.to_string())?;
        let config: Self = serde_yaml_ng::from_value(value).map_err(|e| e.to_string())?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.api_version != "upgrade-factory/v1" {
            return Err("Unsupported api_version; expected upgrade-factory/v1".into());
        }
        nonempty(&self.name, "name")?;
        if self.storage.root != Path::new(".lab") {
            return Err("v1 currently supports storage.root: .lab only".into());
        }
        if self.queue.backend != "sqlite"
            || self.queue.per_repository != 1
            || !(1..=8).contains(&self.queue.scan_workers)
            || !(1..=4).contains(&self.queue.execution_workers)
            || self.queue.transient_retries > 2
        {
            return Err("Queue requires sqlite, per_repository: 1, scan_workers 1..8, execution_workers 1..4 and transient_retries 0..2".into());
        }
        if !self.sandbox.required
            || self.sandbox.backend != "native"
            || self.sandbox.network != "explicit"
        {
            return Err("Sandbox must be required/native with explicit network permission".into());
        }
        for value in [
            &self.branches.development,
            &self.branches.staging,
            &self.branches.production,
        ] {
            branch(value)?;
        }
        if [
            &self.branches.development,
            &self.branches.staging,
            &self.branches.production,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .len()
            != 3
        {
            return Err("Development, staging and production branches must be distinct".into());
        }
        prefix(&self.branches.work_prefix)?;
        prefix(&self.branches.hotfix_stage_prefix)?;
        if self.approvals.work != "batch" || self.approvals.final_result != "manual" {
            return Err("Work approval must be batch and final_result must be manual".into());
        }
        if self.workflow.feedback != "developer_in_the_loop" {
            return Err("Unsupported feedback workflow".into());
        }
        if self.workflow.normal.base != self.branches.development
            || self.workflow.normal.promote
                != [
                    self.branches.development.clone(),
                    self.branches.staging.clone(),
                ]
            || self.workflow.normal.stage_gate != "all_selected_repositories_verified"
        {
            return Err(
                "Normal route must be development -> staging with a complete-batch stage gate"
                    .into(),
            );
        }
        if self.workflow.critical.base != self.branches.production
            || self.workflow.critical.stage_strategy != "isolated_from_production"
            || self.workflow.critical.promote_to != self.branches.production
            || self.workflow.critical.backmerge_to != self.branches.development
        {
            return Err("Critical route must start from production, use isolated staging, return to production and backmerge to development".into());
        }
        if self.workflow.request_sources.is_empty()
            || self.workflow.request_sources.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "cve" | "maintenance" | "platform_upgrade" | "developer_request"
                )
            })
        {
            return Err("Invalid request_sources".into());
        }
        if self.repositories.is_empty() {
            return Err("Configure at least one repository".into());
        }
        for (name, toolchain) in &self.toolchains {
            if !identifier(name) {
                return Err("Invalid toolchain ID".into());
            }
            for value in [&toolchain.jdk, &toolchain.maven, &toolchain.trivy] {
                nonempty(value, "tool version")?;
            }
        }
        for (name, model) in &self.models {
            if !identifier(name)
                || !matches!(
                    model.provider.as_str(),
                    "openai" | "anthropic" | "openai_compatible"
                )
            {
                return Err("Invalid model ID or provider".into());
            }
            nonempty(&model.model_id, "model_id")?;
            env_reference(model.credential_ref.as_deref(), false)?;
        }
        for (name, agent) in &self.agents {
            if !identifier(name)
                || !matches!(agent.runner.as_str(), "codex" | "pi")
                || !self.models.contains_key(&agent.model)
            {
                return Err("Invalid agent ID, runner or model reference".into());
            }
            if agent.mode != "autonomous_with_developer_feedback"
                || agent.permissions.writes != "candidate_only"
                || !agent.permissions.preserve_checks
            {
                return Err("Agents must use candidate-only writes, preserved checks and developer feedback".into());
            }
            if agent.limits.max_attempts == 0
                || agent.limits.max_attempts > 20
                || agent.limits.timeout_seconds == 0
                || agent.limits.timeout_seconds > 86_400
                || !agent.limits.max_cost_usd.is_finite()
                || agent.limits.max_cost_usd <= 0.0
            {
                return Err("Invalid agent attempt/time/cost budget".into());
            }
            if agent.permissions.changes.is_empty()
                || agent.permissions.changes.iter().any(|v| {
                    !matches!(
                        v.as_str(),
                        "dependency_versions" | "source" | "build_configuration" | "tests"
                    )
                })
            {
                return Err("Invalid agent change scope".into());
            }
        }
        if !self.toolchains.contains_key(&self.defaults.toolchain)
            || !self.agents.contains_key(&self.defaults.agent)
        {
            return Err("Unknown default toolchain or agent".into());
        }
        let mut names = BTreeSet::new();
        for repo in &self.repositories {
            if !identifier(&repo.name) || !names.insert(&repo.name) {
                return Err("Repository names must be valid and unique".into());
            }
            if repo.path.is_none()
                && repo
                    .gitlab_project
                    .as_deref()
                    .map_or(true, |s| s.trim().is_empty())
            {
                return Err(format!("{} needs path or gitlab_project", repo.name));
            }
            if let Some(path) = &repo.path {
                if path.as_os_str().is_empty()
                    || path.components().any(|c| matches!(c, Component::ParentDir))
                    || path == Path::new("/")
                {
                    return Err("Repository path must not be empty, / or contain ..".into());
                }
            }
            if repo.scan_branches.is_empty()
                || repo.scan_branches.iter().collect::<BTreeSet<_>>().len()
                    != repo.scan_branches.len()
            {
                return Err("Select unique scan_branches for each repository".into());
            }
            for value in &repo.scan_branches {
                branch(value)?;
            }
            self.selection(repo)?;
        }
        base_url(&self.gitlab.url)?;
        env_reference(self.gitlab.credential_ref.as_deref(), self.gitlab.enabled)?;
        base_url(&self.jira.url)?;
        env_reference(self.jira.credential_ref.as_deref(), self.jira.enabled)?;
        nonempty(&self.jira.project, "Jira project")?;
        nonempty(
            &self.jira.ready_for_test_status,
            "Jira ready_for_test_status",
        )?;
        if self.jira.transition_gate != "all_selected_repositories_staged" {
            return Err("Jira handover must wait for all selected repositories in stage".into());
        }
        Ok(())
    }
    fn selection<'a>(
        &'a self,
        repo: &'a Repository,
    ) -> Result<(&'a Toolchain, &'a Agent, &'a Model)> {
        let toolchain = self
            .toolchains
            .get(repo.toolchain.as_ref().unwrap_or(&self.defaults.toolchain))
            .ok_or_else(|| format!("Unknown toolchain for {}", repo.name))?;
        let agent = self
            .agents
            .get(repo.agent.as_ref().unwrap_or(&self.defaults.agent))
            .ok_or_else(|| format!("Unknown agent for {}", repo.name))?;
        let model = self
            .models
            .get(repo.model.as_ref().unwrap_or(&agent.model))
            .ok_or_else(|| format!("Unknown model for {}", repo.name))?;
        if agent.enabled {
            if model.model_id == "configure-before-enabling" {
                return Err("Select an explicit model_id before enabling an agent".into());
            }
            env_reference(
                model.credential_ref.as_deref(),
                model.provider != "openai_compatible",
            )?;
        }
        Ok((toolchain, agent, model))
    }
    pub fn scan_repositories(&self, base: &Path) -> Result<Vec<(String, String, PathBuf)>> {
        if self.branches.development != "develop" || self.branches.production != "main" {
            return Err("Current scan/decision runtime supports develop/main role names only; custom branch roles are declarative for now".into());
        }
        let mut result = vec![];
        for repo in &self.repositories {
            let (toolchain, _, _) = self.selection(repo)?;
            for (kind, version) in [
                ("jdk", &toolchain.jdk),
                ("maven", &toolchain.maven),
                ("trivy", &toolchain.trivy),
            ] {
                if crate::tools::pinned_version(kind)? != *version {
                    return Err(format!("{} selects an unsupported {kind} version; current scanner uses the pinned tool catalogue",repo.name));
                }
            }
            let path = base.join(
                repo.path
                    .as_ref()
                    .ok_or("Remote checkout is not implemented; scanning requires a local path")?,
            );
            let path = std::fs::canonicalize(&path).unwrap_or(path);
            for branch in &repo.scan_branches {
                if !matches!(branch.as_str(), "main" | "develop") {
                    return Err("Current scanner only supports main/develop; staging promotion remains planned".into());
                }
                result.push((repo.name.clone(), branch.clone(), path.clone()));
            }
        }
        Ok(result)
    }
    pub fn plan(&self, base: &Path) -> Result<Value> {
        let mut repositories = vec![];
        for repo in &self.repositories {
            let (toolchain, agent, model) = self.selection(repo)?;
            repositories.push(json!({"name":repo.name,"local_path":repo.path.as_ref().map(|p|base.join(p)),"gitlab_project":repo.gitlab_project,"scan_branches":repo.scan_branches,
                "toolchain_ref":repo.toolchain.as_ref().unwrap_or(&self.defaults.toolchain),"toolchain":toolchain,"agent":{"id":repo.agent.as_ref().unwrap_or(&self.defaults.agent),"model_ref":repo.model.as_ref().unwrap_or(&agent.model),"runner":agent.runner,"configured_enabled":agent.enabled,"runtime_available":false,"model":model,"limits":agent.limits,"permissions":agent.permissions},
                "normal_route":[format!("{}<branch_id>",self.branches.work_prefix),self.branches.development.clone(),self.branches.staging.clone()],
                "critical_route":{"base":self.branches.production,"isolated_stage":format!("{}<branch_id>",self.branches.hotfix_stage_prefix),"production":self.branches.production,"backmerge":self.branches.development}}));
        }
        Ok(
            json!({"api_version":self.api_version,"factory":self.name,"storage_root":base.join(&self.storage.root),"queue":self.queue,"sandbox":self.sandbox,"approvals":self.approvals,"workflow":self.workflow,"repositories":repositories,
            "integrations":{"gitlab":{"configured":self.gitlab,"runtime_available":false},"jira":{"configured":self.jira,"runtime_available":false}},
            "applied_by_current_scan":["repository selection","scan branches","scan_workers unless overridden on CLI","transient_retries unless overridden on CLI"],
            "declarative_not_executable_yet":["agent/model execution and budgets","non-CVE request intake","developer feedback and final approval","durable multi-step orchestration","branch promotion and isolated hotfix staging","GitLab delivery/backmerge","Jira transitions","execution_workers configuration"],
            "scan_settings_support":match self.scan_repositories(base){Ok(_)=>json!({"supported":true,"tools_installation_checked":false}),Err(error)=>json!({"supported":false,"reason":error})},
            "configuration_digest":crate::queue::digest(&json!({"definition":self,"base_directory":base})),
            "execution_started":false,"credentials_resolved":false}),
        )
    }
}

pub fn load(path: &Path) -> Result<(Factory, PathBuf)> {
    let path = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
    let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 1_048_576 {
        return Err("Factory configuration must be a regular file of at most 1 MiB".into());
    }
    let config = Factory::parse(&std::fs::read(&path).map_err(|e| e.to_string())?)?;
    Ok((
        config,
        path.parent()
            .ok_or("Configuration needs a parent directory")?
            .into(),
    ))
}

pub fn cli(args: &[String]) -> Result<i32> {
    let action = args.first().map(String::as_str).ok_or(HELP)?;
    if !matches!(action, "validate" | "plan" | "show") {
        return Err(HELP.into());
    }
    let path = match args {
        [_] => Path::new("factory.yaml"),
        [_, flag, path] if flag == "--file" => Path::new(path),
        _ => return Err(HELP.into()),
    };
    let (config, base) = load(path)?;
    if action == "validate" {
        println!(
            "Valid {} configuration: {} ({} repositories)",
            config.api_version,
            config.name,
            config.repositories.len()
        );
        println!("Schema valid does not mean every configured feature is executable. Use config plan for capability boundaries. No credentials resolved or work started.");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&config.plan(&base)?).map_err(|e| e.to_string())?
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests;
