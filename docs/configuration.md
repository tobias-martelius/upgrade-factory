# Factory configuration

`factory.yaml` is the operator-owned definition of an UpgradeFactory installation.
It describes repositories, branch routes, job settings, toolchains, agent/model
profiles, approvals and integration targets in one versioned file.

**It is not a set of approvals.** Editing this file never grants permission to
change code, merge a branch or transition a Jira issue.

## Inspect before running

```sh
./target/release/upgrade-lab config validate --file factory.yaml
./target/release/upgrade-lab config plan --file factory.yaml
./target/release/upgrade-lab scan --config factory.yaml --network
```

`validate` checks the schema, references and policy constraints. `plan` resolves
defaults and per-repository selections and shows the effective configuration and
capability boundaries. Both are offline operations: they do not contact model
providers, resolve credentials, clone repositories or start work.

The example defines 20 local repositories, each scanning `develop` and `main`:
40 branch scans. Create the fixtures with `repos init-examples` and install the
pinned tools with `tools bootstrap` first. A network-enabled `smoke` run populates
the dependency and vulnerability caches for subsequent offline scans.

YAML paths are relative to the factory file's directory. When scanning a factory
file, that directory becomes the application's data/tool-cache root. Run other
commands there too so they use the same `.lab` database. Schema v1 currently
requires `storage.root: .lab`.

The legacy repository JSON format is still accepted by `scan --config`; its
paths remain relative to the caller's working directory.

## What is active today?

| Configuration | Current behaviour |
|---|---|
| `repositories[].path` and `scan_branches` | Used by the local scanner; currently `main`/`develop` only. |
| `queue.scan_workers` | Scanner concurrency, unless `--workers` overrides it. |
| `queue.transient_retries` | Bounded transient network retries, unless `--retries` overrides it. |
| `toolchains` | References are validated; selected scan versions must match the built-in pinned catalogue. No custom toolchain is silently substituted. |
| Sandbox and approval requirements | Validated against conservative policy: required native sandbox, explicit networking, batch work approval and manual final approval. The new final-approval workflow itself is not implemented. |
| Agent/model profiles and permissions | Declarative only. No model or agent runner is started. |
| Queue execution settings, repository locks and durable promotion steps | The target orchestration contract. Existing runtime locks/claims remain separate; this file does not configure a durable multi-step job queue yet. |
| Branch promotion, GitLab and Jira | Declarative only; no API calls, remote checkout, promotion, backmerge or issue transitions. |

`factory run`, `queue` and `tools bootstrap` do not yet consume this file. The
existing version-only executor still uses its own approved batch and pinned
catalogue. Do not interpret a schema-valid configuration, or `enabled: true`, as
proof that an integration exists. `config plan` explicitly reports
`runtime_available: false` for agents and integrations.

## Configuration sections

| Section | Responsibility |
|---|---|
| `api_version`, `name` | Configuration format and factory identity. v1 is `upgrade-factory/v1`. |
| `storage` | Application state, evidence and cache location. |
| `queue` | SQLite backend, scan/execution concurrency, per-repository serialisation policy and transient retries. |
| `sandbox` | Required native isolation; networking needs an explicit operator flag. |
| `branches` | Development, staging and production refs, work-branch prefix and isolated hotfix-stage prefix. |
| `approvals` | Batch authorisation of work and separate manual approval of finished changes. |
| `workflow` | CVE and general-upgrade intake, developer feedback, normal promotion and Critical handling. |
| `defaults` | Default toolchain and agent profile. |
| `toolchains` | Named JDK/Maven/Trivy version selections. |
| `models` | Provider, model ID and an optional credential reference. |
| `agents` | Runner, model selection, execution mode, budgets and permitted changes. |
| `gitlab` | Future GitLab base URL and control-plane credential reference. |
| `jira` | Future project, ready-for-test status and complete-batch handover gate. |
| `repositories` | Repository identity, local source or future GitLab project, scan branches and overrides. |

Unknown fields and duplicate YAML mapping keys are rejected, including duplicate
model/agent IDs. Configuration files are limited to 1 MiB. References must resolve,
repository names must be unique, and invalid branch names are rejected. There are
no shell hooks, automatic includes or environment-variable interpolation.

## Defaults and per-repository overrides

A repository inherits `defaults.toolchain` and `defaults.agent`. Its model comes
from the selected agent unless `repositories[].model` overrides that choice.
The sample uses the default `codex` profile for most repositories and a `pi`
profile/model override for `payment-service`.

Agent profiles contain:

- A runner (`codex` or `pi`) and a named model profile.
- Autonomous execution with developer feedback inside the working loop, before
  final approval. Developer decisions need not wait until after approval of the
  finished result.
- Limits on attempts, elapsed time and model cost.
- Writes limited to the candidate, permitted categories of changes and mandatory
  preservation of tests/security checks.

These are requirements for the future coordinator to enforce, not enforcement
provided by the YAML parser. Current agents are disabled. Replace
`configure-before-enabling` with your chosen model ID before enabling a profile.
Validation does not confirm that the provider offers that ID or that credentials
work. Enabling a profile still does not provide a runtime in this version.

## Branch routes and factory orchestration

The intended normal route is:

`upgrade/<branch_id>` → `develop` → `stage` → Jira `ready-for-at-test` → the ordinary test/release process → `main`.

After final approval, the factory should process one job per repository/step:
create/update MR, wait for checks, merge to `develop`, promote to `stage` and record
the outcome. Completed steps must not be repeated. Failed steps remain in the
queue for bounded retry, developer/agent decisions or manual handling. The
operator manages the batch centrally rather than logging into every repository.

The agent may make approved code changes for CVEs **or general upgrade requests**.
The configured request sources include maintenance, platform upgrades and developer
requests. Those non-CVE intake paths are not implemented yet; current proposals
still come from CVE evidence.

Developer feedback belongs inside execution: an agent can work autonomously,
receive a developer's decisions or edits, and iterate until verification succeeds
within budget. The finished revision then receives manual final approval. A
materially different scope requires a new work decision; ordinary in-scope
iterations do not require a new approval for each tool call.

Critical fixes start from `main`, use an isolated main-based staging ref such as
`stage/hotfix-<branch_id>`, then proceed to production and backmerge to `develop`.
Do not merge an unrelated shared `stage` history into production merely to ship a
small patch. The patch can include code changes only within its explicit mandate.

The Jira transition waits for **all selected repositories to be staged**. Its
configured status name is not a hard-coded transition ID. A future adapter must
check the project's allowed transitions and the stage pipeline/deployment evidence
before moving the corresponding issues and triggering the normal acceptance-test
workflow. GitLab/Jira state changes must be idempotent and tracked as factory jobs.

These routes are validated declarations today, not implemented automation. The
factory orchestrates Git and the integrations; Git is not the batch coordinator.

## Secrets and configuration ownership

Use references such as:

```yaml
models:
  primary:
    provider: openai
    model_id: configure-before-enabling
    credential_ref: OPENAI_API_KEY
```

`credential_ref` is an environment-variable **name**, not its value. Literal API
keys, token fields and `${...}` interpolation are not supported. Integration URLs
must use HTTPS and must not embed credentials or token query strings. Do not put
secrets in any free-text field, URL, repository file or model identifier.

The parser does not read these environment variables. The future trusted model
and integration gateways must resolve them without exposing them to build/agent
jobs or plan output. Model data-sharing policy still needs implementation before
sending repository content to an external provider.

Treat `factory.yaml` as operator-controlled policy. Do not automatically load or
trust a factory definition from a repository being upgraded, and do not let an
agent edit the trusted factory file or approval history.

`config plan` includes a digest of the validated definition and its base directory.
Binding that effective configuration to orchestration jobs and approvals is still
future work; existing approvals are not silently rebound by editing this file.
