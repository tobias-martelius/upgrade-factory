//! Native process sandbox. macOS first; unsupported backends fail closed.
//! This is our own minimal policy, not a copy of Codex's full implementation.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Network {
    Denied,
    Outbound,
}

#[derive(Clone, Debug)]
pub enum Access {
    Read(PathBuf),
    Write(PathBuf),
    Protected(PathBuf),
}

pub struct Job {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub access: Vec<Access>,
    pub network: Network,
    pub timeout: Duration,
    pub environment: Vec<(String, String)>,
    pub workdir: Option<PathBuf>,
}

pub struct Output {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

pub fn backend() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Seatbelt"
    } else {
        "unsupported (Linux backend pending)"
    }
}

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, String> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "upgrade-lab-{}-{epoch}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .map_err(|e| format!("Cannot create private scratch directory: {e}"))?;
        match fs::canonicalize(&path) {
            Ok(path) => Ok(Self(path)),
            Err(error) => {
                let _ = fs::remove_dir(&path);
                Err(error.to_string())
            }
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn quoted(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or("Non-UTF-8 sandbox paths are unsupported")?;
    if text.chars().any(char::is_control) {
        return Err("Control characters in sandbox paths are forbidden".into());
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn path_rule(operation: &str, path: &Path) -> Result<String, String> {
    let canonical =
        fs::canonicalize(path).map_err(|e| format!("Cannot resolve {}: {e}", path.display()))?;
    if canonical.parent().is_none() {
        return Err("Granting access to the entire filesystem is forbidden".into());
    }
    let matcher = if canonical.is_dir() {
        "subpath"
    } else {
        "literal"
    };
    Ok(format!(
        "(allow {operation} ({matcher} {}))\n",
        quoted(&canonical)?
    ))
}

fn profile(job: &Job, scratch: &Path, executable: &Path) -> Result<String, String> {
    let mut value = String::from(
        "(version 1)\n(deny default)\n\
        (allow process-exec)\n(allow process-fork)\n\
        (allow signal (target same-sandbox))\n\
        (allow process-info* (target same-sandbox))\n\
        (allow file-read-metadata)\n(allow sysctl-read)\n\
        (allow file-read* (subpath \"/System\") (subpath \"/usr/lib\")\n\
          (subpath \"/usr/share\") (subpath \"/bin\") (subpath \"/usr/bin\")\n\
          (subpath \"/Library/Apple\") (subpath \"/private/var/db/dyld\")\n\
          (subpath \"/private/var/db/timezone\")\n\
          (literal \"/private/etc/localtime\")\n\
          (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\"))\n\
        (allow file-write* (literal \"/dev/null\"))\n\
        (allow mach-lookup (global-name \"com.apple.system.logger\")\n\
          (global-name \"com.apple.logd\"))\n",
    );
    // dyld needs to open the root directory itself (not its descendants).
    value.push_str("(allow file-read-data (literal \"/\"))\n");
    value.push_str("(allow file-map-executable (subpath \"/System\") (subpath \"/usr/lib\") (subpath \"/bin\") (subpath \"/usr/bin\") (subpath \"/Library/Apple\"))\n");
    value.push_str("(allow system-mac-syscall (mac-policy-name \"vnguard\"))\n(allow system-mac-syscall (require-all (mac-policy-name \"Sandbox\") (mac-syscall-number 67)))\n");
    value.push_str("(allow mach-lookup (global-name \"com.apple.secinitd\") (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n");
    value.push_str(&path_rule(
        "file-read* file-write* file-map-executable",
        scratch,
    )?);
    value.push_str(&path_rule("file-read* file-map-executable", executable)?);
    for access in &job.access {
        let (path, operations) = match access {
            Access::Read(path) | Access::Protected(path) => {
                (path, "file-read* file-map-executable")
            }
            Access::Write(path) => (path, "file-read* file-write* file-map-executable"),
        };
        value.push_str(&path_rule(operations, path)?);
    }
    if job.network == Network::Outbound {
        value.push_str(
            "(allow network-outbound)\n\
            (allow mach-lookup (global-name \"com.apple.mDNSResponder\")\n\
              (global-name \"com.apple.trustd.agent\"))\n\
            (allow file-read* (literal \"/private/etc/resolv.conf\")\n\
              (literal \"/private/etc/hosts\") (literal \"/private/etc/services\")\n\
              (subpath \"/private/var/run/resolv.conf\"))\n",
        );
    }
    for access in &job.access {
        if let Access::Protected(path) = access {
            value.push_str(&path_rule("file-write*", path)?.replacen("(allow", "(deny", 1));
            let canonical = fs::canonicalize(path).map_err(|e| e.to_string())?;
            for ancestor in canonical.ancestors().skip(1) {
                value.push_str(&format!(
                    "(deny file-write-unlink (literal {}))\n",
                    quoted(ancestor)?
                ));
            }
        }
    }
    // macOS fcntl extent operations can mutate files through read-only descriptors.
    value.push_str("(deny system-fcntl (fcntl-command 80 110))\n");
    value.push_str("(deny mach-lookup (xpc-service-name-prefix \"\"))\n");
    Ok(value)
}

fn read_log(file: &mut File) -> Result<(Vec<u8>, bool), String> {
    const LIMIT: u64 = 65_536;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let truncated = bytes.len() as u64 > LIMIT;
    bytes.truncate(LIMIT as usize);
    Ok((bytes, truncated))
}

#[cfg(unix)]
fn terminate_group(pid: u32) {
    // The child was spawned into a new process group. Never target our own group.
    extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if let Ok(pid) = i32::try_from(pid) {
        unsafe {
            kill(-pid, 9);
        }
    }
}

pub fn execute(job: &Job) -> Result<Output, String> {
    if !cfg!(target_os = "macos") {
        return Err(
            "No supported native sandbox on this OS yet; refusing unsandboxed execution".into(),
        );
    }
    if !job.program.is_absolute() || job.timeout.is_zero() {
        return Err("Program must be absolute and timeout must be positive".into());
    }
    let executable = fs::canonicalize(&job.program).map_err(|e| e.to_string())?;
    if !executable.is_file() {
        return Err("Program must be a regular file".into());
    }
    let scratch = Scratch::new()?;
    let policy = profile(job, &scratch.0, &executable)?;
    let policy_file = scratch.0.join("policy.sb");
    fs::write(&policy_file, policy).map_err(|e| e.to_string())?;
    let mut stdout = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(scratch.0.join("stdout.log"))
        .map_err(|e| e.to_string())?;
    let mut stderr = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(scratch.0.join("stderr.log"))
        .map_err(|e| e.to_string())?;
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-f"])
        .arg(&policy_file)
        .arg("--")
        .arg(executable)
        .args(&job.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &scratch.0)
        .env("TMPDIR", &scratch.0)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir(match &job.workdir {
            Some(path) => fs::canonicalize(path).map_err(|e| e.to_string())?,
            None => scratch.0.clone(),
        })
        .stdin(Stdio::null())
        .stdout(stdout.try_clone().map_err(|e| e.to_string())?)
        .stderr(stderr.try_clone().map_err(|e| e.to_string())?);
    for (key, value) in &job.environment {
        if !matches!(
            key.as_str(),
            "JAVA_HOME" | "MAVEN_USER_HOME" | "TRIVY_CACHE_DIR" | "PATH" | "GIT_CONFIG_NOSYSTEM"
        ) {
            return Err(format!("Environment override is not permitted: {key}"));
        }
        command.env(key, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot start Seatbelt; no fallback: {e}"))?;
    let start = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if start.elapsed() < job.timeout => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Ok(None) => {
                #[cfg(unix)]
                terminate_group(child.id());
                let _ = child.kill();
                break (child.wait().map_err(|e| e.to_string())?, true);
            }
            Err(error) => {
                #[cfg(unix)]
                terminate_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    };
    #[cfg(unix)]
    terminate_group(child.id());
    let (stdout, a) = read_log(&mut stdout)?;
    let (stderr, b) = read_log(&mut stderr)?;
    Ok(Output {
        code: status.code(),
        timed_out,
        stdout,
        stderr,
        truncated: a || b,
    })
}

pub fn doctor() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Native sandbox not implemented for this OS; no unsandboxed fallback".into());
    }
    let fixture = Scratch::new()?;
    let read_only = fixture.0.join("readonly");
    let writable = fixture.0.join("writable");
    let denied = fixture.0.join("denied");
    for path in [&read_only, &writable, &denied] {
        fs::create_dir(path).map_err(|e| e.to_string())?;
    }
    fs::write(read_only.join("input"), "fixture").map_err(|e| e.to_string())?;
    fs::write(denied.join("secret"), "not-a-real-secret").map_err(|e| e.to_string())?;
    let script = r#"
set -eu
[ "$(/bin/cat "$1/input")" = fixture ]
printf allowed > "$2/output"
if /bin/cat "$3/secret" >/dev/null 2>&1; then exit 41; fi
if (printf denied > "$1/output") 2>/dev/null; then exit 42; fi
if (printf denied > "$3/output") 2>/dev/null; then exit 43; fi
# New child processes must inherit the same restrictions.
if /bin/sh -c '/bin/cat "$1/secret"' child "$3" >/dev/null 2>&1; then exit 44; fi
printf sandbox-ok
"#;
    let job = Job {
        program: PathBuf::from("/bin/sh"),
        args: vec![
            "-c".into(),
            script.into(),
            "doctor".into(),
            read_only.to_string_lossy().into(),
            writable.to_string_lossy().into(),
            denied.to_string_lossy().into(),
        ],
        access: vec![
            Access::Read(read_only.clone()),
            Access::Write(writable.clone()),
        ],
        network: Network::Denied,
        timeout: Duration::from_secs(10),
        environment: vec![],
        workdir: None,
    };
    let result = execute(&job)?;
    if result.code != Some(0)
        || result.timed_out
        || result.stdout != b"sandbox-ok"
        || fs::read(writable.join("output")).map_err(|e| e.to_string())? != b"allowed"
        || read_only.join("output").exists()
        || denied.join("output").exists()
    {
        return Err(format!(
            "Sandbox self-test failed (exit {:?}): {}",
            result.code,
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn job() -> Job {
        Job {
            program: PathBuf::from("/bin/sh"),
            args: vec![],
            access: vec![],
            network: Network::Denied,
            timeout: Duration::from_secs(1),
            environment: vec![],
            workdir: None,
        }
    }
    #[test]
    fn policy_denies_network_and_escapes_paths() {
        let scratch = Scratch::new().unwrap();
        let path = scratch.0.join("quote\"and\\slash");
        fs::create_dir(&path).unwrap();
        let mut job = job();
        job.access.push(Access::Read(path));
        let value = profile(&job, &scratch.0, Path::new("/bin/sh")).unwrap();
        assert!(value.contains("(deny default)"));
        assert!(!value.contains("allow network-outbound"));
        assert!(value.contains("quote\\\"and\\\\slash"));
    }
    #[test]
    fn root_grant_is_rejected() {
        assert!(path_rule("file-read*", Path::new("/")).is_err());
    }
    #[test]
    fn missing_path_is_rejected() {
        let scratch = Scratch::new().unwrap();
        assert!(path_rule("file-read*", &scratch.0.join("missing")).is_err());
    }
    #[test]
    fn outbound_is_explicit() {
        let scratch = Scratch::new().unwrap();
        let mut job = job();
        job.network = Network::Outbound;
        assert!(profile(&job, &scratch.0, Path::new("/bin/sh"))
            .unwrap()
            .contains("allow network-outbound"));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn real_seatbelt_permissions_and_inheritance() {
        doctor().unwrap();
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn real_network_denial_and_explicit_outbound() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let mut job = job();
        job.program = PathBuf::from("/usr/bin/nc");
        job.args = vec![
            "-z".into(),
            "-w".into(),
            "1".into(),
            "127.0.0.1".into(),
            port,
        ];
        job.timeout = Duration::from_secs(3);
        let denied = execute(&job).unwrap();
        assert_ne!(denied.code, Some(0));
        assert!(!denied.timed_out);
        job.network = Network::Outbound;
        let allowed = execute(&job).unwrap();
        assert_eq!(
            allowed.code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn timeout_kills_job() {
        let mut job = job();
        job.args = vec!["-c".into(), "while :; do :; done".into()];
        job.timeout = Duration::from_millis(100);
        assert!(execute(&job).unwrap().timed_out);
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_os_fails_closed() {
        assert!(execute(&job()).is_err());
    }
}
