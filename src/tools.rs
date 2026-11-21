//! Managed tools: trusted SHA-256 pins, sandboxed download/extraction/execution.
use crate::sandbox::{self, Access, Job, Network, Output};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const HELP: &str = "Tools:\n\
  upgrade-lab tools bootstrap  (downloads pinned macOS ARM64 tools)\n\
  upgrade-lab tools install KIND VERSION --sha256 HEX (--archive PATH | --url HTTPS_URL)\n\
  upgrade-lab tools run KIND VERSION [--jdk VERSION] [--repo PATH] [--network] -- [args...]\n\
KIND: jdk, maven, trivy. Tools live in .lab/tools/<kind>/<version>-<os>-<arch>.\n\
Maven requires --jdk. Checksums must come from a trusted, independent source.\n";

fn token(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-_+".contains(&c))
        || matches!(value, "." | "..")
    {
        return Err("Invalid version identifier".into());
    }
    Ok(())
}

fn check_kind(kind: &str) -> Result<(), String> {
    if !matches!(kind, "jdk" | "maven" | "trivy") {
        return Err("Tool kind must be jdk, maven or trivy".into());
    }
    Ok(())
}

fn location(root: &Path, kind: &str, version: &str) -> Result<PathBuf, String> {
    check_kind(kind)?;
    token(version)?;
    Ok(root.join(kind).join(format!(
        "{version}-{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )))
}

fn sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn check_hash(path: &Path, expected: &str) -> Result<(), String> {
    if expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Expected a 64-character SHA-256 checksum".into());
    }
    if sha256(path)? != expected.to_ascii_lowercase() {
        return Err("Archive SHA-256 mismatch; installation refused".into());
    }
    Ok(())
}

fn command(program: &str, args: Vec<String>, access: Vec<Access>, network: Network) -> Job {
    Job {
        program: program.into(),
        args,
        access,
        network,
        timeout: Duration::from_secs(300),
        environment: vec![],
        workdir: None,
    }
}

fn checked(job: &Job) -> Result<Output, String> {
    let output = sandbox::execute(job)?;
    if output.timed_out || output.code != Some(0) {
        return Err(format!(
            "Sandboxed command failed ({:?}, timeout={}): {}",
            output.code,
            output.timed_out,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output)
}

fn safe_members(list: &str) -> Result<(), String> {
    if list.is_empty() {
        return Err("Empty archive".into());
    }
    for name in list.lines() {
        let path = Path::new(name);
        if name.chars().any(char::is_control)
            || path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err("Unsafe archive member path".into());
        }
    }
    Ok(())
}

fn inspect_tree(
    root: &Path,
    directory: &Path,
    kind: &str,
    found: &mut Vec<PathBuf>,
    depth: usize,
) -> Result<(), String> {
    if depth > 32 {
        return Err("Archive nesting too deep".into());
    }
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            if fs::read_link(&path)
                .map_err(|e| e.to_string())?
                .is_absolute()
            {
                return Err("Absolute archive symlinks are forbidden".into());
            }
            let target = fs::canonicalize(&path).map_err(|_| "Dangling archive symlink")?;
            if !target.starts_with(root) {
                return Err("Archive symlink escapes tool installation".into());
            }
            continue;
        }
        if metadata.is_dir() {
            inspect_tree(root, &path, kind, found, depth + 1)?;
        } else if metadata.is_file() {
            let is_program = match kind {
                "jdk" => path.ends_with("bin/java"),
                "maven" => path.ends_with("bin/mvn"),
                "trivy" => entry.file_name() == "trivy",
                _ => false,
            };
            if is_program {
                found.push(path);
            }
        } else {
            return Err("Special files in tool archives are forbidden".into());
        }
    }
    Ok(())
}

pub fn install(
    root: &Path,
    kind: &str,
    version: &str,
    expected: &str,
    source: &str,
    url: bool,
) -> Result<PathBuf, String> {
    let destination = location(root, kind, version)?;
    if expected.len() != 64 || !expected.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("A trusted 64-character SHA-256 checksum is required".into());
    }
    if destination.exists() {
        return Err("Version already installed; refusing overwrite".into());
    }
    sandbox::doctor()?;
    let parent = destination.parent().ok_or("Missing tool parent")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let parent = fs::canonicalize(parent).map_err(|e| e.to_string())?;
    let destination = parent.join(destination.file_name().ok_or("Invalid destination")?);
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let stage = parent.join(format!(".install-{}-{id}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&stage).map_err(|e| e.to_string())?;
    let result = (|| {
        let archive = stage.join("archive");
        if url {
            if !source.starts_with("https://") {
                return Err("Only HTTPS downloads are allowed".into());
            }
            let mut access = vec![Access::Write(stage.clone())];
            if Path::new("/private/etc/ssl").exists() {
                access.push(Access::Read("/private/etc/ssl".into()));
            }
            checked(&command(
                "/usr/bin/curl",
                vec![
                    "--fail".into(),
                    "--location".into(),
                    "--proto".into(),
                    "=https".into(),
                    "--proto-redir".into(),
                    "=https".into(),
                    "--max-time".into(),
                    "240".into(),
                    "--max-filesize".into(),
                    "1073741824".into(),
                    "--output".into(),
                    archive.display().to_string(),
                    source.into(),
                ],
                access,
                Network::Outbound,
            ))?;
        } else {
            // Copy first: hash and extract the same private snapshot, not a mutable caller file.
            fs::copy(source, &archive).map_err(|e| e.to_string())?;
        }
        check_hash(&archive, expected)?;
        let listing = stage.join("members.txt");
        checked(&command(
            "/bin/sh",
            vec![
                "-c".into(),
                "exec /usr/bin/tar -tf \"$1\" > \"$2\"".into(),
                "list".into(),
                archive.display().to_string(),
                listing.display().to_string(),
            ],
            vec![Access::Write(stage.clone())],
            Network::Denied,
        ))?;
        if fs::metadata(&listing).map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
            return Err("Archive listing exceeds 16 MiB inspection limit".into());
        }
        safe_members(&fs::read_to_string(listing).map_err(|e| e.to_string())?)?;
        let payload = stage.join("payload");
        fs::create_dir(&payload).map_err(|e| e.to_string())?;
        checked(&command(
            "/usr/bin/tar",
            vec![
                "--no-same-owner".into(),
                "--no-same-permissions".into(),
                "-xf".into(),
                archive.display().to_string(),
                "-C".into(),
                payload.display().to_string(),
            ],
            vec![Access::Read(archive), Access::Write(payload.clone())],
            Network::Denied,
        ))?;
        let mut programs = Vec::new();
        inspect_tree(&payload, &payload, kind, &mut programs, 0)?;
        if programs.len() != 1 {
            return Err("Expected exactly one tool entry point in archive".into());
        }
        let relative = programs[0]
            .strip_prefix(&payload)
            .map_err(|e| e.to_string())?;
        let relative = relative.to_str().ok_or("Non-UTF-8 program path")?;
        if relative.chars().any(char::is_control) {
            return Err("Invalid program path".into());
        }
        if fs::symlink_metadata(payload.join(".upgrade-lab-receipt")).is_ok() {
            return Err("Archive contains reserved installation receipt".into());
        }
        fs::write(
            payload.join(".upgrade-lab-receipt"),
            format!(
                "{kind}\n{version}\n{}\n{relative}\n",
                expected.to_ascii_lowercase()
            ),
        )
        .map_err(|e| e.to_string())?;
        // Installation is not an execution test; tool run/version must still be verified.
        fs::rename(&payload, &destination).map_err(|e| e.to_string())?;
        Ok(destination.clone())
    })();
    let _ = fs::remove_dir_all(&stage);
    result
}

fn resolve(root: &Path, kind: &str, version: &str) -> Result<(PathBuf, PathBuf), String> {
    let directory = fs::canonicalize(location(root, kind, version)?)
        .map_err(|e| format!("Tool not installed: {e}"))?;
    let receipt =
        fs::read_to_string(directory.join(".upgrade-lab-receipt")).map_err(|e| e.to_string())?;
    let lines: Vec<_> = receipt.lines().collect();
    if lines.len() != 4 || lines[0] != kind || lines[1] != version {
        return Err("Invalid tool receipt".into());
    }
    let program = fs::canonicalize(directory.join(lines[3])).map_err(|e| e.to_string())?;
    if !program.starts_with(&directory) || !program.is_file() {
        return Err("Tool entry point escapes installation".into());
    }
    Ok((directory, program))
}

pub fn run_tool(
    root: &Path,
    kind: &str,
    version: &str,
    jdk: Option<&str>,
    repo: Option<&Path>,
    network: bool,
    args: Vec<String>,
) -> Result<Output, String> {
    sandbox::doctor()?;
    let (directory, program) = resolve(root, kind, version)?;
    let mut job = command(
        program.to_str().ok_or("Non-UTF-8 tool path")?,
        args,
        vec![Access::Read(directory)],
        if network {
            Network::Outbound
        } else {
            Network::Denied
        },
    );
    job.timeout = Duration::from_secs(900);
    if let Some(repo) = repo {
        let repo = fs::canonicalize(repo).map_err(|e| e.to_string())?;
        if !repo.is_dir() {
            return Err("Repository must be a directory".into());
        }
        let tools_root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let data = tools_root.parent().ok_or("Missing data directory")?;
        if tools_root.starts_with(&repo) || repo.starts_with(&tools_root) || repo == data {
            return Err("Repository grant would expose managed tools or application data".into());
        }
        job.access.push(Access::Write(repo.clone()));
        if repo.join(".git").exists() {
            job.access.push(Access::Protected(repo.join(".git")));
        }
        job.workdir = Some(repo);
    }
    let cache = root
        .parent()
        .ok_or("Missing data directory")?
        .join("cache")
        .join(kind);
    fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let cache = fs::canonicalize(cache).map_err(|e| e.to_string())?;
    job.access.push(Access::Write(cache.clone()));
    if kind == "maven" {
        let (java_root, java) = resolve(root, "jdk", jdk.ok_or("Maven requires --jdk VERSION")?)?;
        let home = java
            .parent()
            .and_then(Path::parent)
            .ok_or("Invalid Java installation")?;
        job.environment
            .push(("JAVA_HOME".into(), home.display().to_string()));
        job.environment.push((
            "PATH".into(),
            format!("{}:/usr/bin:/bin", java.parent().unwrap().display()),
        ));
        job.environment
            .push(("MAVEN_USER_HOME".into(), cache.display().to_string()));
        job.args.insert(
            0,
            format!("-Dmaven.repo.local={}", cache.join("repository").display()),
        );
        job.access.push(Access::Read(java_root));
    } else if kind == "trivy" {
        job.environment
            .push(("TRIVY_CACHE_DIR".into(), cache.display().to_string()));
    }
    sandbox::execute(&job)
}

pub fn catalog_pin_digest() -> Result<String, String> {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../tools/macos-aarch64.json"))
            .map_err(|e| e.to_string())?;
    Ok(format!(
        "{:x}",
        Sha256::digest(catalog.to_string().as_bytes())
    ))
}

pub fn catalog() -> Result<serde_json::Value, String> {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../tools/macos-aarch64.json"))
            .map_err(|e| e.to_string())?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    if catalog["platform"].as_str() != Some(platform.as_str()) {
        return Err(format!("No pinned tool catalog for {platform}"));
    }
    Ok(catalog)
}

pub fn pinned_version(kind: &str) -> Result<String, String> {
    let catalog = catalog()?;
    let artifact = catalog["artifacts"]
        .as_array()
        .ok_or("Invalid catalog")?
        .iter()
        .find(|item| item["kind"].as_str() == Some(kind))
        .ok_or("Tool missing from catalog")?;
    Ok(artifact["version"]
        .as_str()
        .ok_or("Missing pinned version")?
        .into())
}

pub fn bootstrap(root: &Path) -> Result<Vec<String>, String> {
    let catalog = catalog()?;
    let mut installed = Vec::new();
    for artifact in catalog["artifacts"].as_array().ok_or("Invalid catalog")? {
        let field = |key: &str| {
            artifact[key]
                .as_str()
                .ok_or_else(|| format!("Missing catalog field: {key}"))
        };
        let kind = field("kind")?;
        let version = field("version")?;
        if location(root, kind, version)?.exists() {
            let (directory, _) = resolve(root, kind, version)?;
            let receipt = fs::read_to_string(directory.join(".upgrade-lab-receipt"))
                .map_err(|e| e.to_string())?;
            if receipt.lines().nth(2) != Some(field("sha256")?) {
                return Err(format!(
                    "Installed {kind} {version} does not match the catalog archive hash"
                ));
            }
            installed.push(format!("Already installed: {kind} {version}"));
        } else {
            eprintln!("Installing {kind} {version} from pinned catalog...");
            install(root, kind, version, field("sha256")?, field("url")?, true)?;
            installed.push(format!("Installed: {kind} {version}"));
        }
    }
    Ok(installed)
}

pub fn cli(args: &[String]) -> Result<Output, String> {
    if args == ["bootstrap"] {
        let root = std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(".lab/tools");
        let messages = bootstrap(&root)?;
        return Ok(Output {
            code: Some(0),
            timed_out: false,
            stdout: (messages.join("\n") + "\n").into_bytes(),
            stderr: vec![],
            truncated: false,
        });
    }
    let action = args.first().ok_or(HELP)?;
    let kind = args.get(1).ok_or(HELP)?;
    let version = args.get(2).ok_or(HELP)?;
    check_kind(kind)?;
    token(version)?;
    let root = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .join(".lab/tools");
    let mut checksum = None;
    let mut source = None;
    let mut url = false;
    let mut jdk = None;
    let mut repo = None;
    let mut network = false;
    let mut index = 3;
    while index < args.len() && args[index] != "--" {
        let option = args[index].as_str();
        if option == "--network" && action == "run" {
            network = true;
            index += 1;
            continue;
        }
        index += 1;
        let value = args.get(index).ok_or("Missing option value")?;
        match (action.as_str(), option) {
            ("install", "--sha256") => checksum = Some(value.as_str()),
            ("install", "--archive" | "--url") => {
                if source.is_some() {
                    return Err("Specify exactly one archive or URL".into());
                }
                source = Some(value.as_str());
                url = option == "--url";
            }
            ("run", "--jdk") => jdk = Some(value.as_str()),
            ("run", "--repo") => repo = Some(Path::new(value)),
            _ => return Err(format!("Unknown tools option: {option}")),
        }
        index += 1;
    }
    match action.as_str() {
        "install" if index == args.len() => {
            let path = install(
                &root,
                kind,
                version,
                checksum.ok_or("--sha256 is required")?,
                source.ok_or("--archive or --url is required")?,
                url,
            )?;
            Ok(Output {
                code: Some(0),
                timed_out: false,
                stdout: format!("Installed {}\n", path.display()).into_bytes(),
                stderr: vec![],
                truncated: false,
            })
        }
        "run" if args.get(index).map(String::as_str) == Some("--") => run_tool(
            &root,
            kind,
            version,
            jdk,
            repo,
            network,
            args[index + 1..].to_vec(),
        ),
        _ => Err(HELP.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_paths_and_versions_are_checked() {
        assert!(safe_members("tool/bin/java\n./tool/lib/a\n").is_ok());
        for path in ["/etc/file", "tool/../../file", "../file"] {
            assert!(safe_members(path).is_err());
        }
        for version in ["../escape", "", "..", "a\nb"] {
            assert!(token(version).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn real_archive_install_hash_gate_and_sandboxed_run() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base =
            std::env::temp_dir().join(format!("upgrade-tools-test-{}-{id}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let base = fs::canonicalize(base).unwrap();
        let _cleanup = Cleanup(base.clone());
        let source = base.join("source");
        fs::create_dir(&source).unwrap();
        let script = source.join("trivy");
        fs::write(&script, "#!/bin/sh\nprintf 'fixture-tool-ok\\n'\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let archive = base.join("tool.tar.gz");
        checked(&command(
            "/usr/bin/tar",
            vec![
                "-czf".into(),
                archive.display().to_string(),
                "-C".into(),
                source.display().to_string(),
                ".".into(),
            ],
            vec![Access::Write(base.clone())],
            Network::Denied,
        ))
        .unwrap();
        let root = base.join("tools");
        let expected = sha256(&archive).unwrap();
        assert!(install(
            &root,
            "trivy",
            "test-wrong",
            &"0".repeat(64),
            archive.to_str().unwrap(),
            false
        )
        .is_err());
        assert!(!location(&root, "trivy", "test-wrong").unwrap().exists());
        install(
            &root,
            "trivy",
            "test",
            &expected,
            archive.to_str().unwrap(),
            false,
        )
        .unwrap();
        let result = run_tool(&root, "trivy", "test", None, None, false, vec![]).unwrap();
        assert_eq!(
            result.code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"fixture-tool-ok\n");
        assert!(install(
            &root,
            "trivy",
            "test",
            &expected,
            archive.to_str().unwrap(),
            false
        )
        .is_err());
        assert!(run_tool(&root, "trivy", "test", None, Some(&base), false, vec![]).is_err());
        // An escape symlink is rejected even if it points to an existing file.
        symlink("../../outside", source.join("escape")).unwrap();
        assert!(inspect_tree(&source, &source, "trivy", &mut vec![], 0).is_err());
    }

    #[test]
    fn pinned_catalog_has_valid_coordinates_and_hashes() {
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!("../tools/macos-aarch64.json")).unwrap();
        let artifacts = catalog["artifacts"].as_array().unwrap();
        assert_eq!(artifacts.len(), 3);
        let mut kinds = std::collections::HashSet::new();
        for artifact in artifacts {
            let kind = artifact["kind"].as_str().unwrap();
            check_kind(kind).unwrap();
            token(artifact["version"].as_str().unwrap()).unwrap();
            assert!(kinds.insert(kind));
            let hash = artifact["sha256"].as_str().unwrap();
            assert_eq!(hash.len(), 64);
            assert!(hash.bytes().all(|c| c.is_ascii_hexdigit()));
            assert!(artifact["url"].as_str().unwrap().starts_with("https://"));
        }
    }

    #[test]
    fn standard_sha256_vector() {
        let hash = Sha256::digest(b"abc");
        assert_eq!(
            format!("{hash:x}"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
