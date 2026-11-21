mod execution;
mod failure;
mod queue;
mod sandbox;
mod scan;
mod smoke;
mod store;
mod tools;

use sandbox::{Access, Job, Network};
use std::path::PathBuf;
use std::time::Duration;

const HELP: &str = "upgrade-lab — native sandbox prototype (no Docker or Python)\n\n\
Usage:\n  upgrade-lab sandbox doctor\n  upgrade-lab sandbox run [--read PATH] [--write PATH] [--network] [--timeout SECONDS] -- /absolute/program [args...]\n\n\
Network is denied by default. --network enables outbound network access, not a domain allowlist.\n\
Each job gets a private temporary HOME, TMPDIR and working directory.\n\
Only explicitly granted paths and minimal OS runtime paths are accessible.\n\
Batch upgrades and GitLab integration are not yet ported; central scans/status are available.\n";

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print!(
            "{HELP}\n{}\n{}\n{}\n{}\n  upgrade-lab smoke [--network]  (real baseline build/SBOM/scan)\n",
            tools::HELP,
            scan::HELP,
            queue::HELP,
            execution::HELP
        );
        return Ok(0);
    }
    if args.first().map(String::as_str) == Some("factory") {
        return execution::cli(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("queue") {
        return queue::cli(&args[1..]);
    }
    if args == ["repos", "init-examples"] {
        scan::init_examples()?;
        return Ok(0);
    }
    if matches!(
        args.first().map(String::as_str),
        Some("scan" | "status" | "inventory")
    ) {
        return scan::cli(&args);
    }
    if args == ["smoke"] || args == ["smoke", "--network"] {
        return smoke::run(args.len() == 2);
    }
    if args.first().map(String::as_str) == Some("tools") {
        return show_output(tools::cli(&args[1..])?);
    }
    if args == ["sandbox", "doctor"] {
        sandbox::doctor()?;
        println!("Sandbox OK: {}. Read/write denial and child inheritance verified; network policy configured but not probed.", sandbox::backend());
        return Ok(0);
    }
    if args.first().map(String::as_str) != Some("sandbox")
        || args.get(1).map(String::as_str) != Some("run")
    {
        return Err(HELP.to_string());
    }
    let mut access = Vec::new();
    let mut network = Network::Denied;
    let mut timeout = Duration::from_secs(120);
    let mut index = 2;
    while index < args.len() && args[index] != "--" {
        match args[index].as_str() {
            "--read" | "--write" => {
                let write = args[index] == "--write";
                index += 1;
                let path = PathBuf::from(args.get(index).ok_or("Missing path")?);
                access.push(if write {
                    Access::Write(path)
                } else {
                    Access::Read(path)
                });
            }
            "--network" => network = Network::Outbound,
            "--timeout" => {
                index += 1;
                let seconds: u64 = args
                    .get(index)
                    .ok_or("Missing timeout")?
                    .parse()
                    .map_err(|_| "Invalid timeout")?;
                if seconds == 0 || seconds > 86_400 {
                    return Err("Timeout must be 1..86400 seconds".into());
                }
                timeout = Duration::from_secs(seconds);
            }
            option => return Err(format!("Unknown option: {option}")),
        }
        index += 1;
    }
    if args.get(index).map(String::as_str) != Some("--") || index + 1 >= args.len() {
        return Err("Expected -- /absolute/program [args...]".into());
    }
    let job = Job {
        program: PathBuf::from(&args[index + 1]),
        args: args[index + 2..].to_vec(),
        access,
        network,
        timeout,
        environment: vec![],
        workdir: None,
    };
    // Probe the backend before executing user commands. No unsandboxed fallback.
    sandbox::doctor()?;
    show_output(sandbox::execute(&job)?)
}

fn show_output(result: sandbox::Output) -> Result<i32, String> {
    use std::io::Write;
    std::io::stdout()
        .write_all(&result.stdout)
        .map_err(|e| e.to_string())?;
    std::io::stderr()
        .write_all(&result.stderr)
        .map_err(|e| e.to_string())?;
    if result.truncated {
        eprintln!("[output truncated to 64 KiB per stream]");
    }
    if result.timed_out {
        eprintln!("Sandbox job exceeded its timeout");
        return Ok(124);
    }
    Ok(result.code.unwrap_or(1))
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
