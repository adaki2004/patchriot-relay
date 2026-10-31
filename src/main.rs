//! Pairing, owned fixtures and opt-in isolated agent reviews of saved evidence.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("The fixture runner currently supports Linux and macOS only.");

mod agent;
mod device;
mod docker;
mod fixtures;
mod inference;
mod process;
mod runner;
mod sandbox;
mod work;

use fixtures::Case;
use runner::{Limits, Outcome};
use std::sync::{Arc, atomic::AtomicBool};
use std::{io, process::ExitCode, time::Duration};

const HELP: &str = "Patchriot Relay — pairing, presence and owned fixtures

patchriot-relay init --state-dir PATH --dispatcher URL --audience NAME --label NAME --compute-group NAME
  [--runtime hermes --runtime-version VERSION --model MODEL]
patchriot-relay pair --state-dir PATH
patchriot-relay connect --state-dir PATH [--once] [--fixtures]
patchriot-relay connect --state-dir PATH --agents --agent-config PATH [--once] [--website-reviews]
patchriot-relay status --state-dir PATH
patchriot-relay pause --state-dir PATH
patchriot-relay resume --state-dir PATH

patchriot-relay demo
patchriot-relay fixture <case> [--timeout-ms N] [--max-output-bytes N] [--cancel-after-ms N]
patchriot-relay sandbox-check --socket PATH --image sha256:IMAGE_ID
patchriot-relay agent-check --config PATH

Cases: original, patched, clean, slow, noisy, split_output, malformed, nonzero, descendant, environment
Fixture defaults: 3000 ms, 8192 combined stdout/stderr bytes. Maximums: 60000 ms, 1048576 bytes.
Agent check: owned example only, 600 seconds overall, four local model calls maximum.
Exit: 0 = completed fixture / passing check; 1 = failed or interrupted run; 2 = input or runner error.
Runtime results are JSON. Completed means execution finished, not that the target is safe.
";

fn main() -> ExitCode {
    match execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn execute() -> Result<u8, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print!("{HELP}");
        return Ok(0);
    }
    if ["init", "pair", "connect", "status", "pause", "resume"].contains(&args[0].as_str()) {
        return device::execute(&args);
    }
    if args[0] == "sandbox-check" {
        return sandbox::execute(&args);
    }
    if args[0] == "agent-check" {
        return agent::execute(&args);
    }
    // The subprocess can run only these compiled-in fixtures, never a shell command.
    if args.len() == 2 && args[0] == "__fixture" {
        return fixtures::execute(args[1].parse()?);
    }
    let demo = args == ["demo"];
    let mut limits = Limits::default();
    let mut cancel_after = None;
    let case = if demo {
        Case::Original
    } else {
        if args.len() < 2 || args[0] != "fixture" {
            return Err("expected demo or fixture; see --help".into());
        }
        let case = args[1].parse()?;
        let mut seen = std::collections::HashSet::new();
        let mut flags = args[2..].chunks_exact(2);
        for pair in &mut flags {
            if !seen.insert(&pair[0]) {
                return Err("duplicate option".into());
            }
            let value: u64 = pair[1]
                .parse()
                .map_err(|_| "expected an unsigned integer")?;
            match pair[0].as_str() {
                "--timeout-ms" => limits.timeout_ms = value,
                "--max-output-bytes" => {
                    limits.max_output_bytes =
                        value.try_into().map_err(|_| "output limit too large")?;
                }
                "--cancel-after-ms" if value <= 60_000 => {
                    cancel_after = Some(Duration::from_millis(value));
                }
                _ => return Err("unknown option or invalid cancellation delay".into()),
            }
        }
        if !flags.remainder().is_empty() {
            return Err("option is missing its value".into());
        }
        limits.validate()?;
        case
    };

    let cancelled = Arc::new(AtomicBool::new(false));
    let signal_flag = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal_flag.store(true, std::sync::atomic::Ordering::Relaxed))?;
    let executable = std::env::current_exe()?;
    let code;
    if demo {
        let mut runs = Vec::new();
        for case in [Case::Original, Case::Patched, Case::Clean] {
            let report = runner::run(&executable, case, limits, &cancelled, None)?;
            let completed = report.process.outcome == Outcome::Completed;
            runs.push(report);
            if !completed {
                break;
            }
        }
        let verified = runs.len() == 3
            && runs.iter().all(|r| r.process.outcome == Outcome::Completed)
            && runs
                .iter()
                .zip([Case::Original, Case::Patched, Case::Clean])
                .all(|(run, case)| {
                    run.evidence
                        .as_ref()
                        .is_some_and(|e| e.matches_expected_fixture(case))
                });
        serde_json::to_writer_pretty(
            io::stdout().lock(),
            &serde_json::json!({
                "schema_version": 1,
                "mode": "owned_fixture",
                "original_fails_and_patch_and_control_pass": verified,
                "runs": runs
            }),
        )?;
        code = u8::from(!verified);
    } else {
        let report = runner::run(&executable, case, limits, &cancelled, cancel_after)?;
        code = u8::from(report.process.outcome != Outcome::Completed);
        serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
    }
    println!();
    Ok(code)
}
