use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Output},
    time::{Duration, Instant},
};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_patchriot-relay"))
}

fn invoke(args: &[&str]) -> (Output, Value) {
    let output = command().args(args).output().expect("run fixture CLI");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON report: {error}; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, report)
}

fn cleaned(report: &Value) {
    assert_eq!(report["process_started"], true);
    assert_eq!(report["direct_child_reaped"], true);
    assert_eq!(report["output_streams_closed"], true);
}

#[test]
fn demo_reproduces_the_specific_flaw_and_checks_the_fix_and_clean_control() {
    let (output, report) = invoke(&["demo"]);
    assert!(output.status.success());
    assert_eq!(report["mode"], "owned_fixture");
    assert_eq!(report["original_fails_and_patch_and_control_pass"], true);
    let runs = report["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 3);
    for (index, case) in ["original", "patched", "clean"].into_iter().enumerate() {
        let run = &runs[index];
        cleaned(run);
        assert_eq!(run["outcome"], "completed");
        assert_eq!(run["evidence"]["case"], case);
        let checks = run["evidence"]["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[0]["actual"], true, "owner retains access");
        assert_eq!(checks[1]["expected"], false);
        assert_eq!(
            checks[1]["actual"],
            index == 0,
            "cross-user access is fixed"
        );
        assert_eq!(
            checks[2]["actual"], false,
            "anonymous access remains denied"
        );
    }
}

#[test]
fn timeout_stops_and_reaps_a_running_child() {
    let started = Instant::now();
    let (output, report) = invoke(&["fixture", "slow", "--timeout-ms", "80"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["outcome"], "timed_out");
    assert_eq!(report["evidence"], Value::Null);
    cleaned(&report);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn cancellation_stops_and_reaps_a_running_child() {
    let started = Instant::now();
    let (output, report) = invoke(&["fixture", "slow", "--cancel-after-ms", "80"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["outcome"], "cancelled");
    cleaned(&report);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn cancelled_before_start_does_not_spawn() {
    let (output, report) = invoke(&["fixture", "slow", "--cancel-after-ms", "0"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["outcome"], "cancelled");
    assert_eq!(report["process_started"], false);
    assert_eq!(report["evidence"], Value::Null);
}

#[test]
fn output_flood_is_bounded_and_does_not_hang_cleanup() {
    let started = Instant::now();
    let (output, report) = invoke(&["fixture", "noisy", "--max-output-bytes", "1024"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["outcome"], "output_limit");
    assert_eq!(report["output_truncated"], true);
    assert_eq!(
        report["stdout_bytes"].as_u64().unwrap() + report["stderr_bytes"].as_u64().unwrap(),
        1024
    );
    assert_eq!(report["evidence"], Value::Null);
    cleaned(&report);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn stdout_and_stderr_share_one_limit() {
    let (_, generous) = invoke(&["fixture", "split_output"]);
    assert_eq!(generous["outcome"], "completed");
    assert!(generous["stdout_bytes"].as_u64().unwrap() < 768);
    assert_eq!(generous["stderr_bytes"], 512);
    let (_, bounded) = invoke(&["fixture", "split_output", "--max-output-bytes", "768"]);
    assert_eq!(bounded["outcome"], "output_limit");
    cleaned(&bounded);
}

#[test]
fn exact_limit_is_allowed_but_one_byte_less_is_rejected() {
    let (_, first) = invoke(&["fixture", "clean"]);
    let size = first["stdout_bytes"].as_u64().unwrap();
    let (output, exact) = invoke(&["fixture", "clean", "--max-output-bytes", &size.to_string()]);
    assert!(output.status.success());
    assert_eq!(exact["outcome"], "completed");
    assert_eq!(exact["output_truncated"], false);
    let (_, short) = invoke(&[
        "fixture",
        "clean",
        "--max-output-bytes",
        &(size - 1).to_string(),
    ]);
    assert_eq!(short["outcome"], "output_limit");
}

#[test]
fn invalid_output_and_failed_process_cannot_produce_accepted_evidence() {
    for (case, outcome) in [
        ("malformed", "invalid_output"),
        ("nonzero", "process_failed"),
    ] {
        let (output, report) = invoke(&["fixture", case]);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(report["outcome"], outcome);
        assert_eq!(report["evidence"], Value::Null);
        cleaned(&report);
    }
}

#[test]
fn descendant_holding_a_pipe_does_not_keep_a_finished_job_alive() {
    let started = Instant::now();
    let (output, report) = invoke(&["fixture", "descendant"]);
    assert!(output.status.success());
    assert_eq!(report["outcome"], "completed");
    assert!(report["evidence"]["descendant_pid"].as_u64().unwrap() > 0);
    cleaned(&report);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "descendant naturally sleeps for ten seconds"
    );
}

#[test]
fn parent_environment_is_not_inherited_or_printed() {
    let output = command()
        .args(["fixture", "environment"])
        .env("PATCHRIOT_TEST_CANARY", "synthetic-parent-only-value")
        .env("HOME", "/synthetic-parent-home")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["evidence"]["checks"][0]["actual"], true);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-parent-only-value"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-parent-only-value"));
}

#[test]
fn arbitrary_commands_and_invalid_limits_are_rejected_before_execution() {
    for args in [
        vec!["fixture", "echo synthetic-command"],
        vec!["run", "synthetic-command"],
        vec!["fixture", "clean", "--timeout-ms", "0"],
        vec!["fixture", "clean", "--timeout-ms", "60001"],
        vec!["fixture", "clean", "--max-output-bytes", "0"],
        vec!["fixture", "clean", "--max-output-bytes", "1048577"],
        vec!["fixture", "clean", "--timeout-ms", "-1"],
        vec!["fixture", "clean", "--timeout-ms"],
        vec!["fixture", "clean", "--shell", "synthetic-command"],
        vec![
            "fixture",
            "clean",
            "--timeout-ms",
            "80",
            "--timeout-ms",
            "90",
        ],
    ] {
        let output = command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "no run was started");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("synthetic-command"),
            "do not echo unknown input"
        );
    }
}

#[test]
fn operating_system_signals_cancel_the_run_and_clean_up() {
    use rustix::process::{Pid, Signal, kill_process};
    use std::process::Stdio;
    for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
        let mut child = command()
            .args(["fixture", "slow"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Readiness follows signal-handler installation and child creation. No
        // sleep-based guess about whether startup has finished.
        let mut line = String::new();
        BufReader::new(child.stderr.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "running owned fixture: slow\n");
        kill_process(Pid::from_child(&child), signal).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["outcome"], "cancelled");
        cleaned(&report);
    }
}
