//! Explicit integration tests require a local Linux Docker engine and the owned
//! image built from sandbox/Dockerfile. CI runs these on Linux; regular unit
//! tests need no container runtime. Missing configuration fails, never skips.
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_patchriot-relay"))
}

fn settings() -> (String, String) {
    (
        std::env::var("PATCHRIOT_DOCKER_SOCKET")
            .expect("set PATCHRIOT_DOCKER_SOCKET to a local Unix socket path"),
        std::env::var("PATCHRIOT_SANDBOX_IMAGE")
            .expect("set PATCHRIOT_SANDBOX_IMAGE to the built probe's sha256 image ID"),
    )
}

fn gone(socket: &str, runs: &[Value]) {
    for run in runs {
        assert_eq!(run["cleanup_confirmed"], true);
        let name = run["container"].as_str().unwrap();
        let result = Command::new("docker")
            .args([
                "--host",
                &format!("unix://{socket}"),
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                &format!("name=^/{name}$"),
            ])
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(result.stdout.is_empty(), "owned container survived cleanup");
    }
}

#[test]
fn arbitrary_images_options_and_remote_sockets_are_rejected() {
    let immutable = format!("sha256:{}", "0".repeat(64));
    for args in [
        vec![
            "sandbox-check",
            "--image",
            "alpine:latest",
            "--socket",
            "/var/run/docker.sock",
        ],
        vec![
            "sandbox-check",
            "--image",
            &immutable,
            "--socket",
            "tcp://untrusted:2375",
        ],
        vec![
            "sandbox-check",
            "--image",
            &immutable,
            "--socket",
            "relative.sock",
        ],
        vec![
            "sandbox-check",
            "--image",
            &immutable,
            "--socket",
            "/dev/null",
        ],
        vec![
            "sandbox-check",
            "--image",
            &immutable,
            "--privileged",
            "true",
        ],
        vec![
            "sandbox-check",
            "--image",
            &immutable,
            "--image",
            &immutable,
        ],
        vec!["sandbox-check", "--socket"],
    ] {
        let result = command().args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}

#[test]
#[ignore = "requires explicitly configured local Docker and the owned probe image"]
fn real_containers_enforce_policy_and_cleanup_every_failure_path() {
    let (socket, image) = settings();
    let started = Instant::now();
    let output = command()
        .args(["sandbox-check", "--socket", &socket, "--image", &image])
        .env("PATCHRIOT_TEST_CANARY", "synthetic-parent-value")
        // Docker's context, proxy and credential settings must not leak in.
        .env("DOCKER_HOST", "tcp://127.0.0.1:1")
        .env("DOCKER_CONTEXT", "untrusted-unused-context")
        .env("DOCKER_CONFIG", "/nonexistent-config")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], true);
    assert_eq!(report["image"], image);
    let runs = report["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 8);
    for run in runs {
        assert_eq!(run["passed"], true);
        assert_eq!(run["policy_verified"], true);
        assert_eq!(run["container_started"], true);
        assert_eq!(run["container_stopped"], true);
        assert_eq!(run["process"]["direct_child_reaped"], true);
        assert_eq!(run["process"]["output_streams_closed"], true);
    }
    assert_eq!(runs[0]["checks"].as_array().unwrap().len(), 16);
    assert_eq!(runs[3]["probe"], "descendant");
    assert_eq!(runs[3]["process"]["outcome"], "completed");
    assert!(runs[3]["process"]["duration_ms"].as_u64().unwrap() < 10_000);
    assert_eq!(runs[4]["oom_killed"], true);
    assert_eq!(runs[4]["exit_code"], 137);
    assert_eq!(runs[5]["process"]["outcome"], "timed_out");
    assert_eq!(runs[6]["process"]["outcome"], "cancelled");
    assert_eq!(runs[7]["process"]["outcome"], "output_limit");
    assert_eq!(runs[7]["process"]["stdout_bytes"], 8192);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-parent-value"));
    gone(&socket, runs);
    assert!(started.elapsed() < Duration::from_secs(60));
}

#[test]
#[ignore = "requires explicitly configured local Docker and the owned probe image"]
fn termination_signal_removes_the_running_container_and_stops_the_suite() {
    use rustix::process::{Pid, Signal, kill_process};
    let (socket, image) = settings();
    let mut child = command()
        .args(["sandbox-check", "--socket", &socket, "--image", &image])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let reader = BufReader::new(child.stderr.take().unwrap());
    let mut signalled = false;
    for line in reader.lines() {
        if line.unwrap() == "running sandbox probe: timeout" {
            kill_process(Pid::from_child(&child), Signal::TERM).unwrap();
            signalled = true;
            break;
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(signalled, "suite never reached the long-running probe");
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["cancelled"], true);
    assert_eq!(report["passed"], false);
    let runs = report["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 6);
    assert_eq!(runs[5]["probe"], "timeout");
    assert_eq!(runs[5]["process"]["outcome"], "cancelled");
    gone(&socket, runs);
}
