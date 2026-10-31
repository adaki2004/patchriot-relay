use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
};

fn invoke(path: &Path, action: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_patchriot-relay"))
        .args([action, "--state-dir"])
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

fn initialize(path: &Path, endpoint: &str) -> Output {
    invoke(
        path,
        "init",
        &[
            "--dispatcher",
            endpoint,
            "--audience",
            "fixture-deployment",
            "--label",
            "Local relay",
            "--compute-group",
            "shared-fixture-host",
        ],
    )
}

#[test]
fn initialization_creates_private_identity_and_never_rotates_an_existing_key() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let output = initialize(&path, "http://127.0.0.1:7411");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["state"], "initialized");
    assert_eq!(result["public_key"].as_str().unwrap().len(), 64);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    for name in ["device.key", "relay.json", "state.lock"] {
        assert_eq!(fs::metadata(path.join(name)).unwrap().mode() & 0o777, 0o600);
    }
    let key_before = fs::read(path.join("device.key")).unwrap();
    assert_eq!(key_before.len(), 32);
    let retry = initialize(&path, "http://127.0.0.1:7411");
    assert!(!retry.status.success());
    assert_eq!(fs::read(path.join("device.key")).unwrap(), key_before);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex::encode(&key_before)));
}

#[test]
fn pause_and_resume_persist_without_network_or_leaking_key_material() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    assert!(
        initialize(&path, "https://dispatcher.invalid")
            .status
            .success()
    );
    for (action, expected) in [
        ("pause", true),
        ("status", true),
        ("resume", false),
        ("status", false),
    ] {
        let output = invoke(&path, action, &[]);
        assert!(output.status.success());
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["paused"], expected);
        assert!(body.get("private_key").is_none());
        assert!(body.get("key").is_none());
        assert_eq!(body["sequence"], 0);
    }
}

#[test]
fn public_http_and_world_readable_state_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    assert!(!initialize(&path, "http://example.com").status.success());
    assert!(!path.exists());
    assert!(
        initialize(&path, "https://dispatcher.invalid")
            .status
            .success()
    );
    fs::set_permissions(path.join("relay.json"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!invoke(&path, "status", &[]).status.success());
}
