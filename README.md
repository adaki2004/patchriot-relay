# Patchriot Relay
**Connect your agent to the defense swarm.**

The Rust relay connects a patcher's PC or VPS to Patchriot. The product is built for agents with **code-review, web/API security and authorized penetration-testing skills**: investigate a claim, reproduce it and test a fix.

> **DON'T TRUST! VERIFY!** Review the source and permissions yourself, or have your own security agent audit them. Run the tests and authorized penetration checks on your deployment before connecting valuable systems. Pairing and agent signatures do not prove safe behavior.

**Working today:** device pairing, manual approval, presence, pause/resume, revocation and queued owned-fixture reviews. **Next:** Linux isolation and a real agent adapter. No customer code or model calls run through the current queue.

## Try the owned example

Place `patchriot-core` beside this repository for its shared protocol crate. Use **Rust 1.94.1** on Linux or macOS.

```sh
cargo run --locked -- demo
```

The demo runs an original access-control bug, a patch and a clean control in separate processes. It reports success only when the original permits cross-user access and both corrected versions block it while preserving legitimate access. This is a known regression example, not an AI-discovered finding.

## Pair your machine

Start the local core website and dispatcher using their READMEs, then:

```sh
cargo run --locked -- init --state-dir .local/relay-one --dispatcher http://127.0.0.1:7411 --audience patchriot-local-v1 --label "My relay" --compute-group "my-machine"
cargo run --locked -- pair --state-dir .local/relay-one
cargo run --locked -- connect --state-dir .local/relay-one
```

1. Sign in to the website and enter the five-minute code under **Pair a relay**.
2. Complete the short operator profile and data-handling consent.
3. An administrator approves the device under **Fleet & approvals**.

The Ed25519 key stays in your private state directory. The relay connects outward; it needs no public inbound port. Use HTTPS or an authenticated tunnel outside loopback. Three devices on one machine should declare the same compute group.

## Control your contribution

| Command after `cargo run --locked --` | Effect |
| --- | --- |
| `status --state-dir .local/relay-one` | Show local pairing and pause state |
| `pause --state-dir .local/relay-one` | Stop accepting work on the next connection cycle |
| `resume --state-dir .local/relay-one` | Resume contribution |
| `connect --state-dir .local/relay-one --fixtures` | Explicitly accept the fixed owned example |

Without `--fixtures`, the connection reports presence only. Heartbeats run every ten seconds; stale devices become offline after 30 seconds. Owners can revoke a device in the website. Revoked keys cannot reconnect.

With **three approved devices** connected using `--fixtures`, choose **Reviews → New fixture review**. Investigator, reproducer and challenger roles run sequentially. Shared machines get one active assignment. Reports show actual device/operator counts; they do not imply three independent operators.

Results are saved locally before submission and retried after connection loss. Cancelled, expired or replaced assignments cannot accept stale results. Keep state directories out of Git and shared backups.

## Execution boundary

The current runner clears inherited environment, uses a temporary directory and limits each fixture to **3 seconds and 8 KiB of combined output**. It terminates its process group on timeout or cancellation.

**That is process supervision, not a sandbox.** Filesystem, network, memory and CPU isolation are the next slice. The dispatcher cannot send arbitrary commands, URLs or source code through this fixture path.

Private customer work will require approved operators and tested isolation. Assigned operators and permitted model providers can see the plaintext they process. Model names, pairing and hosting-provider claims do not establish honesty or model weights.

## Check the controls

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo run --locked -- fixture slow --timeout-ms 100
cargo run --locked -- fixture noisy --max-output-bytes 1024
```

The last two commands intentionally fail with bounded timeout/output reports. Tests also cover cancellation, OS signals, descendants, environment leakage and malformed results. **A completed test is evidence for that check, not a blanket safety verdict.**

For real queue/retry tests, see core's `scripts/smoke-reviews.py`. CI uses a pinned protocol commit; private core access needs the `PATCHRIOT_READ_TOKEN` Actions secret with read-only access to core.

## Small Linux pilot

[deploy/patchriot-relay-demo@.service](deploy/patchriot-relay-demo@.service) runs the owned demo as an unprivileged user with **64 MiB, 10% CPU and 32 tasks**. It expects a dispatcher tunnel on loopback, a binary at `/opt/patchriot-demo/patchriot-relay` and separate private state directories under `/var/lib/patchriot-demo/`.

After installing the unit, initializing/pairing each instance as `patchriot-demo` and approving it, start `patchriot-relay-demo@one` with systemd. Inspect it with `systemctl status` and `journalctl -u`; stop it with `systemctl stop`. The unit is a fixture pilot, not the future customer-code sandbox.

## What's next

**Linux sandbox → CPU agent adapter → scoped customer reviews.** Hermes is the first planned runtime. Operators bring security-capable agents and inference; no stake or on-chain identity is required for this pilot. GPU trials and confidential execution come later.

Original material is [AGPL-3.0-only](LICENSE); attribution is in [NOTICE](NOTICE). Model weights and external runtimes retain their own licenses. This repository is private during development and intended for publication.
