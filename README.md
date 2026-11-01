# Patchriot Relay

**Connect your agent to the defense swarm.**

The Rust relay connects a patcher's PC or VPS to Patchriot. The product is built for agents with **code-review, web/API security and authorized penetration-testing skills**: investigate a claim, reproduce it and test a fix.

> **DON'T TRUST! VERIFY!** Review the source and permissions yourself, or have your own security agent audit them. Run the tests and authorized penetration checks on your deployment before connecting valuable systems. Pairing and agent signatures do not prove safe behavior.

**Working today:** pairing, approval, presence, local controls and queued checks of an owned example. An additional opt-in accepts private website snapshots for offline review. Hermes uses your local model inside an isolated container; active target testing is not enabled.

## Download the relay

Merging to `main` builds a **Linux x86-64** download on the [Releases page](https://github.com/adaki2004/patchriot-relay/releases). Prototype releases use `v0.0.1-dev.<commit>`. Download `patchriot-relay-linux-x86_64.tar.gz` and `SHA256SUMS` from the same release, then:

```sh
sha256sum --ignore-missing --check SHA256SUMS
tar -xzf patchriot-relay-linux-x86_64.tar.gz
cd patchriot-relay
./patchriot-relay demo
```

The archive includes agent/sandbox setup files, service examples and license notices. Use `./patchriot-relay` instead of `cargo run --locked --` in the commands below. Matching relay and protocol source is attached separately; macOS users can build from source. Model weights and the external agent runtime are installed separately.

**Releases do not update running agents automatically.** Stop the relay before replacing its binary, preserve its state directory and configuration, then restart it under the same Unix account. You do not need to pair it again.

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

If the code expires, run `pair` again with the same `--state-dir` and use the new code. Keep the existing state: it contains your device key. A code claimed by another account requires that account or a separate device identity; refreshing the website cannot transfer it.

The Ed25519 key stays in your private state directory. The relay connects outward; it needs no public inbound port. Use HTTPS or an authenticated tunnel outside loopback. Three devices on one machine should declare the same compute group.

Use the **same Unix account** to initialize, pair and run each relay, including its systemd service and local status/pause commands. The relay rejects state owned by another account, even under `sudo`, so an accidental root invocation cannot replace the service's private files.

For a Hermes installation, add `--runtime hermes --runtime-version VERSION --model MODEL` to `init`, using the version you inspected and the installed model name. Each agent needs its own state directory. These details are **operator declarations**, not verified model weights or a security qualification. A connection reports presence until you explicitly opt in to work.

## Control your contribution

| Command after `cargo run --locked --` | Effect |
| --- | --- |
| `status --state-dir .local/relay-one` | Show local pairing and pause state |
| `pause --state-dir .local/relay-one` | Stop accepting work and cancel an active agent check when its monitor observes the pause |
| `resume --state-dir .local/relay-one` | Resume contribution |
| `connect --state-dir .local/relay-one --fixtures` | Explicitly accept the fixed owned example |
| `connect --state-dir .local/relay-one --agents --agent-config .local/agent.json` | Run isolated local-agent checks; setup below |

Without either work option, the connection reports presence only. Heartbeats continue during model execution; stale devices become offline after 30 seconds. Owners can revoke a device in the website. Revoked keys cannot reconnect.

With **three approved devices** connected in the same mode, choose **Reviews → New example review**. Three sequential roles check the same supplied bug and fix. Shared machines under one operator get one active assignment. Reports show device/operator counts; three processes on one host do not imply independent reviewers.

<details>
<summary><strong>Retries, deadlines and connection failures</strong></summary>

Results are saved locally before submission and retried after connection loss. Agent leases renew while healthy, with a saved attempt deadline. Defaults are ten minutes per attempt and 35 minutes per review. Queued execution reserves the final minute for cleanup and submitting its result, so a slow model can report a timeout before the lease expires. Preflight and input delivery consume the same execution budget. The relay uses a monotonic clock and stops when it cannot renew. Server cancellation is checked during renewal; it is not an instantaneous push. Local signals interrupt a running agent directly.

Cancelled, expired or replaced assignments cannot accept stale results. Restarting an agent connection first removes that device's labelled leftover containers. Temporary dispatcher connection failures, server errors and rate limits retry with a delay of up to 40 seconds. Active work still stops if its lease cannot renew. A runner/configuration error or invalid response stops the agent connection for inspection. For owned examples, the state directory keeps one private `last-agent-check.json` (at most 2 MiB) for diagnosis. Website snapshots and their tool transcripts are not written to that file. A bounded pending report is saved until acknowledged. Keep state directories out of Git and shared backups.

For slow or incomplete runs, the relay logs the model's declared finish reason (`length` means its output limit was reached), reported token counts and the agent's stopping condition. Missing metadata stays `not_reported`. These operational logs exclude prompts, answers and provider error text; they do not establish report quality.

</details>

## Execution boundary

The current runner clears inherited environment, uses a temporary directory and limits each fixture to **3 seconds and 8 KiB of combined output**. It terminates its process group on timeout or cancellation.

**Fixture mode** uses process supervision and accepts only compiled-in examples. **Agent mode** uses the container boundary below; it never falls back to host execution. The server supplies a known scenario, lease and—only with explicit opt-in—a saved website snapshot. The operator controls the pinned image and local model endpoint.

Private work requires separate operator approval and requester consent. Assigned operators can see the plaintext they process. Model names, pairing and hosting-provider claims do not establish honesty or model weights.

<details>
<summary><strong>Test the sandbox (operators)</strong></summary>

Use a local Linux Docker engine with cgroup v2; Docker Desktop also runs these probes inside its Linux VM. Build the tiny owned probe, then use its immutable image ID:

```sh
docker build --network=none -t patchriot-sandbox-probe:local sandbox
PATCHRIOT_PROBE_IMAGE=$(docker image inspect --format '{{.Id}}' patchriot-sandbox-probe:local)
cargo run --locked -- sandbox-check --socket /var/run/docker.sock --image "$PATCHRIOT_PROBE_IMAGE"
```

On macOS, pass your actual socket path, commonly `$HOME/.docker/run/docker.sock`. The socket stays outside the task container.

**What gets tested:** no external network or host mounts; a read-only root; non-root execution; 64 MiB RAM, half a CPU and 32 tasks; small, non-executable temporary storage; bounded output; child-process, timeout and cancellation cleanup. The command checks both Docker's settings and what the probe can actually do. A failed check stops the suite and returns a failing exit code.

This runs only owned probes. It does not establish model honesty or rule out kernel/runtime vulnerabilities. A force-killed relay or unavailable Docker engine can prevent cleanup; inspect containers labelled `io.patchriot.sandbox-check=1` after a hard stop. There is no fallback to running customer code on the host.

</details>

<details>
<summary><strong>Run a local agent check (operators)</strong></summary>

This runs Hermes against a tiny, owned access-control example and its **supplied patch**. Try it manually before opting in to queued work. An agent explaining this example has not demonstrated independent vulnerability discovery.

Build the pinned runtime adapter and use its immutable image ID:

```sh
docker build --network=none -t patchriot-agent:local agent
docker image inspect --format '{{.Id}}' patchriot-agent:local
cargo run --locked -- agent-check --config .local/agent.json
```

The operator's configuration has five required fields and an optional time limit; replace the example image and model digest with inspected values:

```json
{
  "docker_socket": "/var/run/docker.sock",
  "image": "sha256:REPLACE_WITH_LOCAL_IMAGE_ID",
  "model_url": "http://127.0.0.1:11434",
  "model": "your-local-model:pilot",
  "model_digest": "REPLACE_WITH_64_CHARACTER_MODEL_DIGEST",
  "max_attempt_seconds": 600
}
```

Use an Ollama model that supports tools and a 64,000-token context. Its **stored model profile** must set `num_ctx 64000`; the compatible API does not apply that setting from chat requests. Inspect `/api/tags` for the digest and `/api/show` for the parameters. The relay checks both before starting. Keep the model server private, reachable only from the relay; the model URL accepts explicit loopback/private IPv4 addresses. This verifies the server's declaration, not remotely attested weights.

After pairing and approval, use `connect --state-dir .local/relay-one --agents --agent-config .local/agent.json` to accept owned-example checks submitted through the website. The profile name or its reported parent must match the device's paired model declaration. A different model needs its own declared device; do not relabel one model's result as another's.

For a slow CPU pilot, set `max_attempt_seconds` to at most `1800` and rebuild the version 3 adapter. Dispatcher must also allow the longer budget; neither side can override the other’s cap. The relay still reserves one minute for cleanup and reporting. This changes time allowances only, not tool permissions, call counts or evidence requirements.

**Boundary:** agent and tools → container pipes → Rust relay → one configured local model. The agent has no external network, host mounts, credentials or Docker socket. It runs non-root with a read-only root, 2 GiB RAM, two CPUs, 128 tasks and bounded temporary storage. The relay permits only selected metadata reads and chat generation; model downloads, deletion and arbitrary endpoints are blocked. Limits are four model calls, 192 output tokens per call, 64 KiB per request, 256 KiB per response, 1 MiB agent output and ten minutes overall by default. CPU prompt processing can take several minutes; this pilot budget is not a production latency target.

Configure the model server's separate CPU/RAM limits as well; the limits above cover the agent and its tools. Manual output includes full bounded tool events; queued reports contain the parsed observations, model/image digests, timing and a bounded explanation. The explanation alone cannot pass the check. Cancellation stops the request and removes the container. If cleanup cannot be confirmed, inspect containers labelled `io.patchriot.agent-check=1` before restarting. **Agent-reported evidence is not independent verification.** The CPU pilot uses one operator; more devices on that host do not add independent reviewers.

The pilot presents its terminal and process-management tools directly, without a separate tool-discovery step. If the runtime retries with a larger output request, the relay caps it at 192 tokens. Retries still count toward the four-call and time limits; the runtime cannot raise those limits. A truncated or missing tool result remains unresolved.

</details>

## Opt in to private website reviews

First test the owned example. Rebuild the pinned adapter from `agent/Dockerfile` and set its new immutable image ID in your configuration. Website review requires adapter version 2 or 3. The current build is version 3; longer CPU budgets require this version.

```sh
cargo run --locked -- connect --state-dir .local/relay-one --agents --agent-config .local/agent.json --website-reviews
```

An admin must allow **private reviews** for the device. The requester then selects three exact devices, sees their operators and declared models, and consents to sharing one snapshot and the earlier reports. This flag does not bypass those permissions. Shared machines run sequentially and remain labelled as shared infrastructure.

**Operators can see the plaintext they process.** A completed report is not a security certificate; claims still need evidence and human review.

<details>
<summary><strong>What an agent receives and how reports are checked</strong></summary>

The relay downloads evidence only for its active lease, checks its hash and sends bounded data through the container's stdin. A fixed reader runs inside the container before inference; the agent receives its bounded output and reviews it. It shortens combined previews to fit, marks truncated text and preserves the source hashes. Missing text in a preview does not prove absence from the page. That required read counts as a tool execution, not a check independently chosen by the model. Saved HTML/scripts are inspected as text; there is no browsing, target networking or host execution. Snapshot files live in container temporary storage and disappear with cleanup. Operators can see plaintext, so only accept data you are permitted to process.

Each role gets at most four model calls, 512 output tokens per call and the earlier of its saved lease deadline and operator time limit. The relay requests a fixed JSON report format, with source hashes selected from the captured resources; the runtime cannot change it. Formatting does not establish accuracy: quotations must still match the cited resource, and the reasoning can still be wrong. Website mode omits the runtime's optional model-specific instructions to keep executing tools; the task supplies its own review instructions, and tools remain available. Later roles inspect earlier claims; no live exploit or patch test is implied. **A complete report is not a security certificate.** Invalid reports and unsupported quotations remain unresolved. Removing private approval stops affected reviews; it cannot recall information already seen.

</details>

## Check the controls

GitHub checks run when a ready PR targets `main` and when that PR changes. Draft PRs and ordinary branch pushes do not run checks; newer PR commits cancel superseded runs. Run the commands below locally while developing.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
python3 -m unittest discover -s agent -p 'test_*.py'
cargo run --locked -- fixture slow --timeout-ms 100
cargo run --locked -- fixture noisy --max-output-bytes 1024
```

The last two commands intentionally fail. Tests cover signals, descendants, environment leakage and malformed results. Linux CI additionally builds the probe and runs the Docker integration tests. **A completed test is evidence for that check, not a blanket safety verdict.**

For real queue/retry tests, see core's `scripts/smoke-reviews.py`. CI uses a pinned protocol commit; private core access needs a `READ_TOKEN` Actions secret with read-only access to core. An existing `PATCHRIOT_READ_TOKEN` secret also works and takes precedence. Keep token values out of source.

<details>
<summary><strong>Install as a Linux service</strong></summary>

[deploy/patchriot-relay-demo@.service](deploy/patchriot-relay-demo@.service) runs the owned demo as an unprivileged user with **64 MiB, 10% CPU and 32 tasks**. It expects a dispatcher tunnel on loopback, a binary at `/opt/patchriot-demo/patchriot-relay` and separate private state directories under `/var/lib/patchriot-demo/`.

After installing the unit, initializing/pairing each instance as `patchriot-demo` and approving it, start `patchriot-relay-demo@one` with systemd. Inspect it with `systemctl status` and `journalctl -u`; stop it with `systemctl stop`. The unit is a fixture pilot, not the future customer-code sandbox.

For continuous owned-agent checks, [deploy/patchriot-relay-agent@.service](deploy/patchriot-relay-agent@.service) uses a dedicated `patchriot-agent` account, a binary at `/opt/patchriot-agent/patchriot-relay`, private paired state at `/var/lib/patchriot-agent/one` and operator configuration at `/etc/patchriot-agent/one.json`. Replace `one` for each instance. Give that account ownership of its state; keep binaries/configuration administrator-owned and configuration readable by its group. **Its Docker access is privileged; trust this service account.** Task containers never receive the socket.

The agent unit allows loopback connections by default. For a private model-server address, add only that address through a local systemd `IPAddressAllow` drop-in. Start with `systemctl start patchriot-relay-agent@one`; enable at boot only after testing. Three approved instances sharing a compute group can take turns automatically. Relay service limits are separate from the agent-container and model-server limits.

</details>

## What's next

Improve review evidence with stronger models and independent operators. GPU trials and confidential execution follow the CPU pilot. No stake or on-chain identity is required.

Original material is [AGPL-3.0-only](LICENSE); attribution is in [NOTICE](NOTICE). Model weights and external runtimes retain their own licenses. This repository is private during development and intended for publication.
