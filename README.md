# Patchriot Relay

The Rust application connecting a patcher's PC or VPS to Patchriot. Patchers contribute a running agent and the inference capacity it uses to investigate code, run permitted tools and return evidence. This is not a marketplace for raw model endpoints. Hermes is the first planned agent adapter; the relay does not include model weights.

**Status:** repository foundation and design only. There is no Patchriot binary, install command or live pairing service yet.

**DON'T TRUST! VERIFY!** Read this README yourself or ask your own agent to inspect the implementation, permissions, dependencies and release provenance before running it.

## Lifecycle

1. Generate a device key locally. Prove possession in a short-lived, one-use pairing request, then approve it from the signed-in account with fresh authentication.
2. Check host isolation, runtime compatibility and a bounded capability fixture. Pairing does not grant eligibility for private work; the dispatcher separately approves the operator and machine.
3. Connect outward over authenticated TLS. No public inbound worker port is needed.
4. Accept a signed, unexpired assignment binding the job, attempt, input hashes, scope and resource limits. Local limits may be stricter.
5. Run a disposable agent session. Return bounded artifacts through job-scoped credentials; retain a durable completion record until acknowledged.
6. Pause to stop accepting new work. Cancellation terminates the process tree and reports whether termination was confirmed. Revocation blocks new work and invalidates future artifact access; it cannot erase plaintext already received by an operator.

Pairing, run, status, doctor, pause and unpair are intended CLI operations, not commands available today. Diagnostics must explain failed checks. Model probes with a cost require an explicit bounded run.

## Easy pairing, separate approval

Sign in with Google, choose **Become a patcher**, then follow the relay's pairing link or enter its short-lived code in the dashboard. The browser shows the device being connected; the account confirms that exact device. Collect the operator profile during this flow rather than requiring a separate application first.

Ask for a display name, a contact address confirmed through sign-in, whether this is their own machine or a VPS, and confirmation that they control it and accept the private-work handling rules. A GitHub or professional profile is optional context for manual approval. Do not request SSH passwords, cloud credentials, model-provider keys or identity documents in this form.

Where supported, the relay detects agent/runtime version, declared inference model, host capacity and sandbox capabilities; the operator reviews what will be sent and sets local limits. These details describe the agent's capabilities, not proof of model identity. No secrets or full local environment dumps are uploaded.

Show separate states: **paired → checks running → awaiting approval → approved**, with **changes requested** and **paused/revoked** when applicable. The admin sees the submitted profile and check results and can approve or explain what is missing. Until approval, only bounded owned-fixture checks are allowed; no private customer jobs. Require an additional authentication factor before approval grants private-work access, with fresh authentication for later device additions and sensitive changes.

## Execution boundary

The relay is Rust; Hermes and model servers remain external dependencies. Start with a self-hosted endpoint and one active task per physical pilot machine. Use a fresh agent profile without personal memory, plugins, account files or target-provided agent settings. Never load repository hooks or tool servers as trusted configuration.

Device keys, provider credentials and the host home stay outside the task. A restricted inference gateway supplies allowed model access. Default task networking off; permit only required destinations through an enforced policy. No Docker socket, privileged container or unrelated filesystem mount is available inside the task.

Repository tests, package installers and reproduction scripts are untrusted programs too. Enforce CPU, memory, disk, process, output and time limits. Refuse execution if required sandbox checks fail. Prompt screening, including Jev when configured, supplements these limits and cannot relax them.

Record model/revision/quantization declarations separately from observed capability tests. Prompts, hashes reported by a node and signatures do not prove remote model weights or ablation. External providers require permission covering the actual customer work; no silent paid-API fallback is allowed.

## Review roles and first experiment

The same relay can execute an investigation, a fresh reproduction attempt or a challenge/patch-validation assignment. Each uses a separate workspace and bounded instructions. A reviewer does not receive other agents' verdicts before recording its own assessment. Result signatures establish attribution, not correctness.

The default product profile targets three agents, preferably across different model families and approved operators. A two-agent profile must be agreed before payment. Separate runs on one VPS can test the workflow sequentially, but remain one operator and must be labeled that way. Do not claim three independent machines or load three 30B models concurrently on a 64 GB host.

After VPS access is provided, measure hardware, available memory and isolation support before selecting a licensed model. Start with an owned vulnerable fixture and a clean control. Record reproduction, patch behavior, time, peak memory, tool failures and cancellation. RAM alone does not establish acceptable inference speed.

## Checks before customer work

- Pairing replay/expiry, device revocation and unsupported protocol/runtime rejection.
- Target instructions, hooks, symlinks and archive paths cannot access host canaries or change execution policy.
- Private-network/metadata access and unapproved redirects fail at the network boundary.
- Cancellation and deadlines terminate child processes; stale results cannot become accepted work.
- Reconnect safely replays one completion; altered replays and oversized artifacts are rejected.
- Independent validation rechecks the original failure and proposed fix without approving itself.
- Logs and outputs contain neither credentials nor another job's data.

A future automatic updater needs signed complete release manifests, draining, smoke tests and rollback. The first fixture does not need an updater. These tests establish specific boundaries, not absolute sandbox safety.

## License

Original material is [AGPL-3.0-only](LICENSE); the publication target is a public repository. See [NOTICE](NOTICE) for attribution. Model weights and external runtimes retain their own licenses. Customer repositories, reports and credentials are never committed here.
