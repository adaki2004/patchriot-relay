# Security

Report vulnerabilities privately through this repository’s **Security → Report a vulnerability** option when available, or through your existing private maintainer contact. If neither is available, open an issue asking for a private reporting channel without including exploit details, credentials or customer data.

Include the affected commit, component, a minimal reproduction using your own fixture and the expected versus observed behavior. Do not test other customers, access their reports or run disruptive probes to demonstrate a problem.

## Trust boundaries

The dispatcher and approved host operator are trusted with assigned plaintext. TLS authenticates the dispatcher; its instructions are not an independent proof of the customer’s legal authority. The broker enforces the exact assigned origins, methods, budgets and credentials even when model output is hostile. Docker access makes the relay service account privileged; task containers must never receive its socket or secrets.

Use the current reviewed release with its matching components. PR checks include dependency advisories and redacted secret scanning; maintainers can run the Security workflow manually between releases. Passing checks is not a security certification. Keep secrets and private evidence outside Git and rotate exposed credentials rather than merely deleting them.
