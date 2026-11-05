"""Versioned, bounded checks. A match is a lead for review, never a safety certificate."""
import json
import re
import secrets
import time
from urllib.parse import urljoin, urlsplit

VERSION = "web-checks-v1"


def denied_anonymous(scope, evidence):
    if evidence.get("authenticated") or evidence.get("error"):
        return False
    if evidence.get("status") in (401, 403):
        return True
    if evidence.get("status") not in (302, 303, 307, 308):
        return False
    login = scope.get("session_login") or {}
    location = evidence.get("headers", {}).get("location")
    if not login or not location:
        return False
    try:
        base = urlsplit(evidence["url"])
        destination = urlsplit(urljoin(evidence["url"], location))
        return (
            (destination.scheme, destination.hostname, destination.port or 443)
            == (base.scheme, base.hostname, base.port or 443)
            and not destination.username and not destination.password
            and destination.path == login.get("page_path", login.get("path"))
        )
    except (ValueError, KeyError):
        return False


def run(scope, deadline, fetch, record):
    started, observed = time.monotonic(), int(time.time())
    checks, refs = [], []

    def get(origin, path, **kwargs):
        if time.monotonic() >= deadline:
            return {}
        try:
            reply = fetch("GET", origin + path, **kwargs)
        except (OSError, ValueError):
            return {}
        evidence = reply.get("evidence", {})
        if evidence.get("id"):
            refs.append(evidence["id"])
        return reply

    def add(origin, key, title, status, summary, replies=()):
        ids = [r.get("evidence", {}).get("id") for r in replies]
        checks.append(dict(id=key, origin=origin, title=title, status=status, summary=summary,
                           evidence_ids=list(dict.fromkeys(i for i in ids if i))))

    def usable(reply):
        e = reply.get("evidence", {})
        return e.get("status") is not None and not e.get("error") and not reply.get("error")

    for origin in scope["origins"]:
        root = get(origin, "/", authenticated=False)
        headers = root.get("evidence", {}).get("headers", {})
        valid = usable(root)
        missing = [name for name in ("strict-transport-security", "x-content-type-options", "content-security-policy") if not headers.get(name)]
        add(origin, "headers", "Browser security headers", "inconclusive" if not valid else "finding" if missing else "completed",
            "No usable response." if not valid else "Absent in this response: " + ", ".join(missing) + ". Hardening advice; not proof of an exploit." if missing else "The checked headers were present; their full policy was not audited.", [root])

        control = get(origin, "/patchriot-missing-" + secrets.token_hex(8), authenticated=False)
        for key, path, title, pattern in [
            ("git-config", "/.git/config", "Exposed Git configuration", r"(?m)^\s*\[core\]\s*$"),
            ("environment", "/.env", "Exposed environment configuration", r"(?m)^(?:DATABASE_URL|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*=\s*\S+"),
        ]:
            probe = get(origin, path, authenticated=False)
            ok = usable(probe) and usable(control)
            e = probe.get("evidence", {})
            matched = e.get("status") == 200 and bool(re.search(pattern, probe.get("body", "")))
            same = probe.get("body") == control.get("body")
            status = "inconclusive" if not ok or matched and same else "finding" if matched else "completed"
            add(origin, key, title, status,
                "Configuration-shaped response differs from the random-path control. Review exposure; values are not repeated here." if status == "finding" else
                "Could not distinguish this response from a valid control." if status == "inconclusive" else
                "No matching configuration signature in the retained response. This does not cover other files.", [probe, control])

        foreign = "https://patchriot-control.invalid"
        cors = get(origin, "/", headers={"Origin": foreign}, authenticated=False)
        ch = cors.get("evidence", {}).get("headers", {})
        risky = ch.get("access-control-allow-origin") == foreign and ch.get("access-control-allow-credentials", "").lower() == "true"
        add(origin, "cors", "Cross-origin response policy", "inconclusive" if not usable(cors) else "finding" if risky else "completed",
            "An arbitrary origin was accepted with credentials. Confirm whether sensitive data is accessible before assigning impact." if risky else
            "No credentialed arbitrary-origin response observed on the homepage." if usable(cors) else "The comparison request did not complete.", [root, cors])

        marker = "patchriot_probe_" + secrets.token_hex(6)
        reflection = get(origin, "/?patchriot_probe=" + marker, authenticated=False)
        reflected = marker in reflection.get("body", "")
        add(origin, "reflection", "Benign query reflection", "inconclusive" if not usable(reflection) or reflected else "completed",
            "The marker was reflected. Context and browser execution need review; reflection alone is not XSS." if reflected else
            "The marker was not reflected in the retained homepage response." if usable(reflection) else "The probe did not complete.", [reflection, root])

        if scope.get("authentication"):
            path = scope["auth_check_path"]
            anonymous = get(origin, path, authenticated=False)
            signed = get(origin, path)
            ae, se = anonymous.get("evidence", {}), signed.get("evidence", {})
            confirmed = usable(anonymous) and usable(signed) and denied_anonymous(scope, ae) and 200 <= se.get("status", 0) < 300 and se.get("authenticated") is True
            add(origin, "test-account", "Test-account access and anonymous control", "completed" if confirmed else "inconclusive",
                "The supplied account reached the protected URL; the anonymous control was denied." if confirmed else
                "Could not prove authenticated access. Check the protected URL and test account; this is a coverage gap, not a vulnerability finding.", [anonymous, signed])
        else:
            add(origin, "test-account", "Test-account access", "skipped", "No test account was supplied.")
        add(origin, "forms", "Form and state-changing tests", "inconclusive" if "POST" in scope["methods"] else "skipped",
            "POST is permitted. Inspect the agents' actual requests and findings; permission alone does not prove a form was tested." if "POST" in scope["methods"] else "This request permits read-only methods; no forms are submitted.")
        add(origin, "browser", "Browser login, SSO and client-side execution", "unsupported", "This runner does not drive a browser or complete interactive login challenges.")

    complete = all(c["status"] != "inconclusive" for c in checks)
    return record("patchriot-baseline", VERSION, ["--profile", VERSION], started, observed, refs,
                  json.dumps({"profile": VERSION, "checks": checks}), 0,
                  "timeout" if time.monotonic() >= deadline and not complete else None)
