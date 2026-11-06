"""ARES-derived web fingerprints, executed only through the scoped HTTP broker.

Path/header/body signatures are adapted from network/http_fingerprint.py at
d09251374a82042f2d8069818febcb08289aa3d5 (MIT, Copyright 2026 Mafifrizi).
See ares-LICENSE.txt. The upstream framework, transport and severity rules are
not used. Observations are leads for the reviewer, not vulnerability verdicts.
"""
import json
import re
import secrets
import time

from web_tools import allowed, fetch_checked, record
from live_http import request

COMMIT = "d09251374a82042f2d8069818febcb08289aa3d5"
VERSION = "http-surface-v1+" + COMMIT
SOURCE = "https://github.com/Mafifrizi/ARES/blob/" + COMMIT + "/ares/modules/network/http_fingerprint.py"

# Reused ARES signatures. Every path is read anonymously on the approved origin.
PATHS = (
    "/admin", "/admin/login", "/.env", "/.git/HEAD", "/wp-admin/",
    "/wp-login.php", "/phpmyadmin/", "/manager/html", "/api/v1/",
    "/api/swagger.json", "/swagger-ui.html", "/actuator", "/actuator/env",
    "/console", "/jenkins", "/solr/", "/kibana", "/grafana",
    "/.htpasswd", "/server-status", "/elmah.axd", "/trace.axd",
)
HEADER_SIGNATURES = (
    ("server", r"Apache[/\s]([0-9.]+)", "Apache"),
    ("server", r"nginx[/\s]([0-9.]+)", "nginx"),
    ("server", r"Microsoft-IIS[/\s]([0-9.]+)", "IIS"),
    ("server", r"Jetty[/\s]([0-9.]+)", "Jetty"),
    ("server", r"Tomcat", "Apache Tomcat"),
    ("x-powered-by", r"PHP[/\s]([0-9.]+)", "PHP"),
    ("x-powered-by", r"ASP\.NET", "ASP.NET"),
    ("x-aspnet-version", r"([0-9.]+)", "ASP.NET"),
    ("x-generator", r".+", "Generator"),
    ("x-drupal-cache", r".+", "Drupal CMS"),
    ("x-wordpress", r".+", "WordPress"),
)
BODY_SIGNATURES = (
    (r"wp-content|wp-includes", "WordPress"), (r"Joomla", "Joomla"),
    (r"Drupal\.settings", "Drupal"), (r"window\.django", "Django"),
    (r"laravel_session|laravel_token", "Laravel"), (r"<title>[^<]*GitLab", "GitLab"),
    (r"Jenkins", "Jenkins"), (r"Grafana", "Grafana"),
)
MAX_REQUESTS = len(PATHS) + 2


def usable(reply):
    evidence = reply.get("evidence", {})
    return (isinstance(evidence.get("id"), int) and evidence["id"] > 0
            and isinstance(evidence.get("status"), int)
            and not evidence.get("error") and not reply.get("error"))


def fingerprints(reply):
    """Only report signature labels; never copy arbitrary headers or secrets."""
    if not usable(reply):
        return []
    headers = reply["evidence"].get("headers", {})
    labels = {label for name, pattern, label in HEADER_SIGNATURES
              if re.search(pattern, str(headers.get(name, ""))[:4096], re.I)}
    body = reply.get("body", "")[:5000]
    labels.update(label for pattern, label in BODY_SIGNATURES if re.search(pattern, body, re.I))
    return sorted(labels)


def content_signatures(path, body):
    """Recognize a few response shapes, without extracting values or claiming impact."""
    body = body[:128 * 1024]
    signatures = []
    if path == "/.git/HEAD" and re.fullmatch(r"\s*ref: refs/heads/[\w./-]+\s*", body):
        signatures.append("git_head")
    if path == "/.env" and re.search(r"(?m)^(?:DATABASE_URL|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*=\s*\S+", body):
        signatures.append("environment_assignments")
    if path == "/.htpasswd" and re.search(r"(?m)^[^\s:<>]{1,100}:\$(?:apr1|2[aby])\$", body):
        signatures.append("password_file_shape")
    if path == "/server-status" and "Apache Server Status" in body and re.search(r"Server (?:Version|Uptime)", body):
        signatures.append("server_status_page")
    if path in ("/api/swagger.json", "/actuator", "/actuator/env"):
        try:
            data = json.loads(body)
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict):
            if path == "/api/swagger.json" and (isinstance(data.get("openapi"), str) or isinstance(data.get("swagger"), str)) and isinstance(data.get("paths"), dict):
                signatures.append("api_schema")
            if path == "/actuator" and isinstance(data.get("_links"), dict) and "self" in data["_links"]:
                signatures.append("actuator_links")
            if path == "/actuator/env" and isinstance(data.get("propertySources"), list):
                signatures.append("actuator_environment")
    return signatures


def observation(path, reply, root, control):
    evidence = reply.get("evidence", {})
    status = evidence.get("status")
    result = {"path": path, "status": status, "evidence_id": evidence.get("id"),
              "technology_hints": fingerprints(reply), "content_signatures": []}
    if not usable(reply):
        state = "unavailable"
    elif status in (401, 403):
        state = "access_restricted"
    elif status in (404, 410):
        state = "not_found"
    elif 300 <= status < 400:
        state = "redirect_not_followed"
    elif not 200 <= status < 300:
        state = "non_success_response"
    elif any(usable(other) and reply.get("body") == other.get("body") for other in (root, control)):
        state = "same_as_home_or_missing_path"
    else:
        # A successful status, framework name or public API schema is not a flaw.
        state = "response_observed"
        signatures = content_signatures(path, reply.get("body", ""))
        if signatures and usable(control):
            result["content_signatures"] = signatures
            result["control_evidence_id"] = control["evidence"]["id"]
            state = "content_lead_needs_review"
        elif signatures:
            state = "missing_control"
    result["state"] = state
    result["response_truncated"] = bool(evidence.get("truncated"))
    return result


def run(origin, deadline, fetch=request):
    started, observed_at = time.monotonic(), int(time.time())
    refs, probes = [], []
    root, control = {}, {}
    stop = None
    if not allowed(origin, origin + "/"):
        stop = "invalid_origin"
    else:
        paths = ("/", "/patchriot-ares-control-" + secrets.token_hex(8), *PATHS)
        for index, path in enumerate(paths):
            if time.monotonic() >= deadline:
                stop = "deadline"
                break
            reply = fetch_checked(fetch, "GET", origin + path, authenticated=False)
            evidence = reply.get("evidence", {})
            if isinstance(evidence.get("id"), int) and evidence["id"] > 0:
                refs.append(evidence["id"])
            if index == 0:
                root = reply
            elif index == 1:
                control = reply
            else:
                probes.append(observation(path, reply, root, control))
            # Do not keep hammering a denied transport or a rate-limited target.
            if not usable(reply) or evidence["status"] in (429, 503):
                stop = "request_failed" if not usable(reply) else "target_backoff"
                break
    output = {"component": "ARES network.http_fingerprint (adapted)", "source": SOURCE,
              "source_commit": COMMIT, "origin": origin, "stop_reason": stop or "completed",
              "request_count": len(refs), "path_count": len(probes),
              "root_evidence_id": root.get("evidence", {}).get("id"),
              "control_evidence_id": control.get("evidence", {}).get("id"),
              "technology_hints": fingerprints(root), "observations": probes,
              "limitations": ["Only the listed anonymous HTTP reads ran, not the full ARES framework or a port scan.",
                              "Fingerprints and content matches are leads. Public documentation, login pages, redirects and denials are not vulnerabilities by themselves.",
                              "No redirects followed, credentials extracted or other origins contacted. Only broker-recorded headers and bounded response bodies were inspected."]}
    failure = "timeout" if stop == "deadline" else "request_error" if stop in ("invalid_origin", "request_failed") else "incomplete" if stop else None
    return record("ares-web-surface", VERSION, [origin, "--max-requests", str(MAX_REQUESTS)],
                  started, observed_at, refs, json.dumps(output), 1 if failure else 0, failure)
