"""Pinned web checks. Every target request crosses the relay's scope broker.

Nuclei sees a loopback mirror of one approved HTTPS origin. Its container has no
external network, and only our three installed templates are selected. Scanner
matches are leads; controls and another role must assess their actual impact.
"""
import hashlib
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.error import URLError

from live_http import request

PROFILE = "owasp-web-v1"
VERSION = "1"
NUCLEI = "/usr/local/bin/nuclei"
TEMPLATES = "/patchriot/templates"
MAX_OUTPUT = 24 * 1024
MAX_PAGES = 12
NUCLEI_VERSION = "3.11.1"


def fetch_checked(fetch, method, url, headers=None, **kwargs):
    """A transport failure stays incomplete; never replace it with HTTP 200."""
    try:
        return fetch(method, url, headers or {}, **kwargs)
    except (OSError, ValueError, URLError):
        return {"error": "request_error", "body": "", "evidence": {}}


def allowed(origin, candidate):
    try:
        url = urlsplit(candidate)
        return (url.scheme == "https" and not url.username and not url.password
                and not url.fragment and f"{url.scheme}://{url.netloc}" == origin
                and len(candidate) <= 4096 and "\\" not in candidate
                and not any(ord(c) < 32 or c.isspace() for c in candidate))
    except ValueError:
        return False


class Links(HTMLParser):
    def __init__(self, base, origin):
        super().__init__()
        self.base, self.origin, self.links, self.forms = base, origin, [], []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in ("a", "script", "link"):
            raw = values.get("src") if tag == "script" else values.get("href")
            if raw:
                parsed = urlsplit(urljoin(self.base, raw))
                candidate = urlunsplit(parsed._replace(fragment=""))
                if allowed(self.origin, candidate) and candidate not in self.links:
                    self.links.append(candidate)
        if tag == "form" and len(self.forms) < 20:
            self.forms.append({"action": (values.get("action") or self.base)[:1024],
                               "declared_method": (values.get("method") or "GET").upper()[:16],
                               "executed": False})


def capture(argv, timeout=30, limit=MAX_OUTPUT):
    """Fixed argv, bounded output and a killed process group on timeout/overflow."""
    started = time.monotonic()
    output = bytearray()
    failure = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, start_new_session=True)
    except OSError:
        return {"exit_code": None, "output": "tool unavailable", "failure": "unavailable", "duration_ms": 0}
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            while poll.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    failure = "timeout"
                    break
                for key, _ in poll.select(min(remaining, .25)):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        poll.unregister(key.fileobj)
                        break
                    available = max(0, limit - len(output))
                    output.extend(chunk[:available])
                    if len(chunk) > available:
                        failure = "output_limit"
                        break
                if failure:
                    break
        if failure:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            code = child.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
            failure = failure or "timeout"
    finally:
        child.stdout.close()
    return {"exit_code": code, "output": output.decode("utf-8", errors="replace"),
            "failure": failure, "duration_ms": round((time.monotonic() - started) * 1000)}


def record(tool, version, argv, started, observed_at, evidence_ids, output, exit_code=0, failure=None):
    # Terminal control characters are not report formatting or JSONB content.
    normalized = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    raw = "".join(c for c in normalized if ord(c) >= 32 or c in "\n\t").encode()
    return {"tool": tool, "version": version, "arguments": argv,
            "started_at": observed_at, "duration_ms": round((time.monotonic() - started) * 1000),
            "exit_code": exit_code, "failure": failure, "evidence_ids": list(dict.fromkeys(evidence_ids)),
            "output_sha256": hashlib.sha256(raw).hexdigest(),
            "output_excerpt": raw[:MAX_OUTPUT].decode("utf-8", errors="ignore"),
            "output_truncated": len(raw) > MAX_OUTPUT or failure == "output_limit"}


def crawl(origin, deadline, fetch=request):
    started, observed = time.monotonic(), int(time.time())
    queue = [origin + "/", origin + "/robots.txt", origin + "/sitemap.xml"]
    seen, pages, forms, refs = set(), [], [], []
    while queue and len(seen) < MAX_PAGES and time.monotonic() < deadline:
        url = queue.pop(0)
        if url in seen or not allowed(origin, url):
            continue
        seen.add(url)
        reply = fetch_checked(fetch, "GET", url)
        evidence = reply.get("evidence", {})
        if evidence.get("id"):
            refs.append(evidence["id"])
        pages.append({"url": url, "status": evidence.get("status"), "evidence_id": evidence.get("id"), "error": reply.get("error") or evidence.get("error")})
        if evidence.get("status") != 200:
            continue
        body = reply.get("body", "")[:128 * 1024]
        content = evidence.get("headers", {}).get("content-type", "")
        if "html" in content:
            parser = Links(url, origin)
            try:
                parser.feed(body)
                queue.extend(parser.links[:24])
                forms.extend(parser.forms[:20])
            except (ValueError, RecursionError):
                pass
        if url.endswith("robots.txt"):
            for line in body.splitlines()[:100]:
                if line.lower().startswith(("allow:", "disallow:")):
                    path = line.split(":", 1)[1].strip()
                    if path.startswith("/") and "*" not in path and "$" not in path:
                        queue.append(origin + path)
    output = json.dumps({"pages": pages, "forms_observed_not_submitted": forms[:20], "remaining_links": len(queue),
                         "limitations": ["Static links only; no JavaScript execution, account login or form submission."]})
    failure = "request_error" if any(p["error"] for p in pages) else ("timeout" if queue and time.monotonic() >= deadline else None)
    return record("patchriot-crawl", VERSION, [origin, "--max-pages", str(MAX_PAGES)], started, observed, refs, output,
                  1 if failure else 0, failure)


class ScopeMirror:
    """The scanner's loopback URL maps to exactly one approved origin."""
    def __init__(self, origin, deadline, fetch=request, methods=None):
        self.methods = methods or ["GET", "HEAD", "OPTIONS"]
        self.origin, self.fetch, self.deadline, self.refs = origin, fetch, deadline, []
        mirror = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.exchange()

            def do_HEAD(self):
                self.exchange()

            def do_OPTIONS(self):
                self.exchange()

            def do_POST(self):
                self.exchange()

            def exchange(self):
                self.close_connection = True
                # BaseHTTPRequestHandler normalizes a leading //; reject the
                # original target before that normalization can hide it.
                raw_target = self.requestline.split(" ", 2)[1]
                raw_length = self.headers.get("Content-Length", "0")
                if not raw_length.isdecimal() or len(self.headers.get_all("Content-Length", [])) > 1:
                    self.send_error(400); return
                length = int(raw_length)
                if (self.command not in mirror.methods or length > 16384 or self.command != "POST" and length != 0
                        or time.monotonic() >= mirror.deadline or not self.path.startswith("/")
                        or raw_target.startswith("//") or not allowed(origin, origin + self.path)
                        or self.headers.get("Transfer-Encoding")
                        or self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}"):
                    self.send_error(400)
                    return
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "connection", "content-length", "accept-encoding", "user-agent")}
                try:
                    self.connection.settimeout(2)
                    raw = self.rfile.read(length) if length else b""
                    if len(raw) != length:
                        self.send_error(400); return
                    data = raw.decode("utf-8") if length else None
                    if data is not None and self.headers.get("Content-Type", "").split(';')[0].strip() not in ("application/json", "application/x-www-form-urlencoded"):
                        self.send_error(415); return
                    kwargs = {"data": data} if data is not None else {}
                    reply = fetch_checked(mirror.fetch, self.command, origin + self.path, headers, **kwargs)
                    evidence = reply.get("evidence", {})
                    if evidence.get("id"):
                        mirror.refs.append(evidence["id"])
                    status = evidence.get("status")
                    payload = reply.get("body", "").encode() if status else b"relay request unavailable"
                    self.send_response(status or 502)
                    for name, value in evidence.get("headers", {}).items():
                        if name.lower() not in ("connection", "content-length", "transfer-encoding", "content-encoding") and "\r" not in value and "\n" not in value:
                            if name.lower() == "location":
                                destination = urljoin(origin + self.path, value)
                                if allowed(origin, destination):
                                    parsed = urlsplit(destination)
                                    value = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(payload)
                except (ValueError, OSError):
                    self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def scanner(origin, deadline, fetch=request, execute=capture):
    started, observed = time.monotonic(), int(time.time())
    version = execute([NUCLEI, "-version"], timeout=3)
    if version["exit_code"] != 0 or NUCLEI_VERSION not in version["output"]:
        return record("nuclei", "unavailable", [NUCLEI, "-version"], started, observed, [], version["output"],
                      version["exit_code"], version["failure"] or "version_mismatch")
    with ScopeMirror(origin, deadline, fetch) as mirror:
        argv = [NUCLEI, "-u", mirror.url, "-t", TEMPLATES, "-jsonl", "-silent", "-omit-raw", "-omit-template",
                "-no-stdin", "-duc", "-ni", "-dr", "-c", "1", "-bs", "1", "-rl", "2", "-timeout", "10", "-retries", "0"]
        run = execute(argv, timeout=max(1, min(30, deadline-time.monotonic())))
        # Keep the scanner's real output. Its loopback addresses and generated
        # curl snippets are not the upstream request; the broker's records are.
        output = run["output"]
        failure = run["failure"] or ("incomplete" if not mirror.refs else None)
        return record("nuclei", NUCLEI_VERSION, argv, started, observed, mirror.refs, output,
                      run["exit_code"], failure)


def controls(origin, deadline, previous, fetch=request, auth_check_path=None):
    started, observed = time.monotonic(), int(time.time())
    probes = [(origin + "/", {}, False), (origin + "/", {"Origin": "null"}, False),
              (origin + "/patchriot-control-" + os.urandom(8).hex(), {}, False)]
    if auth_check_path and allowed(origin, origin + auth_check_path):
        probes.extend([(origin + auth_check_path, {}, False), (origin + auth_check_path, {}, True)])
    for prior in previous:
        cited = {n for f in (prior.get("assessment") or {}).get("findings", []) for n in f.get("evidence_ids", [])}
        for e in prior.get("evidence", []):
            if e.get("id") in cited and e.get("method") == "GET" and allowed(origin, e.get("url", "")):
                probes.append((e["url"], e.get("request_headers", {}), e.get("authenticated", False)))
    # Several roles may cite the same request. Repeat it once per follow-up,
    # preserving anonymous/authenticated comparisons and distinct headers.
    unique = {}
    for url, headers, authenticated in probes:
        unique.setdefault((url, json.dumps(headers, sort_keys=True), authenticated), (url, headers, authenticated))
    probes = list(unique.values())
    refs, results = [], []
    for url, headers, authenticated in probes[:12]:
        if time.monotonic() >= deadline:
            break
        reply = fetch_checked(fetch, "GET", url, headers, authenticated=authenticated)
        e = reply.get("evidence", {})
        if e.get("id"):
            refs.append(e["id"])
        results.append({"url": url, "status": e.get("status"), "sha256": e.get("body_sha256"), "evidence_id": e.get("id"), "error": reply.get("error") or e.get("error")})
    output = json.dumps({"controls_and_repeats": results, "limitations": ["Fresh requests do not automatically confirm the previous claim. Compare bodies, not just status codes."]})
    failure = "request_error" if any(r["error"] for r in results) else ("timeout" if len(results) < min(len(probes), 12) else None)
    return record("patchriot-controls", VERSION, [origin, "--max-requests", "12"], started, observed, refs, output,
                  1 if failure else 0, failure)


def fetch_checked_request(method, url, **kwargs):
    return fetch_checked(request, method, url, **kwargs)


def run(scope, previous, directory=Path("/work"), emit=lambda _: None, role="investigator"):
    from live_review import discovery_plan
    deadline = time.monotonic() + 180
    plan = discovery_plan(role, scope, previous)
    selected = {p['tool'] for p in plan if p['action'] in ('run', 'recover')}
    records = []
    if 'patchriot-baseline' in selected:
        import baseline
        initial = baseline.run(scope, deadline, fetch_checked_request, record)
        records.append(initial)
        emit(initial)
    for origin in scope["origins"]:
        checks = []
        if 'patchriot-crawl' in selected:
            checks.append(lambda: crawl(origin, deadline))
        if 'nuclei' in selected:
            checks.append(lambda: scanner(origin, deadline))
        checks.append(lambda: controls(origin, deadline, previous, auth_check_path=scope.get("auth_check_path") if scope.get("authentication") else None))
        for check in checks:
            if time.monotonic() >= deadline:
                break
            result = check()
            records.append(result)
            emit(result)
    result = {"profile": PROFILE, "role": role, "tool_runs": records, "discovery_plan": plan,
              "limitations": ["Only three curated Nuclei templates; no general CVE, credential, authenticated, headless or network scan.",
                              "The scanner receives selected headers and decoded text through the broker; use recorded target requests as the source of evidence.",
                              "Scanner host/IP and curl snippets describe a loopback mirror, not the target's IP, TLS or exact upstream headers.",
                              "All matches are hypotheses until controls and review establish impact."]}
    (directory / "tool-results.json").write_text(json.dumps(result))
    return result
