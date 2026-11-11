"""Agent-side helper. Requests go through the relay's scoped, recorded broker."""
import argparse
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

EVIDENCE_DIRECTORY = Path('/work/http-evidence')


def binary_response(reply):
    """The broker's decoded text is not a faithful binary download."""
    headers = reply.get('evidence', {}).get('headers', {})
    content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), '')
    media = content_type.split(';', 1)[0].strip().lower()
    binary_type = (not media.endswith(('+json', '+xml')) and
                   media.startswith(('image/', 'audio/', 'video/', 'font/', 'application/vnd.'))) or media in {
        'application/pdf', 'application/zip', 'application/gzip',
        'application/x-gzip', 'application/x-7z-compressed', 'application/x-rar-compressed',
        'application/x-tar', 'application/x-bzip2', 'application/x-xz', 'application/msword',
        'application/x-executable', 'application/x-sharedlib', 'application/x-sqlite3', 'application/wasm',
    }
    body = reply.get('body', '')
    # Generic servers also serve useful plain-text config/JSON as octet-stream.
    # Keep that text; an absent/ambiguous MIME needs byte-loss/control evidence.
    nontext = '\ufffd' in body or any(ord(c) < 32 and c not in '\t\r\n' for c in body)
    return (binary_type or (media in ('', 'application/octet-stream') and nontext)
            or body.startswith(('PK\x03\x04', 'PK\x05\x06', '%PDF-', '\x1f\ufffd')))


def text_response(reply, method):
    # Preserve the exact broker record before changing only the tool-facing body.
    # Re-encoding a lossy UTF-8 string does not recover an XLSX/ZIP/PDF download.
    reply = retain_evidence(reply)
    if method.upper() != 'HEAD' and binary_response(reply):
        reply['body'] = ''
        reply['body_unavailable'] = 'binary_response_not_supported'
    return reply


def retain_evidence(reply):
    """Keep the broker's redacted record available after a scanner finishes.

    This working copy helps the agent cite exact requests without repeating
    them. The relay's own records remain authoritative for the signed report.
    Do not cache the full response body, which is not the retained evidence.
    """
    record = reply.get('evidence')
    if not isinstance(record, dict) or type(record.get('id')) is not int or record['id'] <= 0:
        return reply
    try:
        EVIDENCE_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = EVIDENCE_DIRECTORY / f"{record['id']}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as saved:
            json.dump(record, saved)
        reply['evidence_file'] = str(path)
    except OSError:
        # A cache failure must not lose an already recorded HTTP response.
        reply['evidence_cache_error'] = 'unavailable'
    return reply


def default_account():
    try:
        account = json.loads(Path('/work/default-account.json').read_text())
        if account in ('testing', 'reference'): return account
    except (OSError, ValueError): pass
    return 'testing'


def request(method, url, headers=None, data=None, authenticated=True, *, discovery=False, account=None):
    body = json.dumps({"method": method.upper(), "url": url, "headers": headers or {}, "data": data, "authenticated": authenticated}).encode()
    path = "/patchriot/discovery/http" if discovery else "/patchriot/http"
    account = account or default_account()
    if account not in ('testing', 'reference'): raise ValueError('Unknown account context')
    if account == 'reference': path = path.replace('/patchriot/', '/patchriot/accounts/reference/', 1)
    req = Request(os.environ["PATCHRIOT_BRIDGE_URL"] + path, data=body,
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=75) as response:
            return text_response(json.loads(response.read(2 * 1024 * 1024)), method)
    except HTTPError as error:
        with error:
            return json.loads(error.read(8192))


def verify_changed_password():
    """Replay one privately learned login after an accepted password change."""
    if default_account() != 'testing':
        raise ValueError('Password verification belongs to the testing account')
    req = Request(os.environ['PATCHRIOT_BRIDGE_URL'] + '/patchriot/password/verify',
                  data=b'{}', headers={'Content-Type': 'application/json'})
    try:
        with urlopen(req, timeout=75) as response:
            return retain_evidence(json.loads(response.read(2 * 1024 * 1024)))
    except HTTPError as error:
        with error:
            return json.loads(error.read(8192))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("method", choices=["GET", "HEAD", "OPTIONS", "POST", "VERIFY_CHANGED_PASSWORD"])
    parser.add_argument("url", nargs='?')
    parser.add_argument("--data", help="Approved POST body: JSON or URL-encoded form, at most 16 KiB")
    parser.add_argument("--account", choices=["testing", "reference"])
    parser.add_argument("--anonymous", action="store_true", help="Omit the test account and session cookies for a control request")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--save-body", help="Save response text under /work for analysis")
    parser.add_argument("--body-chars", type=int, default=8192, choices=range(0,32769), metavar="0..32768")
    args = parser.parse_args()
    if args.method == 'VERIFY_CHANGED_PASSWORD':
        if args.url or args.data is not None or args.header or args.anonymous or args.account:
            parser.error('Password verification uses the private observed login and accepts no request fields')
        result = verify_changed_password()
    else:
        if not args.url:
            parser.error('A URL is required for HTTP requests')
        headers = dict(value.split(":", 1) for value in args.header)
        result = request(args.method, args.url, {k.strip(): v.strip() for k, v in headers.items()}, data=args.data, authenticated=not args.anonymous, account=args.account)
    body = result.get("body", "")
    if args.save_body:
        path = Path(args.save_body).resolve()
        if not path.is_relative_to("/work"):
            raise SystemExit("Save analysis files under /work")
        if result.get('body_unavailable'):
            result['save_body_error'] = result['body_unavailable']
        else:
            path.write_text(body)
            result["saved_body"] = str(path)
    result["body"] = body[:args.body_chars]
    result["display_shortened"] = len(body) > args.body_chars
    print(json.dumps(result))
