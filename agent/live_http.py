"""Agent-side helper. Requests go through the relay's scoped, recorded broker."""
import argparse
import json
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def request(method, url, headers=None, data=None, authenticated=True, *, discovery=False):
    body = json.dumps({"method": method.upper(), "url": url, "headers": headers or {}, "data": data, "authenticated": authenticated}).encode()
    path = "/patchriot/artex/http" if discovery else "/patchriot/http"
    req = Request(os.environ["PATCHRIOT_BRIDGE_URL"] + path, data=body,
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=75) as response:
            return json.loads(response.read(2 * 1024 * 1024))
    except HTTPError as error:
        return json.loads(error.read(8192))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("method", choices=["GET", "HEAD", "OPTIONS", "POST"])
    parser.add_argument("url")
    parser.add_argument("--data", help="Approved POST body: JSON or URL-encoded form, at most 16 KiB")
    parser.add_argument("--anonymous", action="store_true", help="Omit the test account and session cookies for a control request")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--save-body", help="Save response text under /work for analysis")
    parser.add_argument("--body-chars", type=int, default=8192, choices=range(0,32769), metavar="0..32768")
    args = parser.parse_args()
    headers = dict(value.split(":", 1) for value in args.header)
    result = request(args.method, args.url, {k.strip(): v.strip() for k, v in headers.items()}, data=args.data, authenticated=not args.anonymous)
    body = result.get("body", "")
    if args.save_body:
        from pathlib import Path
        path = Path(args.save_body).resolve()
        if not path.is_relative_to("/work"):
            raise SystemExit("Save analysis files under /work")
        path.write_text(body)
        result["saved_body"] = str(path)
    result["body"] = body[:args.body_chars]
    result["display_shortened"] = len(body) > args.body_chars
    print(json.dumps(result))
