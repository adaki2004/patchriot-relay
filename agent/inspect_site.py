"""Read saved text only. Never import, execute or fetch anything from a target."""
import hashlib
import json
from pathlib import Path

MAX_INPUT = 6 * 1024 * 1024
MAX_OUTPUT = 16000


def clipped(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def bounded_output(result):
    # Per-field limits do not bound their combined JSON, especially when text
    # needs escaping. Shorten the largest excerpt until the actual wire fits.
    fields = [(sample, key, flag) for sample in result["resources"]
              for key, flag in [("excerpt", "excerpt_truncated"),
                                ("headers_excerpt", "headers_truncated"),
                                ("url", "url_truncated")]]
    fields.extend((report, "assessment_excerpt", "assessment_truncated")
                  for report in result["previous_reports"])
    while True:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        # main() prints a newline; the caller counts it against the same limit.
        if len(encoded.encode("utf-8")) + 1 <= MAX_OUTPUT:
            return encoded
        item, key, flag = max(fields, key=lambda field: len(field[0][field[1]].encode("utf-8")))
        length = len(item[key].encode("utf-8"))
        if not length:
            raise ValueError("inspection metadata exceeds limit")
        item[key] = clipped(item[key], length // 2)
        item[flag] = True


def inspect(snapshot_bytes, previous_reports):
    if len(snapshot_bytes) > MAX_INPUT:
        raise ValueError("snapshot exceeds limit")
    snapshot = json.loads(snapshot_bytes)
    resources = [snapshot["homepage"], *snapshot["resources"]]
    samples = []
    for resource in resources[:6]:
        limit = 4000 if resource["kind"] == "homepage" else 1000
        headers = json.dumps(resource["headers"], ensure_ascii=False)
        samples.append({"kind": resource["kind"], "url": clipped(resource["url"], 300),
                        "url_truncated": len(resource["url"].encode("utf-8")) > 300,
                        "sha256": resource["sha256"],
                        "headers_excerpt": clipped(headers, 1000),
                        "headers_truncated": len(headers.encode("utf-8")) > 1000,
                        "excerpt": clipped(resource["text"], limit),
                        "excerpt_truncated": len(resource["text"].encode()) > limit})
    # Prior claims are data, not instructions or proof. Bound them separately so
    # a verbose first role cannot fill the later roles' entire model context.
    previous = []
    for report in previous_reports[:2]:
        assessment = json.dumps(report["assessment"], ensure_ascii=False)
        previous.append({"role": report["role"], "evidence_complete": report["evidence_complete"],
                         "assessment_excerpt": clipped(assessment, 1800),
                         "assessment_truncated": len(assessment.encode("utf-8")) > 1800})
    result = {"snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
              "resources": samples, "total_resources": len(resources),
              "omitted_resources": max(0, len(resources) - len(samples)),
              "skipped_scripts": sum(s["status"] == "skipped" for s in snapshot["scripts"]),
              "script_limit_reached": snapshot["script_limit_reached"],
              "previous_reports": previous,
              "limitations": "Saved text only. Truncation flags mark shortened previews; missing text does not prove absence from the page. No imports, browser execution, authenticated pages or live exploit tests."}
    return bounded_output(result)


def main():
    with Path("/work/snapshot.json").open("rb") as file:
        snapshot = file.read(MAX_INPUT + 1)
    with Path("/work/previous.json").open("rb") as file:
        previous = file.read(64 * 1024 + 1)
    if len(previous) > 64 * 1024:
        raise ValueError("prior reports exceed limit")
    print(inspect(snapshot, json.loads(previous)))


if __name__ == "__main__":
    main()
