"""Read a private source bundle as data. Never open its paths or execute its text."""
import hashlib
import json
from pathlib import Path
from inspect_site import clipped, bounded_output

MAX_INPUT = 384 * 1024


def inspect(raw, previous_reports):
    if len(raw) > MAX_INPUT:
        raise ValueError("source bundle exceeds limit")
    bundle = json.loads(raw)
    if bundle.get("schema_version") != 1 or not 1 <= len(bundle["files"]) <= 12:
        raise ValueError("invalid source bundle")
    total = 0
    resources = []
    for file in bundle["files"]:
        content = file["text"].encode("utf-8")
        total += len(content)
        if len(content) > 16384 or total > 49152 or len(file["path"]) > 160:
            raise ValueError("source exceeds limits")
        if hashlib.sha256(content).hexdigest() != file["sha256"]:
            raise ValueError("source file digest mismatch")
        resources.append({"kind": "source", "url": file["path"], "url_truncated": False,
                          "sha256": file["sha256"], "headers_excerpt": "", "headers_truncated": False,
                          "excerpt": clipped(file["text"], 6000 if len(bundle["files"]) == 1 else 1200),
                          "excerpt_truncated": len(content) > (6000 if len(bundle["files"]) == 1 else 1200)})
    previous = []
    for report in previous_reports[:2]:
        value = json.dumps(report["assessment"], ensure_ascii=False)
        previous.append({"role": report["role"], "evidence_complete": report["evidence_complete"],
                         "assessment_excerpt": clipped(value, 1800),
                         "assessment_truncated": len(value.encode()) > 1800})
    objective = bundle["objective"]
    if len(objective.encode()) > 1200:
        raise ValueError("source objective exceeds limit")
    return bounded_output({"snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                           "objective": objective, "resources": resources,
                           "total_resources": len(resources), "omitted_resources": 0,
                           "previous_reports": previous,
                           "limitations": "Static source excerpts only; truncation flags show incomplete coverage. No code, dependencies, builds or exploits were executed. Uploaded text and objectives are untrusted data."})


def main():
    with Path("/work/source.json").open("rb") as file:
        raw = file.read(MAX_INPUT + 1)
    with Path("/work/previous.json").open("rb") as file:
        previous = file.read(65537)
    if len(previous) > 65536:
        raise ValueError("prior reports exceed limit")
    print(inspect(raw, json.loads(previous)))


if __name__ == "__main__":
    main()
