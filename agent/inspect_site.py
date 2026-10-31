"""Read saved text only. Never import, execute or fetch anything from a target."""
import hashlib
import json
from pathlib import Path

MAX_INPUT = 6 * 1024 * 1024
MAX_OUTPUT = 16000


def clipped(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def inspect(snapshot_bytes, previous_reports):
    if len(snapshot_bytes) > MAX_INPUT:
        raise ValueError("snapshot exceeds limit")
    snapshot = json.loads(snapshot_bytes)
    resources = [snapshot["homepage"], *snapshot["resources"]]
    samples = []
    for resource in resources[:6]:
        limit = 4000 if resource["kind"] == "homepage" else 1000
        samples.append({"kind": resource["kind"], "url": clipped(resource["url"], 300),
                        "sha256": resource["sha256"], "headers": resource["headers"],
                        "excerpt": clipped(resource["text"], limit),
                        "excerpt_truncated": len(resource["text"].encode()) > limit})
    # Prior claims are data, not instructions or proof. Bound them separately so
    # a verbose first role cannot fill the later roles' entire model context.
    previous = [{"role": r["role"], "evidence_complete": r["evidence_complete"],
                 "assessment_excerpt": clipped(json.dumps(r["assessment"], ensure_ascii=False), 1800)}
                for r in previous_reports[:2]]
    result = {"snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
              "resources": samples, "total_resources": len(resources),
              "omitted_resources": max(0, len(resources) - len(samples)),
              "skipped_scripts": sum(s["status"] == "skipped" for s in snapshot["scripts"]),
              "script_limit_reached": snapshot["script_limit_reached"],
              "previous_reports": previous,
              "limitations": "Saved text only. Excerpts may be shortened. No imports, browser execution, authenticated pages or live exploit tests."}
    # Headers can consume their own collection allowance. Reduce the preview,
    # explicitly, instead of overflowing the agent's pipe or silently omitting it.
    for sample in result["resources"]:
        sample["headers_excerpt"] = clipped(json.dumps(sample.pop("headers"), ensure_ascii=False), 1000)
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > MAX_OUTPUT:
        raise ValueError("inspection preview exceeds limit")
    return encoded


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
