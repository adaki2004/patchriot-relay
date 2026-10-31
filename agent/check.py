"""Verify the original failure and legitimate access after the supplied fix."""
import json
from access import read_report, patched_read_report


def check(read):
    owner_reads = read("alice", "report-1") == "synthetic report"
    try:
        read("bob", "report-1")
        blocked = False
    except PermissionError:
        blocked = True
    return {"owner_reads": owner_reads, "blocks_other_user": blocked}


print(json.dumps({"original": check(read_report), "patched": check(patched_read_report)}))
