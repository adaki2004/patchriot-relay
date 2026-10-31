"""Owned regression example. The corrected version is supplied, not AI-generated."""
REPORTS = {"report-1": {"owner": "alice", "body": "synthetic report"}}


def read_report(current_user, report_id):
    return REPORTS[report_id]["body"]


def patched_read_report(current_user, report_id):
    report = REPORTS[report_id]
    if report["owner"] != current_user:
        raise PermissionError("not your report")
    return report["body"]
