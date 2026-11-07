"""Vulnerable, clean and ambiguous responses must produce different coverage."""
import json
import time
import unittest
from urllib.parse import urlsplit, parse_qs
import baseline
from web_tools import record


class BaselineTests(unittest.TestCase):
    def test_login_redirect_is_proof_only_for_the_declared_same_origin_page(self):
        scope = {"session_login": {"path": "/login", "format": "discover_form"}}
        evidence = {"url": "https://owned.example/private", "status": 302, "headers": {"location": "/login?next=%2Fprivate"}}
        self.assertTrue(baseline.denied_anonymous(scope, evidence))
        for location in ["https://foreign.example/login", "//foreign.example/login", "/maintenance", "https://user@owned.example/login"]:
            evidence["headers"]["location"] = location
            self.assertFalse(baseline.denied_anonymous(scope, evidence))
        evidence["headers"]["location"] = "/login"
        evidence["status"] = 200
        self.assertFalse(baseline.denied_anonymous(scope, evidence))
        evidence["status"] = 403
        self.assertTrue(baseline.denied_anonymous(scope, evidence))

    def run_fixture(self, vulnerable=False, soft404=False, authenticated=False, broken=False):
        calls = []
        def fetch(method, url, headers=None, authenticated=True):
            calls.append((method, url, headers, authenticated))
            if broken:
                raise OSError("fixture transport failure")
            path = urlsplit(url).path
            body, status = "Owned fixture", 200
            response_headers = {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'"}
            if path == "/private":
                status = 200 if authenticated else 401
            elif path != "/":
                status = 404
            if vulnerable and path == "/.git/config" or soft404:
                body, status = "[core]\nrepositoryformatversion = 0", 200
            if vulnerable and headers:
                response_headers.update({"access-control-allow-origin": headers["Origin"], "access-control-allow-credentials": "true"})
            if vulnerable and urlsplit(url).query:
                body = parse_qs(urlsplit(url).query)["patchriot_probe"][0]
            return {"body": body, "evidence": {"id": len(calls), "status": status, "authenticated": authenticated, "headers": response_headers}}
        scope = {"origins": ["https://owned.example"], "methods": ["GET", "HEAD", "OPTIONS"]}
        if authenticated:
            scope.update(authentication="basic", auth_check_path="/private")
        result = baseline.run(scope, time.monotonic()+5, fetch, record)
        return {c["id"]: c for c in json.loads(result["output_excerpt"])["checks"]}, calls

    def test_positive_findings_require_signatures_and_control_comparisons(self):
        checks, calls = self.run_fixture(vulnerable=True)
        self.assertEqual(checks["git-config"]["status"], "finding")
        self.assertEqual(checks["cors"]["status"], "finding")
        self.assertEqual(checks["reflection"]["status"], "inconclusive")
        self.assertEqual(len(checks["git-config"]["evidence_ids"]), 2)
        self.assertTrue(all(c[0] == "GET" and c[1].startswith("https://owned.example/") for c in calls))
        self.assertLessEqual(len(calls), 8)

    def test_clean_soft404_and_failed_sites_do_not_become_confirmed_findings(self):
        clean, _ = self.run_fixture()
        self.assertNotIn("finding", [c["status"] for c in clean.values()])
        self.assertNotIn("No test account", json.dumps(clean))
        self.assertIn("runs anonymously", json.dumps(clean))
        ambiguous, _ = self.run_fixture(soft404=True)
        self.assertEqual(ambiguous["git-config"]["status"], "inconclusive")
        failed, _ = self.run_fixture(broken=True)
        self.assertNotIn("completed", [c["status"] for c in failed.values()])

    def test_test_account_has_an_anonymous_control_and_coverage_exclusions(self):
        checks, calls = self.run_fixture(authenticated=True)
        self.assertEqual(checks["test-account"]["status"], "completed")
        self.assertEqual([c[3] for c in calls if c[1].endswith('/private')], [False, True])
        self.assertEqual(checks["forms"]["status"], "skipped")
        self.assertEqual(checks["browser"]["status"], "unsupported")

if __name__ == '__main__':
    unittest.main()
