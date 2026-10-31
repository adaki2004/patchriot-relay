"""Owned protocol checks; no model, Docker engine or external network required."""
import http.client
import io
import json
import hashlib
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

import adapter
import inspect_site


class BridgeTests(unittest.TestCase):
    def exchange(self, frames, method="GET", path="/api/version", body=None, headers=None):
        wire = io.StringIO()
        incoming = io.TextIOWrapper(io.BytesIO(b"".join(json.dumps(f).encode() + b"\n" for f in frames)))
        adapter.request_id = 0
        server = adapter.ThreadingHTTPServer(("127.0.0.1", 0), adapter.Bridge)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(adapter, "wire_out", wire), patch.object(sys, "stdin", incoming):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                try:
                    connection.request(method, path, body=body, headers=headers or {})
                    response = connection.getresponse()
                    result = (response.status, response.getheader("Content-Type"), response.read())
                except http.client.RemoteDisconnected:
                    result = None
                finally:
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        return result, [json.loads(line) for line in wire.getvalue().splitlines()]

    def test_streaming_response_and_request_survive_the_pipe(self):
        content = b'data: {"answer":"owned test"}\n\ndata: [DONE]\n\n'
        frames = [
            {"type": "start", "id": 1, "status": 200, "content_type": "text/event-stream"},
            {"type": "chunk", "id": 1, "hex": content[:9].hex()},
            {"type": "chunk", "id": 1, "hex": content[9:].hex()},
            {"type": "end", "id": 1},
        ]
        body = {"model": "owned-model", "messages": [{"role": "user", "content": "check"}]}
        result, wire = self.exchange(frames, "POST", "/v1/chat/completions", json.dumps(body))
        self.assertEqual(result, (200, "text/event-stream", content))
        self.assertEqual(wire, [{"type": "request", "request": {"id": 1, "method": "POST", "path": "/v1/chat/completions", "body": body}}])

    def test_response_for_another_request_closes_the_connection(self):
        result, wire = self.exchange([{"type": "start", "id": 2, "status": 200, "content_type": "application/json"}])
        self.assertIsNone(result)
        self.assertEqual(len(wire), 1)

    def test_oversized_http_body_never_enters_the_pipe(self):
        result, wire = self.exchange([], "POST", "/v1/chat/completions", headers={"Content-Length": str(adapter.MAX_REQUEST + 1)})
        self.assertEqual(result[0], 400)
        self.assertEqual(wire, [])

    def test_phase_name_is_data_and_events_remain_bounded(self):
        wire = io.StringIO()
        with patch.object(adapter, "wire_out", wire):
            adapter.event("phase", name="agent_ready")
            with self.assertRaises(RuntimeError):
                adapter.event("result", text="x" * adapter.MAX_REQUEST)
        self.assertEqual(json.loads(wire.getvalue()), {"type": "event", "event": "phase", "data": {"name": "agent_ready"}})


class WebsiteTests(unittest.TestCase):
    def snapshot(self):
        return {"homepage": {"kind": "homepage", "url": "https://example.com/", "sha256": "a" * 64,
                             "headers": {"content-security-policy": "default-src 'self'"},
                             "text": "<h1>Owned fixture é</h1>"}, "resources": [], "scripts": [],
                "script_limit_reached": False}

    def task(self):
        snapshot = json.dumps(self.snapshot(), ensure_ascii=False, separators=(",", ":"))
        return {"kind": "website_snapshot_v1", "role": "investigator", "snapshot_json": snapshot,
                "snapshot_sha256": hashlib.sha256(snapshot.encode()).hexdigest(), "previous_reports": []}

    def test_initial_frame_preserves_exact_evidence_bytes_and_leaves_model_frames_unread(self):
        task = self.task()
        stream = io.BytesIO(json.dumps(task).encode() + b'\n{"id":1}\n')
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(adapter.website_input(stream, Path(folder)), "investigator")
            self.assertEqual((Path(folder) / "snapshot.json").read_bytes(), task["snapshot_json"].encode())
            self.assertEqual(stream.readline(), b'{"id":1}\n')

    def test_corrupt_or_unsupported_input_is_not_written(self):
        for field, value in [("snapshot_sha256", "0" * 64), ("kind", "shell"), ("role", "admin")]:
            task = self.task()
            task[field] = value
            with tempfile.TemporaryDirectory() as folder:
                with self.assertRaises(ValueError):
                    adapter.website_input(io.BytesIO(json.dumps(task).encode() + b"\n"), Path(folder))
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_inspector_treats_target_code_as_text_and_discloses_shortened_coverage(self):
        snapshot = self.snapshot()
        snapshot["homepage"]["text"] = "raise RuntimeError('must not execute target')" + "é" * 4000
        snapshot["resources"] = [dict(snapshot["homepage"], kind="external_script") for _ in range(8)]
        snapshot["scripts"] = [{"status": "skipped"}]
        raw = json.dumps(snapshot, ensure_ascii=False).encode()
        report = json.loads(inspect_site.inspect(raw, [{"role": "investigator", "evidence_complete": False, "assessment": {"summary": "Untrusted previous claim."}}]))
        self.assertEqual(report["snapshot_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["omitted_resources"], 3)
        self.assertEqual(report["skipped_scripts"], 1)
        self.assertTrue(report["resources"][0]["excerpt_truncated"])
        self.assertIn("must not execute target", report["resources"][0]["excerpt"])
        self.assertFalse(report["previous_reports"][0]["evidence_complete"])

    def test_required_inspection_preserves_reader_output_and_discloses_its_origin(self):
        raw = json.dumps(self.snapshot(), ensure_ascii=False).encode()
        output = inspect_site.inspect(raw, []) + "\n"
        wire = io.StringIO()
        with patch.object(adapter, "wire_out", wire), patch.object(adapter.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
            self.assertEqual(adapter.inspect_website(), output)
            # The command is fixed; neither website text nor model output can
            # select a shell program or extra arguments for this required read.
            self.assertEqual(run.call_args.args[0], [sys.executable, "/patchriot/inspect_site.py"])
            self.assertEqual(run.call_args.kwargs["timeout"], 5)
            self.assertNotIn("shell", run.call_args.kwargs)
        events = [json.loads(line) for line in wire.getvalue().splitlines()]
        self.assertEqual([event["event"] for event in events], ["tool_start", "tool_complete"])
        self.assertEqual(events[1]["data"]["origin"], "required_snapshot_inspection")
        self.assertEqual(json.loads(events[1]["data"]["args"][3])["output"], output)

    def test_failed_or_unreadable_required_inspection_cannot_report_success(self):
        for response in [
            subprocess.CompletedProcess([], 1, stdout='{"snapshot_sha256":"' + 'a' * 64 + '"}', stderr="failed"),
            subprocess.CompletedProcess([], 0, stdout="not JSON", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="[]", stderr=""),
            subprocess.CompletedProcess([], 0, stdout='{"snapshot_sha256":"invented"}', stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" " * 16001, stderr=""),
            subprocess.TimeoutExpired("fixed reader", 5),
        ]:
            with self.subTest(response=type(response).__name__):
                wire = io.StringIO()
                with patch.object(adapter, "wire_out", wire), patch.object(adapter.subprocess, "run") as run:
                    if isinstance(response, Exception):
                        run.side_effect = response
                    else:
                        run.return_value = response
                    with self.assertRaises((RuntimeError, ValueError, subprocess.TimeoutExpired)):
                        adapter.inspect_website()
                events = [json.loads(line) for line in wire.getvalue().splitlines()]
                self.assertEqual([event["event"] for event in events], ["tool_start"])


if __name__ == "__main__":
    unittest.main()
