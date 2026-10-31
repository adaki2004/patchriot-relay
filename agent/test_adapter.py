"""Owned protocol checks; no model, Docker engine or external network required."""
import http.client
import io
import json
import sys
import threading
import unittest
from unittest.mock import patch

import adapter


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


if __name__ == "__main__":
    unittest.main()
