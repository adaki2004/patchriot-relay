"""Thin adapter for the external Python runtime. Policy and upstream IO live in Rust.

The container has no network except its own loopback. This local HTTP facade
translates the runtime's requests to bounded pipe messages; it has no credentials.
Neither its events nor a model's answer establish independent verification.
"""
import json
import os
from pathlib import Path
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REQUEST = 65536
wire_out = sys.stdout
wire_lock = threading.Lock()
transaction_lock = threading.Lock()
request_id = 0


def send(value):
    encoded = json.dumps(value, ensure_ascii=True)
    if len(encoded.encode()) > MAX_REQUEST:
        raise RuntimeError("adapter message exceeds its limit")
    with wire_lock:
        wire_out.write(encoded + "\n")
        wire_out.flush()


def event(kind, **data):
    send({"type": "event", "event": kind, "data": data})


class Bridge(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.exchange()

    def do_POST(self):
        self.exchange()

    def exchange(self):
        global request_id
        self.close_connection = True
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_REQUEST or self.headers.get("Transfer-Encoding"):
                return self.send_error(400)
            body = json.loads(self.rfile.read(length)) if length else None
            with transaction_lock:
                request_id += 1
                request = {"id": request_id, "method": self.command, "path": self.path, "body": body}
                send({"type": "request", "request": request})
                while True:
                    line = sys.stdin.buffer.readline(MAX_REQUEST + 1)
                    if not line or len(line) > MAX_REQUEST or not line.endswith(b"\n"):
                        raise RuntimeError("model bridge closed or exceeded its limit")
                    frame = json.loads(line)
                    if frame["id"] != request_id:
                        raise RuntimeError("unexpected model response")
                    if frame["type"] == "start":
                        self.send_response(frame["status"])
                        self.send_header("Content-Type", frame["content_type"])
                        self.send_header("Connection", "close")
                        self.end_headers()
                    elif frame["type"] == "chunk":
                        self.wfile.write(bytes.fromhex(frame["hex"]))
                        self.wfile.flush()
                    elif frame["type"] == "end":
                        return
                    else:
                        raise RuntimeError("model request failed")
        except (ValueError, KeyError, RuntimeError, BrokenPipeError, ConnectionError):
            self.close_connection = True


def main():
    sys.stdout = sys.stderr  # Library chatter must not enter the structured channel.
    if len(sys.argv) != 2:
        raise SystemExit("expected the operator-configured model name")
    model = sys.argv[1]
    home = Path(os.environ["HERMES_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text("model:\n  ollama_num_ctx: 64000\n")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Bridge)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    from run_agent import AIAgent
    observed = []

    def complete(*args, **kwargs):
        observed.append(args)
        event("tool_complete", args=args, kwargs=kwargs)

    agent = AIAgent(
        model=model, provider="custom", api_mode="chat_completions",
        base_url=f"http://127.0.0.1:{server.server_port}/v1", api_key="local-bridge",
        enabled_toolsets=["terminal"], max_iterations=3, max_tokens=192,
        reasoning_config={"enabled": False, "effort": "none"},
        request_overrides={"reasoning_effort": "none"},
        quiet_mode=True, skip_context_files=True, skip_memory=True,
        skip_background_review=True, checkpoints_enabled=False,
        run_budget_seconds=570, cwd="/work",
        tool_start_callback=lambda *a, **k: event("tool_start", args=a, kwargs=k),
        tool_complete_callback=complete,
    )
    try:
        event("phase", name="agent_ready")
        result = agent.run_conversation(
            "You are checking a Patchriot-owned synthetic access-control example. "
            "Use the terminal tool once with exactly: cat /patchriot/access.py && python /patchriot/check.py. "
            "Then explain the bug and whether the supplied patch fixes it in at most two short sentences. "
            "Report only observed output. Do not edit files, install anything or access the network."
        )
        regression = False
        for args in observed:
            if len(args) < 4 or args[1] != "terminal":
                continue
            try:
                tool = json.loads(args[3])
                checks = json.loads(tool["output"].splitlines()[-1])
                regression |= tool["exit_code"] == 0 and checks == {
                    "original": {"owner_reads": True, "blocks_other_user": False},
                    "patched": {"owner_reads": True, "blocks_other_user": True},
                }
            except (ValueError, KeyError, TypeError, IndexError):
                pass
        completed = result.get("completed") is True and not result.get("failed")
        event("result", completed=completed, observed_fixture_regression=regression,
              final_response=result.get("final_response"), api_calls=result.get("api_calls"))
        if not regression or not completed:
            raise SystemExit(1)
    finally:
        agent.close()
        server.shutdown()


if __name__ == "__main__":
    main()
