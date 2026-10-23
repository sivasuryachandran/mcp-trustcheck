"""A small, generic Streamable HTTP MCP server for testing the checker. Not a reference implementation."""
from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "echo", "description": "Return the text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
    {"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a", "b"]},
     "outputSchema": {"type": "object", "properties": {"sum": {"type": "number"}}, "required": ["sum"]}},
]


def make_server(port: int = 0, flaw: str | None = None, sse: bool = False) -> ThreadingHTTPServer:
    """flaw: None | 'old-protocol' | 'wrong-id' | 'echo-secret' | 'bad-structured' | 'no-errors'."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silent
            pass

        def _send(self, status, payload=None, headers=None):
            body = b"" if payload is None else json.dumps(payload).encode()
            ctype = "application/json"
            if sse and payload is not None:
                body, ctype = b"event: message\ndata: " + body + b"\n\n", "text/event-stream"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                msg = json.loads(raw)
            except ValueError:
                return self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            if "id" not in msg:
                return self._send(202)
            rid = str(msg["id"]) if flaw == "wrong-id" else msg["id"]
            method, params = msg.get("method"), msg.get("params") or {}

            def ok(result, headers=None):
                self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result}, headers)

            def err(code, message):
                self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

            if method == "initialize":
                ver = "2025-03-26" if flaw == "old-protocol" else "2025-11-25"
                extra = {"debug": self.headers.get("X-Trustcheck-Canary")} if flaw == "echo-secret" else {}
                return ok({"protocolVersion": ver, "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "1"}, **extra}, {"Mcp-Session-Id": "mock-session"})
            if method == "tools/list":
                return ok({"tools": TOOLS})
            if method == "tools/call":
                name, args = params.get("name"), params.get("arguments") or {}
                if name == "echo":
                    return ok({"content": [{"type": "text", "text": str(args.get("text", ""))}], "isError": False})
                if name == "add":
                    total = "three" if flaw == "bad-structured" else (args.get("a", 0) + args.get("b", 0))
                    return ok({"content": [{"type": "text", "text": str(total)}], "structuredContent": {"sum": total}, "isError": False})
                if flaw == "no-errors":
                    return ok({"content": [{"type": "text", "text": "ok"}], "isError": False})
                return err(-32602, "Unknown tool")
            return ok({}) if flaw == "no-errors" else err(-32601, "Method not found")

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve_in_thread(**kwargs):
    server = make_server(**kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/mcp"


def main() -> None:
    p = argparse.ArgumentParser(description="Generic mock MCP server for trying mcp-trustcheck.")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--sse", action="store_true", help="answer with text/event-stream")
    a = p.parse_args()
    server = make_server(a.port, sse=a.sse)
    print(f"mock MCP server on http://127.0.0.1:{server.server_address[1]}/mcp")
    server.serve_forever()


if __name__ == "__main__":
    main()
