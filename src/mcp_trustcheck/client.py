"""Minimal Streamable HTTP MCP client (stdlib only) that records a redacted trace."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .redact import redact_headers, redact_text, redact_value

CLIENT_PROTOCOL = "2025-11-25"


@dataclass
class Exchange:
    request: Any
    status: int
    elapsed_ms: float
    raw_response: str  # unredacted, used only for in-memory checks
    response: Any = None
    headers: dict[str, str] = field(default_factory=dict)


class McpHttp:
    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 15.0, secrets: list[str] | None = None):
        self.url, self.timeout = url, timeout
        self.headers = dict(headers or {})
        self.secrets = [s for s in (secrets or []) if s]
        self.session_id: str | None = None
        self.protocol: str | None = None
        self.exchanges: list[Exchange] = []
        self._next_id = 1

    def new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def post(self, body: Any, raw: bytes | None = None) -> Exchange:
        data = raw if raw is not None else json.dumps(body).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self.headers}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        start = time.perf_counter()
        status, text, resp_headers = 0, "", {}
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, text, resp_headers = resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
        except urllib.error.HTTPError as err:
            status, text, resp_headers = err.code, err.read().decode("utf-8", "replace"), dict(err.headers)
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            text = f"connection error: {type(err).__name__}"
        elapsed = (time.perf_counter() - start) * 1000
        sid = next((v for k, v in resp_headers.items() if k.lower() == "mcp-session-id"), None)
        if sid and not self.session_id:
            self.session_id = sid
        ex = Exchange(body if raw is None else raw.decode("utf-8", "replace"), status, elapsed, text, parse_body(text), resp_headers)
        ex.sent_headers = headers  # type: ignore[attr-defined]
        self.exchanges.append(ex)
        return ex

    def rpc(self, method: str, params: dict | None = None, rid: Any = None) -> Exchange:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": rid if rid is not None else self.new_id(), "method": method}
        if params is not None:
            body["params"] = params
        return self.post(body)

    def notify(self, method: str, params: dict | None = None) -> Exchange:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        return self.post(body)

    def trace(self) -> list[dict]:
        """Redacted, report-safe copy of everything sent and received."""
        out = []
        for ex in self.exchanges:
            sent = redact_headers(getattr(ex, "sent_headers", {}), self.secrets)
            out.append({
                "request_headers": sent,
                "request": redact_value(ex.request, self.secrets),
                "status": ex.status,
                "elapsed_ms": round(ex.elapsed_ms, 1),
                "response": redact_value(ex.response, self.secrets) if ex.response is not None else redact_text(ex.raw_response[:500], self.secrets),
            })
        return out


def parse_body(text: str) -> Any:
    """Parse a JSON body or the first JSON-RPC message of an SSE stream."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except ValueError:
                continue
    return None
