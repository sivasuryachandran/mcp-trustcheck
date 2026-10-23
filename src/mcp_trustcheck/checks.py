"""The checks. Each returns a Result; none of them needs knowledge of the server's purpose."""
from __future__ import annotations

import json
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Any

from .client import CLIENT_PROTOCOL, McpHttp
from .redact import find_secrets

MIN_PROTOCOL = "2025-11-25"
PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"
JSON_TYPES = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "array": list, "object": dict, "null": type(None)}


@dataclass
class Result:
    name: str
    status: str
    detail: str
    data: dict = field(default_factory=dict)


@dataclass
class Config:
    calls: list[tuple[str, dict]] = field(default_factory=list)
    max_latency_ms: float = 2000.0
    token: str | None = None
    canary: str = field(default_factory=lambda: "canary-" + _secrets.token_hex(12))


def _result(ex) -> dict | None:
    r = ex.response
    return r.get("result") if isinstance(r, dict) and isinstance(r.get("result"), dict) else None


def _error(ex) -> dict | None:
    r = ex.response
    return r.get("error") if isinstance(r, dict) and isinstance(r.get("error"), dict) else None


def check_initialize(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    ex = c.rpc("initialize", {"protocolVersion": CLIENT_PROTOCOL, "capabilities": {}, "clientInfo": {"name": "mcp-trustcheck", "version": "0.1.0"}, "_meta": {"trustcheck-canary": cfg.canary}}, rid=1)
    res = _result(ex)
    if ex.status != 200 or res is None:
        return [Result("initialize", FAIL, f"no valid result (HTTP {ex.status})")]
    missing = [k for k in ("protocolVersion", "capabilities", "serverInfo") if k not in res]
    state["protocol"] = res.get("protocolVersion")
    c.protocol = state["protocol"] if isinstance(state["protocol"], str) else None
    c.notify("notifications/initialized")
    out = [Result("initialize", FAIL if missing else PASS, f"missing fields: {missing}" if missing else f"server {res.get('serverInfo', {}).get('name', '?')}")]
    ver = state["protocol"]
    ok = isinstance(ver, str) and len(ver) == 10 and ver >= MIN_PROTOCOL
    out.append(Result("protocol_version", PASS if ok else FAIL, f"server negotiated {ver!r}; minimum {MIN_PROTOCOL}"))
    return out


def check_tools_list(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    ex = c.rpc("tools/list", {})
    res = _result(ex)
    tools = res.get("tools") if res else None
    if not isinstance(tools, list):
        return [Result("tools_list", FAIL, "tools/list returned no tools array")]
    state["tools"] = {t.get("name"): t for t in tools if isinstance(t, dict)}
    out = [Result("tools_list", PASS, f"{len(tools)} tools", {"names": sorted(map(str, state["tools"]))})]
    bad = [str(t.get("name")) for t in tools if not (isinstance(t, dict) and isinstance(t.get("name"), str) and isinstance(t.get("inputSchema"), dict) and t["inputSchema"].get("type") == "object")]
    out.append(Result("tool_schemas", FAIL if bad else PASS, f"tools without a name or an object inputSchema: {bad}" if bad else "every tool has a name and an object inputSchema"))
    badout = [n for n, t in state["tools"].items() if "outputSchema" in t and not isinstance(t["outputSchema"], dict)]
    if badout:
        out.append(Result("output_schemas", FAIL, f"outputSchema is not an object for: {badout}"))
    return out


def validate(value: Any, schema: dict, path: str = "$") -> list[str]:
    """Small JSON Schema subset: type, required, properties, items, enum."""
    errs: list[str] = []
    t = schema.get("type")
    if t in JSON_TYPES:
        ok = isinstance(value, JSON_TYPES[t]) and not (t in ("number", "integer") and isinstance(value, bool))
        if not ok:
            return [f"{path}: expected {t}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: not in enum")
    if isinstance(value, dict):
        errs += [f"{path}.{k}: required" for k in schema.get("required", []) if k not in value]
        for k, sub in (schema.get("properties") or {}).items():
            if k in value and isinstance(sub, dict):
                errs += validate(value[k], sub, f"{path}.{k}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for i, item in enumerate(value):
            errs += validate(item, schema["items"], f"{path}[{i}]")
    return errs


def check_tools_call(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    if not cfg.calls:
        return [Result("tools_call", SKIP, "no --call given; pass --call NAME=JSON to exercise a tool")]
    out = []
    for name, args in cfg.calls:
        ex = c.rpc("tools/call", {"name": name, "arguments": args})
        res = _result(ex)
        if res is None:
            out.append(Result(f"tools_call:{name}", FAIL, f"no result (HTTP {ex.status}, error={_error(ex)})"))
            continue
        problems = []
        if not isinstance(res.get("content"), list):
            problems.append("content is not a list")
        if "isError" in res and not isinstance(res["isError"], bool):
            problems.append("isError is not a boolean")
        out.append(Result(f"tools_call:{name}", FAIL if problems else PASS, "; ".join(problems) or ("tool reported isError" if res.get("isError") else "valid CallToolResult")))
        schema = (state.get("tools", {}).get(name) or {}).get("outputSchema")
        if isinstance(schema, dict) and not res.get("isError"):
            sc = res.get("structuredContent")
            errs = ["structuredContent missing"] if sc is None else validate(sc, schema)
            out.append(Result(f"structured_output:{name}", FAIL if errs else PASS, "; ".join(errs[:5]) or "structuredContent matches outputSchema"))
        elif isinstance(res.get("structuredContent"), (dict, list)):
            out.append(Result(f"structured_output:{name}", PASS, "structuredContent present (no outputSchema to validate against)"))
        else:
            out.append(Result(f"structured_output:{name}", SKIP, "tool declares no outputSchema"))
    return out


def check_jsonrpc_errors(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    out = []
    ex = c.rpc("trustcheck/no-such-method", {})
    err = _error(ex)
    out.append(Result("error_unknown_method", PASS if err and err.get("code") == -32601 else FAIL, f"expected code -32601, got {err.get('code') if err else 'no error object'}"))
    ex = c.post(None, raw=b"{not json")
    err = _error(ex)
    ok = (err and err.get("code") == -32700) or (ex.status in (400, 422) and not err)
    out.append(Result("error_malformed_json", PASS if ok else FAIL, f"HTTP {ex.status}, code {err.get('code') if err else None}; expected -32700 or an HTTP 4xx"))
    ex = c.rpc("tools/call", {"name": "trustcheck-no-such-tool", "arguments": {}})
    res, err = _result(ex), _error(ex)
    ok = err is not None or bool(res and res.get("isError"))
    out.append(Result("error_unknown_tool", PASS if ok else FAIL, "unknown tool reported as an error" if ok else "unknown tool was accepted"))
    return out


def check_request_ids(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    bad = []
    for rid in (9001, "trustcheck-string-id"):
        ex = c.rpc("tools/list", {}, rid=rid)
        got = ex.response.get("id") if isinstance(ex.response, dict) else None
        if got != rid or type(got) is not type(rid):
            bad.append(f"sent {rid!r}, got {got!r}")
    return [Result("request_ids", FAIL if bad else PASS, "; ".join(bad) or "integer and string ids echoed unchanged")]


def check_latency(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    samples = sorted(ex.elapsed_ms for ex in c.exchanges if ex.status)
    if not samples:
        return [Result("latency", FAIL, "no responses measured")]
    p95 = samples[min(len(samples) - 1, int(len(samples) * 0.95))]
    data = {"requests": len(samples), "median_ms": round(samples[len(samples) // 2], 1), "p95_ms": round(p95, 1), "max_ms": round(samples[-1], 1)}
    return [Result("latency", PASS if p95 <= cfg.max_latency_ms else FAIL, f"p95 {data['p95_ms']} ms (limit {cfg.max_latency_ms:g} ms)", data)]


def check_redaction(c: McpHttp, cfg: Config, state: dict) -> list[Result]:
    secrets = [cfg.canary] + ([cfg.token] if cfg.token else [])
    echoed = [i for i, ex in enumerate(c.exchanges) if any(s in ex.raw_response for s in secrets)]
    out = [Result("server_does_not_echo_secrets", FAIL if echoed else PASS, f"a response echoed a secret we sent (exchanges {echoed})" if echoed else "no response contained the canary or the supplied token")]
    leaks = find_secrets(json.dumps(c.trace()), secrets)
    out.append(Result("trace_is_redacted", FAIL if leaks else PASS, f"the report trace still contains: {leaks}" if leaks else "the captured trace contains no secret patterns"))
    return out


ALL = {
    "initialize": check_initialize,
    "tools_list": check_tools_list,
    "tools_call": check_tools_call,
    "jsonrpc_errors": check_jsonrpc_errors,
    "request_ids": check_request_ids,
    "redaction": check_redaction,
    "latency": check_latency,
}
