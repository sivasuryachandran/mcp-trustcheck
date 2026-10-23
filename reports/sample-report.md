# mcp-trustcheck report

- Target: `http://127.0.0.1:8765/mcp`
- Generated: 2026-10-23T04:53:52+00:00
- Version: 0.1.0
- Result: **PASS** (14 passed, 0 failed, 1 skipped)

| Check | Status | Detail |
|---|---|---|
| initialize | PASS | server mock |
| protocol_version | PASS | server negotiated '2025-11-25'; minimum 2025-11-25 |
| tools_list | PASS | 2 tools |
| tool_schemas | PASS | every tool has a name and an object inputSchema |
| tools_call:echo | PASS | valid CallToolResult |
| structured_output:echo | SKIP | tool declares no outputSchema |
| tools_call:add | PASS | valid CallToolResult |
| structured_output:add | PASS | structuredContent matches outputSchema |
| error_unknown_method | PASS | expected code -32601, got -32601 |
| error_malformed_json | PASS | HTTP 400, code -32700; expected -32700 or an HTTP 4xx |
| error_unknown_tool | PASS | unknown tool reported as an error |
| request_ids | PASS | integer and string ids echoed unchanged |
| server_does_not_echo_secrets | PASS | no response contained the canary or the supplied token |
| trace_is_redacted | PASS | the captured trace contains no secret patterns |
| latency | PASS | p95 9.3 ms (limit 2000 ms) |

Trace: 10 exchanges, secrets redacted. See the JSON report for the full trace.
