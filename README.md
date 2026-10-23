# mcp-trustcheck

A small, dependency-free Python CLI that checks whether a **Streamable HTTP MCP server** behaves the way the protocol says it should, and whether its traces are safe to share. It works against any server; it knows nothing about what the server is for.

Released under the MIT License. Python 3.10+, standard library only (pytest for development).

## What it checks

| Check | What it verifies |
|---|---|
| `initialize` | A valid result with `protocolVersion`, `capabilities`, `serverInfo`; sends `notifications/initialized` |
| `protocol_version` | The server negotiates `2025-11-25` or later |
| `tools_list` / `tool_schemas` | `tools/list` returns tools, each with a name and an object `inputSchema` (and a well-formed `outputSchema` if present) |
| `tools_call` | Calls the tools you name with `--call` and checks the `CallToolResult` shape (`content` list, boolean `isError`) |
| `structured_output` | If a tool declares an `outputSchema`, `structuredContent` must exist and match it (type, required, properties, items, enum) |
| `error_*` | Unknown method gives `-32601`; malformed JSON gives `-32700` or an HTTP 4xx; an unknown tool is reported as an error |
| `request_ids` | Integer and string request ids come back unchanged |
| `latency` | p95 over all requests stays under `--max-latency-ms` |
| `server_does_not_echo_secrets` | A random canary (sent in a header and in `_meta`) and any token you supply never appear in a response |
| `trace_is_redacted` | The trace written to the report contains no secret patterns |

Both `application/json` and `text/event-stream` responses are understood.

## Install

```bash
git clone https://github.com/sivasuryachandran/mcp-trustcheck
cd mcp-trustcheck
pip install -e ".[dev]"
```

## Use

```bash
# try it on the bundled mock server
mcp-trustcheck-mock --port 8765 &
mcp-trustcheck http://127.0.0.1:8765/mcp \
  --call 'echo={"text":"hello"}' --call 'add={"a":2,"b":3}' \
  --json report.json --markdown report.md
```

Exit code: `0` all checks passed, `1` at least one failed, `2` bad usage.

| Option | Meaning |
|---|---|
| `--call NAME=JSON` | Call this tool with these arguments (repeatable). Only name tools that are safe to run. |
| `--header 'Name: value'` | Extra request header; redacted in reports |
| `--token-env VAR` | Bearer token read from an environment variable, never from the command line |
| `--max-latency-ms N` | Latency limit (default 2000) |
| `--skip GROUP` | Skip `initialize`, `tools_list`, `tools_call`, `jsonrpc_errors`, `request_ids`, `redaction` or `latency` |
| `--json FILE` / `--markdown FILE` | Write reports |

A passing example is in [reports/sample-report.md](reports/sample-report.md) and [reports/sample-report.json](reports/sample-report.json). A generic walk-through against PACT is in [examples/pact_example.md](examples/pact_example.md); PACT is just one MCP server and nothing in this project is specific to it.

## Architecture

```
cli.py        arguments, exit code
runner.py     builds the client, runs each check group, assembles the report
client.py     stdlib HTTP client: sessions (Mcp-Session-Id), protocol header, JSON/SSE parsing, redacted trace
checks.py     one function per check group, each returns Result(name, status, detail)
redact.py     header, key and pattern redaction; secret finder
report.py     JSON and Markdown output
mock_server.py  generic mock MCP server with injectable flaws, used by the tests
```

The tests start the mock server, run the checker against a clean server (everything passes) and against five deliberately flawed ones (old protocol, wrong id, echoed secret, wrong structured output, no error handling), and confirm each flaw is caught.

## Security limitations

- This is a conformance and hygiene checker, not a security audit. It does not test authentication strength, authorization, injection, rate limiting or TLS.
- Redaction is pattern based (bearer tokens, `sk-` keys, AWS key ids, GitHub tokens, JWTs, private-key headers, sensitive header and JSON key names, and the literal secrets it was given). A secret in an unusual format can slip through. Read a report before you share it.
- `--call` runs real tool calls on the target server. Use read-only tools, or a test instance.
- The checker is not a full JSON Schema validator; it supports `type`, `required`, `properties`, `items` and `enum`.
- It tests one session at a time and does not exercise server-initiated messages, resumability or SSE streaming beyond the first message.
- The mock server is for testing the checker and is not a reference implementation.

## Development

```bash
python -m compileall -q src tests
pytest -q
```

CI runs the same on Python 3.10, 3.12 and 3.14, runs the checker end to end against the mock server, and scans for secret patterns.
