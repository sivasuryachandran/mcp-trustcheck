# Example: checking PACT with mcp-trustcheck

[PACT](https://github.com/sivasuryachandran/pact) is a household permission layer that exposes its actions as an MCP server over Streamable HTTP. mcp-trustcheck knows nothing about PACT: it only speaks the MCP protocol, so the same steps work for any server.

1. Start the server you want to check (for PACT, follow its `docs/judge-quickstart.md`).
2. Point the checker at the MCP endpoint. PACT serves it at `/mcp`:

```bash
mcp-trustcheck http://127.0.0.1:8000/mcp \
  --json pact-report.json --markdown pact-report.md
```

3. Add tool calls only for tools that are safe to run. List the names first (`tools_list` in the report shows them), then pass read-only ones with `--call NAME='{"arg":"value"}'`.
4. If the server needs a bearer token, put it in an environment variable and pass the variable name, never the value:

```bash
export MCP_TOKEN=...   # your own token; not stored anywhere by mcp-trustcheck
mcp-trustcheck http://127.0.0.1:8000/mcp --token-env MCP_TOKEN
```

A server that requires a login session may answer `initialize` with an HTTP error; the report then fails at `initialize` and says so. That is a true result, not a checker bug.
