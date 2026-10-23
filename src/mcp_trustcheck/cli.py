from __future__ import annotations

import argparse
import json
import os
import sys

from .checks import ALL, Config
from .report import to_json, to_markdown
from .runner import run


def _call(value: str) -> tuple[str, dict]:
    name, _, raw = value.partition("=")
    try:
        args = json.loads(raw) if raw else {}
    except ValueError as err:
        raise argparse.ArgumentTypeError(f"--call {name}: arguments are not valid JSON") from err
    if not name or not isinstance(args, dict):
        raise argparse.ArgumentTypeError("--call expects NAME or NAME=JSON_OBJECT")
    return name, args


def _header(value: str) -> tuple[str, str]:
    k, sep, v = value.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError("--header expects 'Name: value'")
    return k.strip(), v.strip()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcp-trustcheck", description="Check a Streamable HTTP MCP server.")
    p.add_argument("url", help="MCP endpoint, e.g. http://127.0.0.1:8000/mcp")
    p.add_argument("--call", action="append", type=_call, default=[], metavar="NAME=JSON", help="call this tool with these arguments (repeatable)")
    p.add_argument("--header", action="append", type=_header, default=[], metavar="'Name: value'", help="extra request header (redacted in reports)")
    p.add_argument("--token-env", metavar="VAR", help="read a bearer token from this environment variable (never from the command line)")
    p.add_argument("--max-latency-ms", type=float, default=2000.0)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--skip", action="append", default=[], choices=sorted(ALL), help="skip a check group")
    p.add_argument("--json", metavar="FILE", help="write the JSON report here")
    p.add_argument("--markdown", metavar="FILE", help="write the Markdown report here")
    a = p.parse_args(argv)
    token = os.environ.get(a.token_env) if a.token_env else None
    if a.token_env and not token:
        print(f"environment variable {a.token_env} is not set", file=sys.stderr)
        return 2
    cfg = Config(calls=a.call, max_latency_ms=a.max_latency_ms, token=token)
    report = run(a.url, cfg, dict(a.header), a.timeout, set(a.skip))
    if a.json:
        open(a.json, "w").write(to_json(report))
    if a.markdown:
        open(a.markdown, "w").write(to_markdown(report))
    print(to_markdown(report))
    return 0 if report["summary"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
