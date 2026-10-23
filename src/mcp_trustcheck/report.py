from __future__ import annotations

import json

ICON = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False) + "\n"


def to_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# mcp-trustcheck report", "",
        f"- Target: `{report['target']}`", f"- Generated: {report['generated_at']}", f"- Version: {report['version']}",
        f"- Result: **{'PASS' if s['ok'] else 'FAIL'}** ({s['pass']} passed, {s['fail']} failed, {s['skip']} skipped)", "",
        "| Check | Status | Detail |", "|---|---|---|",
    ]
    for r in report["results"]:
        lines.append(f"| {r['name']} | {ICON[r['status']]} | {r['detail'].replace('|', '/')} |")
    lines += ["", f"Trace: {len(report['trace'])} exchanges, secrets redacted. See the JSON report for the full trace.", ""]
    return "\n".join(lines)
