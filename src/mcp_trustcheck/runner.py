from __future__ import annotations

import datetime as dt

from . import __version__
from .checks import ALL, FAIL, Config, Result
from .client import McpHttp
from .redact import redact_text


def run(url: str, cfg: Config, headers: dict[str, str] | None = None, timeout: float = 15.0, skip: set[str] | None = None) -> dict:
    secrets = [cfg.canary] + ([cfg.token] if cfg.token else [])
    hdrs = {"X-Trustcheck-Canary": cfg.canary, **(headers or {})}
    if cfg.token:
        hdrs.setdefault("Authorization", f"Bearer {cfg.token}")
    client = McpHttp(url, hdrs, timeout, secrets)
    state: dict = {}
    results: list[Result] = []
    for name, fn in ALL.items():
        if skip and name in skip:
            continue
        try:
            results.extend(fn(client, cfg, state))
        except Exception as err:  # a crashing check is a failed check, not a crashed run
            results.append(Result(name, FAIL, f"check crashed: {type(err).__name__}"))
        if name == "initialize" and results and results[0].status == FAIL:
            break  # nothing else is meaningful without a session
    # redaction and latency summarise everything above; they run last regardless of order in ALL
    counts = {s: sum(r.status == s for r in results) for s in ("pass", "fail", "warn", "skip")}
    return {
        "tool": "mcp-trustcheck", "version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "target": redact_text(url, secrets),
        "summary": {**counts, "ok": counts["fail"] == 0},
        "results": [r.__dict__ for r in results],
        "trace": client.trace(),
    }
