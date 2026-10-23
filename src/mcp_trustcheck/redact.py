"""Secret redaction for captured traces. Pattern based, so it is a safety net, not a guarantee."""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "mcp-session-id"}
SENSITIVE_KEYS = re.compile(r"(token|secret|password|passwd|api[_-]?key|authorization|credential)", re.I)
PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
MASK = "[REDACTED]"


def redact_text(text: str, extra: list[str] | None = None) -> str:
    for secret in extra or []:
        if secret:
            text = text.replace(secret, MASK)
    for pattern in PATTERNS:
        text = pattern.sub(MASK, text)
    return text


def redact_value(value: Any, extra: list[str] | None = None) -> Any:
    if isinstance(value, dict):
        return {k: (MASK if SENSITIVE_KEYS.search(str(k)) and isinstance(v, (str, int)) else redact_value(v, extra)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, extra) for v in value]
    if isinstance(value, str):
        return redact_text(value, extra)
    return value


def redact_headers(headers: dict[str, str], extra: list[str] | None = None) -> dict[str, str]:
    return {k: (MASK if k.lower() in SENSITIVE_HEADERS else redact_text(v, extra)) for k, v in headers.items()}


def find_secrets(text: str, extra: list[str] | None = None) -> list[str]:
    """Names of secret patterns still present in text (never the secret itself)."""
    found = [f"literal:{i}" for i, s in enumerate(extra or []) if s and s in text]
    found += [f"pattern:{i}" for i, p in enumerate(PATTERNS) if p.search(text)]
    return found
