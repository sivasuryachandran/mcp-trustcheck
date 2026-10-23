import json

import pytest

from mcp_trustcheck.checks import Config, validate
from mcp_trustcheck.cli import main
from mcp_trustcheck.mock_server import serve_in_thread
from mcp_trustcheck.redact import find_secrets, redact_headers, redact_text, redact_value
from mcp_trustcheck.report import to_json, to_markdown
from mcp_trustcheck.runner import run

CALLS = [("echo", {"text": "hi"}), ("add", {"a": 2, "b": 3})]


@pytest.fixture
def serve():
    servers = []

    def start(**kw):
        server, url = serve_in_thread(**kw)
        servers.append(server)
        return url

    yield start
    for s in servers:
        s.shutdown()


def statuses(report):
    return {r["name"]: r["status"] for r in report["results"]}


def test_clean_server_passes_every_check(serve):
    report = run(serve(), Config(calls=CALLS))
    assert report["summary"]["ok"], report["results"]
    st = statuses(report)
    assert st["protocol_version"] == "pass" and st["structured_output:add"] == "pass"
    assert st["structured_output:echo"] == "skip"


def test_sse_responses_are_understood(serve):
    assert run(serve(sse=True), Config(calls=CALLS))["summary"]["ok"]


@pytest.mark.parametrize("flaw,check", [
    ("old-protocol", "protocol_version"),
    ("wrong-id", "request_ids"),
    ("echo-secret", "server_does_not_echo_secrets"),
    ("bad-structured", "structured_output:add"),
    ("no-errors", "error_unknown_method"),
])
def test_each_flaw_is_caught(serve, flaw, check):
    report = run(serve(flaw=flaw), Config(calls=CALLS))
    assert statuses(report)[check] == "fail"
    assert not report["summary"]["ok"]


def test_unreachable_server_fails_without_crashing():
    report = run("http://127.0.0.1:1/mcp", Config(), timeout=1)
    assert not report["summary"]["ok"]
    assert statuses(report)["initialize"] == "fail"


def test_latency_limit_is_enforced(serve):
    assert statuses(run(serve(), Config(max_latency_ms=0.0001)))["latency"] == "fail"


def test_token_never_appears_in_report(serve):
    token = "tok_" + "a1B2c3D4e5F6g7H8"
    report = run(serve(), Config(token=token, calls=CALLS))
    text = to_json(report) + to_markdown(report)
    assert token not in text and "Bearer" not in text.replace("[REDACTED]", "")
    assert report["trace"][0]["request_headers"]["Authorization"] == "[REDACTED]"


def test_canary_is_redacted_in_trace(serve):
    cfg = Config(calls=CALLS)
    assert cfg.canary not in to_json(run(serve(), cfg))


def test_redaction_helpers():
    assert "[REDACTED]" in redact_text("Authorization: Bearer abcdefghij123456")
    assert redact_text("key sk-abcdefghijklmnopqrstuv") == "key [REDACTED]"
    assert redact_value({"api_key": "x", "n": 1, "t": ["AKIAABCDEFGHIJKLMNOP"]}) == {"api_key": "[REDACTED]", "n": 1, "t": ["[REDACTED]"]}
    assert redact_headers({"Cookie": "a=b", "Accept": "x"}) == {"Cookie": "[REDACTED]", "Accept": "x"}
    assert find_secrets("clean text") == [] and find_secrets("mine-secret", ["mine-secret"])


def test_schema_validator():
    schema = {"type": "object", "required": ["n"], "properties": {"n": {"type": "integer"}, "l": {"type": "array", "items": {"type": "string"}}}}
    assert validate({"n": 1, "l": ["a"]}, schema) == []
    assert validate({"n": True}, schema)  # bool is not an integer
    assert validate({}, schema) == ["$.n: required"]
    assert validate({"n": 1, "l": [1]}, schema)


def test_cli_writes_reports_and_exit_codes(serve, tmp_path, capsys):
    out_json, out_md = tmp_path / "r.json", tmp_path / "r.md"
    code = main([serve(), "--call", "echo={\"text\":\"x\"}", "--json", str(out_json), "--markdown", str(out_md)])
    assert code == 0 and json.loads(out_json.read_text())["summary"]["ok"]
    assert out_md.read_text().startswith("# mcp-trustcheck report")
    assert main([serve(flaw="wrong-id")]) == 1
    assert main(["http://127.0.0.1:1/mcp", "--timeout", "1"]) == 1


def test_cli_rejects_bad_arguments(capsys, monkeypatch):
    with pytest.raises(SystemExit):
        main(["http://x/mcp", "--call", "echo={bad"])
    monkeypatch.delenv("NOPE_TOKEN", raising=False)
    assert main(["http://x/mcp", "--token-env", "NOPE_TOKEN"]) == 2
