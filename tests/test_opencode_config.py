"""폐쇄망 OpenCode 설정의 회귀 테스트."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / "opencode.json").read_text(encoding="utf-8"))
def test_opencode_uses_only_local_ollama_provider():
    assert CONFIG["model"] == "ollama/qwen3-instruct-16k"
    assert CONFIG["enabled_providers"] == ["ollama"]
    assert CONFIG["provider"]["ollama"]["options"]["baseURL"] == (
        "http://127.0.0.1:11434/v1"
    )


def test_external_and_host_tool_paths_are_fail_closed():
    assert CONFIG["share"] == "disabled"
    assert CONFIG["autoupdate"] is False
    assert list(CONFIG["tools"].items()) == [
        ("*", False),
        ("compliance-assistant_*", True),
    ]
    assert list(CONFIG["permission"].items()) == [
        ("*", "deny"),
        ("compliance-assistant_*", "allow"),
    ]


def test_qwen_agent_is_deterministic_and_iteration_bounded():
    assert CONFIG["agent"]["build"]["temperature"] == 0.1
    assert CONFIG["agent"]["build"]["steps"] == 4


def test_only_local_compliance_mcp_is_enabled():
    assert set(CONFIG["mcp"]) == {"compliance-assistant"}
    server = CONFIG["mcp"]["compliance-assistant"]
    assert server["type"] == "local"
    assert server["enabled"] is True
    assert server["command"] == [".venv/bin/python", "mcp_server.py"]


def test_runtime_rules_define_non_overlapping_tool_routes():
    rules = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "개인정보·마스킹은 scan" in rules
    assert "미공개·공시·대외공유 위험은 check" in rules
    assert "규정 원문·조항 검색은 search" in rules
    assert "scan/search만 호출했으면 감사 로그가 저장됐다고 말하지 않는다" in rules
