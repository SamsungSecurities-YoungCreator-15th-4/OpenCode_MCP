"""MCP 툴 함수 단위 테스트 (FastMCP @tool 데코레이터는 원본 함수를 그대로 반환한다)."""

import asyncio

import pytest

import mcp_server
from compliance import schema

EXPECTED_TOOLS = {
    "scan_sensitive_info",
    "check_disclosure_risk",
    "search_compliance_rule",
    "log_ai_usage",
}


@pytest.fixture(autouse=True)
def _tmp_audit_db(tmp_path, monkeypatch):
    """log_ai_usage가 실제 data/audit.db 대신 임시 DB에 기록하도록 격리한다."""
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))


def test_exactly_four_tools_registered():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_scan_sensitive_info_uses_real_detector():
    result = mcp_server.scan_sensitive_info("담당자 연락처는 010-1234-5678 입니다.")
    assert result["ok"] is True
    assert result["tool"] == "scan_sensitive_info"
    assert result["data"]["findings"][0]["type"] == "phone"
    assert result["requires_human_review"] is True


def test_every_tool_returns_common_schema():
    results = [
        mcp_server.scan_sensitive_info("점검용 텍스트"),
        mcp_server.check_disclosure_risk("점검용 텍스트"),
        mcp_server.search_compliance_rule("준법감시인 사전확인"),
        mcp_server.log_ai_usage("scan_sensitive_info", "점검용 원문", "요약", True),
    ]
    for result in results:
        assert set(result) == set(schema.RESULT_KEYS)
        assert result["ok"] is True
        assert result["error"] is None


def test_mock_tools_declare_themselves_as_mock():
    # scan·log_ai_usage는 실구현이므로 mock 선언 대상은 check·search 둘뿐이다.
    for result in (
        mcp_server.check_disclosure_risk("x"),
        mcp_server.search_compliance_rule("x"),
    ):
        assert result["data"]["mock"] is True
        assert "[mock]" in result["summary"]


def test_log_ai_usage_is_real_and_records_hash():
    result = mcp_server.log_ai_usage(
        "scan_sensitive_info", "점검용 원문", "phone 1건 탐지", True
    )
    assert result["ok"] is True
    assert result["tool"] == "log_ai_usage"
    assert "mock" not in result["data"]
    # 실제 기록 결과로 record_hash·id가 반환된다.
    assert result["data"]["id"] == 1
    assert len(result["data"]["record_hash"]) == 64
    assert result["data"]["prev_hash"] == "GENESIS"


def test_check_disclosure_risk_mock_is_conservative():
    # 규정 매칭 구현 전에는 무조건 "확인 필요"로 안내한다 (미탐 방지)
    assert mcp_server.check_disclosure_risk("x")["requires_human_review"] is True
