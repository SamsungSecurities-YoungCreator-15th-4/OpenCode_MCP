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


@pytest.fixture(autouse=True)
def _stub_rag(monkeypatch):
    """MCP 단위 테스트는 Ollama/Chroma 없이 tool 응답 계약만 검증한다."""
    sample_match = {
        "source": "표준투자권유준칙",
        "file_name": "rules.pdf",
        "article": "제10조",
        "article_title": "사전확인",
        "chunk_id": "rules_10_0",
        "snippet": "준법감시인 사전확인이 필요하다.",
        "score": 0.1,
    }
    monkeypatch.setattr(mcp_server.rag, "_ensure_ready", lambda: (True, None))
    monkeypatch.setattr(mcp_server.rag, "_search", lambda query, top_k=5: [sample_match])


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


def test_rag_tools_declare_real_local_search():
    for result in (
        mcp_server.check_disclosure_risk("x"),
        mcp_server.search_compliance_rule("x"),
    ):
        assert result["data"]["mock"] is False
        assert "hallucination_guard" in result["data"]


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


def test_check_disclosure_risk_does_not_require_review_for_evidence_only():
    result = mcp_server.check_disclosure_risk("x")

    assert result["data"]["matches"]
    assert result["requires_human_review"] is False


def test_check_disclosure_risk_requires_review_for_risk_signal():
    result = mcp_server.check_disclosure_risk("실적 발표 전 대외 공유 자료입니다.")

    assert result["data"]["risk_signals"]
    assert result["requires_human_review"] is True
