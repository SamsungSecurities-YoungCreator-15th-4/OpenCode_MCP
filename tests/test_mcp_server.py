"""MCP 툴 함수 단위 테스트 (FastMCP @tool 데코레이터는 원본 함수를 그대로 반환한다)."""

import asyncio
import os
import sqlite3

import pytest

import mcp_server
from compliance import schema

EXPECTED_TOOLS = {
    "scan_sensitive_info",
    "check_disclosure_risk",
    "search_compliance_rule",
    "log_ai_usage",
}
AUDIT_CONFIRMATION = (
    "🔒 확인한 내용이 안전하게 기록되었습니다. 개인정보와 미공개 정보 등 "
    "민감한 내용은 노출되지 않도록 보호한 뒤 저장됩니다."
)


def _audit_count() -> int:
    db_path = os.environ["AUDIT_DB_PATH"]
    if not os.path.exists(db_path):
        return 0
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()


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
        "vector_distance": 0.1,
        "vector_similarity": 0.9,
    }
    monkeypatch.setattr(mcp_server.rag, "_ensure_ready", lambda: (True, None))
    monkeypatch.setattr(mcp_server.rag, "_search", lambda query, top_k=5: [sample_match])
    monkeypatch.setattr(
        mcp_server.rag,
        "_generate_answer",
        lambda task, query, matches, risk_signals=None: (
            "검색된 근거를 확인했습니다. [1]",
            {"enabled": True, "model": "qwen3-instruct-16k", "error": None},
        ),
    )


def test_exactly_four_tools_registered():
    tools = asyncio.run(mcp_server.mcp.list_tools())
    assert {t.name for t in tools} == EXPECTED_TOOLS


def test_audit_confirmation_is_declared_for_all_log_saving_paths():
    tools = {tool.name: tool for tool in asyncio.run(mcp_server.mcp.list_tools())}

    check_description = tools["check_disclosure_risk"].description
    log_description = tools["log_ai_usage"].description

    assert "data.audit_log.auto_logged=true" in check_description
    assert AUDIT_CONFIRMATION in check_description
    assert "duplicate check_disclosure_risk log requests are ignored" in log_description
    assert "append this summary verbatim at the end" in log_description


def test_scan_sensitive_info_uses_real_detector():
    result = mcp_server.scan_sensitive_info("담당자 연락처는 010-1234-5678 입니다.")

    assert result["ok"] is True
    assert result["data"]["findings"][0]["type"] == "phone"
    assert result["data"]["masked_text"] == "담당자 연락처는 010-****-5678 입니다."
    assert result["requires_human_review"] is True

def test_scan_sensitive_info_requires_review_for_prohibited_claim():
    result = mcp_server.scan_sensitive_info("이 상품은 원금 보장되고 확정 수익을 제공합니다.")

    assert result["ok"] is True
    assert result["data"]["detected_types"] == ["PROHIBITED_CLAIM"]
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
        assert result["data"]["threshold_passed"] is True
        assert result["data"]["citation_verified"] is True
        assert result["data"]["cited_articles"] == []
        assert result["data"]["answer"]
        assert result["data"]["answer_generation"]["model"] == "qwen3-instruct-16k"


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
    assert {item["criterion_no"] for item in result["data"]["matched_criteria"]} == {
        "1호",
        "6호",
    }
    assert result["requires_human_review"] is True


def test_check_disclosure_risk_auto_records_audit_log():
    result = mcp_server.check_disclosure_risk("실적 발표 전 대외 공유 자료입니다.")

    assert _audit_count() == 1
    assert result["data"]["audit_log"]["id"] == 1
    assert result["data"]["audit_log"]["auto_logged"] is True
    assert result["data"]["audit_log"]["logged_requires_human_review"] is True
    assert len(result["data"]["audit_log"]["record_hash"]) == 64


def test_log_ai_usage_skips_duplicate_check_disclosure_risk_record():
    check = mcp_server.check_disclosure_risk("실적 발표 전 대외 공유 자료입니다.")
    duplicate = mcp_server.log_ai_usage(
        "check_disclosure_risk",
        "실적 발표 전 대외 공유 자료입니다.",
        check["summary"],
        check["requires_human_review"],
    )

    assert _audit_count() == 1
    assert duplicate["ok"] is True
    assert duplicate["summary"] == AUDIT_CONFIRMATION
    assert duplicate["data"]["skipped"] is True
    assert duplicate["data"]["skip_reason"] == (
        "check_disclosure_risk_auto_logs_audit_record"
    )
    assert "id" not in duplicate["data"]
    assert "record_hash" not in duplicate["data"]


def test_check_disclosure_risk_handles_none_data_before_audit_metadata(monkeypatch):
    monkeypatch.setattr(
        mcp_server.rag,
        "check_disclosure_risk",
        lambda text: schema.ok(
            "check_disclosure_risk",
            "점검 결과입니다.",
            data=None,
            requires_human_review=True,
        ),
    )

    result = mcp_server.check_disclosure_risk("실적 발표 전 대외 공유 자료입니다.")

    assert result["ok"] is True
    assert result["data"]["audit_log"]["auto_logged"] is True
    assert _audit_count() == 1


def test_scan_and_search_do_not_auto_record_audit_log():
    mcp_server.scan_sensitive_info("담당자 연락처는 010-1234-5678 입니다.")
    mcp_server.search_compliance_rule("준법감시인 사전확인")

    assert _audit_count() == 0


def test_check_disclosure_risk_requires_review_for_clear_material_signal():
    result = mcp_server.check_disclosure_risk("미공개 실적, 발표 전 유상증자 자료")

    assert result["requires_human_review"] is True
    assert result["data"]["threshold_passed"] is True
    assert {item["criterion_no"] for item in result["data"]["matched_criteria"]} == {
        "1호",
        "5호",
        "6호",
    }


def test_check_disclosure_risk_requires_review_for_ambiguous_signal():
    result = mcp_server.check_disclosure_risk("발표 전 자료인지 애매한 실적 메모")

    assert result["requires_human_review"] is True
    assert result["data"]["risk_signals"]


def test_check_disclosure_risk_cuts_off_weak_retrieval(monkeypatch):
    weak_match = {
        "source": "표준투자권유준칙",
        "file_name": "rules.pdf",
        "article": "제10조",
        "article_title": "사전확인",
        "chunk_id": "rules_10_0",
        "snippet": "준법감시인 사전확인이 필요하다.",
        "score": 0.1,
        "vector_distance": 0.92,
        "vector_similarity": 0.08,
    }
    monkeypatch.setattr(mcp_server.rag, "_search", lambda query, top_k=5: [weak_match])

    result = mcp_server.check_disclosure_risk("오늘 점심 메뉴 추천")

    assert result["requires_human_review"] is True
    assert result["summary"].startswith("관련 규정을 찾지 못했습니다.")
    assert result["data"]["threshold_passed"] is False
    assert result["data"]["matches"] == []
    assert result["data"]["citation_verified"] is True
    assert result["data"]["cited_articles"] == []
    assert result["outputs"] == []


def test_check_disclosure_risk_discards_unsupported_article_citation(monkeypatch):
    monkeypatch.setattr(
        mcp_server.rag,
        "_generate_answer",
        lambda task, query, matches, risk_signals=None: (
            "제999조에 따라 준법감시인 확인이 필요합니다.",
            {"enabled": True, "model": "qwen3-instruct-16k", "error": None},
        ),
    )

    result = mcp_server.check_disclosure_risk("점검용 텍스트")

    assert result["requires_human_review"] is True
    assert result["summary"] != "제999조에 따라 준법감시인 확인이 필요합니다."
    assert result["data"]["answer"] is None
    assert result["data"]["citation_verified"] is False
    assert result["data"]["cited_articles"] == ["제999조"]
    assert result["data"]["answer_generation"]["discarded"] is True


def test_check_disclosure_risk_uses_answer_review_signal_without_regex(monkeypatch):
    monkeypatch.setattr(
        mcp_server.rag,
        "_generate_answer",
        lambda task, query, matches, risk_signals=None: (
            "검색 근거상 준법감시인 확인이 필요합니다. [1]",
            {"enabled": True, "model": "qwen3-instruct-16k", "error": None},
        ),
    )

    result = mcp_server.check_disclosure_risk("점검용 텍스트")

    assert result["data"]["risk_signals"] == []
    assert result["requires_human_review"] is True
