"""scan/check tool의 file_path 입력 통합 테스트 (Ollama/Chroma 불필요)."""

import hashlib
import os
import sqlite3

import pytest

import mcp_server
from compliance import fileio


@pytest.fixture(autouse=True)
def _tmp_audit_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))


@pytest.fixture(autouse=True)
def _stub_rag(monkeypatch):
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


def _write_txt(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_scan_from_file(tmp_path):
    path = _write_txt(tmp_path, "memo.txt", "김철수 010-1234-5678 확정 수익률 보장")
    r = mcp_server.scan_sensitive_info(file_path=path)
    assert r["ok"] is True
    assert r["requires_human_review"] is True
    assert "010-1234-5678" not in r["data"]["masked_text"]
    assert r["data"]["source_file"]["file_name"] == "memo.txt"
    assert r["data"]["source_file"]["truncated"] is False


def test_scan_rejects_both_args(tmp_path):
    path = _write_txt(tmp_path, "memo.txt", "본문")
    r = mcp_server.scan_sensitive_info(text="본문", file_path=path)
    assert r["ok"] is False
    assert r["requires_human_review"] is True
    assert "정확히 하나" in r["summary"]


def test_scan_neither_arg_keeps_legacy_empty_text_path():
    # 인자 없음은 기존 빈 text 계약(tool별 자체 처리)을 따른다 — PR #27 엣지케이스 유지.
    r = mcp_server.scan_sensitive_info()
    assert r["tool"] == "scan_sensitive_info"
    assert "source_file" not in (r["data"] or {})


def test_scan_none_text_uses_legacy_empty_text_path():
    r = mcp_server.scan_sensitive_info(text=None)
    assert r["ok"] is True
    assert r["tool"] == "scan_sensitive_info"


def test_scan_missing_file_fails_closed():
    r = mcp_server.scan_sensitive_info(file_path="/없는/경로/file.txt")
    assert r["ok"] is False
    assert "파일 입력 오류" in r["summary"]


def test_scan_truncated_file_forces_review(tmp_path, monkeypatch):
    monkeypatch.setattr(fileio, "MAX_TEXT_CHARS", 50)
    path = _write_txt(tmp_path, "big.txt", "무해한 본문 " * 30)
    r = mcp_server.scan_sensitive_info(file_path=path)
    assert r["ok"] is True
    assert r["requires_human_review"] is True
    assert r["data"]["source_file"]["truncated"] is True
    assert any("절단" in line for line in r["outputs"])


def test_text_only_behavior_unchanged():
    r = mcp_server.scan_sensitive_info(text="오늘 점심 메뉴 공지")
    assert r["ok"] is True
    assert "source_file" not in r["data"]


def test_check_from_file_logs_extracted_hash(tmp_path):
    path = _write_txt(tmp_path, "draft.txt", "신제품 실적 미공개 자료 초안")
    r = mcp_server.check_disclosure_risk(file_path=path)
    assert r["ok"] is True
    assert r["data"]["source_file"]["file_name"] == "draft.txt"
    assert r["data"]["audit_log"]["auto_logged"] is True
    # 감사 DB에는 원문이 아니라 해시만 남는다.
    conn = sqlite3.connect(os.environ["AUDIT_DB_PATH"])
    try:
        row = conn.execute(
            "SELECT input_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert "미공개" not in row[0]
    assert len(row[0]) == 64


def test_check_truncation_escalation_reaches_audit(tmp_path, monkeypatch):
    monkeypatch.setattr(fileio, "MAX_TEXT_CHARS", 30)
    path = _write_txt(tmp_path, "long.txt", "평범한 내용 " * 20)
    r = mcp_server.check_disclosure_risk(file_path=path)
    assert r["ok"] is True
    assert r["requires_human_review"] is True
    # 절단 격상이 감사 기록 이전에 반영되어야 한다.
    assert r["data"]["audit_log"]["logged_requires_human_review"] is True


def test_check_rejects_both_args(tmp_path):
    path = _write_txt(tmp_path, "memo.txt", "본문")
    r = mcp_server.check_disclosure_risk(text="본문", file_path=path)
    assert r["ok"] is False
    assert "정확히 하나" in r["summary"]


def test_check_none_text_is_logged_as_empty_string():
    r = mcp_server.check_disclosure_risk(text=None)
    assert r["ok"] is True

    conn = sqlite3.connect(os.environ["AUDIT_DB_PATH"])
    try:
        row = conn.execute(
            "SELECT input_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert row == (hashlib.sha256(b"").hexdigest(),)
