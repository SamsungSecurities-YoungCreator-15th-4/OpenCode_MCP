"""엣지케이스 모음 — 4개 tool의 경계 조건과 tool 간 연계를 검증한다.

기존 테스트(test_detector/test_audit/test_rag/test_mcp_server)는 각 모듈의
정상 경로를 덮는다. 이 파일은 그 사이의 틈을 덮는다:

- 탐지 유형이 겹칠 때의 우선순위와 span 정합성
- findings 절단 시 masked_text가 원문을 흘리지 않는지 (절단 != 누출)
- 해시 체인의 직렬화 경계 (구분자 파이프)
- RAG 임계값 경계값과 인용 대조의 엄격도
- scan → log_ai_usage 연계 (실제 시연 경로)

xfail로 표시된 테스트는 "고쳐야 할 알려진 갭"이다. 통과하기 시작하면
strict=True가 XPASS로 실패시켜, 고친 뒤 마커를 지우도록 강제한다.
"""

import hashlib
import sqlite3

import pytest

import mcp_server
from compliance.audit import logger
from compliance.detector import scan_text

# =============================================================================
# 1. scan_sensitive_info — 탐지 유형이 겹칠 때
# =============================================================================


def test_rrn_wins_over_account_on_overlapping_span():
    """계좌 키워드 옆의 주민번호는 계좌가 아니라 주민번호로 잡혀야 한다.

    scan_text는 rrn을 account보다 먼저 돌리고 _SpanClaims로 구간을 선점한다.
    순서가 뒤집히면 주민번호가 '***4567'로만 마스킹돼 고유식별정보라는
    사실이 findings에서 사라진다.
    """
    result = scan_text("계좌번호 900101-1234567 입금")

    assert [f["type"] for f in result["data"]["findings"]] == ["rrn"]
    assert result["data"]["masked_text"] == "계좌번호 900101-1****** 입금"


def test_card_wins_over_account_on_overlapping_span():
    """계좌 키워드 옆의 카드번호는 카드로 잡히고, 계좌로 중복 계상되지 않는다."""
    result = scan_text("계좌 4111-1111-1111-1111 로 입금")

    assert [f["type"] for f in result["data"]["findings"]] == ["card"]
    assert result["data"]["counts"] == {"card": 1}


def test_invalid_rrn_date_falls_through_to_account_detection():
    """주민번호 날짜 검증에 걸러진 13자리는 계좌 후보로 재평가된다.

    991301(13월)은 주민번호가 아니지만, 계좌 키워드가 붙어 있으면 계좌번호로
    잡혀야 한다 — 어느 쪽으로도 안 잡혀 통과하는 게 가장 나쁜 결과다.
    """
    result = scan_text("계좌 991301-1234567 로 입금")

    assert [f["type"] for f in result["data"]["findings"]] == ["account"]
    assert result["data"]["masked_text"] == "계좌 ***4567 로 입금"


def test_finding_span_indexes_original_text_not_masked_text():
    """span은 원문 offset이다. masked_text에 적용하면 엉뚱한 구간이 잘린다.

    소비자(OpenCode 등)가 span으로 원문을 다시 잘라볼 수 있어야 하므로
    이 계약을 고정한다.
    """
    text = "연락처 010-1234-5678 이메일 hong@corp.co.kr"
    result = scan_text(text)

    by_type = {f["type"]: f for f in result["data"]["findings"]}
    phone = by_type["phone"]
    email = by_type["email"]

    assert text[phone["span"][0] : phone["span"][1]] == "010-1234-5678"
    assert text[email["span"][0] : email["span"][1]] == "hong@corp.co.kr"


# =============================================================================
# 2. scan_sensitive_info — 절단이 누출로 이어지지 않는지 (가장 중요)
# =============================================================================


def test_truncated_findings_still_fully_mask_the_text(monkeypatch):
    """findings를 잘라도 masked_text는 탐지된 전부를 마스킹해야 한다.

    SCAN_MAX_FINDINGS는 응답 크기를 제한하는 장치지 마스킹을 끄는 장치가 아니다.
    여기가 깨지면 '상세를 줄였더니 원문이 샜다'가 된다.
    """
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "1")

    result = scan_text("010-1111-1111 그리고 010-2222-2222 그리고 hong@corp.co.kr")
    data = result["data"]

    assert data["returned_findings"] == 1
    assert data["total_findings"] == 3
    assert data["truncated"] is True

    masked = data["masked_text"]
    for secret in ("010-1111-1111", "010-2222-2222", "hong@corp.co.kr"):
        assert secret not in masked


def test_counts_reflect_all_findings_even_when_findings_are_truncated(monkeypatch):
    """counts·detected_types는 절단 전 전체 기준이다 (findings만 잘린다)."""
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "1")

    data = scan_text("010-1111-1111 그리고 010-2222-2222 그리고 hong@corp.co.kr")["data"]

    assert len(data["findings"]) == 1
    assert data["counts"] == {"phone": 2, "email": 1}
    assert data["detected_types"] == ["EMAIL", "PHONE"]
    assert data["truncated_findings"] == 2


def test_whitespace_only_input_is_not_treated_as_empty():
    """공백만 있는 입력은 빈 입력이 아니라 '탐지 0건'으로 처리된다."""
    result = scan_text("   ")

    assert result["ok"] is True
    assert result["data"]["masked_text"] == "   "
    assert result["data"]["log_safe_summary"] != "scan_sensitive_info: 빈 입력"
    assert result["requires_human_review"] is False


# =============================================================================
# 3. scan_sensitive_info — 오탐/미탐 경계
# =============================================================================


def test_repeated_zero_card_number_passes_luhn_and_is_flagged():
    """0000-0000-0000-0000은 Luhn 합이 0이라 유효 판정된다 → 오탐.

    오탐은 미탐보다 안전하므로 현재 동작을 고정한다. Luhn만으로는
    자명한 더미 번호를 거를 수 없다는 사실을 기록해 둔다.
    """
    result = scan_text("카드 0000 0000 0000 0000")

    assert [f["type"] for f in result["data"]["findings"]] == ["card"]


def test_card_requires_consistent_separator():
    """구분자가 섞인 카드번호는 역참조(\\1) 때문에 미탐된다."""
    mixed = scan_text("카드 4111-1111 1111-1111")
    consistent = scan_text("카드 4111-1111-1111-1111")

    assert mixed["data"]["findings"] == []
    assert [f["type"] for f in consistent["data"]["findings"]] == ["card"]


def test_space_separated_rrn_is_high_confidence():
    """하이픈 대신 공백으로 끊긴 주민번호도 구분자가 있으므로 high confidence다."""
    finding = scan_text("주민 900101 1234567")["data"]["findings"][0]

    assert finding["type"] == "rrn"
    assert finding["confidence"] == "high"


def test_account_keyword_outside_window_is_not_detected():
    """계좌 키워드가 근접 창(24자) 밖이면 계좌로 확정하지 않는다.

    설계상 의도된 미탐이다. 창 크기를 바꾸면 이 테스트가 먼저 깨진다.
    """
    result = scan_text("110-222-333333 " + "가" * 30 + " 입금")

    assert result["data"]["findings"] == []


def test_internal_keyword_lookahead_blocks_compound_but_not_real_usage():
    """'공개 전략'은 통과, '공개 전 자료'는 탐지 — 부정형 전방탐색 경계."""
    assert scan_text("공개 전략회의 자료")["data"]["findings"] == []
    assert scan_text("공개 전 자료입니다")["data"]["detected_types"] == [
        "INTERNAL_KEYWORD"
    ]


def test_principal_guarantee_negation_only_handles_specific_particles():
    """'원금 보장이 되지 않습니다'는 부정으로 인식되지만 '보장은'은 아니다.

    부정형 전방탐색이 조사 '이/가'만 처리해, '은'이 붙으면 금지표현으로 잡힌다.
    오탐 방향이라 통과시키되, 조사 커버리지 갭을 여기 고정해 둔다.
    """
    assert scan_text("이 상품은 원금 보장이 되지 않습니다")["data"]["findings"] == []
    assert scan_text("이 상품은 원금 보장은 되지 않습니다")["data"]["detected_types"] == [
        "PROHIBITED_CLAIM"
    ]


@pytest.mark.xfail(
    strict=True,
    reason="미탐: _PHONE_RE가 0으로 시작하는 국내 형식만 허용하고 +82 국가번호를 "
    "국내 0으로 정규화하지 않아 국제표기 휴대전화를 탐지하지 못한다.",
)
def test_international_format_phone_is_detected():
    assert scan_text("연락처 +82-10-1234-5678 입니다")["data"]["findings"]


@pytest.mark.xfail(
    strict=True,
    reason="미탐: _PHONE_RE의 번호 구분자가 하이픈 또는 공백([-\\s])으로 "
    "제한되어 점(.) 구분 휴대전화를 탐지하지 못한다.",
)
def test_dot_separated_phone_is_detected():
    assert scan_text("연락처 010.1234.5678")["data"]["findings"]


@pytest.mark.xfail(
    strict=True,
    reason="미탐: _PHONE_RE가 re.ASCII의 \\d를 사용하고 입력을 NFKC 정규화하지 "
    "않아 전각 숫자 전화번호를 탐지하지 못한다.",
)
def test_fullwidth_digit_phone_is_detected():
    assert scan_text("연락처 ０１０-１２３４-５６７８")["data"]["findings"]


# =============================================================================
# 4. log_ai_usage / 감사 로그 — 해시 체인 경계
# =============================================================================


def _db(tmp_path) -> str:
    return str(tmp_path / "audit.db")


def test_verify_chain_on_empty_db_is_valid():
    """레코드가 하나도 없는 체인은 '깨지지 않은' 상태다."""
    assert logger.verify_chain(db_path=":memory:") == {
        "valid": True,
        "broken_at": None,
        "total_records": 0,
    }


def test_timestamp_is_kst_isoformat(tmp_path):
    record = logger.append("t", "원문", "요약", False, db_path=_db(tmp_path))

    assert record["timestamp"].endswith("+09:00")


def test_input_hash_is_plain_sha256_of_utf8_input(tmp_path):
    """input_hash 계산식을 고정한다 — 준법감시 담당자가 외부에서 재현할 수 있어야 한다."""
    text = "원문 텍스트"
    record = logger.append("t", text, "요약", False, db_path=_db(tmp_path))

    assert record["input_hash"] == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_empty_input_and_summary_are_accepted(tmp_path):
    record = logger.append("t", "", "", False, db_path=_db(tmp_path))

    assert record["result_summary"] == ""
    assert record["input_hash"] == hashlib.sha256(b"").hexdigest()


def test_result_summary_rescan_mangles_legitimate_summaries(tmp_path):
    """저장 전 재스캔이 '정상 요약'까지 마스킹해 버리는 경우를 고정한다.

    "미공개중요정보 위험 없음"은 위험이 없다는 보고인데, '미공개'가 내부정보
    키워드로, '위험 없음'이 금지표현(risk_free)으로 잡혀 양쪽 다 치환된다.
    결과적으로 감사 로그에는 뜻이 뒤집힌 요약이 남고 rhr까지 True로 승격된다.

    안전(원문 미저장) 측면에서는 문제가 없어 현재 동작을 유지하되, 감사 로그
    가독성 문제로 팀 논의가 필요하다.
    """
    record = logger.append(
        "check_disclosure_risk", "원문", "미공개중요정보 위험 없음", False, db_path=_db(tmp_path)
    )

    assert record["result_summary"] == "[내부정보키워드]중요정보 [금지표현]"
    assert record["requires_human_review"] == 1


@pytest.mark.xfail(
    strict=True,
    reason="위변조 미탐: _sanitize()가 해시 직전 '|'를 '/'로 치환하지만 DB에는 원본을 "
    "저장한다. 따라서 저장된 'a|b'를 'a/b'로 바꿔도 record_hash가 그대로라 "
    "verify_chain이 valid=True를 반환한다. 길이 프리픽스나 JSON 직렬화로 "
    "해시 입력을 모호하지 않게 만들어야 한다.",
)
def test_pipe_to_slash_tampering_is_detected(tmp_path):
    db = _db(tmp_path)
    record = logger.append("t", "원문", "요약a|요약b", False, db_path=db)

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE audit_log SET result_summary = ? WHERE id = ?",
        ("요약a/요약b", record["id"]),
    )
    conn.commit()
    conn.close()

    assert logger.verify_chain(db_path=db)["valid"] is False


@pytest.mark.xfail(
    strict=True,
    reason="위변조 미탐: tool_name 원본은 DB에 저장하지만 해시 계산 전 _sanitize()가 "
    "'|'를 '/'로 치환해 'scan|evil'과 'scan/evil'의 record_hash가 같아진다.",
)
def test_tool_name_pipe_tampering_is_detected(tmp_path):
    db = _db(tmp_path)
    record = logger.append("scan|evil", "원문", "요약", False, db_path=db)

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE audit_log SET tool_name = ? WHERE id = ?", ("scan/evil", record["id"])
    )
    conn.commit()
    conn.close()

    assert logger.verify_chain(db_path=db)["valid"] is False


def test_tampering_the_last_record_is_still_detected(tmp_path):
    """체인 끝(뒤에 아무 레코드도 없는 위치) 변조도 record_hash 재계산으로 잡힌다."""
    db = _db(tmp_path)
    logger.append("t", "a", "요약1", False, db_path=db)
    last = logger.append("t", "b", "요약2", False, db_path=db)

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE audit_log SET requires_human_review = 1 WHERE id = ?", (last["id"],)
    )
    conn.commit()
    conn.close()

    result = logger.verify_chain(db_path=db)
    assert result["valid"] is False
    assert result["broken_at"] == last["id"]


def test_deleting_a_middle_record_breaks_the_chain(tmp_path):
    """레코드 삭제도 prev_hash 연결이 끊겨 탐지된다 (변조 = 수정 + 삭제)."""
    db = _db(tmp_path)
    logger.append("t", "a", "요약1", False, db_path=db)
    middle = logger.append("t", "b", "요약2", False, db_path=db)
    third = logger.append("t", "c", "요약3", False, db_path=db)

    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM audit_log WHERE id = ?", (middle["id"],))
    conn.commit()
    conn.close()

    result = logger.verify_chain(db_path=db)
    assert result["valid"] is False
    assert result["broken_at"] == third["id"]


# =============================================================================
# 5. RAG — 임계값 경계와 인용 대조 (환각방지 2단 방어)
# =============================================================================


@pytest.fixture
def stub_rag(monkeypatch):
    """Ollama·Chroma 없이 RAG tool의 판단 로직만 검증한다."""
    import compliance.rag as rag

    state = {
        "vector_similarity": 0.9,
        "article": "제10조",
        "answer": "검색된 근거를 확인했습니다. [1]",
        "generation_error": None,
    }

    def fake_search(query, top_k=5):
        match = {
            "source": "표준내부통제기준",
            "file_name": "rules.pdf",
            "article": state["article"],
            "article_title": "사전확인",
            "chunk_id": "rules_10_0",
            "snippet": "준법감시인 사전확인이 필요하다.",
            "score": 0.1,
        }
        if state["vector_similarity"] is not None:
            match["vector_similarity"] = state["vector_similarity"]
            match["vector_distance"] = 1 - state["vector_similarity"]
        return [match]

    def fake_generate(task, query, matches, risk_signals=None):
        meta = {"enabled": True, "model": "qwen3-instruct-16k", "error": state["generation_error"]}
        if state["generation_error"]:
            return None, meta
        return state["answer"], meta

    monkeypatch.setattr(rag, "_ensure_ready", lambda: (True, None))
    monkeypatch.setattr(rag, "_search", fake_search)
    monkeypatch.setattr(rag, "_generate_answer", fake_generate)
    return state


def test_similarity_exactly_at_threshold_passes(stub_rag):
    """임계값은 >= 비교다. 정확히 0.49면 통과한다 (경계 포함)."""
    stub_rag["vector_similarity"] = 0.49

    result = mcp_server.search_compliance_rule("준법감시인 사전확인")

    assert result["data"]["threshold_passed"] is True


def test_similarity_just_below_threshold_is_cut(stub_rag):
    stub_rag["vector_similarity"] = 0.4899

    result = mcp_server.search_compliance_rule("준법감시인 사전확인")

    assert result["data"]["threshold_passed"] is False
    assert result["data"]["matches"] == []
    assert result["outputs"] == []


def test_bm25_only_hits_without_similarity_are_cut_conservatively(stub_rag):
    """vector_similarity가 없는 히트(BM25 전용)는 신뢰도 미확인 → 근거를 내지 않는다."""
    stub_rag["vector_similarity"] = None

    result = mcp_server.check_disclosure_risk("실적 발표 전 자료")

    assert result["data"]["threshold_passed"] is False
    assert result["data"]["matches"] == []
    assert result["requires_human_review"] is True


def test_risk_signals_survive_retrieval_threshold_cut(stub_rag):
    """근거를 못 찾아도 결정론 위험 신호와 매칭 기준은 버리지 않는다."""
    stub_rag["vector_similarity"] = 0.1

    result = mcp_server.check_disclosure_risk("실적 발표 전 유상증자 자료")

    assert result["data"]["matches"] == []
    assert [s["type"] for s in result["data"]["risk_signals"]]
    assert {c["criterion_no"] for c in result["data"]["matched_criteria"]} == {
        "1호",
        "5호",
        "6호",
    }
    assert result["requires_human_review"] is True


def test_citation_check_treats_article_sub_number_as_distinct(stub_rag):
    """근거가 '제10조의2'인데 답변이 '제10조'를 인용하면 폐기된다.

    사람 눈에는 같은 조를 가리키는 듯 보여도 '제10조'와 '제10조의2'는 다른
    조항이다. 과잉 폐기(오탐) 방향이라 안전하지만, 답변이 사라지므로
    코퍼스 조항 표기와 프롬프트가 어긋나면 체감 품질이 떨어진다.
    """
    stub_rag["article"] = "제10조의2"
    stub_rag["answer"] = "제10조에 따라 준법감시인 확인이 필요합니다. [1]"

    result = mcp_server.check_disclosure_risk("점검용 텍스트")

    assert result["data"]["citation_verified"] is False
    assert result["data"]["answer"] is None
    assert result["data"]["cited_articles"] == ["제10조"]
    assert result["data"]["answer_generation"]["discarded"] is True
    assert result["requires_human_review"] is True


def test_spaced_article_citation_is_normalized(stub_rag):
    """'제 10 조'처럼 띄어 쓴 인용도 '제10조'로 정규화돼 대조를 통과한다."""
    stub_rag["answer"] = "제 10 조에 따라 확인이 필요합니다. [1]"

    result = mcp_server.check_disclosure_risk("점검용 텍스트")

    assert result["data"]["citation_verified"] is True
    assert result["data"]["cited_articles"] == ["제10조"]


def test_check_disclosure_risk_on_empty_text_uses_fallback_query(stub_rag):
    """빈 입력에도 tool은 실패하지 않고 기본 질의로 근거를 찾는다."""
    result = mcp_server.check_disclosure_risk("")

    assert result["ok"] is True
    assert result["data"]["input_chars"] == 0
    assert result["data"]["risk_signals"] == []


def test_answer_generation_failure_still_returns_evidence(stub_rag):
    """Ollama가 죽어도 검색 근거와 결정론 요약은 반환된다 (tool 전체 실패 아님).

    다만 현재는 위험 신호가 없으면 requires_human_review가 False로 남는다.
    '생성 실패'를 애매한 상황으로 볼지는 팀 결정 사항이라 현 동작을 고정한다.
    """
    stub_rag["generation_error"] = "connection refused"

    result = mcp_server.check_disclosure_risk("일반 문의")

    assert result["ok"] is True
    assert result["data"]["answer"] is None
    assert result["data"]["answer_generation"]["error"] == "connection refused"
    assert result["data"]["matches"]
    assert result["requires_human_review"] is False


def test_search_compliance_rule_never_escalates_review_on_success(stub_rag):
    """search는 근거 제시 tool이라 성공 시 requires_human_review를 올리지 않는다."""
    result = mcp_server.search_compliance_rule("원금 보장 광고 가능한가")

    assert result["ok"] is True
    assert result["requires_human_review"] is False


def test_rag_risk_signal_flags_compound_words_that_detector_ignores():
    """'공개 전략회의'를 detector는 통과시키지만 rag 위험 신호는 잡는다.

    detector의 _INTERNAL_RE는 '공개 전' 뒤 한글을 배제하는 전방탐색이 있고,
    rag의 _RISK_SIGNAL_PATTERNS['미공개/발표 전 정보']에는 없다 — 같은 개념을
    두 모듈이 다르게 판정한다. rag 쪽이 더 보수적(오탐 방향)이라 미탐 원칙
    위반은 아니지만, 실제 GUI E2E에서 '공개 전략회의 자료'가 위험으로 판정된
    원인이 이 불일치다. 패턴을 통일하면 이 테스트를 갱신한다.
    """
    import compliance.rag as rag
    from compliance.detector import scan_text as detector_scan

    text = "공개 전략회의 자료입니다"

    assert detector_scan(text)["data"]["findings"] == []
    assert [s["type"] for s in rag._risk_signals(text)] == ["미공개/발표 전 정보"]


# =============================================================================
# 6. tool 간 연계 — scan → log_ai_usage (실제 시연 경로)
# =============================================================================


@pytest.fixture(autouse=True)
def _tmp_audit_db(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "mcp_audit.db"))
    return str(tmp_path / "mcp_audit.db")


def test_scan_then_log_never_persists_original_values(_tmp_audit_db):
    """scan의 log_safe_summary를 그대로 log_ai_usage에 넘기는 게 안전한 경로다.

    tool docstring이 안내하는 흐름 그대로 실행해, DB 바이트 어디에도 원문
    민감값이 남지 않는지 확인한다.
    """
    text = "고객 홍길동 010-1234-5678, 주민 900101-1234567, hong@corp.co.kr"
    scan = mcp_server.scan_sensitive_info(text)

    log_result = mcp_server.log_ai_usage(
        tool_name="scan_sensitive_info",
        input_text=text,
        result_summary=scan["data"]["log_safe_summary"],
        requires_human_review=scan["requires_human_review"],
    )

    assert log_result["ok"] is True
    assert log_result["data"]["logged_requires_human_review"] is True

    conn = sqlite3.connect(_tmp_audit_db)
    rows = conn.execute(
        "SELECT tool_name, requires_human_review FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()
    assert rows == [("scan_sensitive_info", 1)]

    with open(_tmp_audit_db, "rb") as fh:
        raw = fh.read()

    for secret in ("010-1234-5678", "900101-1234567", "hong@corp.co.kr"):
        assert secret.encode("utf-8") not in raw


def test_log_safe_summary_survives_the_rescan_unchanged(_tmp_audit_db):
    """log_safe_summary는 이미 마스킹돼 있어 저장 직전 재스캔에도 바뀌지 않아야 한다.

    여기가 깨지면 재스캔이 마스킹 결과물을 또 마스킹한다는 뜻이고,
    감사 로그 요약이 계속 뭉개진다.
    """
    scan = mcp_server.scan_sensitive_info("연락처 010-1234-5678, hong@corp.co.kr")
    log_safe_summary = scan["data"]["log_safe_summary"]

    result = mcp_server.log_ai_usage(
        "scan_sensitive_info", "원문", log_safe_summary, True
    )

    stored = logger.verify_chain(db_path=_tmp_audit_db)
    assert stored["valid"] is True
    assert result["ok"] is True

    conn = sqlite3.connect(_tmp_audit_db)
    saved = conn.execute("SELECT result_summary FROM audit_log").fetchone()[0]
    conn.close()
    assert saved == log_safe_summary


def test_logging_a_leaky_summary_escalates_review_flag(_tmp_audit_db):
    """호출자(LLM)가 원문을 요약에 흘리고 rhr=False를 넘겨도 True로 승격된다."""
    result = mcp_server.log_ai_usage(
        tool_name="scan_sensitive_info",
        input_text="원문",
        result_summary="문제 없습니다. 연락처는 010-1234-5678 입니다.",
        requires_human_review=False,
    )

    assert result["ok"] is True
    assert result["data"]["logged_requires_human_review"] is True


def test_log_ai_usage_accepts_arbitrary_tool_name_without_validation(_tmp_audit_db):
    """tool_name은 4개 tool 이름으로 검증되지 않고 자유 문자열이 그대로 저장된다.

    실제 GUI E2E에서 qwen이 "scan_sensitive_info + check_disclosure_risk" 같은
    합성 이름을 넘겼고 그대로 기록됐다. 감사 로그를 tool_name으로 집계·필터링
    하려면 신뢰할 수 없다 — 감사 이벤트 기록을 LLM 호출 판단에 맡기지 않고
    코드에서 자동 기록해야 하는 근거이기도 하다. 현재 동작을 고정해 두고,
    검증이 추가되면 이 테스트를 갱신한다.
    """
    fabricated = "scan_sensitive_info + check_disclosure_risk"
    result = mcp_server.log_ai_usage(fabricated, "원문", "요약", True)

    assert result["ok"] is True
    assert result["data"]["tool_name"] == fabricated

    conn = sqlite3.connect(_tmp_audit_db)
    saved = conn.execute("SELECT tool_name FROM audit_log").fetchone()[0]
    conn.close()
    assert saved == fabricated


def test_log_ai_usage_failure_returns_fail_schema_with_review_required(monkeypatch):
    """DB 오류는 조용히 넘기지 않고 fail 스키마(requires_human_review=True)로 보고한다."""
    monkeypatch.setenv("AUDIT_DB_PATH", "/proc/nonexistent-dir/audit.db")

    result = mcp_server.log_ai_usage("scan_sensitive_info", "원문", "요약", False)

    assert result["ok"] is False
    assert result["error"]
    assert result["requires_human_review"] is True
    assert result["outputs"] == []
