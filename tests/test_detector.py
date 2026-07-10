"""scan_sensitive_info 정규식 탐지 단위 테스트."""

from __future__ import annotations

import json

from compliance import detector, schema


def _dump(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False)


def test_clean_text_has_no_findings():
    result = detector.scan_text("오늘 회의는 오후 3시에 진행합니다.")

    assert result["ok"] is True
    assert result["data"]["findings"] == []
    assert result["data"]["masked_text"] == "오늘 회의는 오후 3시에 진행합니다."
    assert result["data"]["detected_types"] == []
    assert result["requires_human_review"] is False

    # outputs는 schema.ok() 계약대로 사람이 읽을 요약 문자열의 list[str]이어야 한다
    assert isinstance(result["outputs"], list)
    assert all(isinstance(item, str) for item in result["outputs"])


def test_empty_and_none_inputs_are_ok_not_error():
    for value in ("", None):
        result = detector.scan_text(value)

        assert result["ok"] is True
        assert result["error"] is None
        assert result["data"]["findings"] == []
        assert result["data"]["masked_text"] == ""
        assert result["requires_human_review"] is False
        assert isinstance(result["outputs"], list)


def test_result_follows_common_seven_key_schema():
    result = detector.scan_text("점검용 텍스트")

    assert set(result) == set(schema.RESULT_KEYS)
    assert result["tool"] == "scan_sensitive_info"


def test_rrn_detected_masked_and_still_requires_review():
    result = detector.scan_text("고객 주민등록번호는 900101-1234567 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["type_code"] == "RRN"
    assert findings[0]["value_masked"] == "900101-1******"
    assert result["data"]["masked_text"] == "고객 주민등록번호는 900101-1****** 입니다."
    assert result["data"]["detected_types"] == ["RRN"]

    # 개인정보가 탐지되면 마스킹 여부와 무관하게 사람 검토가 필요하다
    assert result["requires_human_review"] is True

    # 원본 뒷자리가 반환 어디에도 평문으로 남지 않아야 한다
    assert "1234567" not in _dump(result)


def test_foreigner_rrn_detected_and_masked():
    result = detector.scan_text("외국인 등록번호는 900101-5234567 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["value_masked"] == "900101-5******"
    assert "5234567" not in _dump(result)


def test_plain_13_digits_without_rrn_keyword_kept_as_low_confidence():
    # 키워드 없는 연속 13자리도 생년월일 형태면 완전히 놓치지 않고 낮은 신뢰도로
    # 남긴다 — 준법 도구에서는 미탐 비용이 오탐 비용보다 크다.
    result = detector.scan_text("문서번호 9001011234567 확인 바랍니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["confidence"] == "low"
    assert "1234567" not in _dump(result)


def test_phone_detected_and_masked_with_korean_postposition():
    result = detector.scan_text("담당자 연락처는 010-1234-5678입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "phone"
    assert findings[0]["value_masked"] == "010-****-5678"
    assert result["data"]["masked_text"] == "담당자 연락처는 010-****-5678입니다."
    assert "010-1234-5678" not in _dump(result)
    assert result["requires_human_review"] is True


def test_email_detected_and_masked_with_korean_postposition():
    result = detector.scan_text("자료는 gildong.hong@example.com으로 회신 바랍니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "email"
    assert findings[0]["value_masked"] == "gi***@example.com"
    assert result["data"]["masked_text"] == "자료는 gi***@example.com으로 회신 바랍니다."
    assert "gildong.hong@example.com" not in _dump(result)
    assert result["requires_human_review"] is True


def test_short_email_local_is_fully_masked():
    result = detector.scan_text("메일은 ab@example.com 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["value_masked"] == "***@example.com"
    assert "ab@example.com" not in _dump(result)


def test_card_requires_luhn_checksum():
    valid = detector.scan_text("결제 카드 4111-1111-1111-1111 사용")
    findings = valid["data"]["findings"]

    assert len(findings) == 1
    assert findings[0]["type"] == "card"
    assert findings[0]["value_masked"] == "4111-****-****-1111"
    assert "4111-1111-1111-1111" not in _dump(valid)

    invalid = detector.scan_text("일련번호 1234-5678-9012-3456 확인")
    assert invalid["data"]["findings"] == []


def test_account_with_virtual_account_pattern_detected():
    result = detector.scan_text(
        "신청자 이메일은 hong@example.com 이고 계좌번호는 110-2222-3333333 입니다."
    )

    findings = result["data"]["findings"]
    types = [finding["type"] for finding in findings]

    assert types == ["email", "account"]
    assert result["data"]["detected_types"] == ["ACCOUNT", "EMAIL"]
    assert "hong@example.com" not in _dump(result)
    assert "110-2222-3333333" not in _dump(result)
    assert "ho***@example.com" in result["data"]["masked_text"]
    assert "***3333" in result["data"]["masked_text"]
    assert result["requires_human_review"] is True


def test_contiguous_account_with_keyword_detected():
    result = detector.scan_text("가상계좌 123456789012345 로 입금 바랍니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["value_masked"] == "***2345"
    assert findings[0]["confidence"] == "high"
    assert "123456789012345" not in _dump(result)


def test_long_number_without_account_keyword_not_flagged_to_reduce_false_positive():
    result = detector.scan_text("총 발행 주식 수는 3500000000 이다.")

    assert result["data"]["findings"] == []


def test_date_is_not_flagged_as_account():
    result = detector.scan_text("회의 일자: 2026-07-09 오전")

    assert result["data"]["findings"] == []


def test_prohibited_financial_claim_requires_human_review():
    result = detector.scan_text("이 상품은 원금 보장되고 확정 수익을 제공합니다.")

    findings = result["data"]["findings"]
    assert [finding["type"] for finding in findings] == [
        "prohibited_claim",
        "prohibited_claim",
    ]
    assert result["data"]["detected_types"] == ["PROHIBITED_CLAIM"]
    assert "[금지표현]" in result["data"]["masked_text"]
    assert result["requires_human_review"] is True
    assert "원금 보장" not in result["data"]["masked_text"]
    assert "확정 수익" not in result["data"]["masked_text"]


def test_internal_keyword_requires_human_review():
    result = detector.scan_text("이 문서는 대외비이며 발간 전 자료입니다.")

    findings = result["data"]["findings"]
    assert [finding["type"] for finding in findings] == [
        "internal_keyword",
        "internal_keyword",
    ]
    assert result["requires_human_review"] is True
    assert "[내부정보키워드]" in result["data"]["masked_text"]


def test_mixed_personal_info_and_prohibited_claim():
    result = detector.scan_text(
        "고객 연락처는 010-1234-5678이고, 이 상품은 손실 없음이라고 안내했습니다."
    )

    assert result["data"]["detected_types"] == ["PHONE", "PROHIBITED_CLAIM"]
    assert "010-1234-5678" not in _dump(result)
    assert "손실 없음" not in result["data"]["masked_text"]
    assert result["requires_human_review"] is True


def test_log_safe_summary_does_not_include_original_text_or_masked_text_body():
    text = "A사 관련 대외비 메모입니다. 담당자 연락처는 010-1234-5678입니다."
    result = detector.scan_text(text)

    log_safe_summary = result["data"]["log_safe_summary"]
    assert "010-1234-5678" not in log_safe_summary
    assert "A사 관련" not in log_safe_summary
    assert "PHONE" in log_safe_summary
    assert "INTERNAL_KEYWORD" in log_safe_summary


def test_virtual_safe_number_050_detected_and_masked():
    result = detector.scan_text("안심번호는 0507-1234-5678 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "phone"
    assert findings[0]["value_masked"] == "0507-****-5678"
    assert "0507-1234-5678" not in _dump(result)


def test_account_with_refund_keyword_without_account_word_detected():
    result = detector.scan_text("환불: 110-2222-3333333 으로 처리해주세요.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["confidence"] == "high"
    assert "3333333" not in _dump(result)


def test_prohibited_claim_detects_reversed_word_order_and_particles():
    result = detector.scan_text(
        "이 상품은 수익률 보장되며, 손실이 없음, 위험은 없음이 특징입니다."
    )

    findings = result["data"]["findings"]
    types = [finding["type"] for finding in findings]
    assert types == ["prohibited_claim", "prohibited_claim", "prohibited_claim"]
    assert result["requires_human_review"] is True
    assert "수익률 보장" not in result["data"]["masked_text"]
    assert "손실이 없음" not in result["data"]["masked_text"]
    assert "위험은 없음" not in result["data"]["masked_text"]


def test_principal_guarantee_negation_is_not_flagged():
    # "원금 보장되지 않습니다"류는 오히려 정상적인 위험 고지 문장이므로 제외한다
    negated = detector.scan_text("이 상품은 원금 보장되지 않습니다.")
    assert negated["data"]["findings"] == []

    negated_with_particle = detector.scan_text(
        "원금 보호가 되지 않는 투자상품입니다."
    )
    assert negated_with_particle["data"]["findings"] == []

    # 부정 표현이 없는 정상적인 금지문구는 여전히 탐지되어야 한다
    positive = detector.scan_text("이 상품은 원금 보장이 되어 있습니다.")
    assert [f["type"] for f in positive["data"]["findings"]] == ["prohibited_claim"]


def test_internal_keyword_word_boundary_excludes_compound_words():
    # "발간 전"/"공개 전"이 다른 한글 단어의 일부일 때는 내부정보 키워드로 잡지 않는다
    result = detector.scan_text(
        "정보 공개 전략 회의와 서비스 공개 전환 일정, 보고서 발간 전담팀 안내입니다."
    )
    assert result["data"]["findings"] == []

    # 문맥어가 뒤따르지 않는 독립적인 "발간 전"은 여전히 탐지되어야 한다
    still_detected = detector.scan_text("이 문서는 발간 전 자료입니다.")
    assert [f["type"] for f in still_detected["data"]["findings"]] == ["internal_keyword"]


def test_loss_percentage_decimal_is_not_flagged_as_no_loss_claim():
    # "손실 0.5%"처럼 손실률을 명시한 정상 문장을 "손실 없음(0)"으로 오탐하지 않는다
    result = detector.scan_text("예상 손실 0.5% 수준으로 안내드립니다.")
    assert result["data"]["findings"] == []


def test_summary_and_log_safe_summary_include_masked_values_for_every_type():
    # 계좌번호뿐 아니라 전화번호/이메일/주민번호도 마스킹된 값이 요약에 함께
    # 노출되어야 사람이 결과만 보고 무엇이 탐지됐는지 바로 확인할 수 있다.
    result = detector.scan_text(
        "신청자 홍길동, 주민등록번호 900101-1234567, 연락처 010-1234-5678, "
        "이메일 hong@example.com 입니다"
    )

    summary = result["summary"]
    log_safe_summary = result["data"]["log_safe_summary"]

    for masked_value in ("900101-1******", "010-****-5678", "ho***@example.com"):
        assert masked_value in summary
        assert masked_value in log_safe_summary

    # 원문 값은 어디에도 남지 않아야 한다
    assert "900101-1234567" not in _dump(result)
    assert "010-1234-5678" not in _dump(result)
    assert "hong@example.com" not in _dump(result)


def test_masked_values_text_dedupes_repeated_values_within_same_type():
    result = detector.scan_text(
        "이 상품은 원금 보장되고 확정 수익을 제공합니다."
    )
    # principal_guarantee/guaranteed_return 둘 다 prohibited_claim 타입이라
    # value_masked가 "[금지표현]"으로 동일 — 중복 없이 한 번만 표시되어야 한다.
    assert result["data"]["log_safe_summary"].count("[금지표현]") == 1


def test_masked_values_text_caps_display_count_per_type():
    # 대량 탐지 시 요약 문자열이 무한정 길어지지 않도록 타입별 최대 5개까지만
    # 나열하고 나머지는 "외 N건"으로 축약한다.
    text = (
        "담당자 이메일: ab1@example.com, cd2@example.com, ef3@example.com, "
        "gh4@example.com, ij5@example.com, kl6@example.com 입니다"
    )
    result = detector.scan_text(text)

    assert len(result["data"]["findings"]) == 6

    log_safe_summary = result["data"]["log_safe_summary"]
    assert "외 1건" in log_safe_summary
    assert log_safe_summary.count("@example.com") == 5
    assert "kl***@example.com" not in log_safe_summary


def test_findings_are_truncated_with_metadata_for_large_scan(monkeypatch):
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "3")
    text = (
        "담당자 이메일: ab1@example.com, cd2@example.com, ef3@example.com, "
        "gh4@example.com, ij5@example.com 입니다"
    )

    result = detector.scan_text(text)
    data = result["data"]

    assert len(data["findings"]) == 3
    assert data["total_findings"] == 5
    assert data["returned_findings"] == 3
    assert data["max_findings"] == 3
    assert data["truncated"] is True
    assert data["truncated_findings"] == 2
    assert data["counts"] == {"email": 5}
    assert "상세 반환은 3/5건으로 제한" in result["summary"]
    assert "findings 상세 2건 생략" in data["log_safe_summary"]
    assert isinstance(result["outputs"], list)
    assert result["outputs"] == [data["log_safe_summary"]]

    # masked_text는 호환성을 위해 전체 마스킹 결과를 유지하되 원문은 노출하지 않는다.
    assert "ij5@example.com" not in _dump(result)
    assert "ij***@example.com" in data["masked_text"]


def test_invalid_findings_limit_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "not-a-number")

    result = detector.scan_text("담당자 연락처는 010-1234-5678입니다.")

    assert result["data"]["max_findings"] == 100
    assert result["data"]["returned_findings"] == 1
    assert result["data"]["truncated"] is False


def test_zero_findings_limit_returns_metadata_only(monkeypatch):
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "0")

    result = detector.scan_text("담당자 연락처는 010-1234-5678입니다.")
    data = result["data"]

    assert data["findings"] == []
    assert data["total_findings"] == 1
    assert data["returned_findings"] == 0
    assert data["max_findings"] == 0
    assert data["truncated"] is True
    assert data["truncated_findings"] == 1
    assert data["masked_text"] == "담당자 연락처는 010-****-5678입니다."
    assert "findings 상세 1건 생략" in data["log_safe_summary"]


def test_negative_findings_limit_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SCAN_MAX_FINDINGS", "-1")

    result = detector.scan_text("담당자 연락처는 010-1234-5678입니다.")

    assert result["data"]["max_findings"] == 100
    assert result["data"]["returned_findings"] == 1
    assert result["data"]["truncated"] is False
