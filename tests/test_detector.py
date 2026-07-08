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
    assert result["outputs"]["masked_text"] == "오늘 회의는 오후 3시에 진행합니다."
    assert result["outputs"]["detected_types"] == []
    assert result["requires_human_review"] is False


def test_empty_and_none_inputs_are_ok_not_error():
    for value in ("", None):
        result = detector.scan_text(value)

        assert result["ok"] is True
        assert result["error"] is None
        assert result["data"]["findings"] == []
        assert result["outputs"]["masked_text"] == ""
        assert result["requires_human_review"] is False


def test_result_follows_common_seven_key_schema():
    result = detector.scan_text("점검용 텍스트")

    assert set(result) == set(schema.RESULT_KEYS)
    assert result["tool"] == "scan_sensitive_info"


def test_rrn_detected_masked_and_does_not_force_review_when_masked():
    result = detector.scan_text("고객 주민등록번호는 900101-1234567 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["type_code"] == "RRN"
    assert findings[0]["value_masked"] == "900101-1******"
    assert result["outputs"]["masked_text"] == "고객 주민등록번호는 900101-1****** 입니다."
    assert result["outputs"]["detected_types"] == ["RRN"]

    # 일반 개인정보가 완전히 마스킹된 경우는 P4 합의에 따라 false
    assert result["requires_human_review"] is False

    # 원본 뒷자리가 반환 어디에도 평문으로 남지 않아야 한다
    assert "1234567" not in _dump(result)


def test_foreigner_rrn_detected_and_masked():
    result = detector.scan_text("외국인 등록번호는 900101-5234567 입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["value_masked"] == "900101-5******"
    assert "5234567" not in _dump(result)


def test_plain_13_digits_without_rrn_keyword_not_flagged_as_rrn():
    result = detector.scan_text("문서번호 9001011234567 확인 바랍니다.")

    assert result["data"]["findings"] == []


def test_phone_detected_and_masked_with_korean_postposition():
    result = detector.scan_text("담당자 연락처는 010-1234-5678입니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "phone"
    assert findings[0]["value_masked"] == "010-****-5678"
    assert result["outputs"]["masked_text"] == "담당자 연락처는 010-****-5678입니다."
    assert "010-1234-5678" not in _dump(result)
    assert result["requires_human_review"] is False


def test_email_detected_and_masked_with_korean_postposition():
    result = detector.scan_text("자료는 gildong.hong@example.com으로 회신 바랍니다.")

    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "email"
    assert findings[0]["value_masked"] == "gi***@example.com"
    assert result["outputs"]["masked_text"] == "자료는 gi***@example.com으로 회신 바랍니다."
    assert "gildong.hong@example.com" not in _dump(result)
    assert result["requires_human_review"] is False


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
    assert result["outputs"]["detected_types"] == ["ACCOUNT", "EMAIL"]
    assert "hong@example.com" not in _dump(result)
    assert "110-2222-3333333" not in _dump(result)
    assert "ho***@example.com" in result["outputs"]["masked_text"]
    assert "***3333" in result["outputs"]["masked_text"]
    assert result["requires_human_review"] is False


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
    assert result["outputs"]["detected_types"] == ["PROHIBITED_CLAIM"]
    assert "[금지표현]" in result["outputs"]["masked_text"]
    assert result["requires_human_review"] is True
    assert "원금 보장" not in result["outputs"]["masked_text"]
    assert "확정 수익" not in result["outputs"]["masked_text"]


def test_internal_keyword_requires_human_review():
    result = detector.scan_text("이 문서는 대외비이며 발간 전 자료입니다.")

    findings = result["data"]["findings"]
    assert [finding["type"] for finding in findings] == [
        "internal_keyword",
        "internal_keyword",
    ]
    assert result["requires_human_review"] is True
    assert "[내부정보키워드]" in result["outputs"]["masked_text"]


def test_mixed_personal_info_and_prohibited_claim():
    result = detector.scan_text(
        "고객 연락처는 010-1234-5678이고, 이 상품은 손실 없음이라고 안내했습니다."
    )

    assert result["outputs"]["detected_types"] == ["PHONE", "PROHIBITED_CLAIM"]
    assert "010-1234-5678" not in _dump(result)
    assert "손실 없음" not in result["outputs"]["masked_text"]
    assert result["requires_human_review"] is True


def test_log_safe_summary_does_not_include_original_text_or_masked_text_body():
    text = "A사 관련 대외비 메모입니다. 담당자 연락처는 010-1234-5678입니다."
    result = detector.scan_text(text)

    log_safe_summary = result["data"]["log_safe_summary"]
    assert "010-1234-5678" not in log_safe_summary
    assert "A사 관련" not in log_safe_summary
    assert "PHONE" in log_safe_summary
    assert "INTERNAL_KEYWORD" in log_safe_summary