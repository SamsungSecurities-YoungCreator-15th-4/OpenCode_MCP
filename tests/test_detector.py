"""scan_sensitive_info 정규식 탐지 단위 테스트."""

import json

from compliance import detector, schema


def test_rrn_detected_once_and_masked():
    result = detector.scan_text("고객 주민등록번호는 900101-1234567 입니다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["value_masked"] == "900101-1******"
    # 원본 뒷자리가 반환 어디에도 평문으로 남지 않아야 한다
    assert "1234567" not in json.dumps(result)
    assert result["requires_human_review"] is True


def test_clean_text_has_no_findings():
    result = detector.scan_text("오늘 회의는 오후 3시에 진행합니다.")
    assert result["ok"] is True
    assert result["data"]["findings"] == []
    assert result["requires_human_review"] is False


def test_empty_and_none_inputs_are_ok_not_error():
    for value in ("", None):
        result = detector.scan_text(value)
        assert result["ok"] is True
        assert result["error"] is None
        assert result["data"]["findings"] == []
        assert result["requires_human_review"] is False


def test_account_with_nearby_keyword_is_high_confidence():
    result = detector.scan_text("입금 계좌: 110-123-456789 (신한)")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["confidence"] == "high"
    assert findings[0]["value_masked"] == "***6789"


def test_number_without_keyword_is_low_confidence():
    result = detector.scan_text("총 발행 주식 수는 3500000000 이다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["confidence"] == "low"


def test_date_is_not_flagged_as_account():
    result = detector.scan_text("회의 일자: 2026-07-07 오전")
    assert result["data"]["findings"] == []


def test_phone_detected_and_masked():
    result = detector.scan_text("담당자 연락처는 010-1234-5678 입니다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "phone"
    assert findings[0]["value_masked"] == "010-****-5678"


def test_email_detected_and_masked():
    result = detector.scan_text("자료는 gildong.hong@example.com 으로 회신 바랍니다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "email"
    assert findings[0]["value_masked"] == "gi***@example.com"


def test_card_requires_luhn_checksum():
    # 4111-1111-1111-1111 은 Luhn 유효, 1234-5678-9012-3456 은 무효
    valid = detector.scan_text("결제 카드 4111-1111-1111-1111 사용")
    findings = valid["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "card"
    assert findings[0]["value_masked"] == "4111-****-****-1111"

    invalid = detector.scan_text("일련번호 1234-5678-9012-3456 확인")
    assert invalid["data"]["findings"] == []


def test_internal_keyword_detected():
    result = detector.scan_text("이 문서는 대외비이며 발간 전 자료입니다.")
    types = [f["type"] for f in result["data"]["findings"]]
    assert types == ["internal_keyword", "internal_keyword"]
    assert result["requires_human_review"] is True


def test_result_follows_common_schema():
    result = detector.scan_text("점검용 텍스트")
    assert set(result) == set(schema.RESULT_KEYS)
    assert result["tool"] == "scan_sensitive_info"


def test_korean_postposition_attached_still_detected():
    # 조사가 공백 없이 붙어도 re.ASCII 경계로 탐지되어야 한다 (Gemini 리뷰 지적1)
    phone = detector.scan_text("연락처는 010-1234-5678입니다.")
    assert [f["type"] for f in phone["data"]["findings"]] == ["phone"]

    email = detector.scan_text("자료는 gildong@example.com으로 회신 바랍니다.")
    assert [f["type"] for f in email["data"]["findings"]] == ["email"]


def test_foreigner_rrn_detected_and_masked():
    # 외국인 등록번호(성별코드 5) 미탐 방지 (지적2)
    result = detector.scan_text("외국인 등록번호는 900101-5234567 입니다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "rrn"
    assert findings[0]["value_masked"] == "900101-5******"
    assert "5234567" not in json.dumps(result)


def test_fifteen_digit_account_detected():
    # 연속 15자리 계좌 미탐 방지 (지적3)
    result = detector.scan_text("가상계좌 123456789012345 로 입금")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["confidence"] == "high"


def test_bank_name_keyword_raises_confidence():
    # 은행명이 계좌 앞에 오는 흔한 형태의 신뢰도 판정 (지적4)
    result = detector.scan_text("국민은행 1234567890")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "account"
    assert findings[0]["confidence"] == "high"


def test_short_email_local_is_fully_masked():
    # 로컬파트 2자 이하는 원본 노출 없이 통째로 마스킹 (지적5)
    result = detector.scan_text("메일은 ab@example.com 입니다.")
    findings = result["data"]["findings"]
    assert len(findings) == 1
    assert findings[0]["value_masked"] == "***@example.com"
    assert "ab@example.com" not in json.dumps(result)
