"""scan_sensitive_info 로직 — 정규식 기반 민감정보/금융 금지문구 탐지.

원칙:
- 100% 결정론 코드. LLM·외부 API를 쓰지 않는다.
- 탐지만 한다. "위반이다/괜찮다" 최종 판단은 하지 않는다.
- 원본 민감정보 값은 반환하지 않는다.
- log_ai_usage로 넘길 수 있는 안전한 요약(log_safe_summary)을 함께 제공한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from compliance.schema import ok

TOOL_NAME = "scan_sensitive_info"

# 계좌번호 후보 판정에 쓰는 근접 키워드 탐색 범위
_ACCOUNT_KEYWORD_WINDOW = 24

# 주민등록번호/외국인등록번호 키워드 없는 연속 13자리 숫자는 오탐 가능성이 높으므로,
# 하이픈/공백이 없으면 주변 키워드를 요구한다.
_RRN_KEYWORD_WINDOW = 18

# re.ASCII:
# \b 대신 (?<!\d), (?!\d)를 주로 사용해 한글 조사("입니다", "으로")가 붙어도 탐지되도록 한다.
_RRN_RE = re.compile(r"(?<!\d)(\d{6})([-\s]?)([0-9]\d{6})(?!\d)", re.ASCII)

_PHONE_RE = re.compile(
    r"(?<!\d)("
    r"01[016789][-\s]?\d{3,4}[-\s]?\d{4}"  # 휴대전화
    r"|02[-\s]?\d{3,4}[-\s]?\d{4}"          # 서울 지역번호
    r"|0[3-6][1-5][-\s]?\d{3,4}[-\s]?\d{4}" # 지역번호
    r"|050\d[-\s]?\d{3,4}[-\s]?\d{4}"       # 안심번호/가상번호 (0505, 0507 등)
    r"|070[-\s]?\d{3,4}[-\s]?\d{4}"         # 인터넷전화
    r")(?!\d)",
    re.ASCII,
)

_CARD_RE = re.compile(
    r"(?<!\d)\d{4}([- \s]?)\d{4}\1\d{4}\1\d{4}(?!\d)",
    re.ASCII,
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.ASCII,
)

# 계좌번호:
# - 하이픈 구분: 2~5그룹, 각 그룹 1~9자리 허용
# - 연속 숫자: 10~16자리
# - 실제 탐지 여부는 총 자릿수와 주변 계좌 키워드로 다시 검증한다.
#
# 기존 버그:
# 110-2222-3333333 의 마지막 그룹 7자리가 \d{1,6} 제한 때문에 미탐.
_ACCOUNT_RE = re.compile(
    r"(?<!\d)(?:\d{1,9}(?:-\d{1,9}){1,4}|\d{10,16})(?!\d)",
    re.ASCII,
)

_ACCOUNT_KEYWORD_RE = re.compile(
    r"계좌|계좌번호|가상계좌|입금|출금|송금|이체|예금|은행|환불|"
    r"account|bank|deposit|transfer|refund",
    re.IGNORECASE,
)

_RRN_KEYWORD_RE = re.compile(
    r"주민등록|주민번호|등록번호|외국인등록|rrn",
    re.IGNORECASE,
)

# 금융상품 광고/고객 발송 문구에서 사람 검토가 필요한 금지·주의 표현
_PROHIBITED_CLAIM_PATTERNS: list[tuple[str, str, str]] = [
    (
        "principal_guarantee",
        r"원금\s*(?:이\s*)?(?:보장|보전|보호)(?!\s*(?:이\s*|가\s*)?(?:되지\s*않|안\s*(?:됨|되)|불가))",
        "원금보장 오인 가능 표현",
    ),
    (
        "guaranteed_return",
        r"(?:확정|보장)\s*(?:수익|수익률|이자)|(?:수익|수익률|이자)\s*(?:이\s*)?(?:확정|보장)",
        "확정수익/수익률 보장 표현",
    ),
    (
        "no_loss",
        r"(?:손실\s*(?:이\s*|은\s*)?(?:없음|제로)|무손실|손해\s*(?:가\s*|는\s*)?없음)",
        "손실 가능성 축소 표현",
    ),
    ("risk_free", r"(?:무위험|위험\s*(?:이\s*|은\s*)?(?:없음|제로))", "위험성 축소 표현"),
    ("high_return_stable", r"(?:안정적\s*)?고수익", "고수익 과장 가능 표현"),
    ("always_profit", r"(?:무조건|반드시|100%)\s*(?:수익|상승|오름)", "단정적 수익 표현"),
]

_PROHIBITED_CLAIM_RES: list[tuple[str, re.Pattern[str], str]] = [
    (code, re.compile(pattern, re.IGNORECASE), label)
    for code, pattern, label in _PROHIBITED_CLAIM_PATTERNS
]

# 개인정보는 아니지만, 외부 공유 전 사람이 확인해야 하는 비정형 리스크 신호
_INTERNAL_RE = re.compile(
    r"대외비|내부자료|사외반출금지|미공개|발간\s?전(?![가-힣])|공개\s?전(?![가-힣])|confidential",
    re.IGNORECASE,
)

_REVIEW_REQUIRED_TYPES = {
    "rrn",
    "phone",
    "card",
    "email",
    "account",
    "prohibited_claim",
    "internal_keyword",
}


@dataclass(frozen=True)
class _Replacement:
    start: int
    end: int
    text: str


class _SpanClaims:
    """탐지 유형 간 중복 방지 — 우선순위 높은 유형이 먼저 구간을 점유한다."""

    def __init__(self) -> None:
        self._spans: list[tuple[int, int]] = []

    def overlaps(self, start: int, end: int) -> bool:
        return any(start < existing_end and end > existing_start for existing_start, existing_end in self._spans)

    def claim(self, start: int, end: int) -> None:
        self._spans.append((start, end))


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _context(text: str, start: int, end: int, window: int) -> str:
    return text[max(0, start - window) : min(len(text), end + window)]


def _looks_like_birth_ymd(ymd: str) -> bool:
    """주민등록번호 앞 6자리가 최소한 날짜 형태인지 확인한다.

    완전한 주민번호 검증이 아니라 명백한 오탐을 줄이기 위한 경량 검증이다.
    """
    if len(ymd) != 6 or not ymd.isdigit():
        return False

    month = int(ymd[2:4])
    day = int(ymd[4:6])
    return 1 <= month <= 12 and 1 <= day <= 31


def _luhn_valid(digits: str) -> bool:
    """카드번호 Luhn 체크섬 — 임의의 16자리 숫자 오탐을 줄인다."""
    if not digits.isdigit():
        return False

    total = 0
    for idx, ch in enumerate(reversed(digits)):
        value = int(ch)
        if idx % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_rrn(match: re.Match[str]) -> str:
    return f"{match.group(1)}-{match.group(3)[0]}******"


def _mask_phone(value: str) -> str:
    digits = _digits(value)
    if digits.startswith("02"):
        return f"02-****-{digits[-4:]}"
    if digits.startswith("050"):
        return f"{digits[:4]}-****-{digits[-4:]}"
    return f"{digits[:3]}-****-{digits[-4:]}"


def _mask_card(value: str) -> str:
    digits = _digits(value)
    return f"{digits[:4]}-****-****-{digits[-4:]}"


def _mask_email(value: str) -> str:
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        return f"***@{domain}"
    return f"{local[:2]}***@{domain}"


def _mask_account(value: str) -> str:
    digits = _digits(value)
    return f"***{digits[-4:]}"


def _apply_replacements(text: str, replacements: list[_Replacement]) -> str:
    """원문 text에 마스킹 치환을 적용한다.

    뒤에서 앞으로 치환해야 앞쪽 span 위치가 밀리지 않는다.
    """
    masked = text
    for replacement in sorted(replacements, key=lambda item: item.start, reverse=True):
        masked = masked[: replacement.start] + replacement.text + masked[replacement.end :]
    return masked


def _type_code(kind: str) -> str:
    return {
        "rrn": "RRN",
        "phone": "PHONE",
        "card": "CARD",
        "email": "EMAIL",
        "account": "ACCOUNT",
        "prohibited_claim": "PROHIBITED_CLAIM",
        "internal_keyword": "INTERNAL_KEYWORD",
    }.get(kind, kind.upper())


def _count_by_type(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        kind = finding["type"]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _log_safe_summary(findings: list[dict], requires_human_review: bool) -> str:
    """log_ai_usage의 result_summary에 넘겨도 안전한 요약.

    원문 텍스트나 masked_text 전체를 넣지 않는다.
    masked_text에도 비정형 내부자료 문장이 남을 수 있으므로, 감사 로그용 요약은
    탐지 타입/건수만 담는다.
    """
    if not findings:
        return "scan_sensitive_info: 탐지된 민감정보/금지문구 없음"

    counts = _count_by_type(findings)
    count_text = ", ".join(f"{_type_code(kind)} {count}건" for kind, count in sorted(counts.items()))
    review_text = "사람 검토 필요" if requires_human_review else "자동 마스킹 완료"
    return f"scan_sensitive_info: {count_text}; {review_text}"


def _add_finding(
    *,
    findings: list[dict],
    claims: _SpanClaims,
    replacements: list[_Replacement],
    kind: str,
    label: str,
    masked_value: str,
    start: int,
    end: int,
    confidence: str = "high",
    reason: str | None = None,
) -> None:
    claims.claim(start, end)

    finding = {
        "type": kind,
        "type_code": _type_code(kind),
        "label": label,
        "value_masked": masked_value,
        "span": [start, end],
        "confidence": confidence,
        "requires_human_review": kind in _REVIEW_REQUIRED_TYPES,
    }
    if reason:
        finding["reason"] = reason

    findings.append(finding)
    replacements.append(_Replacement(start=start, end=end, text=masked_value))


def scan_text(text: str | None) -> dict:
    """텍스트에서 민감정보/금융 금지문구를 탐지하고 마스킹 결과를 반환한다.

    반환 형식은 공통 7키 스키마를 유지한다. schema.ok()의 계약대로
    outputs는 사람이 읽을 요약 문자열의 list[str]이며, masked_text·
    detected_types·log_safe_summary 같은 구조화 payload는 data에만 담는다.
    """
    if text is None or text == "":
        empty_summary = "scan_sensitive_info: 빈 입력"
        return ok(
            TOOL_NAME,
            "입력이 비어 있어 탐지할 내용이 없습니다.",
            data={
                "findings": [],
                "counts": {},
                "masked_text": "",
                "detected_types": [],
                "log_safe_summary": empty_summary,
            },
            outputs=[empty_summary],
            requires_human_review=False,
        )

    findings: list[dict] = []
    replacements: list[_Replacement] = []
    claims = _SpanClaims()

    # 1. 주민등록번호/외국인등록번호
    for match in _RRN_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        if not _looks_like_birth_ymd(match.group(1)):
            continue

        # 하이픈/공백 없는 연속 13자리 숫자는 주변에 주민번호 키워드가 없으면 오탐
        # 가능성이 있으나, 실제 유출 텍스트에서는 키워드 없이 붙여 쓰는 경우도 흔해
        # 완전히 놓치는 대신 confidence="low"로 남겨 사람이 확인할 수 있게 한다.
        separator = match.group(2)
        confidence = "high"
        if separator == "":
            nearby = _context(text, match.start(), match.end(), _RRN_KEYWORD_WINDOW)
            if not _RRN_KEYWORD_RE.search(nearby):
                confidence = "low"

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="rrn",
            label="주민등록번호/외국인등록번호",
            masked_value=_mask_rrn(match),
            start=match.start(),
            end=match.end(),
            confidence=confidence,
            reason="고유식별정보 패턴",
        )

    # 2. 카드번호
    for match in _CARD_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        digits = _digits(match.group())
        if not _luhn_valid(digits):
            continue

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="card",
            label="카드번호",
            masked_value=_mask_card(match.group()),
            start=match.start(),
            end=match.end(),
            reason="Luhn checksum 유효 카드번호 패턴",
        )

    # 3. 전화번호
    for match in _PHONE_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="phone",
            label="전화번호",
            masked_value=_mask_phone(match.group()),
            start=match.start(),
            end=match.end(),
            reason="전화번호 패턴",
        )

    # 4. 이메일
    for match in _EMAIL_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="email",
            label="이메일",
            masked_value=_mask_email(match.group()),
            start=match.start(),
            end=match.end(),
            reason="이메일 주소 패턴",
        )

    # 5. 계좌번호
    for match in _ACCOUNT_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        digits = _digits(match.group())

        # 국내 계좌/가상계좌 실무 케이스를 넓게 받되, 너무 짧거나 긴 숫자는 제외
        if not 10 <= len(digits) <= 16:
            continue

        nearby = _context(text, match.start(), match.end(), _ACCOUNT_KEYWORD_WINDOW)
        if not _ACCOUNT_KEYWORD_RE.search(nearby):
            # 숫자만 긴 값은 주식수/일련번호/문서번호 오탐이 많아 계좌로 확정하지 않는다.
            continue

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="account",
            label="계좌번호",
            masked_value=_mask_account(match.group()),
            start=match.start(),
            end=match.end(),
            confidence="high",
            reason="계좌 관련 키워드 주변의 10~16자리 금융계좌 후보",
        )

    # 6. 금융 금지/주의 표현
    for code, pattern, label in _PROHIBITED_CLAIM_RES:
        for match in pattern.finditer(text):
            if claims.overlaps(match.start(), match.end()):
                continue

            _add_finding(
                findings=findings,
                claims=claims,
                replacements=replacements,
                kind="prohibited_claim",
                label=label,
                masked_value="[금지표현]",
                start=match.start(),
                end=match.end(),
                confidence="high",
                reason=f"금융상품 광고/고객 안내문 금지·주의 표현 후보: {code}",
            )

    # 7. 내부자료/대외비 키워드
    for match in _INTERNAL_RE.finditer(text):
        if claims.overlaps(match.start(), match.end()):
            continue

        _add_finding(
            findings=findings,
            claims=claims,
            replacements=replacements,
            kind="internal_keyword",
            label="내부정보/대외비 키워드",
            masked_value="[내부정보키워드]",
            start=match.start(),
            end=match.end(),
            confidence="high",
            reason="외부 공유 전 준법감시 확인이 필요한 내부정보 키워드",
        )

    masked_text = _apply_replacements(text, replacements)
    counts = _count_by_type(findings)
    detected_types = sorted({_type_code(finding["type"]) for finding in findings})
    requires_human_review = any(finding["requires_human_review"] for finding in findings)
    log_safe_summary = _log_safe_summary(findings, requires_human_review)

    if not findings:
        summary = "민감정보·금융 금지문구 패턴이 탐지되지 않았습니다."
    else:
        count_text = ", ".join(f"{_type_code(kind)} {count}건" for kind, count in sorted(counts.items()))
        summary = (
            f"스캔 결과 {len(findings)}건이 탐지되었습니다 ({count_text}). "
            "개인정보는 마스킹했으며, 외부 공유 전 사람 검토가 필요합니다."
        )

    # outputs는 schema.ok()의 계약(list[str])을 따르는 사람이 읽을 요약이며,
    # masked_text/detected_types 같은 구조화 payload는 data에만 둔다 (중복 방지).
    # log_ai_usage의 result_summary에는 masked_text 전체보다 log_safe_summary 사용을 권장한다.
    return ok(
        TOOL_NAME,
        summary,
        data={
            "findings": findings,
            "counts": counts,
            "masked_text": masked_text,
            "detected_types": detected_types,
            "log_safe_summary": log_safe_summary,
        },
        outputs=[log_safe_summary],
        requires_human_review=requires_human_review,
    )
