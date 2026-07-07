"""scan_sensitive_info 로직 — 정규식 기반 민감정보 패턴 탐지.

원칙:
- 100% 결정론 코드. LLM·외부 API를 쓰지 않는다.
- 탐지만 한다. "위반이다/괜찮다" 판단은 하지 않는다.
- 원본 민감정보 값은 마스킹해서만 다룬다 (반환·로그 모두).
"""

import re

from compliance.schema import ok

TOOL_NAME = "scan_sensitive_info"

# 계좌번호 후보 판정에 쓰는 근접 키워드 탐색 범위 (앞뒤 글자 수)
_ACCOUNT_KEYWORD_WINDOW = 20

# re.ASCII: \b가 한글을 단어문자로 보지 않게 해 "5678입니다"처럼 조사가 공백 없이
# 붙어도 경계가 성립하도록 한다. 성별코드는 외국인(5~8)·1800년대(9,0)까지 [0-9]로 확장.
_RRN_RE = re.compile(r"\b(\d{6})[-\s]?([0-9]\d{6})\b", re.ASCII)
_PHONE_RE = re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b", re.ASCII)
_CARD_RE = re.compile(r"\b\d{4}([-\s]?)\d{4}\1\d{4}\1\d{4}\b", re.ASCII)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.ASCII)
# 계좌번호: 하이픈 구분 2~4그룹 또는 연속 10~15자리 (총 자릿수는 스캔 루프에서 재검증)
_ACCOUNT_RE = re.compile(r"\b\d{1,6}(?:-\d{1,6}){1,3}\b|\b\d{10,15}\b", re.ASCII)
_ACCOUNT_KEYWORD_RE = re.compile(r"계좌|account|입금|예금|은행|bank", re.IGNORECASE)
_INTERNAL_RE = re.compile(r"대외비|내부자료|사외반출금지|미공개|발간\s?전|confidential", re.IGNORECASE)


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _luhn_valid(digits: str) -> bool:
    """카드번호 Luhn 체크섬 — 임의의 16자리 숫자 오탐을 줄인다."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask_rrn(match: re.Match) -> str:
    return f"{match.group(1)}-{match.group(2)[0]}******"


def _mask_phone(value: str) -> str:
    d = _digits(value)
    return f"{d[:3]}-****-{d[-4:]}"


def _mask_card(value: str) -> str:
    d = _digits(value)
    return f"{d[:4]}-****-****-{d[-4:]}"


def _mask_email(value: str) -> str:
    local, domain = value.split("@", 1)
    # 로컬파트가 2자 이하이면 앞 2자 노출이 곧 원본 전체 노출이므로 통째로 가린다
    if len(local) <= 2:
        return f"***@{domain}"
    return f"{local[:2]}***@{domain}"


def _mask_account(value: str) -> str:
    return f"***{_digits(value)[-4:]}"


class _SpanClaims:
    """탐지 유형 간 중복 방지 — 우선순위 높은 유형이 먼저 구간을 점유한다."""

    def __init__(self):
        self._spans: list[tuple[int, int]] = []

    def overlaps(self, start: int, end: int) -> bool:
        return any(start < e and end > s for s, e in self._spans)

    def claim(self, start: int, end: int) -> None:
        self._spans.append((start, end))


def scan_text(text: str | None) -> dict:
    """텍스트에서 민감정보 패턴을 탐지해 공통 출력 스키마로 반환한다."""
    if not text:
        return ok(
            TOOL_NAME,
            "입력이 비어 있어 탐지할 내용이 없습니다.",
            data={"findings": [], "counts": {}},
        )

    findings: list[dict] = []
    claims = _SpanClaims()

    def add(kind: str, masked: str, start: int, end: int, **extra) -> None:
        claims.claim(start, end)
        findings.append(
            {"type": kind, "value_masked": masked, "span": [start, end], **extra}
        )

    # 우선순위 순서로 탐지: 주민번호 → 카드 → 전화 → 이메일 → 계좌 → 내부정보 키워드
    for m in _RRN_RE.finditer(text):
        add("rrn", _mask_rrn(m), m.start(), m.end())

    for m in _CARD_RE.finditer(text):
        if claims.overlaps(m.start(), m.end()):
            continue
        if not _luhn_valid(_digits(m.group())):
            continue  # 체크섬 불일치 → 카드번호 오탐으로 보고 제외
        add("card", _mask_card(m.group()), m.start(), m.end())

    for m in _PHONE_RE.finditer(text):
        if claims.overlaps(m.start(), m.end()):
            continue
        add("phone", _mask_phone(m.group()), m.start(), m.end())

    for m in _EMAIL_RE.finditer(text):
        if claims.overlaps(m.start(), m.end()):
            continue
        add("email", _mask_email(m.group()), m.start(), m.end())

    for m in _ACCOUNT_RE.finditer(text):
        if claims.overlaps(m.start(), m.end()):
            continue
        if not 10 <= len(_digits(m.group())) <= 15:
            continue  # 날짜(8자리)·카드(16자리) 등은 계좌 후보에서 제외
        window = text[
            max(0, m.start() - _ACCOUNT_KEYWORD_WINDOW) : m.end()
            + _ACCOUNT_KEYWORD_WINDOW
        ]
        confidence = "high" if _ACCOUNT_KEYWORD_RE.search(window) else "low"
        add(
            "account",
            _mask_account(m.group()),
            m.start(),
            m.end(),
            confidence=confidence,
        )

    for m in _INTERNAL_RE.finditer(text):
        if claims.overlaps(m.start(), m.end()):
            continue
        # 키워드 자체는 민감값이 아니므로 그대로 노출
        add("internal_keyword", m.group(), m.start(), m.end())

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1

    n = len(findings)
    if n == 0:
        summary = "민감정보 패턴이 탐지되지 않았습니다."
    else:
        by_type = ", ".join(f"{k} {v}건" for k, v in sorted(counts.items()))
        summary = (
            f"민감정보 패턴 {n}건이 탐지되었습니다 ({by_type}). "
            "외부 공유 전 준법감시 확인이 필요합니다."
        )

    return ok(
        TOOL_NAME,
        summary,
        data={"findings": findings, "counts": counts},
        requires_human_review=n > 0,
    )
