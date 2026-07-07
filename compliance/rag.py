"""check_disclosure_risk·search_compliance_rule 로직 (현재 mock).

실제 구현 시 로컬 임베딩·Chroma 기반 RAG로 교체 예정.
원칙: "위반/적법" 단정 판단은 하지 않는다 — 규정 근거 제시와
준법감시인 확인 필요 여부 안내까지만 수행한다.
"""

from compliance.schema import ok


def check_disclosure_risk(text: str) -> dict:
    """mock: 규정 매칭 구현 전까지 보수적 기본값(확인 필요)을 반환한다."""
    return ok(
        "check_disclosure_risk",
        "[mock] 위험 신호 분석은 아직 구현 전입니다. "
        "보수적 원칙에 따라 준법감시인 확인이 필요한 것으로 안내합니다.",
        data={"mock": True, "risk_signals": [], "input_chars": len(text)},
        requires_human_review=True,
    )


def search_compliance_rule(query: str) -> dict:
    """mock: 규정 검색 구현 전까지 예시 형식의 더미 결과를 반환한다."""
    return ok(
        "search_compliance_rule",
        "[mock] 규정 검색은 아직 구현 전입니다. 더미 조문 1건을 예시로 반환합니다.",
        data={
            "mock": True,
            "query": query,
            "matches": [
                {
                    "source": "표준내부통제기준(예시)",
                    "article": "제00조",
                    "snippet": "(구현 전 더미 조문 발췌)",
                    "score": 0.0,
                }
            ],
        },
    )
