"""전 tool 공통 출력 스키마와 응답 헬퍼.

모든 tool은 성공·실패와 무관하게 아래 7개 키를 가진 dict를 반환한다.
tool별 로직은 이 모듈의 ok()/fail()만 사용해 응답을 만든다.
"""

RESULT_KEYS = (
    "ok",
    "tool",
    "summary",
    "data",
    "outputs",
    "requires_human_review",
    "error",
)


def ok(
    tool: str,
    summary: str,
    data: dict | None = None,
    outputs: list[str] | None = None,
    requires_human_review: bool = False,
) -> dict:
    """성공 응답. summary는 사람이 읽을 1~3문장."""
    return {
        "ok": True,
        "tool": tool,
        "summary": summary,
        "data": data if data is not None else {},
        "outputs": outputs if outputs is not None else [],
        "requires_human_review": requires_human_review,
        "error": None,
    }


def fail(tool: str, summary: str, error: str, data: dict | None = None) -> dict:
    """실패 응답. 실패 시에는 보수적 원칙에 따라 사람 확인을 기본으로 요구한다."""
    return {
        "ok": False,
        "tool": tool,
        "summary": summary,
        "data": data if data is not None else {},
        "outputs": [],
        "requires_human_review": True,
        "error": error,
    }
