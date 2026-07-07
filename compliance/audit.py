"""log_ai_usage 로직 (현재 mock).

실제 구현 시 로컬 파일 기반 감사 로그(해시 체이닝 검토)로 교체 예정.
원칙: 원본 민감정보 값은 로그에 평문으로 저장하지 않는다.
"""

from compliance.schema import ok


def log_ai_usage(action: str, detail: str = "") -> dict:
    """mock: 감사 로그 기록 구현 전까지 기록 없이 접수 사실만 알린다."""
    return ok(
        "log_ai_usage",
        "[mock] 감사 로그 기록은 아직 구현 전입니다. 실제 파일 기록은 하지 않았습니다.",
        data={"mock": True, "action": action, "detail": detail, "logged": False},
    )
