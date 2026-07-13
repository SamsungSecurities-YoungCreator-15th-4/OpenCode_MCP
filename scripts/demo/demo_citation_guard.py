#!/usr/bin/env python
"""검색 결과에 없는 조항을 MCP 내부 생성 답변에서 폐기하는 경로를 재현한다."""

import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from compliance import rag  # noqa: E402


QUERY = "미공개중요정보 외부 공유 시 준법감시인 확인이 필요한가요?"
FAKE_ANSWER = "제999조에 따라 준법감시인 확인이 필요합니다."


def main() -> int:
    print("=" * 92)
    print("DEMO 2 | MCP 내부 생성 답변 인용 조항 대조")
    print("=" * 92)
    print("범위: MCP 내부의 선택적 생성 답변만 검증합니다.")
    print("주의: OpenCode 호스트가 tool 호출 후 만드는 최종 화면 문장은 검증 대상이 아닙니다.")
    print("감사 로그: 기록하지 않음 (mcp_server wrapper가 아닌 RAG 함수 직접 호출)\n")

    print("[1] 존재하지 않는 조항이 포함된 내부 생성 답변 주입")
    print(f"    {FAKE_ANSWER}\n")

    generation = {"enabled": True, "model": "demo-injected-answer", "error": None}
    with patch.object(rag, "_generate_answer", return_value=(FAKE_ANSWER, generation)):
        result = rag.check_disclosure_risk(QUERY)

    if not result.get("ok"):
        print(f"[실행 실패] RAG 실행 중 오류가 발생했습니다: {result.get('error')}")
        return 1

    data = result.get("data", {})
    if not data.get("threshold_passed"):
        print("[실행 실패] 규정 질의가 검색 임계값을 통과하지 못해 인용 검증까지 진행되지 않았습니다.")
        return 1

    available_articles = sorted(
        {match["article"] for match in data["matches"] if match.get("article")}
    )
    unsupported = data["answer_generation"].get("unsupported_cited_articles", [])

    print("[2] 이번 검색으로 회수된 article metadata")
    print(f"    {', '.join(available_articles) or '(조항 metadata 없음)'}\n")

    print("[3] 코드 대조 결과")
    print(f"    cited_articles              : {data['cited_articles']}")
    print(f"    unsupported_cited_articles  : {unsupported}")
    print(f"    citation_verified           : {data['citation_verified']}\n")

    print("[4] 폐기 및 결정론 폴백")
    print(f"    generated answer retained   : {data['answer'] is not None}")
    print(f"    generated answer discarded  : {data['answer_generation'].get('discarded', False)}")
    print(f"    final deterministic summary : {result['summary']}")

    expected = (
        data["citation_verified"] is False
        and data["answer"] is None
        and data["answer_generation"].get("discarded") is True
        and "제999조" not in result["summary"]
    )
    print("\n" + "-" * 92)
    if expected:
        print("결과: 근거에 없는 제999조 인용을 폐기하고 결정론 summary로 전환했습니다.")
        return 0
    print("결과: 인용 방어의 기대 동작을 재현하지 못했습니다.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
