#!/usr/bin/env python
"""실제 RAG 검색 경로로 규정 질의와 무해 질의의 임계값 판정을 비교한다."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from compliance import rag  # noqa: E402


QUERIES = (
    ("무해 질의", "오늘 점심 뭐 먹지?", "CUT"),
    (
        "규정 질의",
        "미공개중요정보 외부 공유 시 준법감시인 확인이 필요한가요?",
        "PASS",
    ),
)


def main() -> int:
    print("=" * 92)
    print("DEMO 1 | RAG 벡터 유사도 임계값 컷")
    print("=" * 92)
    print("기준: 하이브리드 검색 결과 중 최고 벡터 코사인 유사도(top-1)")
    print(f"현재 임계값: {rag.DEFAULT_VECTOR_SIMILARITY_THRESHOLD:.2f}")
    print("감사 로그: 기록하지 않음 (MCP wrapper가 아닌 RAG 검색 내부 경로 호출)\n")

    ready, error = rag._ensure_ready()
    if not ready:
        print(f"[실행 실패] 로컬 RAG 인덱스를 준비하지 못했습니다: {error}")
        return 1

    print(f"{'구분':<12} {'top-1 유사도':>14} {'컷 여부':>12} {'기대':>8}  질의")
    print("-" * 92)
    results: list[tuple[str, str]] = []
    for label, query, expected in QUERIES:
        matches = rag._search(query, top_k=5)
        confidence = rag._retrieval_confidence(matches)
        similarity = confidence["best_vector_similarity"]
        verdict = "PASS" if confidence["threshold_passed"] else "CUT"
        similarity_text = "N/A" if similarity is None else f"{similarity:.4f}"
        print(f"{label:<12} {similarity_text:>14} {verdict:>12} {expected:>8}  {query}")
        results.append((verdict, expected))

    print("\n" + "-" * 92)
    if all(actual == expected for actual, expected in results):
        print("결과: 무해 질의는 근거 없이 컷되고, 규정 질의는 검색 근거를 통과했습니다.")
        return 0
    print("결과: 현재 로컬 인덱스에서 기대 판정과 다른 결과가 발생했습니다.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
