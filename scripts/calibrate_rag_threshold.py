#!/usr/bin/env python
"""현재 로컬 코퍼스에서 RAG 벡터 유사도 임계값을 일회성 측정한다.

하이브리드 검색이나 임계값 로직을 재구현하지 않고, 컷 이전의 기존
VectorStore.vector_search()를 호출해 순수 벡터 top-1/top-5 유사도를 출력한다.
외부 API나 생성 LLM은 호출하지 않으며 로컬 Ollama bge-m3만 사용한다.

실행:
    .venv/bin/python scripts/calibrate_rag_threshold.py

2026-07-12 측정 결과(현재 로컬 코퍼스 95청크, 고정 질의 16개):
- 규정 질의 6건의 최저 top-1 코사인 유사도: 0.5533
- 무해 질의 6건의 최고 top-1 코사인 유사도: 0.4268
- sweep 완전 분리 구간: 0.44~0.54
- A/B 분리 구간 중앙값으로 채택한 기본 임계값: 0.49
"""

import argparse
import math
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

# `python scripts/calibrate_rag_threshold.py` 직접 실행을 지원한다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compliance.rag import DEFAULT_VECTOR_SIMILARITY_THRESHOLD  # noqa: E402
from compliance.rag.vector_store import COLLECTION, VectorStore  # noqa: E402


@dataclass(frozen=True)
class QueryGroup:
    title: str
    expectation: str
    queries: tuple[str, ...]


QUERY_GROUPS = {
    "A": QueryGroup(
        title="규정 질의",
        expectation="PASS",
        queries=(
            "미공개중요정보를 외부에 공유하기 전에 준법감시인 확인이 필요한가요?",
            "자본시장법상 내부자거래 금지 규정은 무엇인가요?",
            "투자권유를 할 때 지켜야 할 적합성 원칙은 무엇인가요?",
            "회사의 손익구조에 중대한 변경이 생겼을 때 공시 의무가 있나요?",
            "고객의 개인신용정보를 제3자에게 제공할 때 필요한 절차는?",
            "정보교류차단벽(차이니즈월) 관련 내부통제 기준은?",
        ),
    ),
    "B": QueryGroup(
        title="무해 질의",
        expectation="CUT",
        queries=(
            "점심 뭐 먹지",
            "오늘 날씨 어때?",
            "파이썬으로 리스트 정렬하는 법 알려줘",
            "주말에 볼 만한 영화 추천해줘",
            "커피랑 녹차 중에 뭐가 더 좋아?",
            "안녕하세요",
        ),
    ),
    "C": QueryGroup(
        title="경계 질의",
        expectation="참고",
        queries=(
            "삼성전자 주가 오늘 얼마야?",
            "비트코인 지금 사도 될까?",
            "연말정산 환급금 언제 들어와?",
            "적금이랑 예금 중에 뭐가 나아?",
        ),
    ),
}


@dataclass(frozen=True)
class Measurement:
    group: str
    number: int
    query: str
    similarities: tuple[float, ...]

    @property
    def top1(self) -> float:
        return self.similarities[0]


def _measure(store: VectorStore) -> list[Measurement]:
    rows: list[Measurement] = []
    for group, definition in QUERY_GROUPS.items():
        for number, query in enumerate(definition.queries, start=1):
            hits = store.vector_search(query, top_k=5)
            similarities = tuple(
                float(hit["vector_similarity"])
                for hit in hits
                if hit.get("vector_similarity") is not None
            )
            if len(similarities) != 5:
                raise RuntimeError(
                    f"{group}-{number} 검색에서 벡터 유사도 5개를 얻지 못했습니다 "
                    f"(실제 {len(similarities)}개)."
                )
            rows.append(Measurement(group, number, query, similarities))
    return rows


def _decision(similarity: float, threshold: float) -> str:
    return "PASS" if similarity >= threshold else "CUT"


def _print_measurements(rows: list[Measurement], threshold: float) -> None:
    for group, definition in QUERY_GROUPS.items():
        print(
            f"\nGROUP {group} ({definition.title} — {definition.expectation} 기대)"
        )
        print(f"{'query':<45}  top1_sim  top5_sims                             verdict@{threshold:.2f}")
        print("-" * 118)
        for row in (item for item in rows if item.group == group):
            top5 = " ".join(f"{value:.4f}" for value in row.similarities)
            print(
                f"{row.number}. {row.query:<42}  {row.top1:.4f}    {top5}  "
                f"{_decision(row.top1, threshold)}"
            )


def _group_values(rows: list[Measurement]) -> dict[str, list[float]]:
    return {
        group: [row.top1 for row in rows if row.group == group]
        for group in QUERY_GROUPS
    }


def _print_summary(rows: list[Measurement], threshold: float) -> None:
    by_group = _group_values(rows)
    a_pass = sum(value >= threshold for value in by_group["A"])
    b_cut = sum(value < threshold for value in by_group["B"])
    c_pass = sum(value >= threshold for value in by_group["C"])
    c_cut = len(by_group["C"]) - c_pass

    print("\n=== 요약 ===")
    print(f"GROUP A: {a_pass}/{len(by_group['A'])} PASS (기대: 6/6)")
    print(f"GROUP B: {b_cut}/{len(by_group['B'])} CUT  (기대: 6/6)")
    print(f"GROUP C: {c_pass} PASS / {c_cut} CUT (판단 참고용)")

    if a_pass == len(by_group["A"]) and b_cut == len(by_group["B"]):
        judgement = "적절"
    elif b_cut < len(by_group["B"]):
        judgement = "너무 낮음"
    else:
        judgement = "너무 높음"
    print(f"임계값 {threshold:.2f} 판정: {judgement}")

    min_a = min(by_group["A"])
    max_b = max(by_group["B"])
    margin = min_a - max_b
    print(f"GROUP A 최저 top1_sim : {min_a:.6f}")
    print(f"GROUP B 최고 top1_sim : {max_b:.6f}")
    print(f"분리 마진            : {margin:.6f}  (음수면 분리 불가)")
    if margin > 0:
        midpoint = (min_a + max_b) / 2
        print(f"권장 임계값          : {midpoint:.2f}  (A최저와 B최고 사이 중앙값)")
    else:
        print("권장 임계값          : 분리 불가")

    print("\n[그룹별 Top-1 분포]")
    print("group  count  min       mean      max")
    print("-----  -----  --------  --------  --------")
    for group in QUERY_GROUPS:
        values = [row.top1 for row in rows if row.group == group]
        print(
            f"{group:<5}  {len(values):>5}  {min(values):.6f}  "
            f"{statistics.mean(values):.6f}  {max(values):.6f}"
        )


def _print_threshold_sweep(rows: list[Measurement]) -> None:
    candidates = [0.30 + step * 0.02 for step in range(21)]
    by_group = _group_values(rows)

    print("\n=== 임계값 sweep (0.30 ~ 0.70, step 0.02) ===")
    print("threshold  A_pass       A_pass_rate  B_cut        B_cut_rate")
    print("---------  -----------  -----------  -----------  ----------")
    for threshold in candidates:
        a_pass = sum(value >= threshold for value in by_group["A"])
        b_cut = sum(value < threshold for value in by_group["B"])
        print(
            f"{threshold:.2f}       {a_pass}/{len(by_group['A']):<8}  "
            f"{a_pass / len(by_group['A']):>10.1%}  "
            f"{b_cut}/{len(by_group['B']):<8}  {b_cut / len(by_group['B']):>9.1%}"
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="로컬 bge-m3/Chroma의 RAG 임계값 분리력을 측정한다."
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_VECTOR_SIMILARITY_THRESHOLD,
        help=(
            "판정 임계값. 생략하면 RAG_VECTOR_SIMILARITY_THRESHOLD 또는 기본 0.49"
        ),
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="0.30부터 0.70까지 0.02 간격의 A pass율/B cut율을 출력",
    )
    args = parser.parse_args()
    if not math.isfinite(args.threshold) or not -1 <= args.threshold <= 1:
        parser.error("--threshold는 -1 이상 1 이하의 유한한 숫자여야 합니다.")
    return args


def main() -> int:
    args = _parse_args()
    threshold = args.threshold
    store = VectorStore()
    count = store.count()
    if count == 0:
        print(
            f"오류: Chroma collection={COLLECTION!r}에 문서가 없습니다. "
            "먼저 코퍼스를 인제스트하세요.",
            file=sys.stderr,
        )
        return 1

    print("RAG threshold calibration")
    print(f"- collection: {COLLECTION}")
    print(f"- indexed chunks: {count}")
    print("- metric: cosine similarity = 1 - Chroma cosine distance")
    print(f"- configured threshold: {threshold:.6f}")
    print("- retrieval: existing VectorStore.vector_search(top_k=5)")

    try:
        rows = _measure(store)
    except (KeyError, RuntimeError) as exc:
        print(f"오류: 측정에 실패했습니다: {exc}", file=sys.stderr)
        return 1

    _print_measurements(rows, threshold)
    _print_summary(rows, threshold)
    if args.sweep:
        _print_threshold_sweep(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
