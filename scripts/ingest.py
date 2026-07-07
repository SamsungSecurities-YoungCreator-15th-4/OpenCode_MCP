#!/usr/bin/env python
"""규정 텍스트 코퍼스 인덱싱 CLI.

사용:
    python scripts/ingest.py data/corpus/*.txt
    python scripts/ingest.py data/corpus/*.txt --query "정보교류 차단"

입력 텍스트 파일은 "제○조(제목) 본문..." 형태로 이미 추출돼 있어야 한다
(PDF 파싱은 이 스크립트의 상류, 데이터 담당 몫). 파일명이 곧 출처(source)다.
적재 경로 기본값은 data/chroma/ (CHROMA_PATH 환경변수로 변경 가능).
"""

import argparse
import sys
from pathlib import Path

# `python scripts/ingest.py`로 직접 실행해도 compliance 패키지를 import할 수 있도록
# 레포 루트를 경로에 추가한다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compliance.rag import ingest as ingest_mod  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="규정 텍스트 코퍼스를 조항 단위로 청킹·인덱싱한다."
    )
    parser.add_argument("paths", nargs="+", help="구조화된 규정 텍스트 파일들")
    parser.add_argument(
        "--max-chars", type=int, default=800, help="조항 청크 최대 길이(기본 800)"
    )
    parser.add_argument("--query", help="적재 후 확인용 검색 질의(선택)")
    args = parser.parse_args()

    summary = ingest_mod.ingest(args.paths, max_chars=args.max_chars)
    if summary["total_chunks"] == 0:
        print(
            "경고: 조항(제○조) 헤더를 찾지 못해 적재된 청크가 없습니다.", file=sys.stderr
        )
        return 1

    print(f"적재 완료: 총 {summary['total_chunks']}개 청크")
    for source, count in sorted(summary["per_source"].items()):
        print(f"  - {source}: {count}개")

    if args.query:
        from compliance.rag import pipeline

        print(f"\n검색 확인: {args.query!r}")
        for hit in pipeline.search(args.query, top_k=3):
            print(
                f"  [{hit['score']:.4f}] {hit['source']} {hit['article']} "
                f"({hit['article_title']})"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
