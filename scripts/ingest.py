#!/usr/bin/env python
"""규정 코퍼스 인덱싱 CLI.

사용:
    python scripts/ingest.py compliance/rag/data/*
    python scripts/ingest.py compliance/rag/data/* --query "정보교류 차단"

입력은 PDF/TXT/MD를 지원한다. 조항 패턴이 있으면 조항 단위로, 없으면 plain
text 청크로 적재한다. 파일명이 곧 출처(source)다.
적재 경로 기본값은 data/chroma/ (CHROMA_PATH 환경변수로 변경 가능).
"""

import argparse
import glob
import sys
from pathlib import Path

# `python scripts/ingest.py`로 직접 실행해도 compliance 패키지를 import할 수 있도록
# 레포 루트를 경로에 추가한다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compliance.rag import ingest as ingest_mod  # noqa: E402


def _expand(patterns: list[str]) -> list[str]:
    """와일드카드를 직접 확장한다(Windows cmd 등 셸이 확장 안 하는 경우 대비).

    매칭이 없는 패턴은 원문 그대로 남겨, 이후 읽기 단계에서 명확히 에러가 나게 한다.
    """
    expanded: list[str] = []
    for pattern in patterns:
        matched = sorted(glob.glob(pattern))
        expanded.extend(matched if matched else [pattern])
    return expanded


def main() -> int:
    parser = argparse.ArgumentParser(
        description="규정 PDF/TXT/MD 코퍼스를 청킹·인덱싱한다."
    )
    parser.add_argument("paths", nargs="+", help="규정 PDF/TXT/MD 파일들")
    parser.add_argument(
        "--max-chars", type=int, default=900, help="청크 최대 길이(기본 900)"
    )
    parser.add_argument(
        "--overlap",
        type=int,
        default=120,
        help="plain text 청킹 overlap 길이(기본 120)",
    )
    parser.add_argument("--query", help="적재 후 확인용 검색 질의(선택)")
    args = parser.parse_args()

    try:
        summary = ingest_mod.ingest(
            _expand(args.paths), max_chars=args.max_chars, overlap=args.overlap
        )
    except FileNotFoundError as exc:
        print(f"오류: 파일을 찾을 수 없습니다: {exc.filename}", file=sys.stderr)
        return 1
    except ValueError as exc:  # 인코딩 인식 실패 등
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    if summary["total_chunks"] == 0:
        print(
            "경고: 적재된 청크가 없습니다. 입력 파일 내용과 형식을 확인하세요.",
            file=sys.stderr,
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
