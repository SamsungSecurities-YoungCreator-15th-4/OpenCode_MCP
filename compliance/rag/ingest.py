"""규정 코퍼스를 청킹·인덱싱하는 오케스트레이션.

PDF/TXT/MD 파일을 받아 corpus 로더로 텍스트를 추출하고, 조항 패턴이 있으면
조항 단위로, 없으면 고정 길이 plain text 청크로 나눠 pipeline.build_index에
적재한다. 파일명(확장자 제외)을 source 메타데이터로 사용한다.

실제 코퍼스 준비 흐름:
    compliance/rag/data 또는 별도 경로에 규정 PDF/TXT/MD를 둔다.
    → python scripts/ingest.py compliance/rag/data/*
"""

from collections import Counter
from pathlib import Path

from compliance.rag import chunker, pipeline
from compliance.rag.corpus import SUPPORTED_SUFFIXES, load_document_text, source_name


def load_chunks(
    paths: list[str],
    max_chars: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """파일 목록을 읽어 검색용 청크 리스트로 변환한다(순수: 임베딩 없음).

    각 파일의 source는 파일명(확장자 제외)으로 정한다. 조항 헤더가 없으면
    plain text 청킹으로 폴백한다.
    """
    chunks: list[dict] = []
    for path in paths:
        file = Path(path)
        if file.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise ValueError(f"지원하지 않는 코퍼스 파일 형식입니다: {file}")

        source = source_name(file)
        text = load_document_text(file)
        doc_chunks = chunker.chunk_articles(text, source=source, max_chars=max_chars)
        if not doc_chunks:
            doc_chunks = chunker.chunk_plain_text(
                text, source=source, max_chars=max_chars, overlap=overlap
            )
        for chunk in doc_chunks:
            chunk["file_name"] = file.name
        chunks.extend(doc_chunks)
    return chunks


def ingest(
    paths: list[str],
    chroma_path: str | None = None,
    max_chars: int = 900,
    overlap: int = 120,
) -> dict:
    """코퍼스 파일들을 청킹·임베딩·Chroma 적재하고 요약을 반환한다.

    반환: {total_chunks, per_source: {source: count}, files: [...]}.
    청크가 하나도 없으면 build_index를 호출하지 않는다(빈 인덱스 방지).
    """
    chunks = load_chunks(paths, max_chars=max_chars, overlap=overlap)
    per_source = dict(Counter(chunk["source"] for chunk in chunks))

    if chunks:
        pipeline.build_index(chunks, chroma_path=chroma_path)

    return {
        "total_chunks": len(chunks),
        "per_source": per_source,
        "files": [str(p) for p in paths],
    }
