"""규정 텍스트 코퍼스를 청킹·인덱싱하는 오케스트레이션.

실제 PDF 파싱은 이 모듈의 상류다(데이터 담당). 여기서는 이미
"제○조(제목) 본문..." 형태로 추출된 텍스트 파일을 받아
chunker → pipeline.build_index로 적재한다. 파일명(확장자 제외)을
source 메타데이터로 사용한다.

실제 코퍼스 준비 흐름:
    각 규정을 "제○조(제목) 본문..." 텍스트 파일로 만든다(예: KOFIA_표준내부통제기준.txt)
    → python scripts/ingest.py data/corpus/*.txt
"""

from collections import Counter
from pathlib import Path

from compliance.rag import chunker, pipeline


def _read_text(file: Path) -> str:
    """UTF-8로 읽되 실패 시 CP949(EUC-KR)로 폴백한다(국내 규정 텍스트 대비)."""
    for encoding in ("utf-8", "cp949"):
        try:
            return file.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"'{file}'의 인코딩을 인식할 수 없습니다 (UTF-8/CP949 아님).")


def load_chunks(paths: list[str], max_chars: int = 800) -> list[dict]:
    """텍스트 파일 목록을 읽어 조항 단위 청크 리스트로 변환한다(순수: 임베딩 없음).

    각 파일의 source는 파일명(확장자 제외)으로 정한다.
    """
    chunks: list[dict] = []
    for path in paths:
        file = Path(path)
        text = _read_text(file)
        chunks.extend(chunker.chunk_articles(text, source=file.stem, max_chars=max_chars))
    return chunks


def ingest(
    paths: list[str], chroma_path: str | None = None, max_chars: int = 800
) -> dict:
    """텍스트 파일들을 청킹·임베딩·Chroma 적재하고 요약을 반환한다.

    반환: {total_chunks, per_source: {source: count}, files: [...]}.
    청크가 하나도 없으면 build_index를 호출하지 않는다(빈 인덱스 방지).
    """
    chunks = load_chunks(paths, max_chars=max_chars)
    per_source = dict(Counter(chunk["source"] for chunk in chunks))

    if chunks:
        pipeline.build_index(chunks, chroma_path=chroma_path)

    return {
        "total_chunks": len(chunks),
        "per_source": per_source,
        "files": [str(p) for p in paths],
    }
