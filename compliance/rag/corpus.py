"""로컬 규정 코퍼스 로딩.

지원 입력:
- compliance/rag/data/*.pdf
- compliance/rag/data/*.txt, *.md

PDF 원문 파일은 로컬 데이터로 취급되어 Git에는 올리지 않는다. 이 모듈은 검색
시점에 로컬 파일을 읽고, 조항 단위 청킹이 가능하면 조항 청크를, 아니면 고정 길이
청크를 만든다.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from compliance.rag.chunker import chunk_articles, chunk_plain_text

DEFAULT_CORPUS_DIR = Path(__file__).resolve().parent / "data"
SUPPORTED_SUFFIXES = {".pdf", ".txt", ".md"}


def _normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\u00a0", " ")
    return re.sub(r"[ \t]+", " ", text)


def _source_name(path: Path) -> str:
    stem = unicodedata.normalize("NFC", path.stem)
    return re.sub(r"^\d+[_\-\s]*", "", stem).strip() or stem


def _read_pdf(path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages: list[str] = []
    for i, page in enumerate(reader.pages, start=1):
        page_text = page.extract_text() or ""
        if page_text.strip():
            pages.append(f"\n\n[page {i}]\n{page_text}")
    return _normalize_text("\n".join(pages))


def _read_text(path: Path) -> str:
    return _normalize_text(path.read_text(encoding="utf-8"))


def iter_corpus_files(corpus_dir: Path | str = DEFAULT_CORPUS_DIR) -> list[Path]:
    """코퍼스 디렉터리의 지원 파일을 이름순으로 반환한다."""
    root = Path(corpus_dir)
    if not root.exists():
        return []
    return sorted(
        p for p in root.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES
    )


def load_document_text(path: Path) -> str:
    """지원 문서 하나에서 텍스트를 추출한다."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return _read_pdf(path)
    if suffix in {".txt", ".md"}:
        return _read_text(path)
    raise ValueError(f"지원하지 않는 코퍼스 파일 형식입니다: {path}")


def load_corpus_chunks(
    corpus_dir: Path | str = DEFAULT_CORPUS_DIR,
    max_chars: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """로컬 코퍼스를 읽어 검색용 청크 리스트로 변환한다."""
    chunks: list[dict] = []
    for path in iter_corpus_files(corpus_dir):
        source = _source_name(path)
        text = load_document_text(path)
        article_chunks = chunk_articles(text, source=source, max_chars=max_chars)
        doc_chunks = article_chunks or chunk_plain_text(
            text, source=source, max_chars=max_chars, overlap=overlap
        )
        for chunk in doc_chunks:
            chunk["file_name"] = path.name
        chunks.extend(doc_chunks)
    return chunks
