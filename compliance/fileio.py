"""로컬 파일 텍스트 추출 — scan/check tool의 file_path 입력 지원.

폐쇄망 제약: 로컬 파일시스템만 읽는다. 네트워크 경로·URL은 지원하지 않는다.
원문 미저장 원칙: 이 모듈은 추출만 담당하고 저장하지 않는다. 감사 로그에는
기존과 동일하게 SHA-256 해시만 남는다.

추출 텍스트가 상한을 넘어 절단되면 뒷부분은 스캔되지 않으므로 미탐 위험이
있다. 호출자는 truncated=True일 때 requires_human_review를 반드시 True로
강제해야 한다(보수적 바이어스).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from pypdf import PdfReader

ALLOWED_EXTENSIONS = {".pdf", ".txt", ".md"}
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TEXT_CHARS = 100_000


@dataclass
class ExtractedText:
    text: str
    file_name: str
    extension: str
    total_chars: int
    truncated: bool
    pages: int | None = None  # PDF만 해당


class FileInputError(ValueError):
    """사용자에게 그대로 보여줄 수 있는 파일 입력 오류."""


def _read_txt(file_path: str) -> str:
    # 사내 문서는 cp949 인코딩이 흔해 utf-8 실패 시 한 번 더 시도한다.
    try:
        with open(file_path, encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(file_path, encoding="cp949") as f:
            return f.read()


def _read_pdf(file_path: str) -> tuple[str, int]:
    try:
        reader = PdfReader(file_path)
        if reader.is_encrypted:
            raise FileInputError(
                "암호화된 PDF는 지원하지 않습니다. 암호를 해제한 사본으로 다시 시도하세요."
            )
        parts: list[str] = []
        for page in reader.pages:
            parts.append(page.extract_text() or "")
        return "\n".join(parts), len(reader.pages)
    except FileInputError:
        raise
    except Exception as exc:
        raise FileInputError(
            f"PDF를 열 수 없습니다(손상되었거나 암호화됨): {exc}"
        ) from exc


def extract_text(file_path: str) -> ExtractedText:
    """파일에서 텍스트를 추출한다. 실패는 FileInputError로 통일한다."""
    if not file_path or not file_path.strip():
        raise FileInputError("file_path가 비어 있습니다.")
    path = os.path.expanduser(file_path.strip())

    ext = os.path.splitext(path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise FileInputError(f"지원하지 않는 파일 형식입니다({ext or '확장자 없음'}). 지원: {allowed}")
    try:
        if not os.path.isfile(path):
            raise FileInputError(f"파일을 찾을 수 없습니다: {file_path}")
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            raise FileInputError(
                f"파일이 너무 큽니다({size} bytes, 상한 {MAX_FILE_BYTES})."
            )

        pages: int | None = None
        if ext == ".pdf":
            text, pages = _read_pdf(path)
        else:
            text = _read_txt(path)
        text = text or ""
    except FileInputError:
        raise
    except Exception as exc:
        raise FileInputError(f"파일을 읽는 중 오류가 발생했습니다: {exc}") from exc

    if not text.strip():
        raise FileInputError(
            "파일에서 텍스트를 추출하지 못했습니다. 스캔 이미지 PDF 등 텍스트 레이어가 "
            "없는 파일은 지원하지 않습니다."
        )

    total = len(text)
    truncated = total > MAX_TEXT_CHARS
    if truncated:
        text = text[:MAX_TEXT_CHARS]
    return ExtractedText(
        text=text,
        file_name=os.path.basename(path),
        extension=ext,
        total_chars=total,
        truncated=truncated,
        pages=pages,
    )
