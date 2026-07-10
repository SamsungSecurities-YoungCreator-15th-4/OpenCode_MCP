"""compliance/fileio.py — 파일 텍스트 추출 단위 테스트 (Ollama 불필요)."""

import pytest

from compliance import fileio
from compliance.fileio import FileInputError, extract_text


def _minimal_pdf_bytes(text: str) -> bytes:
    """텍스트 한 줄이 들어간 최소 구조의 유효한 PDF를 조립한다(외부 의존성 없이)."""
    content = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def test_extract_txt_utf8(tmp_path):
    p = tmp_path / "memo.txt"
    p.write_text("고객 김철수 010-1234-5678 안내", encoding="utf-8")
    r = extract_text(str(p))
    assert "010-1234-5678" in r.text
    assert r.extension == ".txt"
    assert r.truncated is False
    assert r.pages is None


def test_extract_txt_cp949_fallback(tmp_path):
    p = tmp_path / "memo_cp949.txt"
    p.write_bytes("확정 수익률 보장 문구".encode("cp949"))
    r = extract_text(str(p))
    assert "확정 수익률" in r.text


def test_extract_pdf(tmp_path):
    p = tmp_path / "doc.pdf"
    p.write_bytes(_minimal_pdf_bytes("Call 010-1234-5678 guaranteed"))
    r = extract_text(str(p))
    assert "010-1234-5678" in r.text
    assert r.extension == ".pdf"
    assert r.pages == 1


def test_pdf_page_extraction_error_is_wrapped(monkeypatch):
    class BrokenPage:
        def extract_text(self):
            raise RuntimeError("broken page stream")

    class BrokenReader:
        is_encrypted = False
        pages = [BrokenPage()]

    monkeypatch.setattr(fileio, "PdfReader", lambda _: BrokenReader())

    with pytest.raises(FileInputError, match="PDF를 열 수 없습니다"):
        fileio._read_pdf("broken.pdf")


def test_unsupported_extension(tmp_path):
    p = tmp_path / "run.exe"
    p.write_bytes(b"MZ")
    with pytest.raises(FileInputError, match="지원하지 않는 파일 형식"):
        extract_text(str(p))


def test_missing_file():
    with pytest.raises(FileInputError, match="파일을 찾을 수 없습니다"):
        extract_text("/nonexistent/없는파일.txt")


def test_empty_path():
    with pytest.raises(FileInputError, match="비어 있습니다"):
        extract_text("  ")


def test_empty_content_rejected(tmp_path):
    p = tmp_path / "blank.txt"
    p.write_text("   \n  ", encoding="utf-8")
    with pytest.raises(FileInputError, match="추출하지 못했"):
        extract_text(str(p))


def test_truncation_flag(tmp_path):
    p = tmp_path / "big.txt"
    p.write_text("가" * (fileio.MAX_TEXT_CHARS + 10), encoding="utf-8")
    r = extract_text(str(p))
    assert r.truncated is True
    assert len(r.text) == fileio.MAX_TEXT_CHARS
    assert r.total_chars == fileio.MAX_TEXT_CHARS + 10


def test_oversize_file_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(fileio, "MAX_FILE_BYTES", 10)
    p = tmp_path / "big.txt"
    p.write_text("이 파일은 상한보다 큽니다", encoding="utf-8")
    with pytest.raises(FileInputError, match="너무 큽니다"):
        extract_text(str(p))


def test_file_size_error_is_wrapped(tmp_path, monkeypatch):
    p = tmp_path / "unreadable.txt"
    p.write_text("본문", encoding="utf-8")

    def fail_getsize(_):
        raise PermissionError("permission denied")

    monkeypatch.setattr(fileio.os.path, "getsize", fail_getsize)

    with pytest.raises(FileInputError, match="파일을 읽는 중 오류"):
        extract_text(str(p))


def test_text_decode_error_is_wrapped(tmp_path, monkeypatch):
    p = tmp_path / "invalid.txt"
    p.write_bytes(b"invalid")

    def fail_decode(_):
        raise UnicodeDecodeError("cp949", b"\xff", 0, 1, "invalid byte")

    monkeypatch.setattr(fileio, "_read_txt", fail_decode)

    with pytest.raises(FileInputError, match="파일을 읽는 중 오류"):
        extract_text(str(p))
