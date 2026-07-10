"""코퍼스 인제스트 스모크 테스트.

- load_chunks(파일→청크)는 임베딩이 필요 없어 항상 실행된다.
- ingest→search 전체 경로는 임베딩 불가 시 자동 스킵된다.
"""

import pytest

from compliance.rag import ingest
from compliance.rag.embedder import embed_texts

SAMPLE = """
제1조(목적) 이 기준은 임직원의 직무수행에 필요한 기본 사항을 정함을 목적으로 한다.

제52조(정보교류 차단) 임직원은 부서 간 미공개 정보가 부당하게 교류되지 않도록
정보교류 차단장치를 성실히 준수하여야 한다.
""".strip()


def _check_embedding_or_skip() -> None:
    """임베딩 가능 여부를 '테스트 실행 시점에' 확인한다.

    skipif 데코레이터로 수집(collection) 단계에서 Ollama에 붙으면, 무관한
    테스트 실행 때도 전체 수집이 지연될 수 있어 함수 내부에서 동적으로 스킵한다.
    """
    try:
        if len(embed_texts(["ping"])) == 1:
            return
    except Exception:
        pass
    pytest.skip("bge-m3 임베딩 불가 (Ollama 미기동 또는 모델 미설치) — 스킵")


def test_load_chunks_uses_filename_as_source(tmp_path):
    file = tmp_path / "01_KOFIA_표준내부통제기준.txt"
    file.write_text(SAMPLE, encoding="utf-8")

    chunks = ingest.load_chunks([str(file)])

    # 정렬용 숫자 prefix를 제거한 파일명(확장자 제외)이 source가 된다.
    assert {c["source"] for c in chunks} == {"KOFIA_표준내부통제기준"}
    assert [c["article"] for c in chunks] == ["제1조", "제52조"]
    assert all(c["file_name"] == file.name for c in chunks)


def test_load_chunks_merges_multiple_files(tmp_path):
    f1 = tmp_path / "규정A.txt"
    f2 = tmp_path / "규정B.txt"
    f1.write_text("제1조(목적) 가.", encoding="utf-8")
    f2.write_text("제9조(정의) 나.", encoding="utf-8")

    chunks = ingest.load_chunks([str(f1), str(f2)])

    assert {c["source"] for c in chunks} == {"규정A", "규정B"}
    assert len(chunks) == 2


def test_load_chunks_reads_cp949(tmp_path):
    # 국내 규정 텍스트가 CP949로 저장된 경우에도 읽어야 한다.
    file = tmp_path / "규정_cp949.txt"
    file.write_bytes("제7조(보고) 보고 절차를 정한다.".encode("cp949"))

    chunks = ingest.load_chunks([str(file)])

    assert chunks[0]["article"] == "제7조"
    assert chunks[0]["article_title"] == "보고"


def test_load_chunks_falls_back_to_plain_text_for_unstructured_docs(tmp_path):
    file = tmp_path / "가이드.md"
    file.write_text("조항 헤더가 없는 안내문입니다. " * 20, encoding="utf-8")

    chunks = ingest.load_chunks([str(file)], max_chars=100, overlap=20)

    assert len(chunks) > 1
    assert {c["source"] for c in chunks} == {"가이드"}
    assert all(c["article"] == "" for c in chunks)
    assert all(c["file_name"] == file.name for c in chunks)


def test_ingest_then_search(tmp_path):
    _check_embedding_or_skip()
    from compliance.rag import pipeline

    file = tmp_path / "KOFIA_규정.txt"
    file.write_text(SAMPLE, encoding="utf-8")

    summary = ingest.ingest([str(file)], chroma_path=":memory:")
    assert summary["total_chunks"] == 2
    assert summary["per_source"] == {"KOFIA_규정": 2}

    # ingest가 모듈 전역 파이프라인에 인덱스를 구성했으므로 바로 검색된다.
    hits = pipeline.search("부서 간 정보 교류 차단", top_k=1)
    assert hits[0]["article"] == "제52조"
