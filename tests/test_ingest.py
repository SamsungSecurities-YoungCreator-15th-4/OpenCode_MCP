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


def _embedding_available() -> bool:
    try:
        return len(embed_texts(["ping"])) == 1
    except Exception:
        return False


requires_embedding = pytest.mark.skipif(
    not _embedding_available(),
    reason="bge-m3 임베딩 불가 (Ollama 미기동 또는 모델 미설치) — 스킵",
)


def test_load_chunks_uses_filename_as_source(tmp_path):
    file = tmp_path / "KOFIA_표준내부통제기준.txt"
    file.write_text(SAMPLE, encoding="utf-8")

    chunks = ingest.load_chunks([str(file)])

    # 파일명(확장자 제외)이 source가 된다.
    assert {c["source"] for c in chunks} == {"KOFIA_표준내부통제기준"}
    assert [c["article"] for c in chunks] == ["제1조", "제52조"]


def test_load_chunks_merges_multiple_files(tmp_path):
    f1 = tmp_path / "규정A.txt"
    f2 = tmp_path / "규정B.txt"
    f1.write_text("제1조(목적) 가.", encoding="utf-8")
    f2.write_text("제9조(정의) 나.", encoding="utf-8")

    chunks = ingest.load_chunks([str(f1), str(f2)])

    assert {c["source"] for c in chunks} == {"규정A", "규정B"}
    assert len(chunks) == 2


@requires_embedding
def test_ingest_then_search(tmp_path):
    from compliance.rag import pipeline

    file = tmp_path / "KOFIA_규정.txt"
    file.write_text(SAMPLE, encoding="utf-8")

    summary = ingest.ingest([str(file)], chroma_path=":memory:")
    assert summary["total_chunks"] == 2
    assert summary["per_source"] == {"KOFIA_규정": 2}

    # ingest가 모듈 전역 파이프라인에 인덱스를 구성했으므로 바로 검색된다.
    hits = pipeline.search("부서 간 정보 교류 차단", top_k=1)
    assert hits[0]["article"] == "제52조"
