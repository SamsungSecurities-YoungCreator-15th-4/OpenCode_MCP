"""RAG 파이프라인 스모크 테스트 (더미 코퍼스, 실제 규정 문서 불필요).

- 청킹·메타데이터 테스트(1,2)는 순수 함수라 항상 실행된다.
- 임베딩이 필요한 테스트(3,4)는 Ollama 미기동 환경(CI)에서 자동 스킵된다.
- RRF 병합 로직은 Ollama 없이도 검증되도록 순수 단위 테스트를 별도로 둔다.
"""

import pytest

from compliance.rag import chunker
from compliance.rag.embedder import embed_texts
from compliance.rag.hybrid_search import reciprocal_rank_fusion

# 미공개중요정보 8기준과 무관한 짧은 가짜 조항들(category는 항상 None로 남는다).
DUMMY_CORPUS = """
제1조(목적) 이 기준은 임직원의 직무수행에 필요한 기본 사항을 정함을 목적으로 한다.

제10조(용어의 정의) 이 기준에서 사용하는 용어의 뜻은 관계 법령이 정하는 바에 따른다.

제52조(정보교류 차단) 임직원은 부서 간 미공개 정보가 부당하게 교류되지 않도록
정보교류 차단장치를 성실히 준수하여야 한다.

제77조(교육) 회사는 임직원에게 정기적으로 준법 관련 교육을 실시하여야 한다.
""".strip()

# 항(①②③)을 가진 긴 조항 — max_chars 초과 분할 테스트용.
LONG_ARTICLE = (
    "제99조(보고 절차) 이 조는 보고 절차를 정한다. "
    "① 임직원은 지체 없이 소속 부서장에게 서면으로 보고하여야 한다. "
    "② 부서장은 보고 내용을 검토한 뒤 준법감시부서에 이를 통보하여야 한다. "
    "③ 준법감시부서는 통보받은 사항을 기록하고 필요한 조치를 취하여야 한다."
)

REQUIRED_KEYS = {
    "text",
    "source",
    "article",
    "article_title",
    "chunk_id",
    "category",
}


def _embedding_available() -> bool:
    """실제 임베딩 한 번을 시도해 가능 여부를 판정한다.

    Ollama 미기동뿐 아니라 bge-m3 모델 미설치까지 모두 '불가'로 보고 스킵한다.
    """
    try:
        return len(embed_texts(["ping"])) == 1
    except Exception:
        return False


requires_embedding = pytest.mark.skipif(
    not _embedding_available(),
    reason="bge-m3 임베딩 불가 (Ollama 미기동 또는 모델 미설치) — 임베딩 의존 테스트 스킵",
)


# --- 1. 조항 경계 인식 + 메타데이터 스키마 -------------------------------------


def test_chunk_articles_boundaries_and_metadata():
    chunks = chunker.chunk_articles(DUMMY_CORPUS, source="KOFIA_표준내부통제기준")

    # 조항 4개 → 각 조가 짧아 조당 청크 1개, 총 4개.
    assert len(chunks) == 4
    assert [c["article"] for c in chunks] == ["제1조", "제10조", "제52조", "제77조"]

    for chunk in chunks:
        assert set(chunk) == REQUIRED_KEYS
        assert chunk["source"] == "KOFIA_표준내부통제기준"
        assert chunk["category"] is None
        assert chunk["chunk_id"].startswith("kofia_")
        assert chunk["text"]

    art52 = next(c for c in chunks if c["article"] == "제52조")
    assert art52["article_title"] == "정보교류 차단"
    assert art52["chunk_id"] == "kofia_52_0"


# --- 2. max_chars 초과 → 항 단위 분할 + 부모 조항번호 유지 --------------------


def test_long_article_splits_by_clause_keeping_article():
    source = "KOFIA_표준내부통제기준"

    # 임계값이 크면 한 조가 통째로 1개 청크로 유지된다.
    whole = chunker.chunk_articles(LONG_ARTICLE, source=source, max_chars=800)
    assert len(whole) == 1

    # 임계값을 넘기면 항(①②③) 단위로 분할된다 (3개 항 → 3개 청크).
    parts = chunker.chunk_articles(LONG_ARTICLE, source=source, max_chars=60)
    assert len(parts) == 3
    # 부모 조항번호·제목·category가 모든 분할 청크에서 동일하게 유지된다.
    assert {c["article"] for c in parts} == {"제99조"}
    assert {c["article_title"] for c in parts} == {"보고 절차"}
    assert all(c["category"] is None for c in parts)
    # chunk_id 서브인덱스가 0,1,2로 증가한다.
    assert [c["chunk_id"] for c in parts] == [f"kofia_99_{i}" for i in range(3)]
    # 각 항 마커가 순서대로 한 청크씩에 담긴다.
    assert [any(m in c["text"] for m in "①②③") for c in parts] == [True] * 3


# --- RRF 병합 순수 단위 테스트 (Ollama 불필요) -------------------------------


def test_reciprocal_rank_fusion_math_and_keys():
    vector_ranked = [{"chunk_id": "a"}, {"chunk_id": "b"}, {"chunk_id": "c"}]
    bm25_ranked = [{"chunk_id": "b"}, {"chunk_id": "a"}, {"chunk_id": "d"}]

    merged = reciprocal_rank_fusion([vector_ranked, bm25_ranked], top_k=3, rrf_k=60)

    assert len(merged) == 3
    # a,b는 두 리스트 모두 상위 → c,d보다 점수가 높다.
    top_ids = [m["chunk_id"] for m in merged[:2]]
    assert set(top_ids) == {"a", "b"}
    # 병합 결과에는 score 키가 붙는다.
    assert all("score" in m for m in merged)
    # a의 점수 = 1/(60+1) + 1/(60+2) 로 정확히 계산된다.
    a_score = next(m["score"] for m in merged if m["chunk_id"] == "a")
    assert a_score == pytest.approx(1 / 61 + 1 / 62)


# --- 3. build_index → search 가 예외 없이 돌고 의미상 근접 청크가 상위 --------


@requires_embedding
def test_pipeline_search_returns_relevant_chunk():
    from compliance.rag import pipeline

    chunks = chunker.chunk_articles(DUMMY_CORPUS, source="KOFIA_표준내부통제기준")
    pipeline.build_index(chunks, chroma_path=":memory:")

    results = pipeline.search("부서 간 정보 교류를 차단하는 규정", top_k=3)

    assert results, "검색 결과가 비어 있으면 안 된다"
    # 질의와 의미상 가장 가까운 정보교류 차단(제52조)이 최상위에 온다.
    assert results[0]["article"] == "제52조"


# --- 4. hybrid_search 반환 항목이 요구된 키를 모두 포함 -----------------------


@requires_embedding
def test_search_result_has_required_keys():
    from compliance.rag import pipeline

    chunks = chunker.chunk_articles(DUMMY_CORPUS, source="KOFIA_표준내부통제기준")
    pipeline.build_index(chunks, chroma_path=":memory:")

    results = pipeline.search("준법 교육", top_k=5)

    assert results
    for item in results:
        assert set(item) == REQUIRED_KEYS | {"score"}
        assert item["category"] is None
        assert isinstance(item["score"], float)
