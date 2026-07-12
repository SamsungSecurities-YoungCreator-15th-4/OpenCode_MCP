"""RAG 파이프라인 스모크 테스트 (더미 코퍼스, 실제 규정 문서 불필요).

- 청킹·메타데이터 테스트(1,2)는 순수 함수라 항상 실행된다.
- 임베딩이 필요한 테스트(3,4)는 Ollama 미기동 환경(CI)에서 자동 스킵된다.
- RRF 병합 로직은 Ollama 없이도 검증되도록 순수 단위 테스트를 별도로 둔다.
"""

import pytest

from compliance.rag import chunker, corpus, embedder
from compliance.rag.corpus import corpus_fingerprint, load_corpus_chunks
from compliance.rag.embedder import embed_texts
from compliance.rag.generator import _clean_answer
from compliance.rag.hybrid_search import reciprocal_rank_fusion
from compliance.rag.vector_store import _LOCAL_SETTINGS, _collection_names

# 미공개중요정보 8기준과 무관한 짧은 가짜 조항들(category는 항상 None로 남는다).
DUMMY_CORPUS = """
제1조(목적) 이 기준은 임직원의 직무수행에 필요한 기본 사항을 정함을 목적으로 한다.

제10조(용어의 정의) 이 기준에서 사용하는 용어의 뜻은 관계 법령이 정하는 바에 따른다.

제52조(정보교류 차단) 임직원은 부서 간 미공개 정보가 부당하게 교류되지 않도록
정보교류 차단장치를 성실히 준수하여야 한다.

제77조(교육) 회사는 임직원에게 정기적으로 준법 관련 교육을 실시하여야 한다.
""".strip()


def test_embed_texts_reuses_one_http_client_across_batches(monkeypatch):
    clients = []

    class FakeResponse:
        text = ""

        def __init__(self, batch):
            self._batch = batch

        def raise_for_status(self):
            return None

        def json(self):
            return {"embeddings": [[float(i)] for i, _ in enumerate(self._batch)]}

    class FakeClient:
        def __init__(self, *, timeout):
            self.timeout = timeout
            self.calls = []
            clients.append(self)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def post(self, url, *, json):
            self.calls.append((url, json))
            return FakeResponse(json["input"])

    monkeypatch.setattr(embedder.httpx, "Client", FakeClient)

    result = embedder.embed_texts(["a", "b", "c"], batch_size=2)

    assert len(clients) == 1
    assert len(clients[0].calls) == 2
    assert len(result) == 3


def test_clean_answer_removes_closed_thinking_block():
    assert _clean_answer("<think>내부 추론</think> 최종 답변") == "최종 답변"


def test_clean_answer_discards_unclosed_thinking_tail():
    assert _clean_answer("안전한 앞부분 <THINK>노출되면 안 되는 내부 추론") == "안전한 앞부분"


def test_clean_answer_removes_multiple_thinking_blocks():
    text = "<think>첫 추론</think> 첫 답변 <THINK>둘째 추론</THINK> 둘째 답변"
    assert _clean_answer(text) == "첫 답변 둘째 답변"


def test_corpus_loading_fails_closed_when_a_source_is_unreadable(
    tmp_path, monkeypatch
):
    (tmp_path / "broken.txt").write_text("규정 원문", encoding="utf-8")

    def fail_read(_):
        raise RuntimeError("corrupted source")

    monkeypatch.setattr(corpus, "load_document_text", fail_read)

    with pytest.raises(RuntimeError, match="corrupted source"):
        corpus.load_corpus_chunks(tmp_path)

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


def _check_embedding_or_skip() -> None:
    """임베딩 가능 여부를 '테스트 실행 시점에' 확인해 불가하면 스킵한다.

    skipif 데코레이터로 수집(collection) 단계에서 Ollama에 붙으면 무관한 테스트
    실행 때도 전체 수집이 지연될 수 있어, 함수 내부에서 동적으로 확인한다.
    Ollama 미기동뿐 아니라 bge-m3 모델 미설치까지 모두 '불가'로 보고 스킵한다.
    """
    try:
        if len(embed_texts(["ping"])) == 1:
            return
    except Exception:
        pass
    pytest.skip("bge-m3 임베딩 불가 (Ollama 미기동 또는 모델 미설치) — 스킵")


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

    # 임계값을 넘기면 항(①②③) 단위로 여러 청크로 분할된다.
    parts = chunker.chunk_articles(LONG_ARTICLE, source=source, max_chars=60)
    assert len(parts) >= 3
    # 부모 조항번호·제목·category가 모든 분할 청크에서 동일하게 유지된다.
    assert {c["article"] for c in parts} == {"제99조"}
    assert {c["article_title"] for c in parts} == {"보고 절차"}
    assert all(c["category"] is None for c in parts)
    # chunk_id 서브인덱스가 0,1,2...로 순차 증가한다.
    assert [c["chunk_id"] for c in parts] == [
        f"kofia_99_{i}" for i in range(len(parts))
    ]
    # 분할 후 어떤 청크도 max_chars를 넘지 않는다.
    assert all(len(c["text"]) <= 60 for c in parts)


def test_plain_text_chunking_uses_stable_unique_ids_for_korean_source():
    chunks = chunker.chunk_plain_text(
        "조항 헤더가 없는 안내문입니다. " * 20,
        source="표준투자권유준칙",
        max_chars=100,
        overlap=20,
    )

    assert len(chunks) > 1
    assert len({c["chunk_id"] for c in chunks}) == len(chunks)
    assert all(c["source"] == "표준투자권유준칙" for c in chunks)
    assert all(c["article"] == "" for c in chunks)


def test_plain_text_chunking_advances_when_overlap_reaches_boundary():
    text = ("가" * 110) + ". " + ("나" * 300)

    chunks = chunker.chunk_plain_text(
        text,
        source="plain_rules",
        max_chars=200,
        overlap=150,
    )

    assert 1 < len(chunks) < 10
    assert len({c["chunk_id"] for c in chunks}) == len(chunks)


def test_corpus_loader_supports_text_files(tmp_path):
    corpus_dir = tmp_path / "data"
    corpus_dir.mkdir()
    (corpus_dir / "01_rules.txt").write_text(
        "제1조(목적) 준법감시 사전확인을 정한다.\n"
        "제2조(광고) 투자광고는 준법감시인의 확인을 받는다.",
        encoding="utf-8",
    )

    chunks = load_corpus_chunks(corpus_dir)
    fingerprint = corpus_fingerprint(corpus_dir)

    assert [c["article"] for c in chunks] == ["제1조", "제2조"]
    assert all(c["file_name"] == "01_rules.txt" for c in chunks)
    assert fingerprint["files"][0]["name"] == "01_rules.txt"


# --- RRF 병합 순수 단위 테스트 (Ollama 불필요) -------------------------------


def test_reciprocal_rank_fusion_math_and_keys():
    vector_ranked = [
        {"chunk_id": "a", "vector_similarity": 0.9, "vector_distance": 0.1},
        {"chunk_id": "b", "vector_similarity": 0.8, "vector_distance": 0.2},
        {"chunk_id": "c", "vector_similarity": 0.7, "vector_distance": 0.3},
    ]
    bm25_ranked = [{"chunk_id": "b"}, {"chunk_id": "a"}, {"chunk_id": "d"}]

    merged = reciprocal_rank_fusion([vector_ranked, bm25_ranked], top_k=3, rrf_k=60)

    assert len(merged) == 3
    # a,b는 두 리스트 모두 상위 → c,d보다 점수가 높다.
    top_ids = [m["chunk_id"] for m in merged[:2]]
    assert set(top_ids) == {"a", "b"}
    # 병합 결과에는 score 키가 붙는다.
    assert all("score" in m for m in merged)
    assert next(m for m in merged if m["chunk_id"] == "a")["vector_similarity"] == 0.9
    # a의 점수 = 1/(60+1) + 1/(60+2) 로 정확히 계산된다.
    a_score = next(m["score"] for m in merged if m["chunk_id"] == "a")
    assert a_score == pytest.approx(1 / 61 + 1 / 62)


# --- 3. build_index → search 가 예외 없이 돌고 의미상 근접 청크가 상위 --------


def test_pipeline_search_returns_relevant_chunk():
    _check_embedding_or_skip()
    from compliance.rag import pipeline

    chunks = chunker.chunk_articles(DUMMY_CORPUS, source="KOFIA_표준내부통제기준")
    pipeline.build_index(chunks, chroma_path=":memory:")

    results = pipeline.search("부서 간 정보 교류를 차단하는 규정", top_k=3)

    assert results, "검색 결과가 비어 있으면 안 된다"
    # 질의와 의미상 가장 가까운 정보교류 차단(제52조)이 최상위에 온다.
    assert results[0]["article"] == "제52조"


# --- 재구성(build_index) 시 영속 컬렉션이 초기화되는지 (하이브리드 정합성) -----


def test_rebuild_resets_persistent_collection(tmp_path):
    _check_embedding_or_skip()
    from compliance.rag.vector_store import VectorStore

    corpus_a = chunker.chunk_articles("제1조(옛 조항) 폐기될 이전 코퍼스 내용.", source="DOC_A")
    corpus_b = chunker.chunk_articles(
        "제52조(정보교류 차단) 부서 간 정보 교류를 차단한다.", source="DOC_B"
    )
    path = str(tmp_path / "chroma")

    VectorStore(path=path, reset=True).upsert_chunks(corpus_a)
    store = VectorStore(path=path, reset=True)  # 재구성 → A는 비워져야 한다
    store.upsert_chunks(corpus_b)

    hits = store.vector_search("조항", top_k=10)
    # 과거 코퍼스 A의 청크는 남지 않고 B만 검색된다.
    assert {h["chunk_id"] for h in hits} == {c["chunk_id"] for c in corpus_b}


def test_vector_search_tolerates_none_distances(monkeypatch):
    from compliance.rag.vector_store import VectorStore

    class FakeCollection:
        def count(self):
            return 1

        def query(self, query_embeddings, n_results, include):
            return {
                "ids": [["chunk-1"]],
                "documents": [["제1조(목적) 테스트 조항입니다."]],
                "metadatas": [[{"article": "제1조", "chunk_id": "chunk-1"}]],
                "distances": None,
            }

    monkeypatch.setattr("compliance.rag.embedder.embed_texts", lambda texts: [[0.0]])
    store = VectorStore.__new__(VectorStore)
    store._collection = FakeCollection()

    hits = store.vector_search("테스트", top_k=1)

    assert hits[0]["chunk_id"] == "chunk-1"
    assert "vector_distance" not in hits[0]
    assert "vector_similarity" not in hits[0]


def test_collection_names_supports_chroma_0_6_and_1_x_results():
    """0.6은 문자열, 1.x는 Collection 객체를 반환하므로 둘 다 지원한다."""

    class CollectionObject:
        name = "from-object"

    class FakeClient:
        def list_collections(self):
            return ["from-string", CollectionObject()]

    assert _collection_names(FakeClient()) == {"from-string", "from-object"}


def test_chroma_anonymized_telemetry_is_disabled():
    assert _LOCAL_SETTINGS.anonymized_telemetry is False


# --- 4. hybrid_search 반환 항목이 요구된 키를 모두 포함 -----------------------


def test_search_result_has_required_keys():
    _check_embedding_or_skip()
    from compliance.rag import pipeline

    chunks = chunker.chunk_articles(DUMMY_CORPUS, source="KOFIA_표준내부통제기준")
    pipeline.build_index(chunks, chroma_path=":memory:")

    results = pipeline.search("준법 교육", top_k=5)

    assert results
    for item in results:
        assert set(item) == REQUIRED_KEYS | {
            "score",
            "vector_distance",
            "vector_similarity",
        }
        assert item["category"] is None
        assert isinstance(item["score"], float)
        assert isinstance(item["vector_distance"], float)
        assert isinstance(item["vector_similarity"], float)
