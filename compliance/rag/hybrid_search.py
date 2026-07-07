"""하이브리드 검색: 벡터(bge-m3/Chroma) + BM25 → RRF 병합.

두 검색기를 각각 독립 순위화한 뒤 Reciprocal Rank Fusion으로 병합한다.
    score(d) = Σ 1 / (rrf_k + rank_i(d)),  rank는 1부터, rrf_k 기본 60

BM25 인덱스와 벡터 저장소는 상태를 가지므로, 파이프라인이 구성한 컴포넌트를
주입받는 HybridSearcher로 캡슐화한다(청크 리스트는 BM25 결과를 메타데이터로
되돌리는 데 쓰인다).
"""

import re

from rank_bm25 import BM25Okapi

# 형태소 분석기 없이 한글/영숫자 토큰만 추출하는 단순 토크나이저(스켈레톤 수준).
_TOKEN_RE = re.compile(r"[가-힣]+|[A-Za-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def reciprocal_rank_fusion(
    ranked_lists: list[list[dict]], top_k: int, rrf_k: int = 60
) -> list[dict]:
    """chunk_id 기준으로 여러 순위 리스트를 RRF 병합해 상위 top_k를 반환한다."""
    scores: dict[str, float] = {}
    items: dict[str, dict] = {}
    for ranked in ranked_lists:
        for rank, item in enumerate(ranked, start=1):
            cid = item["chunk_id"]
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (rrf_k + rank)
            items.setdefault(cid, item)

    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
    merged: list[dict] = []
    for cid, score in ordered:
        item = dict(items[cid])
        item["score"] = score
        merged.append(item)
    return merged


class HybridSearcher:
    """벡터 검색기 + BM25 인덱스를 묶어 하이브리드 검색을 수행한다."""

    def __init__(self, vector_store, chunks: list[dict]):
        self._vector_store = vector_store
        self._chunks = chunks
        self._bm25 = (
            BM25Okapi([_tokenize(c["text"]) for c in chunks]) if chunks else None
        )

    def _bm25_search(self, query: str, top_k: int) -> list[dict]:
        if self._bm25 is None:
            return []
        scores = self._bm25.get_scores(_tokenize(query))
        ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return [self._chunks[i] for i in ranked[:top_k] if scores[i] > 0]

    def search(self, query: str, top_k: int = 5, rrf_k: int = 60) -> list[dict]:
        """벡터·BM25 결과를 RRF로 병합해 상위 top_k 청크를 반환한다.

        각 항목: {text, source, article, article_title, chunk_id, category, score}.
        병합 전 각 검색기는 여유 있게(top_k, 10 중 큰 값) 후보를 뽑는다.
        """
        pool = max(top_k, 10)
        vector_hits = self._vector_store.vector_search(query, top_k=pool)
        bm25_hits = self._bm25_search(query, top_k=pool)
        return reciprocal_rank_fusion([vector_hits, bm25_hits], top_k, rrf_k)
