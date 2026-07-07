"""Chroma 벡터 저장소 래퍼.

임베딩은 embedder(bge-m3/Ollama)로 우리가 직접 만들어 넣는다 →
Chroma 기본 임베딩 함수(외부 모델 다운로드)를 쓰지 않는다(폐쇄망).

저장 경로 기본값은 data/chroma/. 경로가 None 또는 ":memory:"이면
영속화 없이 인메모리(EphemeralClient)로 동작한다(테스트용).
"""

import os

import chromadb

DEFAULT_PATH = os.environ.get("CHROMA_PATH", "data/chroma")
COLLECTION = "compliance_rules"

# Chroma 메타데이터 값은 None을 허용하지 않으므로 category=None은 ""로 저장하고
# 조회 시 다시 None으로 복원한다.
_META_KEYS = ("source", "article", "article_title", "chunk_id", "category")


def _to_meta(chunk: dict) -> dict:
    meta = {}
    for key in _META_KEYS:
        value = chunk.get(key)
        meta[key] = "" if value is None else value
    return meta


def _from_meta(document: str, meta: dict | None, fallback_id: str) -> dict:
    meta = meta or {}  # Chroma가 메타데이터 없이 None을 돌려줘도 안전하게.
    return {
        "text": document,
        "source": meta.get("source", ""),
        "article": meta.get("article", ""),
        "article_title": meta.get("article_title", ""),
        "chunk_id": meta.get("chunk_id") or fallback_id,
        "category": meta.get("category") or None,
    }


class VectorStore:
    """Chroma persistent(또는 인메모리) 컬렉션 래퍼."""

    def __init__(
        self,
        path: str | None = DEFAULT_PATH,
        collection: str = COLLECTION,
        reset: bool = False,
    ):
        if path in (None, ":memory:"):
            client = chromadb.EphemeralClient()
        else:
            client = chromadb.PersistentClient(path=path)
        # reset=True면 기존 컬렉션을 지우고 새로 만든다 — 영속 저장소에 과거 청크가
        # 남아 BM25 인덱스(현재 청크만)와 어긋나는 하이브리드 검색 불일치를 방지.
        if reset and collection in {c.name for c in client.list_collections()}:
            client.delete_collection(name=collection)
        self._collection = client.get_or_create_collection(
            name=collection, metadata={"hnsw:space": "cosine"}
        )

    def upsert_chunks(self, chunks: list[dict]) -> int:
        """청크를 임베딩해 컬렉션에 upsert하고 적재 건수를 반환한다."""
        if not chunks:
            return 0
        from compliance.rag.embedder import embed_texts

        texts = [c["text"] for c in chunks]
        self._collection.upsert(
            ids=[c["chunk_id"] for c in chunks],
            embeddings=embed_texts(texts),
            documents=texts,
            metadatas=[_to_meta(c) for c in chunks],
        )
        return len(chunks)

    def vector_search(self, query: str, top_k: int) -> list[dict]:
        """질의를 임베딩해 유사 청크를 메타데이터 포함으로 반환한다(순위순)."""
        if self._collection.count() == 0:
            return []  # 빈 컬렉션이면 불필요한 임베딩 호출 없이 즉시 반환.
        from compliance.rag.embedder import embed_texts

        result = self._collection.query(
            query_embeddings=[embed_texts([query])[0]], n_results=top_k
        )
        ids = result["ids"][0]
        documents = result["documents"][0]
        metadatas = result["metadatas"][0]
        return [
            _from_meta(documents[i], metadatas[i], ids[i]) for i in range(len(ids))
        ]
