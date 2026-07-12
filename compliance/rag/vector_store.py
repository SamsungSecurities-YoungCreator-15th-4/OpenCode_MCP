"""Chroma 벡터 저장소 래퍼.

임베딩은 embedder(bge-m3/Ollama)로 우리가 직접 만들어 넣는다 →
Chroma 기본 임베딩 함수(외부 모델 다운로드)를 쓰지 않는다(폐쇄망).

저장 경로 기본값은 data/chroma_0_6/. 경로가 None 또는 ":memory:"이면
영속화 없이 인메모리(EphemeralClient)로 동작한다(테스트용).
"""

import os

import chromadb
from chromadb.config import Settings

# Chroma 1.x 인덱스는 0.6.3과 역호환되지 않는다. CVE-2026-45829 대응으로
# 0.6.3을 사용하므로 기존 data/chroma와 분리해 첫 검색 때 안전하게 재구성한다.
DEFAULT_PATH = os.environ.get("CHROMA_PATH", "data/chroma_0_6")
COLLECTION = "compliance_rules"
_LOCAL_SETTINGS = Settings(anonymized_telemetry=False)

# Chroma 메타데이터 값은 None을 허용하지 않으므로 category=None은 ""로 저장하고
# 조회 시 다시 None으로 복원한다.
_META_KEYS = ("source", "article", "article_title", "chunk_id", "category", "file_name")


def _cosine_similarity(distance: float) -> float:
    """Chroma cosine distance를 사람이 해석하기 쉬운 유사도로 변환한다."""
    return max(-1.0, min(1.0, 1.0 - distance))


def _collection_names(client) -> set[str]:
    """Chroma 0.6의 문자열과 1.x의 Collection 반환을 모두 이름으로 정규화한다."""
    return {
        item if isinstance(item, str) else getattr(item, "name", str(item))
        for item in client.list_collections()
    }


def _to_meta(chunk: dict) -> dict:
    meta = {}
    for key in _META_KEYS:
        value = chunk.get(key)
        meta[key] = "" if value is None else value
    return meta


def _from_meta(document: str, meta: dict | None, fallback_id: str) -> dict:
    meta = meta or {}  # Chroma가 메타데이터 없이 None을 돌려줘도 안전하게.
    chunk = {
        "text": document,
        "source": meta.get("source", ""),
        "article": meta.get("article", ""),
        "article_title": meta.get("article_title", ""),
        "chunk_id": meta.get("chunk_id") or fallback_id,
        "category": meta.get("category") or None,
    }
    if meta.get("file_name"):
        chunk["file_name"] = meta["file_name"]
    return chunk


class VectorStore:
    """Chroma persistent(또는 인메모리) 컬렉션 래퍼."""

    def __init__(
        self,
        path: str | None = DEFAULT_PATH,
        collection: str = COLLECTION,
        reset: bool = False,
    ):
        if path in (None, ":memory:"):
            client = chromadb.EphemeralClient(settings=_LOCAL_SETTINGS)
        else:
            client = chromadb.PersistentClient(path=path, settings=_LOCAL_SETTINGS)
        # reset=True면 기존 컬렉션을 지우고 새로 만든다 — 영속 저장소에 과거 청크가
        # 남아 BM25 인덱스(현재 청크만)와 어긋나는 하이브리드 검색 불일치를 방지.
        if reset and collection in _collection_names(client):
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

    def count(self) -> int:
        """컬렉션에 저장된 청크 수를 반환한다."""
        return self._collection.count()

    def all_chunks(self) -> list[dict]:
        """영속 컬렉션에서 BM25 재구성용 청크를 읽어온다."""
        if self._collection.count() == 0:
            return []
        result = self._collection.get(include=["documents", "metadatas"])
        ids = result.get("ids", [])
        documents = result.get("documents", [])
        metadatas = result.get("metadatas", [])
        return [
            _from_meta(documents[i], metadatas[i], ids[i]) for i in range(len(ids))
        ]

    def vector_search(self, query: str, top_k: int) -> list[dict]:
        """질의를 임베딩해 유사 청크를 메타데이터 포함으로 반환한다(순위순)."""
        if self._collection.count() == 0:
            return []  # 빈 컬렉션이면 불필요한 임베딩 호출 없이 즉시 반환.
        from compliance.rag.embedder import embed_texts

        result = self._collection.query(
            query_embeddings=[embed_texts([query])[0]],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )
        ids = result["ids"][0]
        documents = result["documents"][0]
        metadatas = result["metadatas"][0]
        distances_list = result.get("distances")
        distances = distances_list[0] if distances_list else []
        hits = []
        for i in range(len(ids)):
            item = _from_meta(documents[i], metadatas[i], ids[i])
            if i < len(distances):
                distance = float(distances[i])
                item["vector_distance"] = distance
                item["vector_similarity"] = _cosine_similarity(distance)
            hits.append(item)
        return hits
