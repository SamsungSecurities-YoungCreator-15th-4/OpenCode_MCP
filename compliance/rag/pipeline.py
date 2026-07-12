"""RAG 파이프라인 상위 인터페이스 — 두 tool의 단일 진입점.

search_compliance_rule / check_disclosure_risk 는 이 모듈의
build_index() / search() 만 import해 사용한다. 하위 모듈
(chunker/embedder/vector_store/hybrid_search)의 조립을 여기서 감춘다.

실제 코퍼스 준비 후 흐름:
    chunks = chunker.chunk_articles(구조화_텍스트, source="KOFIA_...")
    pipeline.build_index(chunks)         # 임베딩 + Chroma 적재 + BM25 구성
    hits = pipeline.search("질의", top_k=5)
"""

from compliance.rag.hybrid_search import HybridSearcher
from compliance.rag.vector_store import VectorStore


class _Pipeline:
    def __init__(self) -> None:
        self._searcher: HybridSearcher | None = None
        self._chunk_count = 0

    def build_index(self, chunks: list[dict], chroma_path: str | None = None) -> None:
        """청크를 임베딩·Chroma 적재하고 BM25 인덱스를 구성한다.

        chroma_path=None이면 vector_store 기본 경로(data/chroma_0_6)를 쓴다.
        테스트에서는 ":memory:"를 넘겨 영속화 없이 인메모리로 돌린다.

        build_index는 "전체 재구성" 의미다 → reset=True로 기존 컬렉션을 비우고
        현재 chunks만 적재해, 벡터 저장소와 BM25 인덱스의 대상 청크를 일치시킨다.
        """
        vector_store = (
            VectorStore(reset=True)
            if chroma_path is None
            else VectorStore(path=chroma_path, reset=True)
        )
        vector_store.upsert_chunks(chunks)
        self._searcher = HybridSearcher(vector_store, chunks)
        self._chunk_count = len(chunks)

    def load_index(self, chroma_path: str | None = None) -> bool:
        """기존 Chroma 컬렉션이 있으면 BM25만 재구성해 로드한다."""
        vector_store = VectorStore() if chroma_path is None else VectorStore(path=chroma_path)
        chunks = vector_store.all_chunks()
        if not chunks:
            return False
        self._searcher = HybridSearcher(vector_store, chunks)
        self._chunk_count = len(chunks)
        return True

    def ensure_index(self, chunks: list[dict], chroma_path: str | None = None) -> None:
        """메모리에 검색기가 없으면 기존 Chroma를 재사용하거나 새로 구성한다."""
        if self._searcher is not None:
            return
        if self.load_index(chroma_path=chroma_path):
            return
        self.build_index(chunks, chroma_path=chroma_path)

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if self._searcher is None:
            raise RuntimeError(
                "인덱스가 없습니다. 먼저 build_index(chunks)를 호출하세요."
            )
        return self._searcher.search(query, top_k=top_k)


_pipeline = _Pipeline()


def build_index(chunks: list[dict], chroma_path: str | None = None) -> None:
    """모듈 전역 파이프라인에 인덱스를 구성한다(단일 진입점)."""
    _pipeline.build_index(chunks, chroma_path=chroma_path)


def load_index(chroma_path: str | None = None) -> bool:
    """영속 Chroma 인덱스를 전역 파이프라인에 로드한다."""
    return _pipeline.load_index(chroma_path=chroma_path)


def ensure_index(chunks: list[dict], chroma_path: str | None = None) -> None:
    """전역 파이프라인에 검색 인덱스가 없으면 준비한다."""
    _pipeline.ensure_index(chunks, chroma_path=chroma_path)


def search(query: str, top_k: int = 5) -> list[dict]:
    """구성된 인덱스에서 하이브리드 검색을 수행한다(단일 진입점)."""
    return _pipeline.search(query, top_k=top_k)
