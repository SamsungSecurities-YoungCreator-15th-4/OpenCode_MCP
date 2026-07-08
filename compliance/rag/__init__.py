"""check_disclosure_risk·search_compliance_rule 로직.

이 패키지는 두 층으로 구성된다.
- 이 __init__.py: mcp_server.py가 호출하는 tool 진입점.
- 하위 모듈(corpus/chunker/embedder/vector_store/hybrid_search/pipeline): RAG 파이프라인.
  무거운 의존성(chromadb 등)은 이 __init__.py에서 import하지 않는다 —
  mcp_server.py 기동 시 불필요하게 로드되지 않도록 소비 시점에만 import한다.

원칙: "위반/적법" 단정 판단은 하지 않는다 — 규정 근거 제시와
준법감시인 확인 필요 여부 안내까지만 수행한다.
"""

import json
import os
import re
from pathlib import Path

from compliance.schema import fail, ok

_DEFAULT_TOP_K = 5
_INDEX_MANIFEST = Path(os.environ.get("RAG_INDEX_MANIFEST", "data/chroma_manifest.json"))
_RISK_SIGNAL_PATTERNS = {
    "미공개/발표 전 정보": r"미공개|발표\s*전|공개\s*전|내부\s*자료|대외비|confidential",
    "실적/재무 전망": r"실적|매출|영업이익|순이익|손익|전망|가이던스|forecast",
    "투자권유/수익 표현": r"투자\s*권유|추천|목표가|수익률|원금\s*보장|확정\s*수익",
    "공시/중요 경영사항": r"공시|합병|분할|인수|증자|감자|배당|신규\s*사업",
    "개인/신용정보": r"개인정보|신용정보|주민등록|계좌|전화번호|이메일",
    "정보교류 차단": r"정보\s*교류|차단벽|chinese\s*wall",
}


def _ensure_ready() -> tuple[bool, str | None]:
    """로컬 코퍼스와 Chroma 인덱스를 준비한다."""
    try:
        from compliance.rag.corpus import corpus_fingerprint, load_corpus_chunks
        from compliance.rag import pipeline

        fingerprint = corpus_fingerprint()
        if not fingerprint["files"]:
            return False, "compliance/rag/data에 검색 가능한 코퍼스 문서가 없습니다."

        if _INDEX_MANIFEST.exists():
            try:
                current = json.loads(_INDEX_MANIFEST.read_text(encoding="utf-8"))
                if current.get("corpus") == fingerprint and pipeline.load_index():
                    return True, None
            except Exception:
                pass

        chunks = load_corpus_chunks()
        if not chunks:
            return False, "compliance/rag/data에 검색 가능한 코퍼스 문서가 없습니다."
        pipeline.build_index(chunks)
        _INDEX_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        _INDEX_MANIFEST.write_text(
            json.dumps({"corpus": fingerprint, "chunks": len(chunks)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True, None
    except Exception as exc:
        return False, str(exc)


def _snippet(text: str, limit: int = 260) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else f"{text[: limit - 1].rstrip()}…"


def _format_match(item: dict) -> dict:
    return {
        "source": item.get("source", ""),
        "file_name": item.get("file_name", ""),
        "article": item.get("article", ""),
        "article_title": item.get("article_title", ""),
        "chunk_id": item.get("chunk_id", ""),
        "snippet": _snippet(item.get("text", "")),
        "score": round(float(item.get("score", 0.0)), 6),
    }


def _search(query: str, top_k: int = _DEFAULT_TOP_K) -> list[dict]:
    from compliance.rag import pipeline

    return [_format_match(item) for item in pipeline.search(query, top_k=top_k)]


def _risk_signals(text: str) -> list[dict]:
    signals: list[dict] = []
    for label, pattern in _RISK_SIGNAL_PATTERNS.items():
        matched = sorted(set(re.findall(pattern, text, flags=re.IGNORECASE)))
        if matched:
            signals.append({"type": label, "matched_terms": matched[:5]})
    return signals


def check_disclosure_risk(text: str) -> dict:
    """로컬 RAG 근거로 대외 공유 전 확인 필요 신호를 점검한다."""
    ready, error = _ensure_ready()
    if not ready:
        return fail(
            "check_disclosure_risk",
            "규정 코퍼스 인덱스를 준비하지 못했습니다. 보수적으로 준법감시 확인이 필요합니다.",
            error or "unknown error",
        )

    signals = _risk_signals(text)
    query = text if text.strip() else "공시 위험 준법감시 사전확인"
    matches = _search(query, top_k=_DEFAULT_TOP_K)
    requires_review = bool(signals)

    if signals:
        signal_text = ", ".join(s["type"] for s in signals)
        summary = (
            f"공시/대외공유 관련 위험 신호가 감지되었습니다: {signal_text}. "
            "아래 규정 근거를 참고하되 최종 판단은 준법감시인이 확인해야 합니다."
        )
    else:
        summary = (
            "명시적인 위험 키워드는 탐지되지 않았습니다. "
            "다만 아래 검색 근거만으로 단정하지 말고 필요 시 준법감시 확인을 받으세요."
        )

    return ok(
        "check_disclosure_risk",
        summary,
        data={
            "mock": False,
            "risk_signals": signals,
            "matches": matches,
            "input_chars": len(text),
            "hallucination_guard": "응답은 로컬 코퍼스 검색 결과와 결정론 키워드 신호만 사용합니다.",
        },
        outputs=[
            f"{m['source']} {m['article']} {m['article_title']}: {m['snippet']}"
            for m in matches[:3]
        ],
        requires_human_review=requires_review,
    )


def search_compliance_rule(query: str) -> dict:
    """로컬 Chroma/BM25 하이브리드 검색으로 규정 근거를 반환한다."""
    ready, error = _ensure_ready()
    if not ready:
        return fail(
            "search_compliance_rule",
            "규정 코퍼스 인덱스를 준비하지 못했습니다.",
            error or "unknown error",
        )

    matches = _search(query, top_k=_DEFAULT_TOP_K)
    if matches:
        summary = f"로컬 규정 코퍼스에서 관련 근거 {len(matches)}건을 찾았습니다."
    else:
        summary = "로컬 규정 코퍼스에서 관련 근거를 찾지 못했습니다."

    return ok(
        "search_compliance_rule",
        summary,
        data={
            "mock": False,
            "query": query,
            "matches": matches,
            "embedding_model": "bge-m3",
            "vector_db": "Chroma",
            "hallucination_guard": "검색 결과 원문 snippet만 근거로 반환합니다.",
        },
        outputs=[
            f"{m['source']} {m['article']} {m['article_title']}: {m['snippet']}"
            for m in matches
        ],
    )
