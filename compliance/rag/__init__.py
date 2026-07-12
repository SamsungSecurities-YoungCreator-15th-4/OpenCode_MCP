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
DEFAULT_VECTOR_SIMILARITY_THRESHOLD = float(
    os.environ.get("RAG_VECTOR_SIMILARITY_THRESHOLD", "0.49")
)
_INDEX_MANIFEST = Path(os.environ.get("RAG_INDEX_MANIFEST", "data/chroma_manifest.json"))
_GENERATE_ANSWER = os.environ.get("RAG_GENERATE_ANSWER", "1").lower() not in {
    "0",
    "false",
    "no",
}
_RISK_SIGNAL_PATTERNS = {
    "미공개/발표 전 정보": r"미공개|발표\s*전|공개\s*전|내부\s*자료|대외비|confidential",
    "실적/재무 전망": r"실적|매출|영업이익|순이익|손익|전망|가이던스|forecast",
    "투자·출자/M&A": r"투자\s*계획|신규\s*투자|시설\s*투자|출자|타법인|지분\s*취득|합병|분할|인수|m&a|유상\s*증자|증자|감자|신규\s*사업",
    "회계 관련": r"회계|회계\s*처리|재무제표|감사\s*의견|분식|충당금|손상",
    "투자권유/수익 표현": (
        r"투자\s*권유|추천|목표가|"
        r"(?:수익|수익률|이자)\s*(?:확정|보장)|"
        r"수익률|"
        r"원금\s*(?:보장|보전|보호)|"
        r"(?:확정|보장)\s*(?:수익|수익률|이자)|"
        r"무손실|손실\s*(?:이\s*|은\s*)?(?:없음|제로)|"
        r"무위험|위험\s*(?:이\s*|은\s*)?(?:없음|제로)|"
        r"(?:안정적\s*)?고수익|"
        r"(?:무조건|반드시)\s*수익"
    ),
    "공시/중요 경영사항": r"공시|합병|분할|인수|증자|감자|배당|신규\s*사업",
    "개인/신용정보": r"개인정보|신용정보|주민등록|계좌|전화번호|이메일",
    "정보교류 차단": r"정보\s*교류|차단벽|chinese\s*wall",
}
_CRITERIA_SIGNAL_MAP = {
    "1호": {"name": "재무구조", "signals": {"실적/재무 전망"}},
    "2호": {"name": "", "signals": set()},
    "3호": {"name": "", "signals": set()},
    "4호": {"name": "", "signals": set()},
    "5호": {"name": "투자·출자", "signals": {"투자·출자/M&A"}},
    "6호": {"name": "손익구조", "signals": {"실적/재무 전망"}},
    "7호": {"name": "회계처리", "signals": {"회계 관련"}},
    "8호": {"name": "", "signals": set()},
}
_ARTICLE_RE = re.compile(r"제\s*(\d+)\s*조(?:\s*의\s*(\d+))?")
_REVIEW_RE = re.compile(
    r"준법감시(?:인|부서)?\s*(?:의\s*)?(?:확인|검토)|"
    r"사전\s*확인|확인(?:이|가)?\s*필요|검토(?:가)?\s*필요|"
    r"위험\s*신호|공시\s*위험",
    flags=re.IGNORECASE,
)


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
    match = {
        "source": item.get("source", ""),
        "file_name": item.get("file_name", ""),
        "article": item.get("article", ""),
        "article_title": item.get("article_title", ""),
        "chunk_id": item.get("chunk_id", ""),
        "snippet": _snippet(item.get("text", "")),
        "score": round(float(item.get("score", 0.0)), 6),
    }
    if item.get("vector_distance") is not None:
        match["vector_distance"] = round(float(item["vector_distance"]), 6)
    if item.get("vector_similarity") is not None:
        match["vector_similarity"] = round(float(item["vector_similarity"]), 6)
    return match


def _search(query: str, top_k: int = _DEFAULT_TOP_K) -> list[dict]:
    from compliance.rag import pipeline

    return [_format_match(item) for item in pipeline.search(query, top_k=top_k)]


def _generate_answer(
    task: str,
    query: str,
    matches: list[dict],
    risk_signals: list[dict] | None = None,
) -> tuple[str | None, dict]:
    if not _GENERATE_ANSWER:
        return None, {"enabled": False, "model": None, "error": None}

    from compliance.rag.generator import CHAT_MODEL, generate_grounded_answer

    try:
        answer = generate_grounded_answer(
            task=task,
            query=query,
            matches=matches,
            risk_signals=risk_signals,
        )
        return answer, {"enabled": True, "model": CHAT_MODEL, "error": None}
    except Exception as exc:
        return None, {"enabled": True, "model": CHAT_MODEL, "error": str(exc)}


def _skipped_generation(reason: str) -> dict:
    return {"enabled": _GENERATE_ANSWER, "model": None, "error": None, "skipped": reason}


def _risk_signals(text: str) -> list[dict]:
    signals: list[dict] = []
    for label, pattern in _RISK_SIGNAL_PATTERNS.items():
        matched = sorted(set(re.findall(pattern, text, flags=re.IGNORECASE)))
        if matched:
            signals.append({"type": label, "matched_terms": matched[:5]})
    return signals


def _matched_criteria(signals: list[dict]) -> list[dict]:
    signal_types = {signal["type"] for signal in signals}
    matched: list[dict] = []
    for criterion_no, definition in _CRITERIA_SIGNAL_MAP.items():
        triggered = sorted(signal_types & definition["signals"])
        if triggered:
            matched.append(
                {
                    "criterion_no": criterion_no,
                    "name": definition["name"],
                    "triggered_signals": triggered,
                }
            )
    return matched


def _retrieval_confidence(matches: list[dict]) -> dict:
    scored = [
        match
        for match in matches
        if match.get("vector_similarity") is not None
    ]
    best = max(
        scored,
        key=lambda match: float(match.get("vector_similarity", float("-inf"))),
        default=None,
    )
    best_similarity = None
    best_distance = None
    if best is not None:
        best_similarity = float(best["vector_similarity"])
        if best.get("vector_distance") is not None:
            best_distance = float(best["vector_distance"])
    return {
        "metric": "vector_similarity",
        "threshold": DEFAULT_VECTOR_SIMILARITY_THRESHOLD,
        "best_vector_similarity": best_similarity,
        "best_vector_distance": best_distance,
        "threshold_passed": (
            best_similarity is not None
            and best_similarity >= DEFAULT_VECTOR_SIMILARITY_THRESHOLD
        ),
    }


def _normalize_article(value: str) -> str | None:
    match = _ARTICLE_RE.search(value or "")
    if not match:
        return None
    suffix = f"의{match.group(2)}" if match.group(2) else ""
    return f"제{match.group(1)}조{suffix}"


def _extract_cited_articles(answer: str | None) -> list[str]:
    if not answer:
        return []
    articles = []
    for match in _ARTICLE_RE.finditer(answer):
        suffix = f"의{match.group(2)}" if match.group(2) else ""
        articles.append(f"제{match.group(1)}조{suffix}")
    return list(dict.fromkeys(articles))


def _verify_citations(answer: str | None, matches: list[dict]) -> dict:
    cited_articles = _extract_cited_articles(answer)
    available_articles = {
        article
        for article in (_normalize_article(match.get("article", "")) for match in matches)
        if article
    }
    unsupported = [
        article for article in cited_articles if article not in available_articles
    ]
    return {
        "citation_verified": not unsupported,
        "cited_articles": cited_articles,
        "unsupported_cited_articles": unsupported,
        "available_articles": sorted(available_articles),
    }


def _discard_unsupported_answer(
    answer: str | None, generation: dict, citation: dict
) -> tuple[str | None, dict]:
    if answer and not citation["citation_verified"]:
        generation = dict(generation)
        generation["discarded"] = True
        generation["discard_reason"] = "unsupported_article_citation"
        generation["unsupported_cited_articles"] = citation["unsupported_cited_articles"]
        return None, generation
    return answer, generation


def _answer_requests_human_review(answer: str | None) -> bool:
    return bool(answer and _REVIEW_RE.search(answer))


def _disclosure_fallback_summary(signals: list[dict]) -> str:
    if signals:
        signal_text = ", ".join(s["type"] for s in signals)
        return (
            f"공시/대외공유 관련 위험 신호가 감지되었습니다: {signal_text}. "
            "아래 규정 근거를 참고하되 최종 판단은 준법감시인이 확인해야 합니다."
        )
    return (
        "명시적인 위험 키워드는 탐지되지 않았습니다. "
        "검색된 규정 근거를 함께 확인해 보수적으로 판단하세요."
    )


def _no_reliable_evidence_summary(requires_review: bool) -> str:
    suffix = ""
    if requires_review:
        suffix = " 근거를 찾지 못한 것은 안전하다는 뜻이 아니므로 준법감시인 확인이 필요합니다."
    return f"관련 규정을 찾지 못했습니다.{suffix}"


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
    matched_criteria = _matched_criteria(signals)
    query = text if text.strip() else "공시 위험 준법감시 사전확인"
    raw_matches = _search(query, top_k=_DEFAULT_TOP_K)
    confidence = _retrieval_confidence(raw_matches)
    threshold_passed = confidence["threshold_passed"]
    if not threshold_passed:
        return ok(
            "check_disclosure_risk",
            _no_reliable_evidence_summary(requires_review=True),
            data={
                "mock": False,
                "risk_signals": signals,
                "matched_criteria": matched_criteria,
                "matches": [],
                "input_chars": len(text),
                "answer": None,
                "answer_generation": _skipped_generation("retrieval_threshold_not_passed"),
                "threshold_passed": False,
                "retrieval_confidence": confidence,
                "citation_verified": True,
                "cited_articles": [],
                "hallucination_guard": "벡터 유사도 임계값 미달 시 근거와 생성 답변을 반환하지 않습니다.",
            },
            outputs=[],
            requires_human_review=True,
        )

    matches = raw_matches
    answer, generation = _generate_answer(
        "대외 공유 전 공시/준법 위험 신호를 점검하고 근거 기반으로 안내",
        query,
        matches,
        risk_signals=signals,
    )
    citation = _verify_citations(answer, matches)
    answer, generation = _discard_unsupported_answer(answer, generation, citation)

    summary = answer or _disclosure_fallback_summary(signals)
    requires_review = (
        bool(signals)
        or not citation["citation_verified"]
        or _answer_requests_human_review(answer)
    )

    return ok(
        "check_disclosure_risk",
        summary,
        data={
            "mock": False,
            "risk_signals": signals,
            "matched_criteria": matched_criteria,
            "matches": matches,
            "input_chars": len(text),
            "answer": answer,
            "answer_generation": generation,
            "threshold_passed": True,
            "retrieval_confidence": confidence,
            "citation_verified": citation["citation_verified"],
            "cited_articles": citation["cited_articles"],
            "hallucination_guard": "qwen 답변은 로컬 코퍼스 검색 결과와 결정론 키워드 신호만 근거로 생성합니다.",
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
    confidence = _retrieval_confidence(matches)
    threshold_passed = confidence["threshold_passed"]
    if not threshold_passed:
        return ok(
            "search_compliance_rule",
            _no_reliable_evidence_summary(requires_review=False),
            data={
                "mock": False,
                "query": query,
                "matches": [],
                "answer": None,
                "answer_generation": _skipped_generation("retrieval_threshold_not_passed"),
                "embedding_model": "bge-m3",
                "vector_db": "Chroma",
                "threshold_passed": False,
                "retrieval_confidence": confidence,
                "citation_verified": True,
                "cited_articles": [],
                "hallucination_guard": "벡터 유사도 임계값 미달 시 근거와 생성 답변을 반환하지 않습니다.",
            },
            outputs=[],
        )

    answer, generation = _generate_answer(
        "준법 규정 질의에 대해 검색 근거만 사용해 답변",
        query,
        matches,
    )
    citation = _verify_citations(answer, matches)
    answer, generation = _discard_unsupported_answer(answer, generation, citation)
    if answer:
        summary = answer
    elif matches:
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
            "answer": answer,
            "answer_generation": generation,
            "embedding_model": "bge-m3",
            "vector_db": "Chroma",
            "threshold_passed": True,
            "retrieval_confidence": confidence,
            "citation_verified": citation["citation_verified"],
            "cited_articles": citation["cited_articles"],
            "hallucination_guard": "qwen 답변은 검색 결과 원문 snippet만 근거로 생성합니다.",
        },
        outputs=[
            f"{m['source']} {m['article']} {m['article_title']}: {m['snippet']}"
            for m in matches
        ],
    )
