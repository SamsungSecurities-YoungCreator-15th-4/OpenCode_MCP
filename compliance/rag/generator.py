"""로컬 qwen 기반 grounded answer 생성.

검색된 로컬 코퍼스 snippet만 근거로 자연어 답변을 만들기 위한 얇은 래퍼다.
외부 API는 사용하지 않고 Ollama 로컬 chat endpoint만 호출한다.
"""

from __future__ import annotations

import os
import re

import httpx

# embedder.py와 동일 사유: localhost→::1 선해석 폴백 왕복을 피해 IPv4로 고정.
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
CHAT_MODEL = os.environ.get("RAG_CHAT_MODEL", "qwen3-instruct-16k")
_TIMEOUT = float(os.environ.get("RAG_CHAT_TIMEOUT", "120"))
_MAX_EVIDENCE = int(os.environ.get("RAG_CHAT_MAX_EVIDENCE", "5"))
_MAX_SNIPPET_CHARS = int(os.environ.get("RAG_CHAT_MAX_SNIPPET_CHARS", "700"))


def _clean_answer(text: str) -> str:
    """qwen 계열이 thinking 태그를 내보내도 tool 응답에는 제거한다."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip()


def _evidence_block(matches: list[dict]) -> str:
    lines: list[str] = []
    for i, match in enumerate(matches[:_MAX_EVIDENCE], start=1):
        source = match.get("source") or match.get("file_name") or "unknown"
        article = " ".join(
            part
            for part in (match.get("article"), match.get("article_title"))
            if part
        )
        snippet = (match.get("snippet") or "")[:_MAX_SNIPPET_CHARS]
        lines.append(
            f"[{i}] source={source} article={article or '-'} snippet={snippet}"
        )
    return "\n".join(lines)


def generate_grounded_answer(
    *,
    task: str,
    query: str,
    matches: list[dict],
    risk_signals: list[dict] | None = None,
) -> str:
    """검색 근거와 위험 신호만 사용해 자연어 답변을 생성한다."""
    if not matches:
        return (
            "로컬 규정 코퍼스에서 답변에 사용할 근거를 찾지 못했습니다. "
            "추가 자료 확인 또는 준법감시인 검토가 필요합니다."
        )

    signal_line = ""
    if risk_signals is not None:
        signal_text = "없음"
        if risk_signals:
            signal_text = ", ".join(
                f"{signal['type']}({', '.join(signal.get('matched_terms', []))})"
                for signal in risk_signals
            )
        signal_line = f"위험 신호: {signal_text}\n"

    system = (
        "당신은 증권사 준법감시 사전확인 어시스턴트입니다. "
        "반드시 제공된 근거 snippet과 명시된 위험 신호만 사용하세요. "
        "근거에 없는 사실, 조항, 결론을 만들지 마세요. "
        "위반/적법 여부를 단정하지 말고 준법감시인 최종 확인 필요성을 안내하세요. "
        "답변은 한국어 3문장 이내로 작성하고, 문장 끝에 사용한 근거 번호를 [1] 형식으로 표시하세요."
    )
    user = (
        f"작업: {task}\n"
        f"사용자 입력: {query}\n"
        f"{signal_line}"
        "근거:\n"
        f"{_evidence_block(matches)}"
    )

    url = f"{OLLAMA_HOST}/api/chat"
    try:
        resp = httpx.post(
            url,
            json={
                "model": CHAT_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {
                    "temperature": 0,
                    "num_predict": 512,
                },
            },
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Ollama qwen 답변 생성 실패 (url={url}, model={CHAT_MODEL}): {exc}. "
            "`ollama serve` 기동과 qwen 모델 생성 여부를 확인하세요."
        ) from exc

    content = resp.json().get("message", {}).get("content", "")
    answer = _clean_answer(content)
    if not answer:
        raise RuntimeError("Ollama qwen 답변 생성 응답이 비어 있습니다.")
    return answer
