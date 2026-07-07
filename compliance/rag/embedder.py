"""bge-m3 임베딩 — 로컬 Ollama 경유.

폐쇄망 대비: 임베딩 벡터는 로컬 Ollama(localhost:11434)의 임베딩 엔드포인트로만
얻는다. 모델은 사전 `ollama pull bge-m3`로 받아두며, HuggingFace 등 외부에서
가중치를 내려받는 경로가 전혀 없다(외부 API 호출 금지 제약 충족).
"""

import os

import httpx

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
EMBED_MODEL = os.environ.get("BGE_M3_MODEL", "bge-m3")
_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "120"))
# 대량 코퍼스를 단일 요청으로 보내면 타임아웃·OOM 위험이 있어 배치로 나눠 호출한다.
_BATCH_SIZE = int(os.environ.get("EMBED_BATCH_SIZE", "32"))


def _embed_batch(batch: list[str]) -> list[list[float]]:
    url = f"{OLLAMA_HOST}/api/embed"
    try:
        resp = httpx.post(
            url, json={"model": EMBED_MODEL, "input": batch}, timeout=_TIMEOUT
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Ollama 임베딩 호출 실패 (url={url}, model={EMBED_MODEL}): {exc}. "
            f"`ollama serve` 기동과 `ollama pull {EMBED_MODEL}` 여부를 확인하세요."
        ) from exc

    embeddings = resp.json().get("embeddings")
    if not isinstance(embeddings, list) or len(embeddings) != len(batch):
        raise RuntimeError(
            f"Ollama 임베딩 응답이 비정상입니다 (요청 {len(batch)}건, "
            f"응답 {0 if not embeddings else len(embeddings)}건): {resp.text[:200]}"
        )
    return embeddings


def embed_texts(texts: list[str], batch_size: int = _BATCH_SIZE) -> list[list[float]]:
    """텍스트 리스트를 bge-m3 임베딩 벡터 리스트로 변환한다.

    batch_size 단위로 나눠 Ollama에 요청한다(대량 인덱싱 시 타임아웃·OOM 방지).
    실패(Ollama 미기동·모델 없음·응답 이상) 시 조용히 넘어가지 않고
    원인을 담은 RuntimeError를 던진다.
    """
    if not texts:
        return []

    embeddings: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        embeddings.extend(_embed_batch(texts[start : start + batch_size]))
    return embeddings
