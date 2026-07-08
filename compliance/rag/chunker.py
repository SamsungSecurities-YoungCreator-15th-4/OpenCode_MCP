"""조항(제○조) 단위 청킹 — 외부 의존성 없는 순수 함수.

실제 PDF 파싱은 이 함수의 상류다. 여기서는 파싱 결과를 흉내낸
"제○조(제목) 본문..." 형태의 구조화 텍스트를 입력으로 받아
조항 단위 청크로 자른다. 한 조가 max_chars를 넘으면 항(①②③) 단위로
재분할하되 부모 조항번호 메타데이터를 유지한다.

각 청크 dict는 팀 확정 메타데이터 스키마를 따른다:
    text, source, article, article_title, chunk_id, category(항상 None)
"""

import hashlib
import re

# 조항 헤더: "제52조(정보교류 차단)" / "제52조의2(...)" 형태.
# group(1)=조 번호, group(2)=의N 접미(없을 수 있음), group(3)=제목.
_ARTICLE_RE = re.compile(r"제\s*(\d+)\s*조(의\s*\d+)?\s*\(([^)]*)\)")

# 항 마커(원문자 ①~⑳). 형태소 분석기 없이 항 경계만 인식한다.
_CLAUSE_MARKERS = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
_CLAUSE_RE = re.compile(f"[{_CLAUSE_MARKERS}]")


def _id_prefix(source: str) -> str:
    """source 앞부분의 ASCII 영숫자 또는 짧은 해시를 chunk_id 접두로 쓴다."""
    m = re.match(r"[A-Za-z0-9]+", source)
    if m:
        return m.group(0).lower()
    digest = hashlib.sha1(source.encode("utf-8")).hexdigest()[:10]
    return f"doc_{digest}"


def _greedy_split(text: str, max_chars: int) -> list[str]:
    """항 마커가 없을 때의 폴백: 문장/줄 경계로 max_chars 이하가 되게 누적 분할한다."""
    parts = re.split(r"(?<=[.。])\s+|\n+", text)
    segments: list[str] = []
    current = ""
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if current and len(current) + len(part) + 1 > max_chars:
            segments.append(current)
            current = part
        else:
            current = f"{current} {part}".strip() if current else part
    if current:
        segments.append(current)
    return segments or [text]


def _split_if_long(text: str, max_chars: int) -> list[str]:
    """조항 본문이 max_chars 이하면 그대로, 초과하면 항 단위로 분할한다.

    첫 항 앞의 헤더(제○조 제목 등)는 첫 세그먼트에 붙여 문맥을 유지한다.
    """
    if len(text) <= max_chars:
        return [text]

    positions = [m.start() for m in _CLAUSE_RE.finditer(text)]
    if len(positions) >= 2:
        head = text[: positions[0]].strip()
        bounds = positions + [len(text)]
        segments: list[str] = []
        for i in range(len(positions)):
            piece = text[bounds[i] : bounds[i + 1]].strip()
            if i == 0 and head:
                piece = f"{head} {piece}".strip()
            if not piece:
                continue
            # 개별 항이 여전히 max_chars를 넘으면 문장 단위로 한 번 더 쪼갠다.
            if len(piece) > max_chars:
                segments.extend(_greedy_split(piece, max_chars))
            else:
                segments.append(piece)
        return segments

    return _greedy_split(text, max_chars)


def chunk_articles(
    structured_text: str, source: str, max_chars: int = 800
) -> list[dict]:
    """구조화 텍스트를 조항 단위 청크 리스트로 변환한다.

    Args:
        structured_text: "제○조(제목) 본문..."이 반복되는 텍스트(PDF 파싱 결과 흉내).
        source: 출처 문서명 (예: "KOFIA_표준내부통제기준").
        max_chars: 조항 청크 최대 길이. 초과 시 항 단위로 분할.

    Returns:
        메타데이터 스키마를 만족하는 dict 리스트. 조항 헤더가 하나도 없으면 빈 리스트.
    """
    prefix = _id_prefix(source)
    matches = list(_ARTICLE_RE.finditer(structured_text))
    chunks: list[dict] = []
    used_ids: dict[str, int] = {}

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(structured_text)
        article_text = structured_text[start:end].strip()

        num = m.group(1)
        sub = m.group(2)  # "의2" 등 또는 None
        sub_digits = re.sub(r"\D", "", sub) if sub else ""
        article = f"제{num}조" + (f"의{sub_digits}" if sub_digits else "")
        article_title = m.group(3).strip()
        artnum_token = num + (f"_{sub_digits}" if sub_digits else "")

        for j, segment in enumerate(_split_if_long(article_text, max_chars)):
            base_chunk_id = f"{prefix}_{artnum_token}_{j}"
            count = used_ids.get(base_chunk_id, 0)
            used_ids[base_chunk_id] = count + 1
            chunk_id = base_chunk_id if count == 0 else f"{base_chunk_id}_{count}"
            chunks.append(
                {
                    "text": segment,
                    "source": source,
                    "article": article,
                    "article_title": article_title,
                    "chunk_id": chunk_id,
                    "category": None,  # 8기준 수동 태깅은 이후 단계
                }
            )

    return chunks


def chunk_plain_text(
    text: str,
    source: str,
    max_chars: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """조항 헤더가 없는 문서를 고정 길이 청크로 나눈다.

    PDF 추출 결과가 목차·가이드라인처럼 "제○조(제목)" 구조를 갖지 않을 때의
    폴백이다. 메타데이터 스키마는 조항 청크와 동일하게 유지한다.
    """
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return []
    if max_chars <= overlap:
        raise ValueError("max_chars must be greater than overlap")

    prefix = _id_prefix(source)
    chunks: list[dict] = []
    start = 0
    index = 0
    while start < len(cleaned):
        end = min(len(cleaned), start + max_chars)
        if end < len(cleaned):
            boundary = cleaned.rfind(". ", start, end)
            if boundary > start + max_chars // 2:
                end = boundary + 2
        segment = cleaned[start:end].strip()
        if segment:
            chunks.append(
                {
                    "text": segment,
                    "source": source,
                    "article": "",
                    "article_title": "",
                    "chunk_id": f"{prefix}_plain_{index}",
                    "category": None,
                }
            )
            index += 1
        if end >= len(cleaned):
            break
        next_start = end - overlap
        start = next_start if next_start > start else end
    return chunks
