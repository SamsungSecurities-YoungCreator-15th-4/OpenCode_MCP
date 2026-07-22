<div align="center">

<img src="docs/assets/logo.svg" width="112" alt="S.ecret logo"/>

# S.ecret

**금융권 폐쇄망을 위한 AI 준법감시 사전확인 어시스턴트**

정보를 외부로 공유하거나 AI에 입력하기 전에, *"이거 준법감시인 확인이 필요한가?"* 를
**규정 원문 근거로** 알려주는 로컬 전용 MCP 서버.

`로컬 전용` · `외부 상용 LLM/API 0건` · `화이트박스` · `감사 해시체인`

</div>

---

## 왜 만들었나

금융회사 업무망은 외부 인터넷이 차단된 **폐쇄망**입니다. ChatGPT 같은 상용 AI도, 외부 API도 쓸 수 없고, 내부 데이터가 밖으로 나가면 법적 책임이 따릅니다. 쓸 수 있는 건 **로컬에서 도는 작은 모델뿐**입니다.

그런데 직원들은 매일 *"이 정보를 AI에 넣어도 되나?"*, *"이 자료 외부에 공유해도 되나?"* 를 마주칩니다. 규정집을 뒤지거나, 준법감시팀에 묻거나, 그냥 넘어가거나 — 대부분 세 번째를 택하고, 그게 곧 **규정 위반·정보 유출 리스크**가 됩니다.

**S.ecret은 그 사전확인을, 규정 원문 근거와 함께, 로컬에서 즉시 해줍니다.**

```
사용자 자연어 요청 → OpenCode → 로컬 qwen (4B) → MCP 서버 (mcp_server.py) → 4개 툴
```

---

## 핵심 설계 — 신뢰 경계를 좁힌다

저희가 쓸 수 있는 모델은 **4B, CPU 환경**입니다. 준법감시는 틀리면 안 됩니다. 그래서 질문을 바꿨습니다.

> **"작은 모델을 어떻게 똑똑하게 만들까"가 아니라, "작은 모델에게 무엇을 맡기지 않을 것인가."**

판정·탐지·마스킹·감사는 전부 **결정론 코드**가 하고, LLM은 **도구 선택과 설명 문장**만 담당합니다.

| 코드가 한다 (결정론) | LLM이 한다 (확률적) |
| --- | --- |
| 민감정보 탐지·마스킹 (정규식 + Luhn) | 도구 선택 |
| 위험 신호·미공개중요정보 8기준 스크리닝 | 화면에 보여줄 설명 문장 |
| 규정 검색 (벡터 + BM25 + RRF) | |
| 유사도 임계값 컷 (0.49) | |
| 인용 조항 대조 → 폐기 | |
| 감사 로그 기록·재마스킹 | |

판정 결과는 LLM의 문장이 아니라 **구조화된 7키 스키마**로 나옵니다. 자연어 문장은 설명 레이어일 뿐입니다.
→ **LLM이 틀려도 판정 근거·마스킹·감사 로그는 코드가 보장합니다.**

---

## 4개 툴

| 툴 | 하는 일 | LLM |
| --- | --- | --- |
| **`scan_sensitive_info`** | 주민번호·전화·카드(Luhn)·이메일·계좌·금지표현·대외비 키워드를 정규식으로 탐지하고 **마스킹**해서만 반환 | ❌ 순수 결정론 |
| **`check_disclosure_risk`** | 위험 신호·8기준 매핑(결정론) + 로컬 RAG 근거로 대외공유/공시 위험을 보수적으로 안내. **감사 로그 자동 기록** | 설명 문장만 |
| **`search_compliance_rule`** | 로컬 규정 코퍼스에서 Chroma + BM25 하이브리드 검색으로 근거 원문 snippet 반환 (판단 없음) | 설명 문장만 |
| **`log_ai_usage`** | SQLite 해시체인 감사 로그. 원문은 SHA-256으로만 저장, `verify_chain`으로 수정·삭제 탐지 | ❌ 순수 결정론 |

> 모든 툴은 "위반/적법"을 **단정하지 않고**, 규정 근거 제시와 `requires_human_review`(준법감시인 확인 필요 여부)까지만 안내합니다. **최종 판단은 사람이 합니다.**
> `check_disclosure_risk`는 LLM의 별도 tool 호출과 무관하게 같은 프로세스에서 `audit.append()`를 직접 호출해 감사 증적을 남깁니다. `scan`·`search`는 과다 기록을 피해 자동 로그를 남기지 않고, 필요 시 `log_ai_usage`로 명시 기록합니다.

---

## 환각 방지 2단 방어

1. **검색 신뢰도 임계값 컷** — 벡터 유사도가 임계값 **0.49** 미달이면 근거·답변을 반환하지 않고 정직하게 *"관련 규정을 찾지 못했습니다"* 로 답합니다.
2. **인용 조항 코드 대조** — LLM이 생성한 답변의 `제N조`가 실제 검색 청크에 존재하는지 코드로 대조하고, 없으면 답변을 **폐기**한 뒤 결정론 폴백으로 대체합니다.

**임계값 0.49는 추측이 아니라 실측값입니다.** 규정 질의 6건·무해 질의 6건·경계 질의 4건으로 유사도를 측정해(규정 최저 0.5533 ↔ 무해 최고 0.4268, 분리 마진 0.1265), 완전분리 구간 0.44~0.54의 중앙값을 채택했습니다. 재현 스크립트: `scripts/calibrate_rag_threshold.py`

---

## 감사 로그 (SQLite 해시체인)

- **원문 미저장** — 입력은 SHA-256 해시로만 남습니다.
- **저장 직전 재마스킹** — 요약을 한 번 더 스캔해 민감값을 마스킹한 뒤 저장합니다.
- **수정·삭제 탐지** — 각 레코드가 이전 레코드의 해시를 포함하는 체인 구조라, 중간이 조작되면 이후 해시가 전부 깨지고 `verify_chain()`이 어느 지점에서 끊겼는지(`broken_at`) 특정합니다.

---

## 빠른 시작

### 1. 사전 준비
- Python 3.11+, Node.js (npm)
- [Ollama](https://ollama.com) 설치 후 `ollama serve` 실행

### 2. 모델 준비
기본 `qwen3:4b`(thinking)은 tool 호출 시 무한 루프에 빠지므로 **instruct 변형**을 쓰고, 기본 컨텍스트(4096)로는 OpenCode 시스템 프롬프트가 잘리므로 **16k 파생 모델**을 만듭니다.

```bash
ollama pull qwen3:4b-instruct
ollama create qwen3-instruct-16k -f Modelfile.instruct
ollama pull bge-m3
```

### 3. OpenCode + Python 환경
```bash
npm install -g opencode-ai

# 레포 루트에서 (venv 이름·위치 고정 — opencode.json이 .venv 상대경로 사용)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

> `chromadb`는 CVE-2026-45829 영향 범위 밖인 `0.6.3`으로 고정합니다. 로컬 `PersistentClient`만 사용하며 외부 Chroma 서버·텔레메트리·임베딩 API를 쓰지 않습니다.
> Windows는 WSL 권장.

### 4. 규정 코퍼스 준비
규정 PDF/텍스트를 `compliance/rag/data/`에 둡니다(로컬 데이터, `.gitignore` 처리). 첫 `search`/`check` 호출 시 `pypdf` 추출 → 조항 단위 청킹 → `bge-m3` 임베딩 → `data/chroma_0_6/`에 Chroma 인덱스를 자동 생성합니다. 코퍼스가 바뀌면 manifest 지문이 달라져 다음 호출 때 재인덱싱합니다.

### 5. 연결 확인
```bash
opencode mcp list          # → ✓ compliance-assistant connected
```

---

## PDF 첨부

OpenCode는 PDF를 `file_path`가 아니라 바이너리로 모델에 넘기는데, 텍스트 전용 qwen은 이를 읽거나 한글 경로를 재현하지 못합니다. 로컬 플러그인 `.opencode/plugins/compliance-pdf-attachment.js`가 **PDF 바이너리를 제거하고, 원본을 복사하지 않은 채 `/tmp`에 ASCII 심볼릭 링크**를 만들어 그 경로를 scan/check의 `file_path`로 넘깁니다. 세션 종료 시 임시 링크는 정리되고, 로컬 경로를 알 수 없는 첨부는 *검사한 척하지 않고 보수적으로 실패*합니다.

```bash
opencode run --file "/절대/경로/검토자료.pdf" \
  "첨부 PDF의 민감정보와 미공개중요정보 위험을 모두 검사해줘"
```

> CPU 지연 완화를 위해 운영 `opencode.json`은 MCP 제한시간을 10분으로 늘리고, `RAG_GENERATE_ANSWER=0`으로 내부 중복 생성을 끄며, `SCAN_MAX_FINDINGS=10`으로 프리필 크기를 줄입니다. 임계값 컷·인용 검증·결정론 summary·근거 snippet은 그대로 반환됩니다.

---

## 검증

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/ruff check .        # → All checks passed!
.venv/bin/pytest              # → 173 passed, 5 xfailed
```

```bash
# MCP 서버 단독 (OpenCode 없이) — 툴 4개 목록 조회 후 모두 호출
.venv/bin/python scripts/check_client.py

# 재현 데모 3종
.venv/bin/python scripts/demo/demo_threshold_cut.py    # 임계값 컷 (무해 CUT / 규정 PASS)
.venv/bin/python scripts/demo/demo_citation_guard.py   # 환각 조항 폐기 (제999조 → citation_verified: False)
.venv/bin/python scripts/demo/demo_chain_tamper.py     # 해시체인 수정 탐지 (broken_at) · 원본 보존
```

`5 xfailed`는 **고쳐야 할 알려진 갭을 테스트에 고정**한 것입니다(아래 한계 참조). 통과하기 시작하면 xfail이 풀려 알려줍니다.

---

## 알려둘 한계 (숨기지 않습니다)

준법 도구는 정직해야 하므로, 남은 한계를 명시합니다.

- **도구 선택은 모델이 합니다.** 4B라 호출이 누락될 수 있습니다. 대신 각 도구가 독립적으로 안전하게 설계돼, 선택이 틀려도 잘못된 판정이 나오지는 않습니다.
- **OpenCode가 화면에 출력하는 최종 문장은 MCP의 검증 범위 밖**입니다. 저희가 보증하는 것은 구조화된 결과와 감사 로그입니다.
- **전화번호 미탐 3건** — `+82` 국제표기·점 구분자·전각 숫자. 국내 표기 기준으로만 정규식을 짰습니다. (`xfail`)
- **해시체인 canonicalization 미탐 2건** — 구분자 `|`·`/`가 동일하게 해시되는 특수 케이스. 일반적인 수정·삭제는 정상 탐지됩니다. 그래서 *"위변조 불가"* 대신 *"수정·삭제 탐지"* 라고 씁니다. (`xfail`)
- **OpenCode 자체 세션 DB에는 입력 원문이 평문으로** 남습니다. 저희 감사 로그는 원문을 저장하지 않지만, 실행 환경까지는 통제하지 못합니다.
- **CPU 콜드 스타트** — 첫 요청은 5분 이상 걸릴 수 있습니다. **데모 전 워밍업 필수.**

> 저희는 4B 모델로 완벽한 준법감시 AI를 만들지 못했습니다. 대신 **모델이 틀려도 판정과 기록은 흔들리지 않는 구조**를 만들었습니다.

---

## 기술 스택

| 영역 | 사용 |
| --- | --- |
| MCP 서버 | Python · FastMCP (stdio) |
| 로컬 LLM | Ollama `qwen3:4b-instruct` (num_ctx 16384) |
| 임베딩 | `bge-m3` (로컬 Ollama) |
| 벡터DB / 검색 | Chroma `0.6.3` + BM25 하이브리드 (RRF) |
| 감사 로그 | SQLite + SHA-256 해시체인 |
| 클라이언트 | OpenCode (로컬 provider allowlist) |

---

## 팀

| 이름 | 역할 |
| --- | --- |
| **최정현** | 리드 · 풀스택 · 인프라 (RAG 튜닝·PDF 브릿지·보안·CI) |
| **국준호** | MCP 서버 · RAG 파이프라인 · 메인테이너(리뷰·통합) |
| **오지은** | 민감정보 탐지기 (`scan` · 정규식·마스킹) |
| **고다경** | 감사 로그 (`audit` · 해시체인) |
| **나승민** | RAG 코퍼스 구축 · E2E 통합·재현성 검증 |

---

## 개발 규칙

- GitFlow: `feature/*` → `develop` → `main` (main/develop 직접 푸시 불가, PR + 승인 1명 필수)
- 커밋: `타입: 한국어 설명` (예: `feat: scan_sensitive_info 계좌번호 탐지 추가`)
- 상세: [CONTRIBUTING.md](CONTRIBUTING.md) · 개발 컨텍스트: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
