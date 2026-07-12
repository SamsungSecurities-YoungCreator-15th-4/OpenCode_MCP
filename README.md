# OpenCode_MCP

[과제3] 오픈코드(OpenCode) 연동 MCP 개발 — **준법감시 사전확인 어시스턴트**

AI에 업무 내용을 입력하기 전에, OpenCode에 자연어로 요청하면 로컬 Ollama 모델이 우리 MCP 서버의
준법감시 툴을 호출해 민감정보·공시위험을 사전 점검하는 체인을 구현한다.

```
사용자 자연어 요청 → OpenCode → Ollama (qwen3-instruct-16k, 로컬) → MCP 서버 (mcp_server.py)
```

**과제 제약: MCP 서버에서 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.**

> **구현 범위 안내:** 4개 툴 모두 실제 로컬 로직으로 동작한다. `search_compliance_rule`과
> `check_disclosure_risk`는 `compliance/rag/data/`의 로컬 코퍼스를 청킹한 뒤 Ollama `bge-m3`
> 임베딩과 Chroma 벡터DB, BM25 하이브리드 검색을 사용한다. 검색된 원문 snippet과
> 결정론 키워드 신호만 qwen 로컬 LLM에 전달해 근거 기반 자연어 답변을 만들며,
> 법적 적합성은 단정하지 않는다.

## 툴 구성

| 툴 | 상태 | 하는 일 | 구현 예정 |
| --- | --- | --- | --- |
| `scan_sensitive_info(text)` | ✅ **실제** | 정규식으로 주민번호·전화·카드(Luhn)·이메일·계좌·대외비 키워드 탐지 후 **마스킹**해서만 반환 | — |
| `check_disclosure_risk(text)` | ✅ **실제** | 로컬 RAG 근거와 키워드 신호로 대외공유/공시 위험을 보수적으로 안내하고 감사 로그를 자동 기록 | — |
| `search_compliance_rule(query)` | ✅ **실제** | 로컬 규정 코퍼스에서 Chroma + BM25 하이브리드 검색으로 근거 snippet 반환. 자동 로그는 남기지 않음 | — |
| `log_ai_usage(tool_name, input_text, result_summary, requires_human_review)` | ✅ **실제** | SQLite 해시체인 감사 로그. 원문은 SHA-256으로만 저장(원문 미보관), `verify_chain`으로 위변조 탐지 | — |

설계 원칙: 모든 툴은 "위반/적법"을 **단정하지 않고**, 규정 근거 제시와 준법감시인 확인 필요 여부
(`requires_human_review`)까지만 안내한다. 전 툴은 `compliance/schema.py`의 공통 출력 스키마(dict)로 응답한다.
공시/대외공유 판정 성격이 있는 `check_disclosure_risk`는 LLM의 추가 tool 호출 여부와 무관하게
같은 프로세스에서 `compliance.audit.append()`를 직접 호출해 감사 증적을 남긴다. `scan_sensitive_info`와
`search_compliance_rule`은 과다 기록을 피하기 위해 자동 로그를 남기지 않으며, 보관이 필요한 경우에만
`log_ai_usage`를 별도로 호출한다.

## 구성 파일

| 파일 | 역할 |
| --- | --- |
| `mcp_server.py` | MCP 서버 (Python SDK `FastMCP`, stdio). 위 4개 툴 등록 |
| `compliance/` | 툴 로직 — `detector.py`, `rag/`, `audit/`, `schema.py` |
| `compliance/rag/data/` | 로컬 규정 PDF/텍스트 코퍼스. Git에는 올리지 않고 각자 로컬에 둔다 |
| `opencode.json` | OpenCode 설정 — Ollama provider + MCP 서버(`local`) 등록 |
| `Modelfile.instruct` | `num_ctx 16384` 파생 모델(`qwen3-instruct-16k`) 생성용 |
| `scripts/check_client.py` | 수동 검증용 stdio 클라이언트 (툴 4개 목록 조회 후 모두 호출) |
| `tests/` | pytest 단위 테스트 (CI에서 실행) |

## 개발 환경 설정

### 1. 사전 준비

- Python 3.11+, Node.js (npm)
- [Ollama](https://ollama.com) 설치 후 `ollama serve` 실행 상태

### 2. 모델 준비

기본 `qwen3:4b`(thinking 모드)는 툴 호출 시 무한 생성 루프에 빠지므로 **반드시 instruct 변형**을 쓰고,
Ollama 기본 컨텍스트(4096)로는 OpenCode 시스템 프롬프트(~6,400 토큰)가 잘리므로 **16k 파생 모델을 생성**해야 한다.

```bash
ollama pull qwen3:4b-instruct
ollama create qwen3-instruct-16k -f Modelfile.instruct
ollama pull bge-m3
```

`bge-m3`는 RAG 임베딩 전용 모델이고, `qwen3-instruct-16k`는 OpenCode의 tool 호출 및
RAG 자연어 답변 생성에 사용한다. MCP 서버는 외부 LLM/임베딩 API를 쓰지 않고
Ollama 로컬 엔드포인트(`http://localhost:11434`)만 호출한다.

### 3. OpenCode 설치

```bash
npm install -g opencode-ai
```

### 4. Python 환경

레포 루트에서:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`opencode.json`의 MCP command가 `.venv/bin/python` 상대경로를 사용하므로, venv는 반드시 레포 루트에 `.venv` 이름으로 만들고 OpenCode도 레포 루트에서 실행한다.
(Windows는 WSL 사용을 권장한다. 네이티브 Windows에서 쓰려면 `opencode.json`의 경로를 `.venv\Scripts\python.exe`로 로컬에서 수정해야 하며, 이 구성은 검증되지 않았다.)

### PDF 첨부

OpenCode는 PDF 첨부를 MCP의 `file_path`로 자동 변환하지 않고 모델 입력에 바이너리로
전달한다. 텍스트 전용 qwen이 이를 직접 읽거나 한글 경로를 정확히 재생성할 수 없으므로,
프로젝트 로컬 플러그인 `.opencode/plugins/compliance-pdf-attachment.js`가 다음을 수행한다.

1. PDF 바이너리를 모델 입력에서 제거한다.
2. 원본을 복사하지 않고 `/tmp` 아래에 ASCII 심볼릭 링크를 만든다.
3. qwen이 그 경로를 scan/check tool의 `file_path`로 전달하도록 지시한다.
4. 세션 완료/삭제 또는 OpenCode 종료 시 임시 링크를 삭제하고, 다음 시작 때 잔여 링크도 정리한다.

플러그인은 OpenCode 시작 시 자동 로드된다. 변경 후 OpenCode를 재시작하고 TUI/VS Code
Extension에서 PDF를 첨부하거나 CLI에서 아래처럼 실행한다.

```bash
opencode run --file "/절대/경로/검토자료.pdf" \
  "첨부 PDF의 민감정보와 미공개중요정보 위험을 모두 검사해줘"
```

tool 호출 입력에 `text: ""`와 ASCII `/tmp/.../attachment-1.pdf`가 표시되면 정상이다.
`opencode run --attach ... --file ...`처럼 서버가 원본 로컬 경로를 알 수 없는 첨부는
검사했다고 가장하지 않고 보수적으로 실패한다.

CPU 환경에서 `check_disclosure_risk`의 내부 qwen 답변 생성과 OpenCode의 최종 답변
생성을 연속 실행하면 MCP 기본 제한시간을 넘길 수 있다. 운영 `opencode.json`은 MCP
요청 제한을 10분으로 늘리고 `RAG_GENERATE_ANSWER=0`으로 내부 중복 생성을 끈다.
검색 임계값, 인용 검증, 결정론 summary와 근거 snippet은 그대로 반환된다.
또한 `SCAN_MAX_FINDINGS=10`으로 전체 건수·마스킹은 유지하면서 상세 finding 배열만
제한해 긴 문서의 최종 qwen 프리필 크기를 줄인다.

### 5. RAG 코퍼스 준비

규정 PDF 또는 텍스트 파일을 레포 루트 기준 `compliance/rag/data/`에 둔다. 이 경로는
로컬 데이터로 취급되어 `.gitignore`의 `data/` 패턴에 의해 커밋되지 않는다.

첫 `search_compliance_rule` 또는 `check_disclosure_risk` 호출 시:

1. `pypdf`로 PDF 텍스트를 추출한다.
2. 조항 패턴이 있으면 조항 단위로, 없으면 고정 길이로 청킹한다.
3. Ollama `bge-m3`로 임베딩한다.
4. `data/chroma/`에 Chroma 인덱스를 저장하고 `data/chroma_manifest.json`에 코퍼스 지문을 기록한다.
5. 검색된 snippet과 위험 신호만 qwen에 전달해 3문장 이내 근거 기반 답변을 생성한다.

코퍼스 파일이 바뀌면 manifest 지문이 달라져 다음 호출 때 인덱스를 재생성한다.
qwen 답변 생성에 실패해도 tool은 검색 snippet과 결정론 summary를 반환하도록 fallback한다.

## 검증

```bash
# 1. MCP 서버 단독 (OpenCode 없이) — 툴 4개 목록 조회 후 모두 호출
.venv/bin/python scripts/check_client.py
# → tools: ['scan_sensitive_info', 'check_disclosure_risk',
#           'search_compliance_rule', 'log_ai_usage']

# 2. OpenCode ↔ MCP 연결 확인 (레포 루트에서)
opencode mcp list
# → ✓ compliance-assistant connected

# 3. E2E: 자연어 → LLM → 툴 호출
opencode run --auto -m ollama/qwen3-instruct-16k \
  "이 문장에 민감정보 있는지 스캔해줘: 담당자 연락처는 010-1234-5678 입니다"

# 4. RAG 직접 검증 (첫 실행은 bge-m3 임베딩 때문에 오래 걸릴 수 있음)
.venv/bin/python - <<'PY'
from compliance import rag
print(rag.search_compliance_rule("준법감시인 사전확인 광고 투자권유")["summary"])
print(rag.check_disclosure_risk("3분기 실적 발표 전 내부 검토 자료")["summary"])
PY
```

OpenCode 1.17.18 실측에서는 신형 `/api/session/.../prompt`가 MCP tool을 모델에
전달하지 않았다. GUI/TUI 또는 `opencode serve`의 기존 `/session` 경로로 E2E를
검증하고, 응답 모델이 `ollama/qwen3-instruct-16k`인지 반드시 확인한다.
`opencode.json`은 로컬 Ollama와 MCP 4종만 허용하고 내장 Web/셸 도구 및 공유 기능을
차단한다. 설정을 바꾼 뒤에는 `opencode debug config`로 적용 상태를 확인한다.

## 알아둘 것 (스파이크 검증 결과, 2026-07-03)

- **CPU 전용 머신 성능**: 콜드 프리필 ~30 tok/s → 첫 요청 5분+ 걸릴 수 있음. Ollama 프롬프트 캐시가 데워진 뒤엔 30초~1분. **데모 전 워밍업 필수.**
- **툴 개수 최소화**: 툴 스키마가 프리필 토큰을 늘려 응답이 느려진다. 내장 tool을
  비활성화하고 MCP 4종만 등록한다.
- **긴 세션 분리**: 대화와 tool 결과가 누적되면 매 요청의 프리필이 다시 커진다.
  워밍된 서버·모델은 유지하되 시연 시나리오별로 새 세션을 사용한다.
- 스파이크에서 툴 호출 3/3 성공 (영어/한국어 요청 포함).

## 개발 규칙

- GitFlow: `feature/*` → `develop` → `main` (main/develop 직접 푸시 불가, PR + 승인 1명 필수)
- 커밋 컨벤션: `타입: 한국어 설명` (예: `feat: scan_sensitive_info 계좌번호 탐지 추가`)
- 상세: [CONTRIBUTING.md](CONTRIBUTING.md)
