# OpenCode_MCP

[과제3] 오픈코드(OpenCode) 연동 MCP 개발 — **준법감시 사전확인 어시스턴트**

AI에 업무 내용을 입력하기 전에, OpenCode에 자연어로 요청하면 로컬 Ollama 모델이 우리 MCP 서버의
준법감시 툴을 호출해 민감정보·공시위험을 사전 점검하는 체인을 구현한다.

```
사용자 자연어 요청 → OpenCode → Ollama (qwen3-instruct-16k, 로컬) → MCP 서버 (mcp_server.py)
```

**과제 제약: MCP 서버에서 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.**

> **구현 범위 안내 (뼈대 단계):** 4개 툴 중 `scan_sensitive_info`·`log_ai_usage`는 실제 로직으로
> 구현했고, 나머지 2개(`check_disclosure_risk`·`search_compliance_rule`)는 mock이다. mock 툴은
> 응답에 `"mock": true`와 안내 문구를 담아 스스로 시연용임을 밝힌다. 아래
> [툴 구성](#툴-구성-실제-vs-mock) 표에서 실제/시연 범위를 확인할 수 있다.

## 툴 구성 (실제 vs mock)

| 툴 | 상태 | 하는 일 | 구현 예정 |
| --- | --- | --- | --- |
| `scan_sensitive_info(text)` | ✅ **실제** | 정규식으로 주민번호·전화·카드(Luhn)·이메일·계좌·대외비 키워드 탐지 후 **마스킹**해서만 반환 | — |
| `check_disclosure_risk(text)` | 🧪 mock | 미공개 중대정보 여부 안내 (현재 보수적 기본값: 확인 필요) | 로컬 RAG 기반 규정 매칭 |
| `search_compliance_rule(query)` | 🧪 mock | 내부 규정 조문 근거 검색 (현재 더미 조문 1건) | 로컬 임베딩·Chroma RAG |
| `log_ai_usage(tool_name, input_text, result_summary, requires_human_review)` | ✅ **실제** | SQLite 해시체인 감사 로그. 원문은 SHA-256으로만 저장(원문 미보관), `verify_chain`으로 위변조 탐지 | — |

설계 원칙: 모든 툴은 "위반/적법"을 **단정하지 않고**, 규정 근거 제시와 준법감시인 확인 필요 여부
(`requires_human_review`)까지만 안내한다. 전 툴은 `compliance/schema.py`의 공통 출력 스키마(dict)로 응답한다.

## 구성 파일

| 파일 | 역할 |
| --- | --- |
| `mcp_server.py` | MCP 서버 (Python SDK `FastMCP`, stdio). 위 4개 툴 등록 |
| `compliance/` | 툴 로직 — `detector.py`(scan 실구현), `rag.py`·`audit.py`(mock), `schema.py`(공통 스키마) |
| `opencode.json` | OpenCode 설정 — Ollama provider + MCP 서버(`local`) 등록 |
| `Modelfile.instruct` | `num_ctx 16384` 파생 모델(`qwen3-instruct-16k`) 생성용 |
| `test_client.py` | 수동 검증용 stdio 클라이언트 (툴 4개 목록 조회 후 모두 호출) |
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
```

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

## 검증

```bash
# 1. MCP 서버 단독 (OpenCode 없이) — 툴 4개 목록 조회 후 모두 호출
.venv/bin/python test_client.py
# → tools: ['scan_sensitive_info', 'check_disclosure_risk',
#           'search_compliance_rule', 'log_ai_usage']

# 2. OpenCode ↔ MCP 연결 확인 (레포 루트에서)
opencode mcp list
# → ✓ compliance-assistant connected

# 3. E2E: 자연어 → LLM → 툴 호출
opencode run --auto -m ollama/qwen3-instruct-16k \
  "이 문장에 민감정보 있는지 스캔해줘: 담당자 연락처는 010-1234-5678 입니다"
```

## 알아둘 것 (스파이크 검증 결과, 2026-07-03)

- **CPU 전용 머신 성능**: 콜드 프리필 ~30 tok/s → 첫 요청 5분+ 걸릴 수 있음. Ollama 프롬프트 캐시가 데워진 뒤엔 30초~1분. **데모 전 워밍업 필수.**
- **툴 개수 최소화**: 툴 스키마가 프리필 토큰을 늘려 응답이 느려진다. 꼭 필요한 툴만 등록.
- 스파이크에서 툴 호출 3/3 성공 (영어/한국어 요청 포함).

## 개발 규칙

- GitFlow: `feature/*` → `develop` → `main` (main/develop 직접 푸시 불가, PR + 승인 1명 필수)
- 커밋 컨벤션: `타입: 한국어 설명` (예: `feat: scan_sensitive_info 계좌번호 탐지 추가`)
- 상세: [CONTRIBUTING.md](CONTRIBUTING.md)
