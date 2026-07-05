# OpenCode_MCP

[과제3] 오픈코드(OpenCode) 연동 MCP 개발

OpenCode에 자연어로 요청하면 로컬 Ollama 모델이 우리가 만든 MCP 서버의 툴을 실제로 호출하는 체인을 구현한다.

```
사용자 자연어 요청 → OpenCode → Ollama (qwen3-instruct-16k, 로컬) → MCP 서버 (mcp_server.py)
```

**과제 제약: MCP 서버에서 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.**

## 구성 파일

| 파일 | 역할 |
| --- | --- |
| `mcp_server.py` | MCP 서버 (Python SDK `FastMCP`, stdio). 툴: `ping`, `list_files` |
| `opencode.json` | OpenCode 설정 — Ollama provider + MCP 서버(`local`) 등록 |
| `Modelfile.instruct` | `num_ctx 16384` 파생 모델(`qwen3-instruct-16k`) 생성용 |
| `test_client.py` | 수동 검증용 stdio 클라이언트 (서버 단독 테스트) |
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
# 1. MCP 서버 단독 (OpenCode 없이)
.venv/bin/python test_client.py
# → tools: ['ping', 'list_files'] / ping -> pong: hello

# 2. OpenCode ↔ MCP 연결 확인 (레포 루트에서)
opencode mcp list
# → ✓ local connected

# 3. E2E: 자연어 → LLM → 툴 호출
opencode run --auto -m ollama/qwen3-instruct-16k "ping 툴로 hello 메시지를 보내줘"
```

## 알아둘 것 (스파이크 검증 결과, 2026-07-03)

- **CPU 전용 머신 성능**: 콜드 프리필 약 30 tok/s → 첫 요청 5분+ 걸릴 수 있음. Ollama 프롬프트 캐시가 데워진 뒤엔 30초~1분. **데모 전 워밍업 필수.**
- **툴 개수 최소화**: 툴 스키마가 프리필 토큰을 늘려 응답이 느려진다. 꼭 필요한 툴만 등록.
- 스파이크에서 툴 호출 3/3 성공 (영어/한국어 요청 포함).

## 개발 규칙

- GitFlow: `feature/*` → `develop` → `main` (main/develop 직접 푸시 불가, PR + 승인 1명 필수)
- 커밋 컨벤션: `타입: 한국어 설명` (예: `feat: ping 툴 추가`)
- 상세: [CONTRIBUTING.md](CONTRIBUTING.md)
