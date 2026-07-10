# DEVELOPMENT.md — OpenCode_MCP 개발 컨텍스트

이 문서는 Codex·Claude Code 등 AI 코딩 에이전트가 **개발 작업** 시 읽는 공용 컨텍스트다.
새 작업을 시작하기 전 이 문서를 먼저 읽고, 아래 불변 규칙을 위반하지 않는다.

> AGENTS.md는 OpenCode 런타임(준법감시 어시스턴트)이 매 세션 프롬프트에 싣는 파일이라
> 의도적으로 짧게 유지한다(CPU prefill 비용). 개발 규칙은 이 문서가 원본이다.

## 프로젝트
금융권 폐쇄망을 가정한 "준법감시 사전확인 어시스턴트" MCP 서버.
직원이 정보를 외부 공유하거나 AI에 입력하기 전, 준법감시인 확인이 필요한지를
규정 원문 근거로 안내한다. 최종 판단은 사람이 하고, AI는 근거 인용과 확인 권고까지만 한다(화이트박스).

## 3대 불변 규칙 (위반 금지)
1. 외부 상용 LLM/API 호출 금지. 로컬만 사용한다(폐쇄망 가정).
2. 원문·민감값을 저장하지 않는다. 감사 로그는 SHA-256 해시와 메타데이터만 남긴다.
3. 미탐(위험한데 통과)이 오탐보다 치명적이다. 애매하면 requires_human_review=True(보수적 바이어스).

## 기술 스택
- MCP 서버: Python + FastMCP, stdio 전송
- 로컬 LLM: Ollama qwen3:4b-instruct
  - thinking 변형 금지(tool calling 시 무한루프)
  - num_ctx 16384 필수(기본 4096은 OpenCode 시스템 프롬프트에서 잘림)
- 임베딩: bge-m3 (Ollama, http://localhost:11434/api/embed). 외부 임베딩 API 사용 안 함
- 벡터DB: Chroma (collection: compliance_rules)
- 검색: Chroma 벡터 + BM25를 RRF로 병합, 기본 top-k 5
- 감사 로그: SQLite + 해시 체이닝(위변조 탐지)
- 파일 처리: pypdf, python-docx / 테스트: pytest / 린트: ruff

## 공통 출력 스키마 (전 tool 공통 7키)
ok(bool) / tool(str) / summary(str) / data(dict) / outputs(list[str]) / requires_human_review(bool) / error(str|None)
- 성공·실패 무관 항상 이 형태. schema.py의 ok()/fail() 헬퍼만 사용한다.
- outputs는 반드시 list[str]. dict로 바꾸지 않는다.

## tool 4종
- check_disclosure_risk(text): 미공개중요정보 위험 1차 스크리닝 + 근거 인용. 환각방지 2단 방어.
- scan_sensitive_info(text): 개인정보·금지표현·내부정보 정규식 탐지 + 마스킹. 순수 결정론.
- search_compliance_rule(query): 규정 원문 검색·인용(RAG).
- log_ai_usage(...): 호출 감사 로그 기록(해시 체이닝).
- tool은 4개로 유지한다(작은 모델의 tool 선택 정확도 때문에 늘리지 않는다).

## 환각방지 2단 방어 (check/search)
1. 검색 신뢰도 임계값 컷: 벡터 유사도 기준(RRF 점수 아님). 미달 시 근거 없이 정직 응답.
2. 인용 조항번호 코드 대조: 생성 답변의 "제N조"가 검색 청크의 article에 실존하는지 대조,
   없으면 답변 폐기 후 결정론 폴백.

## 디렉토리 & 역할 경계
- compliance/rag/     : RAG(청킹·임베딩·검색·check·search) — P2
- compliance/detector.py : scan — P4(지은)
- compliance/audit/   : log — P4(다경)
- compliance/schema.py : 공통 스키마(수정 시 전 tool 영향, 팀 합의 필요)
- 자기 트랙 외 파일은 수정 전 담당자와 합의한다.

## 코퍼스
- compliance/rag/data/ (gitignore, 로컬만). 조항 단위 청크.
- 청크 metadata: text, source, article, article_title, chunk_id, category, file_name

## 작업 규칙
- CLI 출력만 사용. 요약용 .md 파일을 새로 만들지 않는다.
- GitFlow: feature→develop→main. PR + 리뷰 1명 필수. main 직접 커밋 금지.
- 코드 리뷰 봇: Gemini만 사용(Copilot·Code Quality 사용 금지).
- 기존 테스트를 깨지 않는다. Ollama 의존 테스트는 skip 마커를 유지한다.

## 에이전트 컨텍스트 파일 규칙
- AGENTS.md: OpenCode 런타임이 매 세션 자동 로드(비활성화 불가) → 어시스턴트 동작 규칙만 짧게 유지. 개발 규칙을 다시 넣지 않는다.
- docs/DEVELOPMENT.md(이 파일): 개발 컨텍스트 원본. Codex는 AGENTS.md 끝의 포인터를 따라 읽는다.
- CLAUDE.md는 이 두 줄만 둔다 (단독 행 import 구문):
  @AGENTS.md
  @docs/DEVELOPMENT.md
