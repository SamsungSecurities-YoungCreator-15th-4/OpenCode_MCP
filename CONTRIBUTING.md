# 기여 가이드 (Contributing)

삼성증권 영크리에이터 15기 4조 · **OpenCode 연동 MCP 개발** 프로젝트에
기여해 주셔서 감사합니다. 이 문서는 협업의 기본 규칙을 요약합니다.
보안·비밀 관리는 [`SECURITY.md`](SECURITY.md)를 참고하세요.

## 브랜치 전략

GitFlow를 따릅니다.

```
feature/*, fix/*  →  develop  →  main
```

- `main` 직접 커밋은 금지합니다. 모든 변경은 **PR + 최소 1명 리뷰 승인** 후 머지합니다.
- 작업은 `feature/*`(신규 기능), `fix/*`(버그 수정) 등 목적별 브랜치에서 진행합니다.

## 커밋 메시지

한국어로 `타입: 설명` 형식을 사용합니다. 타입은 다음 중 하나입니다.

`feat` · `fix` · `docs` · `chore` · `refactor` · `test`

- 예) `feat: list_files tool에 확장자 필터 추가`

## PR 전 체크리스트

PR을 올리기 전 로컬에서 아래를 확인해 주세요. (자세한 항목은 PR 템플릿에 있습니다.)

- [ ] MCP 서버 단독 테스트 통과
- [ ] `opencode mcp list`에서 서버 connected 확인
- [ ] 자동 테스트: `pytest` 통과
- [ ] `.env` · API 키 · 비밀번호 등 비밀 정보를 커밋에 포함하지 않음
- [ ] 커밋 메시지가 `타입: 설명` 컨벤션을 따름

## 과제 제약 (중요)

- MCP 서버에서 **외부 상용 LLM API(OpenAI/Anthropic/Google)와 Web/외부 API를 호출하지 않습니다.**
- LLM 추론은 로컬 Ollama 모델로만 수행합니다.

## 문의

협업 관련 문의는 팀 회의 안건으로 올리거나 **team4youngcreator@gmail.com** 으로 알려 주세요.
