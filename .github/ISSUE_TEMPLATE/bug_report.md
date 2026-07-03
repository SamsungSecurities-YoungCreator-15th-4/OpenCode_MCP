---
name: 버그 제보
about: 동작 오류·잘못된 tool 응답 등 버그를 제보합니다
title: "fix: "
labels: bug
assignees: ''
---

## 버그 설명

<!-- 무엇이 잘못 동작하는지 한두 줄로 적어 주세요. -->

## 재현 절차

1.
2.
3.

## 기대 동작 / 실제 동작

- **기대**:
- **실제**:

## 환경

- 영역: <!-- mcp-server(tool 구현) / opencode(설정·연동) / ollama(모델·추론) / docs -->
- OS·모델: <!-- 예: WSL2 Ubuntu, qwen3:4b-instruct -->
- 브랜치·커밋: <!-- 예: develop, abc1234 -->

## 스크린샷·로그 (선택)

<!-- 첨부 전 확인: API 키·계정 정보·개인 정보가 포함되지 않았는지 꼭 확인해 주세요.
     보안 취약점은 이슈가 아니라 SECURITY.md의 비공개 제보 절차를 이용해 주세요. -->

## 참고

- tool 호출 실패 버그라면 `opencode mcp list` 출력과 Ollama 로그(`journalctl -u ollama`)를 함께 적어 주세요.
