"""감사 로그 패키지 — 수정·삭제 탐지용 SQLite 해시 체인.

mcp_server.py의 log_ai_usage tool이 append()로 기록하고, 시연 시 verify_chain()으로
일반적인 레코드 수정·삭제 여부를 검증한다. 자세한 원리는 logger.py 참고.
"""

from compliance.audit.logger import append, init_db, latest_record_matches, verify_chain

__all__ = ["append", "init_db", "latest_record_matches", "verify_chain"]
