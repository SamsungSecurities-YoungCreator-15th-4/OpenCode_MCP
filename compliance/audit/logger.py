"""위변조 불가 감사 로그 — SQLite 해시 체인.

각 레코드는 직전 레코드의 record_hash를 prev_hash로 품는다. 한 줄이라도 사후에
바뀌면 그 뒤 모든 record_hash가 어긋나 위변조가 즉시 탐지된다(블록체인과 같은 원리).

원칙(팀 확정):
- 원문·민감값은 저장하지 않는다. input_text는 즉시 SHA-256으로만 남기고 버린다.
- result_summary는 호출자가 넘긴 값을 저장하되, LLM이 마스킹을 우회해 원문을
  재노출했을 가능성에 대비해 저장 직전 scan_text()로 한 번 더 재검증·재마스킹한다
  (호출자를 신뢰하지 않는 마지막 방어선).
- timestamp는 KST(UTC+9) 기준으로 저장한다. 국내 전용 로컬 감사 로그라, 준법감시
  담당자가 별도 변환 없이 바로 읽을 수 있는 걸 우선한다.

표준 라이브러리(sqlite3/hashlib/datetime) + compliance.detector.scan_text만 사용한다.
"""

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from compliance.detector import scan_text

KST = timezone(timedelta(hours=9))

GENESIS = "GENESIS"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp             TEXT    NOT NULL,
    tool_name             TEXT    NOT NULL,
    input_hash            TEXT    NOT NULL,
    result_summary        TEXT    NOT NULL,
    requires_human_review INTEGER NOT NULL,
    prev_hash             TEXT    NOT NULL,
    record_hash           TEXT    NOT NULL
)
"""


def _default_db_path() -> str:
    """호출 시점에 환경변수를 읽어 기본 경로를 정한다(테스트에서 재지정 가능)."""
    return os.environ.get("AUDIT_DB_PATH", "data/audit.db")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sanitize(field: str) -> str:
    """구분자 파이프(|)가 필드 내부에 섞여 해시 경계가 모호해지는 것을 막는다."""
    return field.replace("|", "/")


def _hash_record(fields: dict) -> str:
    """record_hash를 계산하는 순수 함수.

    SHA-256(timestamp | tool_name | input_hash | result_summary
            | requires_human_review | prev_hash).
    자유 텍스트 필드(tool_name/result_summary)는 파이프를 치환해 이어붙인다.
    """
    payload = "|".join(
        [
            fields["timestamp"],
            _sanitize(fields["tool_name"]),
            fields["input_hash"],
            _sanitize(fields["result_summary"]),
            str(int(fields["requires_human_review"])),
            fields["prev_hash"],
        ]
    )
    return _sha256(payload)


def _connect(db_path: str) -> sqlite3.Connection:
    if db_path != ":memory:":
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
    # isolation_level=None: 파이썬 sqlite3의 암묵적 트랜잭션을 끄고 append에서
    # BEGIN IMMEDIATE를 직접 걸 수 있게 한다(읽기-수정-쓰기 원자화 → 체인 레이스 방지).
    conn = sqlite3.connect(db_path, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(_CREATE_TABLE)
    except Exception:
        conn.close()  # 테이블 생성 실패 시 연결 누수를 막는다.
        raise
    return conn


def init_db(db_path: str | None = None) -> None:
    """테이블이 없으면 생성한다(멱등). _connect가 생성까지 수행한다."""
    _connect(db_path or _default_db_path()).close()


def _last_record_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute(
        "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["record_hash"] if row else GENESIS


def append(
    tool_name: str,
    input_text: str,
    result_summary: str,
    requires_human_review: bool,
    db_path: str | None = None,
) -> dict:
    """새 레코드를 체인 끝에 추가하고 저장된 레코드(원문 제외)를 dict로 반환한다.

    input_text는 여기서 SHA-256으로만 남기고 원문 문자열은 DB에 저장하지 않는다.
    result_summary는 호출자(LLM)가 이미 마스킹했다고 신뢰하지 않고, 저장 직전
    scan_text()로 다시 스캔해 마스킹된 버전으로 치환한다 — 호출자가 마스킹을
    빠뜨리거나 원문을 재노출해도 감사 로그에는 항상 안전한 텍스트만 남는다.
    이 재스캔에서 민감정보가 실제로 발견되면(=호출자가 유출을 시도했다는 뜻),
    호출자가 requires_human_review=False를 넘겼더라도 True로 강제 승격한다.
    """
    input_hash = _sha256(input_text)
    # 이후로 input_text 원문은 사용하지 않는다(해시만 보관).
    scan_result = scan_text(result_summary)
    result_summary = scan_result["data"]["masked_text"]
    rhr = 1 if (requires_human_review or scan_result["requires_human_review"]) else 0
    timestamp = datetime.now(KST).strftime("%Y-%m-%dT%H:%M:%S+09:00")

    conn = _connect(db_path or _default_db_path())
    try:
        # BEGIN IMMEDIATE로 쓰기 락을 즉시 잡아, 동시 append가 같은 prev_hash를
        # 읽고 체인을 분기시키는 레이스를 막는다(경합 시 busy timeout 동안 대기).
        conn.execute("BEGIN IMMEDIATE")
        prev_hash = _last_record_hash(conn)
        fields = {
            "timestamp": timestamp,
            "tool_name": tool_name,
            "input_hash": input_hash,
            "result_summary": result_summary,
            "requires_human_review": rhr,
            "prev_hash": prev_hash,
        }
        record_hash = _hash_record(fields)
        cursor = conn.execute(
            "INSERT INTO audit_log (timestamp, tool_name, input_hash, "
            "result_summary, requires_human_review, prev_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                timestamp,
                tool_name,
                input_hash,
                result_summary,
                rhr,
                prev_hash,
                record_hash,
            ),
        )
        conn.commit()
        record_id = cursor.lastrowid
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "id": record_id,
        "timestamp": timestamp,
        "tool_name": tool_name,
        "input_hash": input_hash,
        "result_summary": result_summary,
        "requires_human_review": rhr,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }


def verify_chain(db_path: str | None = None) -> dict:
    """첫 레코드부터 끝까지 순회하며 각 record_hash를 재계산해 대조한다.

    반환: {valid: bool, broken_at: int|None, total_records: int}.
    prev_hash 연결이나 record_hash 재계산이 처음으로 어긋나는 id를 broken_at로 보고한다.
    """
    conn = _connect(db_path or _default_db_path())
    try:
        rows = conn.execute(
            "SELECT id, timestamp, tool_name, input_hash, result_summary, "
            "requires_human_review, prev_hash, record_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    prev = GENESIS
    broken_at = None
    for row in rows:
        expected = _hash_record(
            {
                "timestamp": row["timestamp"],
                "tool_name": row["tool_name"],
                "input_hash": row["input_hash"],
                "result_summary": row["result_summary"],
                "requires_human_review": row["requires_human_review"],
                "prev_hash": row["prev_hash"],
            }
        )
        if row["prev_hash"] != prev or row["record_hash"] != expected:
            broken_at = row["id"]
            break
        prev = row["record_hash"]

    return {
        "valid": broken_at is None,
        "broken_at": broken_at,
        "total_records": len(rows),
    }
