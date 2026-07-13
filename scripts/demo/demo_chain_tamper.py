#!/usr/bin/env python
"""원본 DB를 보존하면서 임시 복사본에서 감사 체인의 수정 탐지를 재현한다."""

import sqlite3
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from compliance.audit import logger  # noqa: E402


AUDIT_DB = REPO_ROOT / "data" / "audit.db"


def _row_count(db_path: Path) -> int:
    connection = sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        return int(connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
    finally:
        connection.close()


def _backup(source_path: Path, destination_path: Path) -> None:
    source = sqlite3.connect(f"{source_path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        destination = sqlite3.connect(destination_path)
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()


def main() -> int:
    print("=" * 92)
    print("DEMO 3 | SQLite 감사 해시 체인의 수정 탐지")
    print("=" * 92)
    print("범위: 일반적인 레코드 수정·삭제 탐지")
    print("안전장치: 원본 data/audit.db는 읽기만 하고, 수정은 임시 복사본에서 수행\n")

    if not AUDIT_DB.is_file():
        print(f"[실행 실패] 원본 감사 DB가 없습니다: {AUDIT_DB}")
        return 1

    before_count = _row_count(AUDIT_DB)
    before = logger.verify_chain(db_path=str(AUDIT_DB))
    print("[1] 원본 감사 로그 검증")
    print(f"    path          : {AUDIT_DB}")
    print(f"    total_records : {before['total_records']}")
    print(f"    valid         : {before['valid']}")
    print(f"    broken_at     : {before['broken_at']}\n")
    if not before["valid"] or before_count == 0:
        print("[실행 실패] 원본 체인이 유효하고 레코드가 1건 이상이어야 합니다.")
        return 1

    temporary_path: Path | None = None
    tampered: dict | None = None
    changed_id: int | None = None
    with tempfile.TemporaryDirectory(prefix="compliance-chain-demo-") as temp_dir:
        temporary_path = Path(temp_dir) / "audit-demo.db"
        _backup(AUDIT_DB, temporary_path)

        print("[2] 임시 복사본 생성 및 한 행 수정")
        print(f"    temporary copy: {temporary_path}")
        connection = sqlite3.connect(temporary_path)
        try:
            row = connection.execute(
                "SELECT id FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if row is None:
                print("[실행 실패] 수정할 레코드가 없습니다.")
                return 1
            changed_id = int(row[0])
            connection.execute(
                "UPDATE audit_log SET result_summary = result_summary || ? WHERE id = ?",
                (" [DEMO 수정]", changed_id),
            )
            connection.commit()
        finally:
            connection.close()
        print(f"    modified row : id={changed_id}\n")

        tampered = logger.verify_chain(db_path=str(temporary_path))
        print("[3] 수정된 임시 복사본 재검증")
        print(f"    valid         : {tampered['valid']}")
        print(f"    broken_at     : {tampered['broken_at']}")
        print(f"    total_records : {tampered['total_records']}\n")

    after_count = _row_count(AUDIT_DB)
    cleaned = temporary_path is not None and not temporary_path.exists()
    print("[4] 정리 및 원본 보존 확인")
    print(f"    temporary copy removed : {cleaned}")
    print(f"    original rows before   : {before_count}")
    print(f"    original rows after    : {after_count}")

    expected = (
        tampered is not None
        and tampered["valid"] is False
        and tampered["broken_at"] == changed_id
        and cleaned
        and before_count == after_count
    )
    print("\n" + "-" * 92)
    if expected:
        print("결과: 임시 복사본의 수정 위치를 탐지했고 원본 감사 로그는 보존됐습니다.")
        return 0
    print("결과: 수정 탐지 또는 원본 보존의 기대 동작을 재현하지 못했습니다.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
