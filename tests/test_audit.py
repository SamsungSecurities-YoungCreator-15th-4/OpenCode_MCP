"""감사 로그(해시 체인) 스모크 테스트 — 임시 DB로 실제 audit.db를 건드리지 않는다.

이 tool의 존재 이유는 두 가지다:
- 원문·민감값을 저장하지 않는다 (test_original_text_never_stored).
- 위변조를 탐지한다 (test_verify_chain_detects_tampering).
"""

import hashlib
import sqlite3

from compliance.audit import logger


def _db(tmp_path) -> str:
    return str(tmp_path / "audit.db")


# --- 1. append 3회 → 레코드 3개 + prev_hash가 직전 record_hash와 연결 -----------


def test_append_builds_hash_chain(tmp_path):
    db = _db(tmp_path)
    r1 = logger.append("scan_sensitive_info", "원문1", "요약1", False, db_path=db)
    r2 = logger.append("check_disclosure_risk", "원문2", "요약2", True, db_path=db)
    r3 = logger.append("search_compliance_rule", "원문3", "요약3", False, db_path=db)

    # 레코드 3개가 생긴다.
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 3
    conn.close()

    # 각 레코드의 prev_hash가 직전 레코드의 record_hash와 일치한다.
    assert r2["prev_hash"] == r1["record_hash"]
    assert r3["prev_hash"] == r2["record_hash"]


# --- 2. 첫 레코드의 prev_hash는 GENESIS ---------------------------------------


def test_first_record_prev_hash_is_genesis(tmp_path):
    db = _db(tmp_path)
    first = logger.append("scan_sensitive_info", "원문", "요약", False, db_path=db)
    assert first["prev_hash"] == "GENESIS"


# --- 3. 원문 미저장 (이 tool의 존재 이유 ①) ----------------------------------


def test_original_text_never_stored(tmp_path):
    db = _db(tmp_path)
    secret = "주민번호_900101-1234567_대외비원문_SECRET"
    logger.append("scan_sensitive_info", secret, "민감정보 1건 탐지", True, db_path=db)

    # (a) SELECT * 로 조회한 모든 컬럼 값 어디에도 원문이 없다.
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT * FROM audit_log").fetchall()
    conn.close()
    flat = " ".join(str(value) for row in rows for value in row)
    assert secret not in flat

    # (b) DB 파일 원본 바이트에도 원문이 없다 (가장 강한 검증).
    with open(db, "rb") as fh:
        assert secret.encode("utf-8") not in fh.read()

    # (c) 대신 원문의 SHA-256 해시는 저장돼 있다.
    assert hashlib.sha256(secret.encode("utf-8")).hexdigest() in flat


# --- 4. 정상 체인 검증 --------------------------------------------------------


def test_verify_chain_valid_on_intact_chain(tmp_path):
    db = _db(tmp_path)
    for i in range(5):
        logger.append("scan_sensitive_info", f"원문{i}", f"요약{i}", False, db_path=db)

    result = logger.verify_chain(db_path=db)
    assert result == {"valid": True, "broken_at": None, "total_records": 5}


# --- 5. 위변조 탐지 (이 tool의 존재 이유 ②, 시연 핵심) -----------------------


def test_verify_chain_detects_tampering(tmp_path):
    db = _db(tmp_path)
    logger.append("t", "a", "요약1", False, db_path=db)
    r2 = logger.append("t", "b", "원래 요약", False, db_path=db)
    logger.append("t", "c", "요약3", False, db_path=db)

    # 2번 레코드의 result_summary를 DB에서 직접 변조한다.
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE audit_log SET result_summary = ? WHERE id = ?", ("변조된 요약", r2["id"])
    )
    conn.commit()
    conn.close()

    result = logger.verify_chain(db_path=db)
    assert result["valid"] is False
    assert result["broken_at"] == r2["id"]
    assert result["total_records"] == 3


# --- 6. 같은 입력이라도 record_hash는 매번 달라진다 ---------------------------


def test_same_input_yields_different_record_hash(tmp_path):
    db = _db(tmp_path)
    r1 = logger.append("t", "동일 원문", "동일 요약", False, db_path=db)
    r2 = logger.append("t", "동일 원문", "동일 요약", False, db_path=db)

    # 원문이 같으므로 input_hash는 같다.
    assert r1["input_hash"] == r2["input_hash"]
    # 그러나 prev_hash가 달라(첫째는 GENESIS, 둘째는 r1 해시) record_hash는 다르다.
    assert r1["prev_hash"] != r2["prev_hash"]
    assert r1["record_hash"] != r2["record_hash"]
