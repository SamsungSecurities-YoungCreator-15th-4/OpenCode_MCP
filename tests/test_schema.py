"""공통 출력 스키마 헬퍼(ok/fail) 단위 테스트."""

from compliance import schema


def test_ok_returns_all_schema_keys():
    result = schema.ok("ping", "정상 동작")
    assert set(result) == set(schema.RESULT_KEYS)
    assert result["ok"] is True
    assert result["tool"] == "ping"
    assert result["summary"] == "정상 동작"
    assert result["data"] == {}
    assert result["outputs"] == []
    assert result["requires_human_review"] is False
    assert result["error"] is None


def test_ok_accepts_data_outputs_and_review_flag():
    result = schema.ok(
        "scan_sensitive_info",
        "1건 탐지",
        data={"findings": [1]},
        outputs=["out/masked.txt"],
        requires_human_review=True,
    )
    assert result["data"] == {"findings": [1]}
    assert result["outputs"] == ["out/masked.txt"]
    assert result["requires_human_review"] is True


def test_ok_does_not_share_mutable_defaults():
    first = schema.ok("t", "s")
    first["data"]["x"] = 1
    first["outputs"].append("f.txt")
    second = schema.ok("t", "s")
    assert second["data"] == {}
    assert second["outputs"] == []


def test_fail_returns_all_schema_keys_with_error():
    result = schema.fail("log_ai_usage", "기록 실패", "disk full")
    assert set(result) == set(schema.RESULT_KEYS)
    assert result["ok"] is False
    assert result["error"] == "disk full"
    assert result["outputs"] == []


def test_fail_requires_human_review():
    result = schema.fail("scan_sensitive_info", "실패", "boom")
    assert result["requires_human_review"] is True
