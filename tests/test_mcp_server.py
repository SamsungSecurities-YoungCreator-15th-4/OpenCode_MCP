"""MCP 툴 함수 단위 테스트 (FastMCP @tool 데코레이터는 원본 함수를 그대로 반환한다)."""

import mcp_server


def test_ping_echoes_message():
    assert mcp_server.ping("hello") == "pong: hello"


def test_list_files_returns_sorted_names(tmp_path):
    (tmp_path / "b.txt").touch()
    (tmp_path / "a.txt").touch()
    (tmp_path / "sub").mkdir()
    assert mcp_server.list_files(str(tmp_path)) == ["a.txt", "b.txt", "sub"]


def test_list_files_rejects_non_directory(tmp_path):
    missing = tmp_path / "nope"
    result = mcp_server.list_files(str(missing))
    assert len(result) == 1
    assert result[0].startswith("error:")
