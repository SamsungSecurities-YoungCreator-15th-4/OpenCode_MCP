"""OpenCode 연동용 로컬 MCP 서버.

제약: 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.
stdio transport로 동작한다 (FastMCP.run() 기본값).
"""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("local")


@mcp.tool()
def ping(message: str) -> str:
    """Echo the input message back unchanged. Use this to test the MCP connection."""
    return f"pong: {message}"


@mcp.tool()
def list_files(directory: str = ".") -> list[str]:
    """List the names of files and subdirectories in the given local directory."""
    p = Path(directory).expanduser()
    if not p.is_dir():
        return [f"error: {directory} is not a directory"]
    try:
        return sorted(entry.name for entry in p.iterdir())
    except OSError as e:
        return [f"error: cannot list {directory}: {e}"]


if __name__ == "__main__":
    mcp.run()
