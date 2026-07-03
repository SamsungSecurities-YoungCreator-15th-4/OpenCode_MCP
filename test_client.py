"""수동 검증용 standalone 클라이언트: mcp_server.py를 stdio로 띄워 툴 목록 조회 후 둘 다 호출.

실행: .venv/bin/python test_client.py
(pytest 대상이 아님 — 자동 테스트는 tests/ 참고)
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parent

SERVER = StdioServerParameters(
    command=sys.executable,
    args=[str(REPO_ROOT / "mcp_server.py")],
)


async def main() -> None:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("tools:", [t.name for t in tools.tools])

            r1 = await session.call_tool("ping", {"message": "hello"})
            print("ping ->", r1.content[0].text)

            r2 = await session.call_tool("list_files", {"directory": str(REPO_ROOT)})
            print("list_files ->", [c.text for c in r2.content])


asyncio.run(main())
