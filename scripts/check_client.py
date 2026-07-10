"""수동 검증용 standalone 클라이언트: mcp_server.py를 stdio로 띄워 툴 목록 조회 후 4개 모두 호출.

실행: .venv/bin/python scripts/check_client.py
(pytest 대상이 아님 — 자동 테스트는 tests/ 참고)
"""

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO_ROOT = Path(__file__).resolve().parent.parent

SERVER = StdioServerParameters(
    command=sys.executable,
    args=[str(REPO_ROOT / "mcp_server.py")],
)

# 민감정보 원본 대신 검증용 더미 값만 사용한다
CALLS = [
    ("scan_sensitive_info", {"text": "담당자 연락처는 010-1234-5678 입니다."}),
    ("check_disclosure_risk", {"text": "3분기 실적 발표 전 내부 검토 자료"}),
    ("search_compliance_rule", {"query": "준법감시인 사전확인 절차"}),
    (
        "log_ai_usage",
        {
            "tool_name": "scan_sensitive_info",
            "input_text": "수동 검증 입력",
            "result_summary": "수동 검증",
            "requires_human_review": False,
        },
    ),
]


async def main() -> None:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("tools:", [t.name for t in tools.tools])

            for name, args in CALLS:
                result = await session.call_tool(name, args)
                print(f"{name} ->", result.content[0].text)


if __name__ == "__main__":
    asyncio.run(main())
