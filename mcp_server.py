"""준법감시 사전확인 어시스턴트 MCP 서버 (OpenCode 연동용).

제약: 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.
stdio transport로 동작한다 (FastMCP.run() 기본값).

tool 4개 중 scan_sensitive_info만 실제 로직이며 나머지는 mock이다.
모든 tool은 compliance.schema의 공통 출력 스키마(dict)로 응답한다.
"""

from mcp.server.fastmcp import FastMCP

from compliance import audit, detector, rag

mcp = FastMCP("compliance-assistant")


@mcp.tool()
def scan_sensitive_info(text: str) -> dict:
    """Scan text for sensitive information (Korean resident registration
    numbers, phone numbers, card numbers, emails, account numbers,
    confidential keywords) before sharing it externally.
    Returns masked findings only — never the original values."""
    return detector.scan_text(text)


@mcp.tool()
def check_disclosure_risk(text: str) -> dict:
    """Check whether text may contain undisclosed material information
    that requires compliance officer confirmation before external
    disclosure. Advisory only — it never gives a final legal judgment."""
    return rag.check_disclosure_risk(text)


@mcp.tool()
def search_compliance_rule(query: str) -> dict:
    """Search internal compliance rules and return relevant rule excerpts
    as evidence for a compliance question."""
    return rag.search_compliance_rule(query)


@mcp.tool()
def log_ai_usage(action: str, detail: str = "") -> dict:
    """Record an AI usage event to the local audit log for compliance
    tracking. Sensitive values must already be masked by the caller."""
    return audit.log_ai_usage(action, detail)


if __name__ == "__main__":
    mcp.run()
