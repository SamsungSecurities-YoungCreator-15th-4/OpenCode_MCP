"""준법감시 사전확인 어시스턴트 MCP 서버 (OpenCode 연동용).

제약: 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.
stdio transport로 동작한다 (FastMCP.run() 기본값).

tool 4개 중 scan_sensitive_info·log_ai_usage는 실제 로직이며 나머지 2개는 mock이다.
모든 tool은 compliance.schema의 공통 출력 스키마(dict)로 응답한다.
"""

from mcp.server.fastmcp import FastMCP

from compliance import audit, detector, rag
from compliance.schema import fail, ok

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
def log_ai_usage(
    tool_name: str,
    input_text: str,
    result_summary: str,
    requires_human_review: bool,
) -> dict:
    """Record an AI-usage / compliance-check event to the local tamper-evident
    audit log so there is a compliance audit trail of what was checked with AI.
    Call this after a sensitive-info scan or disclosure-risk check to log the
    event. The input text is stored only as a SHA-256 hash, never in plaintext;
    result_summary must already be free of sensitive values. Returns the stored
    record id and hash."""
    try:
        record = audit.append(
            tool_name=tool_name,
            input_text=input_text,
            result_summary=result_summary,
            requires_human_review=requires_human_review,
        )
    except Exception as exc:  # DB 오류 등은 조용히 넘기지 않고 실패로 보고한다.
        return fail("log_ai_usage", "감사 로그 기록에 실패했습니다.", str(exc))

    return ok(
        "log_ai_usage",
        f"감사 로그에 기록했습니다 (id={record['id']}, "
        f"record_hash={record['record_hash'][:12]}…). 원문은 해시로만 저장됩니다.",
        data={
            "id": record["id"],
            "timestamp": record["timestamp"],
            "tool_name": record["tool_name"],
            "input_hash": record["input_hash"],
            "prev_hash": record["prev_hash"],
            "record_hash": record["record_hash"],
            "logged_requires_human_review": bool(record["requires_human_review"]),
        },
        outputs=[
            f"id={record['id']}",
            f"record_hash={record['record_hash']}",
        ],
    )


if __name__ == "__main__":
    mcp.run()
