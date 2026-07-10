"""준법감시 사전확인 어시스턴트 MCP 서버 (OpenCode 연동용).

제약: 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.
stdio transport로 동작한다 (FastMCP.run() 기본값).

tool 4개 모두 실제 로컬 로직으로 동작한다.
모든 tool은 compliance.schema의 공통 출력 스키마(dict)로 응답한다.
"""

from mcp.server.fastmcp import FastMCP

from compliance import audit, detector, rag
from compliance.schema import fail, ok

mcp = FastMCP("compliance-assistant")


@mcp.tool()
def scan_sensitive_info(text: str) -> dict:
    """Scan text for sensitive information and financial prohibited claims before
    sharing it externally.

    The returned result never contains original sensitive values. Use
    data.masked_text when showing the scanned text to the user. If this scan
    result is later recorded with log_ai_usage, pass data.log_safe_summary as
    result_summary, not the original input text. Detected personal information
    also requires human review; masking prevents plaintext exposure but does
    not mean the input is risk-free. Prohibited financial claims or
    internal/confidential keywords also require human review.
    """
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
    result_summary must already be free of sensitive values. The record id and
    hash are returned in the 'data' field of the response for internal/audit
    lookup only — never read them aloud to the user. The 'summary' field in the
    returned dictionary is the final, complete confirmation message for the
    user as-is: repeat its value verbatim as your final reply and do not add
    any other sentence about the log being saved, masked, or protected — the
    summary already covers that; restating it in different words is redundant
    and must not happen. Even if re-masking occurred while storing the log,
    the server already forces requires_human_review to True in that case —
    just pass through your best-effort value."""
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
        "🔒 확인한 내용이 안전하게 기록되었습니다. 개인정보와 미공개 정보 등 "
        "민감한 내용은 노출되지 않도록 보호한 뒤 저장됩니다.",
        data={
            "id": record["id"],
            "timestamp": record["timestamp"],
            "tool_name": record["tool_name"],
            "input_hash": record["input_hash"],
            "prev_hash": record["prev_hash"],
            "record_hash": record["record_hash"],
            "logged_requires_human_review": bool(record["requires_human_review"]),
        },
    )


if __name__ == "__main__":
    mcp.run()
