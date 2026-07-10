"""준법감시 사전확인 어시스턴트 MCP 서버 (OpenCode 연동용).

제약: 외부 상용 LLM API(OpenAI/Anthropic/Google) 및 Web/외부 API 호출 금지 — 로컬 전용.
stdio transport로 동작한다 (FastMCP.run() 기본값).

tool 4개 모두 실제 로컬 로직으로 동작한다.
모든 tool은 compliance.schema의 공통 출력 스키마(dict)로 응답한다.
"""

from mcp.server.fastmcp import FastMCP

from compliance import audit, detector, fileio, rag
from compliance.schema import fail, ok

mcp = FastMCP("compliance-assistant")


def _load_input(tool_name: str, text: str, file_path: str):
    """text/file_path 중 정확히 하나를 검사 대상 텍스트로 확정한다.

    반환: (content, extracted|None, error_dict|None). 파일 원문은 여기서
    메모리로만 흐르고 저장되지 않는다(감사 로그는 기존대로 해시만 기록).
    """
    has_text = bool(text and text.strip())
    has_file = bool(file_path and file_path.strip())
    if has_text and has_file:
        return None, None, fail(
            tool_name,
            "text와 file_path 중 정확히 하나만 전달하세요.",
            "invalid_arguments: exactly one of text/file_path required",
        )
    if not has_file:
        # 빈 text 허용은 기존 계약(폴백 쿼리 등 tool별 처리)을 그대로 따른다.
        return text, None, None
    try:
        extracted = fileio.extract_text(file_path)
    except fileio.FileInputError as exc:
        return None, None, fail(tool_name, f"파일 입력 오류: {exc}", str(exc))
    return extracted.text, extracted, None


def _apply_file_meta(result: dict, extracted) -> dict:
    """파일 입력이었다면 결과에 출처 메타를 붙이고, 절단 시 보수적으로 격상한다."""
    if extracted is None:
        return result
    result["data"] = dict(result.get("data") or {})
    result["data"]["source_file"] = {
        "file_name": extracted.file_name,
        "extension": extracted.extension,
        "pages": extracted.pages,
        "total_chars": extracted.total_chars,
        "truncated": extracted.truncated,
    }
    if extracted.truncated:
        # 절단된 뒷부분은 스캔되지 않아 미탐 가능 → 통과로 두지 않는다.
        result["requires_human_review"] = True
        result["outputs"] = list(result.get("outputs") or []) + [
            f"⚠️ 파일 텍스트가 {fileio.MAX_TEXT_CHARS:,}자에서 절단되어 이후 내용은 "
            "검사되지 않았습니다. 문서 전체는 준법감시인 확인이 필요합니다."
        ]
    return result


@mcp.tool()
def scan_sensitive_info(text: str = "", file_path: str = "") -> dict:
    """Scan text for sensitive information and financial prohibited claims before
    sharing it externally. Pass exactly one of text or file_path (local
    .pdf/.txt/.md file); with file_path the raw document never enters the chat.

    The returned result never contains original sensitive values. Use
    data.masked_text when showing the scanned text to the user. If this scan
    result is later recorded with log_ai_usage, pass data.log_safe_summary as
    result_summary, not the original input text. Detected personal information
    also requires human review; masking prevents plaintext exposure but does
    not mean the input is risk-free. Prohibited financial claims or
    internal/confidential keywords also require human review.
    """
    content, extracted, err = _load_input("scan_sensitive_info", text, file_path)
    if err is not None:
        return err
    return _apply_file_meta(detector.scan_text(content), extracted)


@mcp.tool()
def check_disclosure_risk(text: str = "", file_path: str = "") -> dict:
    """Check whether text may contain undisclosed material information
    that requires compliance officer confirmation before external
    disclosure. Advisory only — it never gives a final legal judgment.
    Pass exactly one of text or file_path (local .pdf/.txt/.md file).

    This tool automatically writes a tamper-evident audit record in the
    same process after the disclosure-risk check is completed, so material
    disclosure decisions do not depend on the LLM separately calling
    log_ai_usage.
    """
    content, extracted, err = _load_input("check_disclosure_risk", text, file_path)
    if err is not None:
        return err
    result = _apply_file_meta(rag.check_disclosure_risk(content), extracted)
    try:
        record = audit.append(
            tool_name="check_disclosure_risk",
            input_text=content,
            result_summary=result["summary"],
            requires_human_review=result["requires_human_review"],
        )
    except Exception as exc:
        return fail("check_disclosure_risk", "감사 로그 기록에 실패했습니다.", str(exc))

    result["data"] = dict(result.get("data") or {})
    result["data"]["audit_log"] = {
        "id": record["id"],
        "timestamp": record["timestamp"],
        "record_hash": record["record_hash"],
        "logged_requires_human_review": bool(record["requires_human_review"]),
        "auto_logged": True,
    }
    return result


@mcp.tool()
def search_compliance_rule(query: str) -> dict:
    """Search internal compliance rules and return relevant rule excerpts
    as evidence for a compliance question. This search-only tool does not
    automatically write an audit log; call log_ai_usage separately when the
    search event itself must be retained as evidence."""
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
    Call this after a sensitive-info scan or search-only request when that
    event must be retained. check_disclosure_risk already records its own audit
    event automatically, so do not duplicate it unless explicitly requested.
    The input text is stored only as a SHA-256 hash, never in plaintext;
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
