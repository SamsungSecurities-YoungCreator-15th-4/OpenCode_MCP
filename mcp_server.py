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
AUDIT_CONFIRMATION = (
    "🔒 확인한 내용이 안전하게 기록되었습니다. 개인정보와 미공개 정보 등 "
    "민감한 내용은 노출되지 않도록 보호한 뒤 저장됩니다."
)
CHECK_LOG_SKIP_SUMMARY = ""


def _with_audit_confirmation(summary: str) -> str:
    """Append the audit confirmation once when a tool saved an audit log."""
    if AUDIT_CONFIRMATION in summary:
        return summary
    return f"{summary}\n\n{AUDIT_CONFIRMATION}"


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
        return text or "", None, None
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
    """개인정보·금융 금지표현 탐지와 마스킹 전용 tool이다.

    주민번호·전화·이메일·계좌·카드 또는 민감정보 스캔/마스킹 요청에 사용한다.
    미공개중요정보, 공시 전 실적, 인수합병(M&A), 유상증자, 대외공유 위험에는
    사용하지 말고 check_disclosure_risk를 호출한다. text 또는 로컬
    file_path(.pdf/.txt/.md) 하나만 전달하고, 결과는 data.masked_text를 사용한다.
    이 tool은 감사 로그를 기록하지 않는다. 실제로 log_ai_usage를 호출하지 않았다면
    기록됐다고 말하지 않는다.
    """
    content, extracted, err = _load_input("scan_sensitive_info", text, file_path)
    if err is not None:
        return err
    return _apply_file_meta(detector.scan_text(content), extracted)


@mcp.tool()
def check_disclosure_risk(text: str = "", file_path: str = "") -> dict:
    """미공개중요정보·공시·대외공유 위험 스크리닝 전용 tool이다.

    구체 문서나 정보를 공유해도 되는지, 공시 전 실적·인수합병(M&A)·유상증자·
    투자정보인지 묻는 경우 반드시 이 tool을 사용하고 scan_sensitive_info나
    search_compliance_rule로 대신하지 않는다. text 또는 로컬
    file_path(.pdf/.txt/.md) 하나만 전달한다. 최종 법률 판단은 하지 않는다.
    같은 호출에서 감사 로그를 자동 기록하며 data.audit_log.auto_logged=true를
    반환한다. summary에 기록 확인이 이미 있으므로 그대로 사용하고 id/hash는 노출하지 않는다.
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

    result["summary"] = _with_audit_confirmation(result["summary"])
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
    """규정 원문·조항 검색과 근거 인용 전용 tool이다.

    사용자가 규정/법령 검색, 조항 번호, 원문 또는 근거 인용을 명시적으로 요청할
    때 사용한다. 구체 정보의 공유 가능 여부나 미공개중요정보·공시 위험은
    check_disclosure_risk를 사용한다. 이 tool은 감사 로그를 기록하지 않는다.
    실제로 log_ai_usage를 호출하지 않았다면 기록됐다고 말하지 않는다."""
    return rag.search_compliance_rule(query)


@mcp.tool()
def log_ai_usage(
    tool_name: str,
    input_text: str,
    result_summary: str,
    requires_human_review: bool,
) -> dict:
    """감사 로그 기록 전용 tool이다.

    사용자가 기록을 명시 요청했거나 scan_sensitive_info/search_compliance_rule
    결과를 기록할 때 사용한다. check_disclosure_risk는 자동 기록하므로 같은 입력의
    직전 기록이 있으면 skipped=true로 중복을 막는다. skipped=true 또는 summary가
    비어 있으면 새 기록이 없으므로 저장됐다고 말하지 않는다. 그 외에는 summary를
    그대로 사용하고 id/hash를 노출하지 않는다. input_text는 원문 대신 SHA-256
    해시로만 저장되며 result_summary는 저장 직전 다시 마스킹된다."""
    normalized_tool_name = tool_name.strip().lower() if isinstance(tool_name, str) else ""
    try:
        is_duplicate_check = (
            normalized_tool_name == "check_disclosure_risk"
            and audit.latest_record_matches("check_disclosure_risk", input_text)
        )
    except Exception as exc:
        return fail("log_ai_usage", "감사 로그 확인에 실패했습니다.", str(exc))

    if is_duplicate_check:
        return ok(
            "log_ai_usage",
            CHECK_LOG_SKIP_SUMMARY,
            data={
                "skipped": True,
                "skip_reason": "check_disclosure_risk_auto_logs_audit_record",
                "tool_name": tool_name,
                "logged_requires_human_review": bool(requires_human_review),
            },
        )

    try:
        record = audit.append(
            tool_name=(
                "check_disclosure_risk"
                if normalized_tool_name == "check_disclosure_risk"
                else tool_name
            ),
            input_text=input_text,
            result_summary=result_summary,
            requires_human_review=requires_human_review,
        )
    except Exception as exc:  # DB 오류 등은 조용히 넘기지 않고 실패로 보고한다.
        return fail("log_ai_usage", "감사 로그 기록에 실패했습니다.", str(exc))

    return ok(
        "log_ai_usage",
        AUDIT_CONFIRMATION,
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
