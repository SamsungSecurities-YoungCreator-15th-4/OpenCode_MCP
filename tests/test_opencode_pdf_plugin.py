"""OpenCode PDF attachment bridge의 Node 단위 테스트."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / ".opencode/plugins/compliance-pdf-attachment.js"
NODE = shutil.which("node")


def _run_plugin(pdf_path: Path | None, include_read_path: bool = True) -> dict:
    script = r"""
const fs = require("node:fs")
const pdfPath = process.argv[2] || ""
const includeReadPath = process.argv[3] === "true"

;(async () => {
  const source = fs.readFileSync(process.argv[1], "utf8")
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`)
  const plugin = module.CompliancePdfAttachmentPlugin
  const hooks = await plugin({})
  const parts = []
  if (includeReadPath) {
    parts.push({
      id: "read",
      sessionID: "ses_test",
      messageID: "msg_test",
      type: "text",
      synthetic: true,
      text: `Called the Read tool with the following input: ${JSON.stringify({ filePath: pdfPath })}`,
    })
  }
  parts.push({
    id: "pdf",
    sessionID: "ses_test",
    messageID: "msg_test",
    type: "file",
    mime: "application/pdf",
    filename: pdfPath ? pdfPath.split("/").at(-1) : "attachment.pdf",
    url: "data:application/pdf;base64,JVBERg==",
  })
  parts.push({ id: "prompt", type: "text", text: "첨부 PDF를 검사해줘" })

  await hooks["chat.message"]({ sessionID: "ses_test" }, { parts })
  const text = parts.map((part) => part.text || "").join("\n")
  const match = text.match(/MCP file_path: (.+)/)
  const alias = match?.[1]
  const beforeDispose = alias ? fs.existsSync(alias) : false
  const target = alias ? fs.realpathSync(alias) : null
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_test" } } })
  const afterIdle = alias ? fs.existsSync(alias) : false
  await hooks.dispose()
  console.log(JSON.stringify({ parts, text, alias, beforeDispose, target, afterIdle, afterDispose: alias ? fs.existsSync(alias) : false }))
})().catch((error) => {
  console.error(error)
  process.exit(1)
})
"""
    result = subprocess.run(
        [NODE, "-e", script, str(PLUGIN), str(pdf_path or ""), str(include_read_path).lower()],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return json.loads(result.stdout)


@pytest.mark.skipif(NODE is None, reason="Node.js is required by OpenCode")
def test_pdf_attachment_becomes_ascii_file_path_without_binary(tmp_path):
    pdf = tmp_path / "미공개_실적.pdf"
    pdf.write_bytes(b"%PDF-1.4\nsynthetic test\n%%EOF")

    result = _run_plugin(pdf)

    assert all(part["type"] != "file" for part in result["parts"])
    assert "COMPLIANCE_PDF_ATTACHMENT" in result["text"]
    assert "scan_sensitive_info" in result["text"]
    assert "check_disclosure_risk" in result["text"]
    assert str(pdf) not in result["text"]
    assert result["beforeDispose"] is True
    assert Path(result["target"]) == pdf.resolve()
    assert result["alias"].isascii()
    assert result["afterIdle"] is False
    assert result["afterDispose"] is False


@pytest.mark.skipif(NODE is None, reason="Node.js is required by OpenCode")
def test_data_only_pdf_fails_closed_without_claiming_it_was_read():
    result = _run_plugin(None, include_read_path=False)

    assert all(part["type"] != "file" for part in result["parts"])
    assert "BLOCKED" in result["text"]
    assert "검사했다고 말하지 마라" in result["text"]
    assert result.get("alias") is None


@pytest.mark.skipif(NODE is None, reason="Node.js is required by OpenCode")
def test_pdf_bridge_preserves_non_pdf_attachment_context(tmp_path):
    pdf = tmp_path / "검토.pdf"
    txt = tmp_path / "참고.txt"
    pdf.write_bytes(b"%PDF-1.4\nsynthetic test\n%%EOF")
    txt.write_text("참고 내용", encoding="utf-8")
    script = r"""
const fs = require("node:fs")
;(async () => {
  const source = fs.readFileSync(process.argv[1], "utf8")
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`)
  const hooks = await module.CompliancePdfAttachmentPlugin({})
  const [pdf, txt] = [process.argv[2], process.argv[3]]
  const read = (id, filePath) => ({
    id,
    type: "text",
    synthetic: true,
    text: `Called the Read tool with the following input: ${JSON.stringify({ filePath })}`,
  })
  const parts = [
    read("pdf-read", pdf),
    { id: "pdf", type: "file", mime: "application/pdf", filename: pdf.split("/").at(-1) },
    read("txt-read", txt),
    { id: "txt", type: "file", mime: "text/plain", filename: txt.split("/").at(-1) },
  ]
  await hooks["chat.message"]({ sessionID: "ses_mixed" }, { parts })
  await hooks.dispose()
  console.log(JSON.stringify(parts))
})()
"""
    result = subprocess.run(
        [NODE, "-e", script, str(PLUGIN), str(pdf), str(txt)],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    parts = json.loads(result.stdout)

    assert not any(part.get("mime") == "application/pdf" for part in parts)
    assert any(part.get("mime") == "text/plain" for part in parts)
    assert any(str(txt) in part.get("text", "") for part in parts)


@pytest.mark.skipif(NODE is None, reason="Node.js is required by OpenCode")
def test_non_pdf_parts_are_unchanged():
    script = r"""
const fs = require("node:fs")
;(async () => {
  const source = fs.readFileSync(process.argv[1], "utf8")
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`)
  const plugin = module.CompliancePdfAttachmentPlugin
  const hooks = await plugin({})
  const parts = [{ id: "text", type: "text", text: "일반 질문" }]
  await hooks["chat.message"]({ sessionID: "ses_text" }, { parts })
  await hooks.dispose()
  console.log(JSON.stringify(parts))
})()
"""
    result = subprocess.run(
        [NODE, "-e", script, str(PLUGIN)],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert json.loads(result.stdout) == [{"id": "text", "type": "text", "text": "일반 질문"}]
