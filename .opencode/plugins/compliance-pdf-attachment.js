import * as fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

const READ_PREFIX = "Called the Read tool with the following input:"
const ROOT = path.join(os.tmpdir(), `opencode-compliance-pdf-${process.pid}`)

function readFilePath(part) {
  if (part?.type !== "text" || !part.synthetic || !part.text?.startsWith(READ_PREFIX)) return
  try {
    const payload = JSON.parse(part.text.slice(READ_PREFIX.length).trim())
    return typeof payload.filePath === "string" ? payload.filePath : undefined
  } catch {
    return
  }
}

function normalizedBasename(value) {
  return path.basename(value || "").normalize("NFC")
}

async function existingPdf(value) {
  if (typeof value !== "string" || path.extname(value).toLowerCase() !== ".pdf") return
  try {
    const real = await fs.realpath(value)
    const stat = await fs.stat(real)
    return stat.isFile() ? real : undefined
  } catch {
    return
  }
}

async function aliasPdf(sessionID, index, source) {
  const safeSession = String(sessionID || "session").replace(/[^A-Za-z0-9_-]/g, "_")
  const dir = path.join(ROOT, safeSession)
  await fs.mkdir(dir, { recursive: true, mode: 0o700 })
  const alias = path.join(dir, `attachment-${index + 1}.pdf`)
  await fs.rm(alias, { force: true })
  await fs.symlink(source, alias)
  return alias
}

function bridgeMessage(ready, blocked) {
  const lines = ["[COMPLIANCE_PDF_ATTACHMENT]"]
  for (const item of ready) {
    lines.push(`PDF ${item.index + 1} MCP file_path: ${item.alias}`)
  }
  for (const item of blocked) {
    lines.push(`PDF ${item.index + 1} BLOCKED: ${item.name}의 로컬 경로를 확인할 수 없습니다.`)
  }
  if (ready.length) {
    lines.push(
      "PDF 바이너리를 직접 해석하지 말고, 사용자 질문을 검사 text로 보내지도 마라.",
      "개인정보·민감정보·금지표현 검사는 scan_sensitive_info의 file_path에 위 ASCII 경로를 그대로 전달하라.",
      "미공개중요정보·공시·대외공유 위험 검사는 check_disclosure_risk의 file_path에 같은 경로를 그대로 전달하라.",
      "두 검사를 모두 요청하면 두 tool을 모두 호출하라. check_disclosure_risk는 감사 로그를 자동 기록한다.",
    )
  }
  if (blocked.length) {
    lines.push(
      "BLOCKED PDF는 검사했다고 말하지 마라. 같은 WSL/로컬 OpenCode에서 파일을 다시 첨부하거나 절대 경로를 요청하라.",
    )
  }
  return lines.join("\n")
}

export async function CompliancePdfAttachmentPlugin() {
  return {
    "chat.message": async (input, output) => {
      const pdfs = output.parts.filter(
        (part) => part?.type === "file" && part.mime === "application/pdf",
      )
      if (!pdfs.length) return

      const readPaths = output.parts.map(readFilePath).filter(Boolean)
      const usedPaths = new Set()
      const consumedReadPaths = new Set()
      const ready = []
      const blocked = []

      for (const [index, pdf] of pdfs.entries()) {
        const sourcePath = pdf.source?.type === "file" ? pdf.source.path : undefined
        const filename = normalizedBasename(pdf.filename)
        const readPath =
          readPaths.find(
            (candidate) => !usedPaths.has(candidate) && normalizedBasename(candidate) === filename,
          ) || readPaths.find((candidate) => !usedPaths.has(candidate))
        if (readPath) {
          usedPaths.add(readPath)
          consumedReadPaths.add(readPath)
        }
        const candidates = [
          sourcePath,
          path.isAbsolute(pdf.filename || "") ? pdf.filename : undefined,
          readPath,
        ]

        let source
        for (const candidate of candidates) {
          source = await existingPdf(candidate)
          if (source) break
        }
        if (!source) {
          blocked.push({ index, name: path.basename(pdf.filename || `attachment-${index + 1}.pdf`) })
          continue
        }
        try {
          ready.push({ index, alias: await aliasPdf(input.sessionID, index, source) })
        } catch {
          blocked.push({
            index,
            name: path.basename(pdf.filename || `attachment-${index + 1}.pdf`),
          })
        }
      }

      const firstPdf = output.parts.findIndex(
        (part) => part?.type === "file" && part.mime === "application/pdf",
      )
      const anchor = output.parts[firstPdf]
      const replacement = {
        id: anchor.id,
        sessionID: anchor.sessionID,
        messageID: anchor.messageID,
        type: "text",
        synthetic: true,
        text: bridgeMessage(ready, blocked),
      }
      const next = output.parts.filter((part) => {
        if (part?.type === "file" && part.mime === "application/pdf") return false
        const filePath = readFilePath(part)
        return !filePath || !consumedReadPaths.has(filePath)
      })
      next.splice(Math.min(firstPdf, next.length), 0, replacement)
      output.parts.splice(0, output.parts.length, ...next)
    },
    dispose: async () => {
      await fs.rm(ROOT, { recursive: true, force: true })
    },
  }
}
