import { describe, expect, test } from "bun:test"
import { canPreviewTextFile, MAX_TEXT_PREVIEW_BYTES, readTextPreview } from "./text-preview"

describe("Files text preview", () => {
  test("permits small text/source files only", () => {
    expect(canPreviewTextFile({ type: "file", name: "vk-export.user.js", size_bytes: 20000 })).toBe(true)
    expect(canPreviewTextFile({ type: "file", name: "notes.MD", size_bytes: 0 })).toBe(true)
    expect(canPreviewTextFile({ type: "file", name: "script.js", size_bytes: MAX_TEXT_PREVIEW_BYTES })).toBe(true)
    expect(canPreviewTextFile({ type: "file", name: "video.mp4", size_bytes: 100 })).toBe(false)
    expect(canPreviewTextFile({ type: "file", name: ".env", size_bytes: 100 })).toBe(false)
    expect(canPreviewTextFile({ type: "file", name: "large.json", size_bytes: MAX_TEXT_PREVIEW_BYTES + 1 })).toBe(false)
    expect(canPreviewTextFile({ type: "directory", name: "notes.md", size_bytes: 100 })).toBe(false)
  })

  test("fetches text for inline display, with cookies and a bounded Range", async () => {
    let options = {}
    const fetcher = (async (_url, init) => {
      options = init ?? {}
      return new Response("const answer = 42", { status: 206 })
    })
    const result = await readTextPreview("/files/download?path=script.js", undefined, fetcher)
    expect(result).toBe("const answer = 42")
    expect(options.credentials).toBe("include")
    expect(new Headers(options.headers).get("range")).toBe("bytes=0-" + MAX_TEXT_PREVIEW_BYTES)
  })

  test("rejects non-success responses", async () => {
    await expect(readTextPreview("/files/download", undefined, (async () =>
      new Response("Forbidden", { status: 403 })))).rejects.toThrow("HTTP 403")
  })

  test("rejects changed oversized files even if server ignores Range", async () => {
    await expect(readTextPreview("/files/download", undefined, (async () =>
      new Response(new Uint8Array(MAX_TEXT_PREVIEW_BYTES + 1)))))
      .rejects.toThrow("File exceeds preview limit")
  })

  test("does not render binary content or invalid UTF-8", async () => {
    await expect(readTextPreview("/files/download", undefined, (async () =>
      new Response(new Uint8Array([65, 0, 66])))))
      .rejects.toThrow("Binary files cannot be previewed")
    await expect(readTextPreview("/files/download", undefined, (async () =>
      new Response(new Uint8Array([0xff, 0xfe])))))
      .rejects.toThrow()
  })
})
