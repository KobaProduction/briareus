export const MAX_TEXT_PREVIEW_BYTES = 256 * 1024

const TEXT_EXTENSIONS = /\.(?:txt|md|mdx|js|jsx|ts|tsx|vue|json|jsonl|css|scss|html|htm|xml|yml|yaml|toml|ini|conf|py|sh|sql|csv|log|diff|patch)$/i

export function canPreviewTextFile(record: Record<string, unknown>): boolean {
  return record.type === "file"
    && typeof record.name === "string"
    && TEXT_EXTENSIONS.test(record.name)
    && typeof record.size_bytes === "number"
    && Number.isFinite(record.size_bytes)
    && record.size_bytes >= 0
    && record.size_bytes <= MAX_TEXT_PREVIEW_BYTES
}

export async function readTextPreview(
  url: string,
  signal?: AbortSignal,
  fetcher: typeof fetch = fetch,
): Promise<string> {
  // Fetch does not save a file even with Content-Disposition: attachment.
  // Range plus a streamed size cap protects against files changed since listing.
  const response = await fetcher(url, {
    credentials: "include",
    headers: { Range: "bytes=0-" + MAX_TEXT_PREVIEW_BYTES },
    signal,
  })
  if (!response.ok) throw new Error("HTTP " + response.status)
  const length = Number(response.headers.get("content-length"))
  if (response.headers.has("content-length") && length > MAX_TEXT_PREVIEW_BYTES) {
    await response.body?.cancel()
    throw new Error("File exceeds preview limit")
  }

  if (!response.body) throw new Error("File cannot be previewed")
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_TEXT_PREVIEW_BYTES) {
        await reader.cancel()
        throw new Error("File exceeds preview limit")
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  if (text.includes("\0")) throw new Error("Binary files cannot be previewed")
  return text
}
