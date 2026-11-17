/** A polling deadline also bounds an individual observation that never returns. */
export async function waitFor(predicate: () => Promise<boolean>, description: string, timeoutMs = 40_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) throw new Error(`PILOT_DURABLE_PROGRESS_TIMEOUT: ${description}`)
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const complete = await Promise.race([predicate(), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`PILOT_DURABLE_PROGRESS_TIMEOUT: ${description}`)), remaining)
      })])
      if (complete) return
    } finally { if (timer !== undefined) clearTimeout(timer) }
    await new Promise(resolve => setTimeout(resolve, Math.min(100, Math.max(0, deadline - Date.now()))))
  }
}
