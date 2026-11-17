import { decodeSignedEnvelope, isFinalityClosureRecord, decodeLedgerRecord } from '@chronolog/node-core'
import { bytesToHex, transactionDigest } from '@chronolog/protocol'

import type { NativeBrowserFixture } from '../browser-event-fixture.js'
import { waitFor } from './wait-for.js'

export interface AdmissionWindow {
  readonly scenario: string
  readonly heldAtMs: number
  heldForMs: number
  proposalIds: readonly string[]
  status: 'authoring' | 'included' | 'failed'
  error?: string
}

/** Fixture-only admission control: never changes a proposal, key or signed timestamp. */
export function createAdmissionClock(options: { readonly now?: () => number; readonly timeoutMs?: number } = {}) {
  const now = options.now ?? Date.now, timeoutMs = options.timeoutMs ?? 25_000
  // The fixture genesis allows 30s of future author time. End the hold before
  // a slow author could outlive that window; production policy stays unchanged.
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 25_000) throw new Error('PILOT_ADMISSION_TIMEOUT_INVALID')
  let held: number | undefined
  const windows: AdmissionWindow[] = []
  return {
    now: () => held ?? now(), windows,
    async include<T>(scenario: string, author: () => Promise<{ readonly value: T; readonly proposalIds: readonly string[] }>,
      included: (proposalIds: readonly string[]) => Promise<boolean>): Promise<T> {
      if (held !== undefined) throw new Error('PILOT_ADMISSION_WINDOW_ALREADY_OPEN')
      held = now()
      const started = performance.now(), window: AdmissionWindow = { scenario, heldAtMs: held, heldForMs: 0, proposalIds: [], status: 'authoring' }
      windows.push(window)
      let settled = false
      const current = () => { if (settled) throw new Error('PILOT_ADMISSION_WINDOW_ENDED') }
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        return await Promise.race([(async () => {
          const receipt = await author()
          current()
          window.proposalIds = [...receipt.proposalIds]
          if (receipt.proposalIds.length === 0 || new Set(receipt.proposalIds).size !== receipt.proposalIds.length) throw new Error('PILOT_ADMISSION_PROPOSALS_REQUIRED')
          await waitFor(async () => { current(); const complete = await included(receipt.proposalIds); current(); return complete }, `original proposal inclusion: ${scenario}`,
            Math.max(1, timeoutMs - (performance.now() - started)))
          current()
          window.status = 'included'
          return receipt.value
        })(), new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`PILOT_ADMISSION_WINDOW_TIMEOUT: ${scenario}`)), timeoutMs)
        })])
      } catch (error) { window.status = 'failed'; window.error = String(error); throw error }
      finally { settled = true; clearTimeout(timer); window.heldForMs = performance.now() - started; held = undefined }
    },
  }
}

/** Match the original signed core to an actual native inclusion receipt. */
export function observeIncludedProposals(native: Pick<NativeBrowserFixture, 'agent' | 'transport' | 'governed'>) {
  const observed = new Set<string>()
  const decoded = new Set<string>()
  return async () => {
    const authority = native.agent.finality
    if (authority === null) throw new Error('PILOT_NATIVE_AUTHORITY_REQUIRED')
    const range = await authority.read({ limit: 256 })
    if (range.hasMore) throw new Error('PILOT_INCLUSION_HISTORY_TRUNCATED')
    for (const entry of range.entries) {
      if (decoded.has(entry.recordId) || isFinalityClosureRecord(entry.bytes)) continue
      const record = decodeLedgerRecord(entry.bytes)
      if (record.kind !== 'candidate') { decoded.add(entry.recordId); continue }
      const body = await native.transport.getPayload(record.payloadHash)
      if (body === null) continue
      const wire = await decodeSignedEnvelope(body, native.governed.descriptor.groupRoute, native.governed.governance.cipherRing)
      if (wire.type !== 'candidate') throw new Error('PILOT_INCLUDED_CANDIDATE_REQUIRED')
      observed.add(`tx_${bytesToHex(await transactionDigest(wire.payload))}`)
      decoded.add(entry.recordId)
    }
    return observed
  }
}
