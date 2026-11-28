import { bytesToHex } from '@chronolog/canonical'
import { decodeRecord, encodeRecord, evidenceDigest, type AdmissionEvidence } from '@chronolog/authority'
import { decodeSignedOperation, encryptedEnvelopeDigest, operationIdDigest } from '@chronolog/protocol'
import type { ApplicationSession, FactScope, FactsDelta } from './session.js'
import { FactIdSet } from './reconcile.js'
import { createHttpSyncClient, type HttpSyncClientOptions, type HttpSyncFactItem, type HttpSyncReconcileResult, type HttpSyncScope } from './http-sync.js'
import type { MirrorCasNode } from './cas-mirror.js'

/** `FactsDelta` source tag of facts delivered by an HTTP sync link. */
export const HTTP_SYNC_SOURCE = 'http-sync'

const SCOPES: Readonly<Record<FactScope, HttpSyncScope>> = { public: 'control', private: 'mailbox' }

/**
 * The fact id a sync-v3 store must index `bytes` under, matching session fact ids: public
 * scope (`control`) holds signed operations (op id) and encoded admission evidence (evidence
 * digest); private scope (`mailbox`) holds encrypted envelopes (envelope digest).
 */
export async function httpSyncFactId(scope: HttpSyncScope, bytes: Uint8Array): Promise<string> {
  if (scope === 'mailbox') return bytesToHex(encryptedEnvelopeDigest(bytes))
  try { return bytesToHex(operationIdDigest(decodeSignedOperation(bytes).coreBytes)) } catch { /* evidence */ }
  return evidenceDigest(decodeRecord<AdmissionEvidence>(bytes))
}

export interface HttpSyncLinkOptions extends HttpSyncClientOptions {
  /** Base URL of a `createHttpSyncHandler` endpoint (without `/sync/<scope>`). */
  readonly baseUrl: string
  /**
   * `'fallback'` (default): synchronize automatically (on local facts and every `intervalMs`)
   * only while the session has no peer link. `'always'`: regardless of peer links.
   * `synchronize()` always runs.
   */
  readonly mode?: 'fallback' | 'always'
  /** Poll period in ms (default 15 000; 0 disables polling). */
  readonly intervalMs?: number
  /** Debounce for pushing new local facts, in ms (default 50). */
  readonly pushDelayMs?: number
  readonly signal?: AbortSignal
}

export interface HttpSyncLinkResult {
  readonly control: HttpSyncReconcileResult
  readonly mailbox?: HttpSyncReconcileResult
}

export interface HttpSyncLink {
  readonly signal: AbortSignal
  /** Result of the last completed synchronization, or null. */
  readonly last: HttpSyncLinkResult | null
  /** Reconcile both scopes now (coalesced with a running synchronization). */
  synchronize(): Promise<HttpSyncLinkResult>
  close(): void
}

/**
 * Use a sync-v3 HTTP endpoint as a fact source for `session`: public facts reconcile over
 * `/sync/control`, encrypted envelopes over `/sync/mailbox` (private logs, readers only).
 * Received bytes are verified by `session.mergeFacts` and only accepted ids count as held;
 * CAS nodes replay reports missing are pulled with `casWant`. Facts the link delivers are
 * tagged `HTTP_SYNC_SOURCE`, so they are not pushed back.
 */
export function connectHttpSync(session: ApplicationSession, options: HttpSyncLinkOptions): HttpSyncLink {
  const client = createHttpSyncClient(options.baseUrl, options)
  const lifetime = new AbortController()
  const signal = AbortSignal.any([lifetime.signal, session.signal, ...(options.signal === undefined ? [] : [options.signal])])
  const mode = options.mode ?? 'fallback', intervalMs = options.intervalMs ?? 15_000, pushDelayMs = options.pushDelayMs ?? 50
  let last: HttpSyncLinkResult | null = null
  let running: Promise<HttpSyncLinkResult> | undefined, again = false
  let pushTimer: ReturnType<typeof setTimeout> | undefined

  const getFacts = (scope: FactScope) => (ids: readonly string[]): Promise<readonly HttpSyncFactItem[]> => {
    const out: HttpSyncFactItem[] = []
    for (const id of ids) {
      const facts = session.exportFactsById(scope, [id])
      const raw = facts.publicOps[0] ?? facts.encryptedEnvelopes[0]
      if (raw !== undefined) out.push({ id, bytes: raw })
      else if (facts.evidence[0] !== undefined) out.push({ id, bytes: encodeRecord(facts.evidence[0]) })
    }
    return Promise.resolve(out)
  }

  const onReceive = (scope: FactScope) => async (items: readonly HttpSyncFactItem[], casNodes: readonly MirrorCasNode[]): Promise<readonly string[]> => {
    const publicOps: Uint8Array[] = [], encryptedEnvelopes: Uint8Array[] = [], evidence: AdmissionEvidence[] = []
    for (const item of items) {
      if (scope === 'private') { encryptedEnvelopes.push(item.bytes); continue }
      try { decodeSignedOperation(item.bytes); publicOps.push(item.bytes); continue } catch { /* evidence */ }
      try { evidence.push(decodeRecord<AdmissionEvidence>(item.bytes)) } catch { /* rejected */ }
    }
    try {
      await session.mergeFacts({
        publicOps, encryptedEnvelopes, evidence, retentions: [],
        casNodes: casNodes.map(node => ({ hash: node.hash, bytes: node.bytes, partition: 'public' as const })),
      }, { source: HTTP_SYNC_SOURCE })
    } catch { /* a bad batch is reported below by what the session now holds */ }
    const held = session.factIds(scope)
    return items.filter(item => held.has(item.id)).map(item => item.id)
  }

  const reconcileScope = async (scope: FactScope): Promise<HttpSyncReconcileResult> => {
    const reconcile = (casWant?: readonly string[]) => {
      // A private copy: the client adds ids as it accepts them; the session's own set is
      // updated by mergeFacts.
      const ids = new FactIdSet()
      for (const id of session.factIds(scope).ids('')) ids.add(id)
      return client.reconcile(SCOPES[scope], {
        ids, signal, getFacts: getFacts(scope), onReceive: onReceive(scope),
        ...(casWant === undefined ? {} : { casWant }),
      })
    }
    let result = await reconcile()
    const requested = new Set<string>()
    for (let attempt = 0; attempt < 8 && !signal.aborted; attempt++) {
      const missing = session.missingCasDependencies().filter(hash => !requested.has(hash)).slice(0, 256)
      if (missing.length === 0) break
      for (const hash of missing) requested.add(hash)
      result = await reconcile(missing)
    }
    return result
  }

  const syncOnce = async (): Promise<HttpSyncLinkResult> => {
    signal.throwIfAborted()
    const control = await reconcileScope('public')
    const mailbox = session.genesis.privateLog && session.isReader(session.device.identity.publicKey)
      ? await reconcileScope('private')
      : undefined
    return last = { control, ...(mailbox === undefined ? {} : { mailbox }) }
  }

  const synchronize = (): Promise<HttpSyncLinkResult> => {
    if (running !== undefined) { again = true; return running }
    running = (async () => {
      try {
        let result = await syncOnce()
        while (again && !signal.aborted) { again = false; result = await syncOnce() }
        return result
      } finally { running = undefined; again = false }
    })()
    return running
  }

  const automatic = (): boolean => !signal.aborted && (mode === 'always' || session.diagnostics().length === 0)
  const background = (): void => { if (automatic()) void synchronize().catch(() => undefined) }

  const stopFacts = session.onFacts((delta: FactsDelta) => {
    if (!delta.items.some(item => item.source !== HTTP_SYNC_SOURCE)) return
    if (pushTimer !== undefined || !automatic()) return
    pushTimer = setTimeout(() => { pushTimer = undefined; background() }, pushDelayMs)
  })
  const poll = intervalMs > 0 ? setInterval(background, intervalMs) : undefined
  ;(poll as { unref?(): void } | undefined)?.unref?.()

  const close = (): void => {
    if (lifetime.signal.aborted) return
    lifetime.abort(new Error('HTTP_SYNC_CLOSED'))
    stopFacts()
    clearInterval(poll)
    clearTimeout(pushTimer)
  }
  signal.addEventListener('abort', close, { once: true })
  background()

  return {
    signal,
    get last() { return last },
    synchronize,
    close,
  }
}
