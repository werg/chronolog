import { bytesToHex, hexToBytes, utf8 } from '@chronolog/canonical'
import { verifyEd25519Sync } from '@chronolog/crypto'
import { canonicalJson, DEFAULT_RUNTIME_MANIFEST, type JsonValue } from '@chronolog/protocol'
import {
  casRef,
  decodeDerivationNode,
  parseCasRef,
  tryParseCasRef,
  type BytesStore,
  type CasPartition,
  type ChronologDerivationNode,
  type ContentAddressedStore,
} from '@chronolog/records'
import { MissingDependencyError, type QuickJsSandbox } from './quickjs-sandbox.js'

export interface BuildAttestationPayload {
  readonly format: 'chronolog-attestation/v1'
  readonly kind: 'build'
  readonly drvRef: string
  readonly outputRef: string
  readonly runtime: string
}

export interface AuditAttestationPayload {
  readonly format: 'chronolog-attestation/v1'
  readonly kind: 'audit'
  readonly pkgRef: string
  readonly verdict: 'approved' | 'revoked'
  readonly notes?: string
}

export interface SignedBuildAttestation {
  readonly payload: BuildAttestationPayload
  readonly signer: string
  readonly signature: string
}

export interface SignedAuditAttestation {
  readonly payload: AuditAttestationPayload
  readonly signer: string
  readonly signature: string
}

export function canonicalAttestationMessage(payload: BuildAttestationPayload | AuditAttestationPayload): string {
  return `chronolog/attestation/v1:${canonicalJson(payload as unknown as JsonValue)}`
}

export async function signBuildAttestation(
  payload: Omit<BuildAttestationPayload, 'format' | 'kind'>,
  signerPublicKeyHex: string,
  privateKey: CryptoKey,
): Promise<SignedBuildAttestation> {
  const full: BuildAttestationPayload = {
    format: 'chronolog-attestation/v1',
    kind: 'build',
    drvRef: casRef(parseCasRef(payload.drvRef)),
    outputRef: casRef(parseCasRef(payload.outputRef)),
    runtime: payload.runtime,
  }
  const msg = utf8(canonicalAttestationMessage(full))
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, new Uint8Array(msg)))
  return { payload: full, signer: signerPublicKeyHex, signature: bytesToHex(sig) }
}

export function verifyBuildAttestation(attestation: SignedBuildAttestation): boolean {
  if (attestation.payload.format !== 'chronolog-attestation/v1' || attestation.payload.kind !== 'build') return false
  if (tryParseCasRef(attestation.payload.drvRef) === null || tryParseCasRef(attestation.payload.outputRef) === null) return false
  if (!/^[0-9a-f]{64}$/u.test(attestation.signer) || !/^[0-9a-f]{128}$/u.test(attestation.signature)) return false
  return verifyEd25519Sync(
    hexToBytes(attestation.signer),
    utf8(canonicalAttestationMessage(attestation.payload)),
    hexToBytes(attestation.signature),
  )
}

export async function signAuditAttestation(
  payload: Omit<AuditAttestationPayload, 'format' | 'kind'>,
  signerPublicKeyHex: string,
  privateKey: CryptoKey,
): Promise<SignedAuditAttestation> {
  const full: AuditAttestationPayload = {
    format: 'chronolog-attestation/v1',
    kind: 'audit',
    pkgRef: casRef(parseCasRef(payload.pkgRef)),
    verdict: payload.verdict,
    ...(payload.notes === undefined ? {} : { notes: payload.notes }),
  }
  const msg = utf8(canonicalAttestationMessage(full))
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, new Uint8Array(msg)))
  return { payload: full, signer: signerPublicKeyHex, signature: bytesToHex(sig) }
}

export function verifyAuditAttestation(attestation: SignedAuditAttestation): boolean {
  if (attestation.payload.format !== 'chronolog-attestation/v1' || attestation.payload.kind !== 'audit') return false
  if (tryParseCasRef(attestation.payload.pkgRef) === null) return false
  if (attestation.payload.verdict !== 'approved' && attestation.payload.verdict !== 'revoked') return false
  if (!/^[0-9a-f]{64}$/u.test(attestation.signer) || !/^[0-9a-f]{128}$/u.test(attestation.signature)) return false
  return verifyEd25519Sync(
    hexToBytes(attestation.signer),
    utf8(canonicalAttestationMessage(attestation.payload)),
    hexToBytes(attestation.signature),
  )
}

export type WasiDerivationRunner = (
  drv: ChronologDerivationNode,
  cas: ContentAddressedStore,
  partition: CasPartition,
) => Promise<string>

export interface DerivationMemoCache {
  get(drvHash: string): Promise<string | null>
  set(drvHash: string, outputHash: string): Promise<void>
}

export function createBytesStoreDerivationMemo(store: BytesStore, prefix = 'drv-memo/'): DerivationMemoCache {
  const mem = new Map<string, string>()
  return {
    async get(drvHash: string): Promise<string | null> {
      const hit = mem.get(drvHash)
      if (hit !== undefined) return hit
      const raw = await store.get(`${prefix}${drvHash}`)
      if (raw === null) return null
      const hash = new TextDecoder().decode(raw)
      if (!/^[0-9a-f]{64}$/u.test(hash)) return null
      mem.set(drvHash, hash)
      return hash
    },
    async set(drvHash: string, outputHash: string): Promise<void> {
      mem.set(drvHash, outputHash)
      await store.put(`${prefix}${drvHash}`, utf8(outputHash), { durability: 'relaxed' })
    },
  }
}

export interface EvaluateDerivationOptions {
  readonly drvRefOrHash: string
  readonly cas: ContentAddressedStore
  readonly sandbox: QuickJsSandbox
  readonly partition?: CasPartition
  readonly memo?: DerivationMemoCache
  readonly skipMemo?: boolean
  readonly wasiRunners?: Readonly<Record<string, WasiDerivationRunner>>
  readonly imports?: Readonly<Record<string, string>>
}

export interface DerivationEvalResult {
  readonly drvHash: string
  readonly drvRef: string
  readonly outputHash: string
  readonly outputRef: string
  readonly fromCache: boolean
}

/**
 * Evaluate a content-addressed chronolog-drv/v1 derivation deterministically (CAS -> CAS).
 * - 'quickjs-inline' derivations execute directly in QuickJsSandbox (zero external authority).
 * - 'wasi-cas-v1' derivations execute via a registered deterministic CAS-backed runner.
 * Results are permanently memoizable by drvHash because execution is pure and deterministic.
 */
export async function evaluateDerivation(options: EvaluateDerivationOptions): Promise<DerivationEvalResult> {
  const drvHash = tryParseCasRef(options.drvRefOrHash) ?? options.drvRefOrHash
  if (!/^[0-9a-f]{64}$/u.test(drvHash)) throw new Error(`DRV_HASH_INVALID:${options.drvRefOrHash}`)
  const partition: CasPartition = options.partition ?? 'public'

  if (!options.skipMemo && options.memo !== undefined) {
    const cached = await options.memo.get(drvHash)
    if (cached !== null && await options.cas.ensureLoaded(cached, partition)) {
      return {
        drvHash,
        drvRef: casRef(drvHash),
        outputHash: cached,
        outputRef: casRef(cached),
        fromCache: true,
      }
    }
  }

  const drvNode = await options.cas.get(drvHash, partition)
  if (drvNode === null) throw new MissingDependencyError(drvHash, 'cas')
  const drv = decodeDerivationNode(drvNode.bytes)

  let outputHash: string
  if (drv.profile === 'quickjs-inline') {
    options.cas.beginBatch()
    try {
      const res = await options.sandbox.invoke({
        imports: { ...(options.imports ?? {}), __builder__: drv.builder },
        builtins: DEFAULT_RUNTIME_MANIFEST.builtins,
        moduleSpecifier: '__builder__',
        exportName: 'default',
        method: 'derive',
        logId: null,
        state: null,
        payload: {
          inputs: drv.inputs,
          args: drv.args as JsonValue,
        },
        topics: {},
        cas: options.cas,
        casPartition: partition,
        readOnly: false,
        maxMemoryBytes: drv.limits.maxMemoryBytes,
        maxFuel: drv.limits.maxFuel,
      })
      if (!res.ok) {
        throw new Error(`DERIVATION_EXEC_FAILED:${res.code}:${res.detail ?? ''}`)
      }
      const val = res.value
      const rawOut = typeof val === 'string'
        ? val
        : (val !== null && typeof val === 'object' && !Array.isArray(val) && typeof (val as Record<string, unknown>).output === 'string')
          ? String((val as Record<string, unknown>).output)
          : null
      if (rawOut === null) throw new Error('DERIVATION_OUTPUT_INVALID')
      const parsedOut = tryParseCasRef(rawOut) ?? rawOut
      if (!/^[0-9a-f]{64}$/u.test(parsedOut)) throw new Error(`DERIVATION_OUTPUT_HASH_INVALID:${rawOut}`)
      if (!options.cas.hasSync(parsedOut, partition)) throw new Error(`DERIVATION_OUTPUT_MISSING_IN_CAS:${parsedOut}`)
      await options.cas.flushBatch()
      outputHash = parsedOut
    } catch (err) {
      options.cas.rollbackBatch()
      throw err
    }
  } else {
    const runner = options.wasiRunners?.[drv.builder] ?? options.wasiRunners?.['*']
    if (runner === undefined) {
      throw new Error(`DERIVATION_WASI_RUNNER_MISSING:${drv.builder}`)
    }
    const rawOut = await runner(drv, options.cas, partition)
    const parsedOut = tryParseCasRef(rawOut) ?? rawOut
    if (!/^[0-9a-f]{64}$/u.test(parsedOut)) throw new Error(`DERIVATION_OUTPUT_HASH_INVALID:${rawOut}`)
    outputHash = parsedOut
  }

  if (options.memo !== undefined) {
    await options.memo.set(drvHash, outputHash)
  }
  return {
    drvHash,
    drvRef: casRef(drvHash),
    outputHash,
    outputRef: casRef(outputHash),
    fromCache: false,
  }
}

/** Permissionlessly recompute a derivation and verify that it matches an attested output hash. */
export async function verifyDerivationOutput(
  options: EvaluateDerivationOptions & { readonly expectedOutputRef: string },
): Promise<{ readonly valid: boolean; readonly expectedOutputRef: string; readonly actualOutputRef: string }> {
  const expectedHash = tryParseCasRef(options.expectedOutputRef) ?? options.expectedOutputRef
  const evaluated = await evaluateDerivation({ ...options, skipMemo: true })
  return {
    valid: evaluated.outputHash === expectedHash,
    expectedOutputRef: casRef(expectedHash),
    actualOutputRef: evaluated.outputRef,
  }
}
