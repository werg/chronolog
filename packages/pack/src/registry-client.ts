import {
  signAuditAttestation,
  signBuildAttestation,
  verifyAuditAttestation,
  verifyBuildAttestation,
  type SignedAuditAttestation,
  type SignedBuildAttestation,
} from '@chronolog/materializer'
import type { ApplicationOperation, ApplicationSession, SessionCasNode } from '@chronolog/peer-session'
import type { JsonValue } from '@chronolog/protocol'
import { parseCasRef, type ChronologBuiltinName, type ChronologPackageRuntime } from '@chronolog/records'

export interface RegistryPackageMatch {
  readonly name: string
  readonly description: string
  readonly latestVersion: string
  readonly publisher: string
  readonly updatedAt: number
}

export interface RegistryResolvedPackage {
  readonly name: string
  readonly version: string
  readonly pkgRef: string
  readonly drvRef: string | null
  readonly runtime: ChronologPackageRuntime
  readonly builtins: readonly ChronologBuiltinName[]
  readonly describeSchema: JsonValue | null
  readonly publisher: string
  readonly publishedAt: number
  readonly revoked: boolean
  readonly attestations: readonly {
    readonly kind: 'build' | 'audit'
    readonly verdict: string | null
    readonly signer: string
    readonly signature: string
    readonly drvRef: string | null
    readonly runtime: string | null
    readonly notes: string | null
  }[]
}

/**
 * Ergonomic client wrapper around a dogfooded Chronolog Registry session (`createRegistryGenesis`).
 * Supports publishing packages + CAS DAGs, recording signed build/audit attestations,
 * FTS5 search, version resolution, and one-call verified install into any target ApplicationSession.
 */
export class RegistryClient {
  constructor(readonly session: ApplicationSession) {}

  async publish(options: {
    readonly name: string
    readonly version: string
    readonly pkgRef: string
    readonly drvRef?: string
    readonly runtime?: ChronologPackageRuntime
    readonly builtins?: readonly ChronologBuiltinName[]
    readonly description?: string
    readonly describeSchema?: JsonValue
    readonly casNodes?: readonly SessionCasNode[]
  }): Promise<ApplicationOperation> {
    if (options.casNodes !== undefined && options.casNodes.length > 0) {
      await this.session.cas.putManyVerified(options.casNodes)
    }
    return this.session.submit({
      awaitMaterialized: true,
      updates: [{
        topic: 'packages',
        input: {
          action: 'publish',
          name: options.name,
          version: options.version,
          pkgRef: options.pkgRef,
          ...(options.drvRef === undefined ? {} : { drvRef: options.drvRef }),
          runtime: options.runtime ?? 'esm-quickjs',
          builtins: [...(options.builtins ?? [])],
          description: options.description ?? '',
          ...(options.describeSchema === undefined ? {} : { describeSchema: options.describeSchema }),
        },
      }],
    })
  }

  async attestBuild(options: {
    readonly drvRef: string
    readonly outputRef: string
    readonly runtime: string
    readonly signer?: string
    readonly privateKey?: CryptoKey
  }): Promise<{ readonly attestation: SignedBuildAttestation; readonly operation: ApplicationOperation }> {
    const attestation = await signBuildAttestation(
      { drvRef: options.drvRef, outputRef: options.outputRef, runtime: options.runtime },
      options.signer ?? this.session.device.identity.publicKey,
      options.privateKey ?? this.session.device.identity.privateKey,
    )
    const operation = await this.session.submit({
      awaitMaterialized: true,
      updates: [{
        topic: 'packages',
        input: { action: 'attest', attestation: attestation as unknown as JsonValue },
      }],
    })
    return { attestation, operation }
  }

  async attestAudit(options: {
    readonly pkgRef: string
    readonly verdict: 'approved' | 'revoked'
    readonly notes?: string
    readonly signer?: string
    readonly privateKey?: CryptoKey
  }): Promise<{ readonly attestation: SignedAuditAttestation; readonly operation: ApplicationOperation }> {
    const attestation = await signAuditAttestation(
      {
        pkgRef: options.pkgRef,
        verdict: options.verdict,
        ...(options.notes === undefined ? {} : { notes: options.notes }),
      },
      options.signer ?? this.session.device.identity.publicKey,
      options.privateKey ?? this.session.device.identity.privateKey,
    )
    const operation = await this.session.submit({
      awaitMaterialized: true,
      updates: [{
        topic: 'packages',
        input: { action: 'attest', attestation: attestation as unknown as JsonValue },
      }],
    })
    return { attestation, operation }
  }

  async search(q: string, limit = 25): Promise<readonly RegistryPackageMatch[]> {
    const res = await this.session.query('packages', { query: 'search', q, limit })
    return Array.isArray(res.value) ? (res.value as readonly RegistryPackageMatch[]) : []
  }

  async resolve(name: string, version?: string): Promise<RegistryResolvedPackage | null> {
    const res = await this.session.query('packages', {
      query: 'resolve',
      name,
      ...(version === undefined ? {} : { version }),
    })
    return res.value === null ? null : (res.value as unknown as RegistryResolvedPackage)
  }

  async resolveByHash(pkgRef: string): Promise<JsonValue> {
    const res = await this.session.query('packages', { query: 'resolveByHash', pkgRef })
    return res.value as JsonValue
  }

  /**
   * Resolve a package from this Registry Chronolog, verify optional attestation policy,
   * transfer its CAS Merkle-DAG subgraph to `targetSession`, and install it into `$reducers`.
   */
  async installInto(
    targetSession: ApplicationSession,
    options: {
      readonly name: string
      readonly version?: string
      readonly alias?: string
      readonly topics?: Readonly<Record<string, { readonly export?: string; readonly config?: JsonValue }>>
      readonly minBuildAttestations?: number
      readonly requireAudit?: boolean
      readonly trustedBuilders?: readonly string[]
      readonly trustedAuditors?: readonly string[]
    },
  ): Promise<{ readonly resolved: RegistryResolvedPackage; readonly operation: ApplicationOperation }> {
    const resolved = await this.resolve(options.name, options.version)
    if (resolved === null) throw new Error(`REGISTRY_PACKAGE_NOT_FOUND:${options.name}`)
    if (resolved.revoked) throw new Error(`REGISTRY_PACKAGE_REVOKED:${options.name}@${resolved.version}`)

    const verifiedAttestations: JsonValue[] = []
    const buildSigners = new Set<string>()
    const auditSigners = new Set<string>()
    for (const a of resolved.attestations) {
      if (a.kind === 'build' && a.drvRef !== null && a.runtime !== null) {
        const signed: SignedBuildAttestation = {
          payload: {
            format: 'chronolog-attestation/v1',
            kind: 'build',
            drvRef: a.drvRef,
            outputRef: resolved.pkgRef,
            runtime: a.runtime,
          },
          signer: a.signer,
          signature: a.signature,
        }
        if (verifyBuildAttestation(signed)) {
          if (options.trustedBuilders === undefined || options.trustedBuilders.includes(a.signer)) {
            buildSigners.add(a.signer)
            verifiedAttestations.push(signed as unknown as JsonValue)
          }
        }
      } else if (a.kind === 'audit' && (a.verdict === 'approved' || a.verdict === 'revoked')) {
        const signed: SignedAuditAttestation = {
          payload: {
            format: 'chronolog-attestation/v1',
            kind: 'audit',
            pkgRef: resolved.pkgRef,
            verdict: a.verdict,
            ...(a.notes === null ? {} : { notes: a.notes }),
          },
          signer: a.signer,
          signature: a.signature,
        }
        if (verifyAuditAttestation(signed) && a.verdict === 'approved') {
          if (options.trustedAuditors === undefined || options.trustedAuditors.includes(a.signer)) {
            auditSigners.add(a.signer)
            verifiedAttestations.push(signed as unknown as JsonValue)
          }
        }
      }
    }

    if (options.minBuildAttestations !== undefined && buildSigners.size < options.minBuildAttestations) {
      throw new Error(`REGISTRY_BUILD_ATTESTATIONS_INSUFFICIENT:${buildSigners.size}<${options.minBuildAttestations}`)
    }
    if (options.requireAudit === true && auditSigners.size < 1) {
      throw new Error(`REGISTRY_AUDIT_REQUIRED:${resolved.pkgRef}`)
    }

    const pkgHash = parseCasRef(resolved.pkgRef)
    const casNodes = await this.session.exportCasNodes([pkgHash], false, { subgraph: true })
    const installed = await targetSession.installPackage(
      { ref: resolved.pkgRef, casNodes },
      {
        alias: options.alias ?? resolved.name,
        ...(options.topics === undefined ? {} : { topics: options.topics }),
        ...(verifiedAttestations.length > 0 ? { attestations: verifiedAttestations } : {}),
      },
    )
    return { resolved, operation: installed.operation }
  }
}
