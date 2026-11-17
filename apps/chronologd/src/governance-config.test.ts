import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { generateEd25519KeyPair } from '@chronolog/protocol'
import { afterEach, describe, expect, it } from 'vitest'

import { loadOrCreateGovernanceBootstrap } from './governance-config.js'
import { MemoryDaemonSecretStore } from './secret-store.js'

const directories: string[] = []
afterEach(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))))

describe('daemon governance bootstrap', () => {
  it('pins the signed clock policy and rejects a local override on reopen', async () => {
    const dataDirectory = await mkdtemp(join(tmpdir(), 'chronolog-governance-clock-'))
    directories.push(dataDirectory)
    const options = { dataDirectory, groupId: bytes32(61), schemaId: bytes32(62),
      identity: await generateEd25519KeyPair(), transportAuthor: '@root.ed25519',
      clockPolicy: { cutoffLagMs: 250n, maxFutureSkewMs: 5_000n, heartbeatIntervalMs: 25n } }
    const first = await loadOrCreateGovernanceBootstrap(options)
    expect(first.genesis.manifest.clockPolicy).toEqual(options.clockPolicy)
    const { clockPolicy: _clockPolicy, ...reopen } = options
    expect((await loadOrCreateGovernanceBootstrap(reopen)).genesis).toEqual(first.genesis)
    await expect(loadOrCreateGovernanceBootstrap({ ...options,
      clockPolicy: { ...options.clockPolicy, cutoffLagMs: 251n } })).rejects.toThrow('GOVERNANCE_CLOCK_POLICY_MISMATCH')
    expect((await loadOrCreateGovernanceBootstrap(options)).genesis).toEqual(first.genesis)
  })

  it('persists one private bootstrap and reloads its signed genesis exactly', async () => {
    const dataDirectory = await mkdtemp(join(tmpdir(), 'chronolog-governance-config-'))
    directories.push(dataDirectory)
    const identity = await generateEd25519KeyPair()
    const options = {
      dataDirectory,
      groupId: bytes32(1),
      schemaId: bytes32(2),
      identity,
      transportAuthor: '@root.ed25519',
      now: () => 100,
    }
    const first = await loadOrCreateGovernanceBootstrap(options)
    const second = await loadOrCreateGovernanceBootstrap(options)
    expect((await stat(join(dataDirectory, 'governance.json'))).mode & 0o777).toBe(0o600)
    expect(second.genesis).toEqual(first.genesis)
    expect(second.validationPolicyId).toEqual(first.validationPolicyId)
    expect(second.recipientId).toEqual(identity.publicKeyBytes)
  })

  it('keeps the recipient private key out of the governance document', async () => {
    const dataDirectory = await mkdtemp(join(tmpdir(), 'chronolog-governance-secrets-'))
    directories.push(dataDirectory)
    const secretStore = new MemoryDaemonSecretStore()
    const options = {
      dataDirectory,
      groupId: bytes32(11),
      schemaId: bytes32(12),
      identity: await generateEd25519KeyPair(),
      transportAuthor: '@root.ed25519',
      secretStore,
      now: () => 100,
    }
    const first = await loadOrCreateGovernanceBootstrap(options)
    const document = JSON.parse(await readFile(join(dataDirectory, 'governance.json'), 'utf8')) as Record<string, unknown>
    expect(document.format).toBe('chronolog-governance-bootstrap-v2')
    expect(document).not.toHaveProperty('recipientPrivateKeyPkcs8')
    const second = await loadOrCreateGovernanceBootstrap(options)
    expect(second.genesis).toEqual(first.genesis)
    const { secretStore: _secretStore, ...withoutSecretStore } = options
    await expect(loadOrCreateGovernanceBootstrap(withoutSecretStore))
      .rejects.toThrow('DAEMON_SECRET_STORE_REQUIRED')
  })

  it('pins one native authority and rejects policy/profile changes on an existing history', async () => {
    const dataDirectory = await mkdtemp(join(tmpdir(), 'chronolog-coordinated-config-'))
    directories.push(dataDirectory)
    const options = { dataDirectory, groupId: bytes32(21), schemaId: bytes32(22),
      identity: await generateEd25519KeyPair(), transportAuthor: '@root.ed25519', historyPolicy: 'coordinated' as const,
      clockPolicy: { cutoffLagMs: 250n, maxFutureSkewMs: 30_000n, heartbeatIntervalMs: 25n } }
    const first = await loadOrCreateGovernanceBootstrap(options)
    const second = await loadOrCreateGovernanceBootstrap(options)
    expect(first.genesis.manifest.historyPolicy).toMatchObject({ kind: 'coordinated', authorityPublicKey: options.identity.publicKeyBytes })
    expect(first.genesis.manifest.historyPolicy?.historyId).toMatch(/^h_[0-9a-f]{32}$/u)
    expect(second.genesis).toEqual(first.genesis)
    expect(first.genesis.manifest.clockPolicy).toEqual(options.clockPolicy)
    expect(first.genesis.manifest.initialCapabilities.find((capability) => capability.role === 'writer')?.program)
      .toEqual({ sql: true, topics: ['*'], signals: ['*'], forwarded: false })
    await expect(loadOrCreateGovernanceBootstrap({ ...options, historyPolicy: 'peer' })).rejects.toThrow('GOVERNANCE_HISTORY_POLICY_MISMATCH')
    await expect(loadOrCreateGovernanceBootstrap({ ...options, schemaId: bytes32(23) })).rejects.toThrow('GOVERNANCE_EXECUTION_PROFILE_MISMATCH')
    await expect(loadOrCreateGovernanceBootstrap({ ...options,
      clockPolicy: { ...options.clockPolicy, cutoffLagMs: 0n } })).rejects.toThrow('GOVERNANCE_CLOCK_POLICY_MISMATCH')
  })
})

function bytes32(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_value, index) => (seed + index) & 0xff)
}
