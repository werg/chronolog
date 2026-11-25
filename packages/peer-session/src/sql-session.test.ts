import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, expect, it } from 'vitest'
import { createNativeSqlEngine } from './sql-native.js'
import { createSqlMaterializationRuntime } from './sql.js'
import { createApplicationSession } from './runtime.js'
import { openApplicationDevice } from './device.js'
import { sessionFixture, eventDefinition } from './test-fixture.js'
import { bytesToHex, executionManifestArtifacts, hexToBytes, program, emit, platformOp } from '@chronolog/protocol'
import { signMembership } from '@chronolog/authority'
import type { ApplicationChange } from './session-types.js'
const closes: Array<() => Promise<void>> = []
afterEach(async () => { for (const close of closes.splice(0).reverse()) await close() })
it('replays ordinary signed DDL/grants/data after offline union, revises SQL outcomes/events, and reopens coherently', async () => {
  const engine = createNativeSqlEngine(), digest = bytesToHex((await executionManifestArtifacts(engine.executionManifest)).executionManifestDigest), f = await sessionFixture({ manifestDigest: digest }), directory = await mkdtemp(join(tmpdir(), 'authored-session-sql-')); closes.push(() => rm(directory, { recursive: true, force: true }))
  const open = async (index: number) => createApplicationSession({ device: await openApplicationDevice({ store: f.stores[index]!, create: true, managedSigner: f.identities[index]! }), definition: eventDefinition, authority: f.bundle, epochKeys: new Map([[0, f.epochKey]]), createMaterializer: ({ rootPrincipal }) => createSqlMaterializationRuntime({ engine, path: join(directory, `${index}.db`), rootPrincipal, checkpointEvery: 1 }) })
  const a = await open(0), b = await open(1); closes.push(() => a.close(), () => b.close())
  const insert = await b.submit({ operationId: 'offline-insert', authorTimestampMs: 20n, program: program("INSERT INTO notes (id, value) VALUES (1, 'offline')", emit('note', { id: 1 })) }); expect((await insert.materialized()).outcome).toBe('rejected'); expect((await b.readEvents()).events).toHaveLength(0)
  const before = await b.readView(); expect(() => before.query('SELECT * FROM notes')).toThrow()
  const schema = await a.submit({ operationId: 'ordinary-schema', authorTimestampMs: 10n, program: program('CREATE TABLE notes (id INTEGER PRIMARY KEY, value TEXT)', platformOp.grant({ table: 'notes', grantee: hexToBytes(f.identities[1]!.publicKey), operations: ['insert', 'update'] })) }); expect((await schema.materialized()).outcome).toBe('accepted')
  const changes: ApplicationChange[] = []; const stop = b.onChange(value => changes.push(value))
  const af = a.exportFacts(), bf = b.exportFacts(); await a.mergeFacts(bf); await b.mergeFacts(af); await a.retryMaterialization(); await b.retryMaterialization(); stop()
  expect(insert.inspect().materialized?.outcome).toBe('accepted'); expect(changes.some(change => change.revisedProposalIds.includes(insert.id))).toBe(true)
  const first = await a.readView(), second = await b.readView(); expect(first.query('SELECT value FROM notes').rows).toEqual([['offline']]); expect(second.query('SELECT value FROM notes').rows).toEqual(first.query('SELECT value FROM notes').rows); expect(first.revision.digest).toBe(second.revision.digest); expect(second.readEvents().events.map(event => event.topic)).toEqual(['note']); first.release(); second.release()
  expect(() => before.query('SELECT value FROM notes')).toThrow(); before.release()
  const denied = await b.submit({ authorTimestampMs: 30n, program: program('CREATE TABLE denied (id INTEGER PRIMARY KEY)') }); expect((await denied.materialized()).rejectionCode).toBe('denied')
  const membership = await signMembership({ ...f.membership.payload, revision: 1, previous: f.membershipId, authorTimeAfterMs: 100n, members: f.membership.payload.members.map(member => ({ ...member, administrator: true })) }, f.authorityIdentity)
  await b.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, membership] }); const stillDenied = await b.submit({ authorTimestampMs: 110n, program: program('CREATE TABLE still_denied (id INTEGER PRIMARY KEY)') }); expect((await stillDenied.materialized()).rejectionCode).toBe('denied')
  await a.mergeAuthority({ descriptor: f.descriptor, memberships: [f.membership, membership] }); const grant = await a.submit({ authorTimestampMs: 120n, program: program(platformOp.grantDdl({ scope: { kind: 'namespace', name: 'main' }, grantee: hexToBytes(f.identities[1]!.publicKey), operations: ['create'] })) }); expect((await grant.materialized()).outcome).toBe('accepted')
  await b.mergeFacts(a.exportFacts()); await b.retryMaterialization(); const created = await b.submit({ authorTimestampMs: 130n, program: program('CREATE TABLE own_new (id INTEGER PRIMARY KEY)') }); expect((await created.materialized()).outcome).toBe('accepted')
  const stable = (await b.readEvents()).revision.digest; await b.close(); const reopened = await open(1); closes.push(() => reopened.close()); const read = await reopened.readView(); expect(read.query('SELECT value FROM notes').rows).toEqual([['offline']]); expect(read.query("SELECT name FROM sqlite_schema WHERE name='own_new'").rows).toEqual([['own_new']]); expect(read.revision.digest).toBe(stable); read.release()
})
