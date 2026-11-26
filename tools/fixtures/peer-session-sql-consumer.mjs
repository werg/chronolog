import assert from 'node:assert/strict';
import { join } from 'node:path';
import process from 'node:process';
import {
  createApplicationSession, createSigningIdentity, signAppDescriptor, signMembership,
  epochKeyCommitment, executionManifestArtifacts, bytesToHex, defineApplication,
  defineCommand, defineQuery, emit, program, sqlStatement,
} from '@chronolog/peer-session';
import { openNativeDevice } from '@chronolog/peer-session/native';
import { createSqlMaterializationRuntime } from '@chronolog/peer-session/sql';

const directory = process.argv[2], sessions = [];
let engine;
if (process.argv[3]) {
  const { loadNodeWasmEngine, createNodeWasmSqlEngine } = await import('@chronolog/peer-session/sql-wasm');
  const loaded = await loadNodeWasmEngine(process.argv[3]);
  engine = createNodeWasmSqlEngine({ module: loaded.module, manifest: loaded.manifest });
} else {
  const { createNativeSqlEngine } = await import('@chronolog/peer-session/sql-native');
  engine = createNativeSqlEngine();
}
const object = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const title = { type: 'string', minLength: 1, maxLength: 100 };
const definition = defineApplication({ id: 'packed-shared-board', version: '1', commands: {
  create: defineCommand({ description: 'Create a signer-owned task', input: object({ id: { type: 'integer' }, title }),
    prepare: ({ id, title }) => program(sqlStatement('INSERT INTO tasks(id,title) VALUES(?,?)', [id, title]), emit('task.created', { id, title })) }),
  rename: defineCommand({ description: 'Review and rename an owned task', input: object({ id: { type: 'integer' }, expected: title, title }),
    prepare: ({ id, expected, title }) => program(
      sqlStatement("SELECT chronolog_assert((SELECT title FROM tasks WHERE id=?)=?, 'title_changed')", [id, expected]),
      sqlStatement('UPDATE tasks SET title=? WHERE id=?', [title, id]), emit('task.renamed', { id, title })) }),
}, queries: { tasks: defineQuery({ description: 'Read current tasks', input: { type: 'null' },
  read: view => view.query('SELECT id,title FROM tasks ORDER BY id') }) } });
const initialization = program(sqlStatement('CREATE TABLE tasks(id INTEGER PRIMARY KEY,title TEXT NOT NULL UNIQUE)'));
let captured;
try {
  const issuer = await createSigningIdentity();
  const aDevice = await openNativeDevice({ path: join(directory, 'a.sqlite'), create: true });
  const bDevice = await openNativeDevice({ path: join(directory, 'b.sqlite'), create: true });
  const applicationId = 'db'.repeat(32), key = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const { executionManifestDigest } = await executionManifestArtifacts(engine.executionManifest);
  const descriptor = await signAppDescriptor({ applicationId, rootPrincipal: aDevice.identity.publicKey,
    authorityPublicKey: issuer.publicKey, executionManifestDigest: bytesToHex(executionManifestDigest), finalityPolicy: { kind: 'none' } }, issuer);
  const membership = await signMembership({ admission: { mode: 'attested', hostKey: 'ee'.repeat(32), accounts: [], grant: { reader: true, writer: true, administrator: true } }, admitted: [], invites: [], applicationId, revision: 0, previous: null, authorTimeAfterMs: -1n,
    epoch: 0, epochKeyDigest: await epochKeyCommitment(applicationId, 0, key), members: [aDevice, bDevice].map((device, index) => ({
      publicKey: device.identity.publicKey, wrapKey: null, reader: true, writer: true, administrator: index === 0, publisher: index === 0, finalizer: false,
    })) }, issuer);
  const bundle = { descriptor, memberships: [membership] };
  async function open(device, name, fresh = true) {
    const session = await createApplicationSession({ device, definition,
      ...(fresh ? { authority: bundle, epochKeys: new Map([[0, key]]) } : { applicationId }),
      createMaterializer: ({ rootPrincipal }) => createSqlMaterializationRuntime({ engine, path: join(directory, `${name}-materialized.sqlite`), rootPrincipal }),
    });
    sessions.push(session); return session;
  }
  async function exchange(a, b) {
    const left = a.exportFacts(), right = b.exportFacts();
    await Promise.all([a.mergeFacts(right), b.mergeFacts(left)]);
    await Promise.all([a.retryMaterialization(), b.retryMaterialization()]);
  }
  const accepted = async operation => assert.equal((await operation.materialized({ timeoutMs: 15_000 })).outcome, 'accepted');
  const a = await open(aDevice, 'a'), b = await open(bDevice, 'b');
  await accepted(await a.submit({ operationId: 'ordinary-schema', authorTimestampMs: 1n, program: initialization }));
  await exchange(a, b);

  // Both stores author and materialize with no connection or external participant.
  const first = await a.command('create', { id: 1, title: 'retained' }, { operationId: 'create-once', authorTimestampMs: 20n });
  const second = await b.command('create', { id: 2, title: 'other' }, { operationId: 'independent', authorTimestampMs: 10n });
  assert.equal(first.stored, true); await accepted(first); await accepted(second);
  await exchange(a, b);
  assert.deepEqual((await a.query('tasks', null)).value.rows, [[1, 'retained'], [2, 'other']]);
  assert.deepEqual((await b.query('tasks', null)).value.rows, [[1, 'retained'], [2, 'other']]);
  captured = await a.readView();

  const duplicate = await a.command('create', { id: 3, title: 'other' }, { operationId: 'constraint-revises', authorTimestampMs: 40n });
  assert.equal((await duplicate.materialized({ timeoutMs: 15_000 })).outcome, 'rejected');
  const originalReference = duplicate.id;
  const earlier = await b.command('rename', { id: 2, expected: 'other', title: 'renamed' }, { operationId: 'late-earlier', authorTimestampMs: 15n });
  await accepted(earlier); await exchange(a, b);
  assert.equal((await duplicate.inspect()).materialized.outcome, 'accepted');
  assert.equal((await a.operations.retry('constraint-revises')).id, originalReference);
  assert.deepEqual(captured.query('SELECT id,title FROM tasks ORDER BY id').rows, [[1, 'retained'], [2, 'other']]);
  await captured.release(); captured = null;

  // A normal DDL proposal arrives after SQL which needs it; replay revises rejection.
  const needsColumn = await b.submit({ operationId: 'needs-column', authorTimestampMs: 60n,
    program: program(sqlStatement("UPDATE tasks SET detail='qualified' WHERE id=2")) });
  assert.equal((await needsColumn.materialized({ timeoutMs: 15_000 })).outcome, 'rejected');
  const ddl = await a.submit({ operationId: 'ordinary-alter', authorTimestampMs: 50n,
    program: program(sqlStatement('ALTER TABLE tasks ADD COLUMN detail TEXT')) });
  await accepted(ddl); await exchange(a, b);
  assert.equal((await needsColumn.inspect()).materialized.outcome, 'accepted');
  const read = await b.readView();
  try { assert.deepEqual(read.query('SELECT id,title,detail FROM tasks ORDER BY id').rows,
    [[1, 'retained', null], [2, 'renamed', 'qualified'], [3, 'other', null]]); } finally { await read.release(); }

  const denied = await b.submit({ operationId: 'cross-object-ddl', authorTimestampMs: 70n,
    program: program(sqlStatement('DROP TABLE tasks')) });
  assert.equal((await denied.materialized({ timeoutMs: 15_000 })).outcome, 'rejected');
  const rollback = await a.submit({ operationId: 'atomic-ddl', authorTimestampMs: 80n,
    program: program(sqlStatement('CREATE TABLE must_rollback(id INTEGER PRIMARY KEY)'), sqlStatement("SELECT chronolog_assert(0,'rollback')")) });
  assert.equal((await rollback.materialized({ timeoutMs: 15_000 })).outcome, 'rejected');
  const check = await a.readView();
  try { assert.deepEqual(check.query("SELECT name FROM sqlite_schema WHERE name='must_rollback'").rows, []); } finally { await check.release(); }

  const identity = b.identity.publicKey;
  await a.close(); await b.close();
  const reopened = await open(await openNativeDevice({ path: join(directory, 'b.sqlite') }), 'b', false);
  assert.equal(reopened.identity.publicKey, identity);
  const restored = await reopened.operations.get('needs-column');
  assert.equal((await restored.inspect()).proposalId, needsColumn.id);
  await accepted(restored);
  assert.equal((await restored.inspect()).materialized.outcome, 'accepted');
  assert.deepEqual((await reopened.query('tasks', null)).value.rows, [[1, 'retained'], [2, 'renamed'], [3, 'other']]);
  await assert.rejects((await reopened.operations.get('needs-column')).finalized(), { code: 'FINALITY_UNSUPPORTED' });
  process.stdout.write(JSON.stringify({ status: 'passed', profile: 'chronolog-crdt-v1', application: definition.id,
    transport: 'explicit-authenticated-fact-union', checks: ['ordinary authored schema', 'independent offline materialization',
      'deterministic fact union', 'late predecessor revises rejection', 'exact retry identity', 'captured read stability',
      'ordinary late DDL revises SQL', 'scoped DDL denial', 'mixed DDL rollback', 'cached keys and identity reopen', 'no-finality unsupported wait'] }) + '\n');
} finally {
  await captured?.release();
  for (const session of sessions.reverse()) await session.close();
}
