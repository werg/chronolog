import assert from 'node:assert/strict';
import { join } from 'node:path';
import process from 'node:process';
import { webcrypto as crypto } from 'node:crypto';
import {
  APPLICATION_COLLECTIVE_ID, OWNER_FOR_KEY_SQL, bytesDigest, connectApplications, controlParticipantGrant,
  createGenerationRegistry, createPeerIdentity, defineApplication, defineCommand, defineQuery, emit,
  MemoryPeerStore, participantGrant, program, signApplicationDescriptor, signControlRevision, signTransitionRequest, sqlStatement,
} from '@chronolog/peer-session';
import { openNativeDevice } from '@chronolog/peer-session/native';
import { openNativeSqlApplication, prepareNativeSqlApplication } from '@chronolog/peer-session/sql-native';

const directory = process.argv[2], sessions = [], links = [];
const definition = defineApplication({ id: 'packed-shared-board', version: '1',
  schema: program('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT NOT NULL UNIQUE)'),
  commands: {
    create: defineCommand({ description: 'Create a shared task', input: { type: 'object', properties: {
      id: { type: 'integer' }, title: { type: 'string', minLength: 1, maxLength: 100 },
    }, required: ['id', 'title'] }, prepare: ({ id, title }) => program(sqlStatement(
      `INSERT INTO tasks (id,title,chronolog_owner) VALUES (?, ?, ${OWNER_FOR_KEY_SQL})`, [id, title, APPLICATION_COLLECTIVE_ID]), emit('task.created', { id, title })) }),
    rename: defineCommand({ description: 'Rename a shared task', input: { type: 'string', minLength: 1, maxLength: 100 },
      prepare: title => program(sqlStatement('UPDATE tasks SET title=? WHERE id=1', [title]), emit('task.renamed', { title })) }),
  },
  queries: { tasks: defineQuery({ description: 'Read current tasks', input: { type: 'null' }, read: view => view.query('SELECT id,title FROM tasks ORDER BY id') }) },
});
try {
  const host = await createPeerIdentity(), aDevice = await openNativeDevice({ path: join(directory, 'a.sqlite'), create: true });
  const bDevice = await openNativeDevice({ path: join(directory, 'b.sqlite'), create: true });
  const applicationId = 'db'.repeat(32), key = crypto.getRandomValues(new Uint8Array(32));
  const prepared = await prepareNativeSqlApplication({ applicationId, definition, schemaAdministrator: aDevice.identity });
  const descriptor = await signApplicationDescriptor({ applicationId, historyId: 'packed-sql', profile: 'peer-generation-v1', policy: 'eligible-members-v1',
    controlPublicKey: host.publicKey, ...prepared.binding }, host);
  const control = await signControlRevision({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    revision: 0, previous: null, epoch: 0, keyDigest: await bytesDigest(key), recoveryFloor: null,
    grants: [controlParticipantGrant(host.publicKey), participantGrant(aDevice.identity.publicKey), participantGrant(bDevice.identity.publicKey)] }, host);
  const registry = await createGenerationRegistry({ store: new MemoryPeerStore(), descriptor, controls: [control], signer: host });
  await registry.select(await signTransitionRequest({ applicationId, profile: descriptor.payload.profile, policy: descriptor.payload.policy,
    expectedGeneration: null, requester: aDevice.identity.publicKey, coordinator: aDevice.identity.publicKey,
    controlRevision: 0, base: null, reason: 'create', transitionId: 'initial' }, aDevice.identity));
  const open = async (device, name) => {
    const app = await openNativeSqlApplication({ device, databasePath: join(directory, `${name}-materialized.sqlite`), definition,
      authority: await registry.read(), epochKeys: new Map([[0, key]]), schema: prepared.schema });
    sessions.push(app); return app;
  };
  const a = await open(aDevice, 'a'), b = await open(bDevice, 'b');
  const link = await connectApplications(a, b); links.push(link);
  assert.equal((await (await a.command('create', { id: 1, title: 'retained' }, { operationId: 'create-once' })).applied()).outcome, 'accepted');
  await link.synchronize(); link.close();
  const rejected = await (await a.command('create', { id: 2, title: 'retained' }, { operationId: 'duplicate' })).applied();
  assert.equal(rejected.outcome, 'rejected');
  assert.equal(rejected.rejectionCode, 'constraint');
  const controlHost = { application: () => registry.read(), selectGeneration: request => registry.select(request) };
  await b.recovery.takeover(controlHost, { transitionId: 'creator-offline' });
  const recovered = await connectApplications(a, b); links.push(recovered);
  assert.equal((await a.operations.get('duplicate')).status, 'abandoned');
  recovered.close(); await a.close();
  assert.equal((await (await b.command('rename', 'edited after creator closed', { operationId: 'rename-once' })).applied()).outcome, 'accepted');
  assert.deepEqual((await b.query('tasks', null)).value.rows, [[1, 'edited after creator closed']]);
  const bId = b.deviceId; await b.close();
  const reopened = await open(await openNativeDevice({ path: join(directory, 'b.sqlite') }), 'b');
  assert.equal(reopened.deviceId, bId);
  assert.deepEqual((await reopened.query('tasks', null)).value.rows, [[1, 'edited after creator closed']]);
  assert.equal((await reopened.operations.get('rename-once')).outcome, 'accepted');
  process.stdout.write(JSON.stringify({ status: 'passed', profile: 'peer-generation-v1', application: definition.id,
    checks: ['signed schema bootstrap', 'real SQL constraints', 'earlier prefix recovery', 'shared rows after creator closes', 'native reopen identity and outcomes'] }) + '\n');
} finally {
  for (const link of links) link.close();
  for (const session of sessions.reverse()) await session.close();
}
