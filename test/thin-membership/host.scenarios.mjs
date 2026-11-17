/* global fetch, URL, performance, setTimeout */
import { beforeAll, expect, inject, it } from 'vitest';
import { createTestPage, initializeTestService } from '@tendriller/engine/testing';
import { createMembersClient } from '@tendriller/core/members';
import { base64UrlToBytes, bytesToBase64Url, decodeMembershipLedgerResponse, decodeSignedGenesis } from './membership-api.mjs';

beforeAll(() => initializeTestService(inject('d1Migrations')));
const fixtureBase = inject('fixtureBase');
const writerProgram = { sql: true, topics: ['qualification'], signals: [] };

async function fixture(path, body) {
  const response = await fetch(fixtureBase + '/fixture/' + path, {
    method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(`Fixture ${path}: ${JSON.stringify(value)}`);
  return value;
}
const device = command => fixture('device', command);
const passed = (name, evidence = {}) => fixture('check', { name, evidence });
const phase = name => fixture('phase', { name });

function members(api, onResponse) {
  return createMembersClient({ base: 'https://qualification.invalid', fetch: async (url, input) => {
    const parsed = new URL(url), body = input?.body === undefined ? undefined : JSON.parse(input.body);
    const response = await api(input?.method ?? 'GET', parsed.pathname.slice(1) + parsed.search, body);
    await onResponse?.(parsed.pathname, response);
    return response;
  } });
}

async function history(client) {
  const pages = [];
  let after = 0;
  for (;;) {
    const bytes = await client.history({ after, limit: 128 });
    const page = decodeMembershipLedgerResponse(bytes, 'read');
    pages.push(bytesToBase64Url(bytes));
    if (!page.hasMore) return pages;
    const next = page.entries.at(-1)?.index;
    if (next === undefined || next <= after) throw new Error('Membership history made no progress');
    after = next;
  }
}

async function until(read, accept, label, timeout = 75_000) {
  const start = performance.now();
  let value;
  do {
    value = await read();
    if (accept(value)) return { value, elapsedMs: Math.round(performance.now() - start) };
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (performance.now() - start < timeout);
  throw new Error(`${label}: ${JSON.stringify(value)}`);
}

async function decision(client, method, input, timeout = 30_000) {
  // Retrying a pending durable action must use exactly the original operation
  // identity and contents. Conflicts, authorization failures and lost replies
  // keep their original errors; only the named host progress wait is retried.
  const encoded = JSON.stringify(input), deadline = performance.now() + timeout;
  let pending;
  do {
    try { return await client[method](JSON.parse(encoded)); }
    catch (error) {
      if (error?.status !== 503 || error?.code !== 'membership_pending') throw error;
      pending = error;
    }
    const remaining = deadline - performance.now();
    if (remaining <= 0) break;
    await new Promise(resolve => setTimeout(resolve, Math.min(100, remaining)));
  } while (performance.now() < deadline);
  throw new Error(`Membership ${method} ${input.operationId} remained pending after ${timeout}ms`, { cause: pending });
}

const entries = pages => pages.flatMap(bytes => decodeMembershipLedgerResponse(base64UrlToBytes(bytes), 'read').entries);

// The runner owns the bounded aggregate budget for all phases. Individual
// enrollment decisions, commands, framing and authentication retain their bounds.
it('administers an independently ordered native/browser group through the actual Cloudflare membership provider', async () => {
  await phase('membership configuration');
  const setup = await fixture('configuration');
  const page = await createTestPage({ application: { kind: 'peer', id: setup.nativeAuthority.historyId }, lifetime: 'resident' });
  const owner = members(page.ownerApi), applicant = await page.participant(), other = await page.participant();
  const applicantMembers = members(applicant.api), otherMembers = members(other.api);
  await expect(applicantMembers.configure(setup)).rejects.toMatchObject({ status: 403 });
  const configured = await owner.configure(setup);
  expect(configured.descriptor).not.toBeNull();
  const genesis = decodeSignedGenesis(base64UrlToBytes(configured.descriptor.genesis));
  expect(bytesToBase64Url(genesis.manifest.rootAdminPublicKey)).not.toBe(setup.nativeAuthority.publicKey);
  expect(bytesToBase64Url(genesis.manifest.schemaAdminPublicKey)).toBe(setup.schemaAdministratorPublicKey);
  const rootRoles = genesis.manifest.initialCapabilities.filter(grant =>
    bytesToBase64Url(grant.signingPublicKey) === bytesToBase64Url(genesis.manifest.rootAdminPublicKey)).map(grant => grant.role);
  expect(rootRoles).toEqual(['administrator']);
  const bootstrap = await fixture('start', configured.descriptor);
  await owner.sync();
  await passed('Cloudflare owns a durable membership-only root; the separate native signer owns application schema and ordering');

  await phase('large and small native workloads');
  const small = await fixture('workload', { namespace: 'host-small', count: 4, payloadBytes: 16 });
  await owner.sync();
  const large = await fixture('workload', { namespace: 'host-large', count: 4, payloadBytes: 196_608 });
  await owner.sync();
  const more = await fixture('workload', { namespace: 'host-more', count: 8, payloadBytes: 16 });
  await owner.sync();
  expect(small.count).toBe(4); expect(large.count).toBe(4);
  expect(more.count).toBe(8);
  expect(large.detachedEnvelopeBytes).toBeGreaterThan(700_000);
  expect(Math.abs(large.descriptorBytes - small.descriptorBytes)).toBeLessThanOrEqual(16);
  expect(more.descriptorBytes).toBe(small.descriptorBytes * 2);
  const traffic = (await fixture('snapshot')).traffic;
  expect((await fixture('snapshot')).schemaRoles).toEqual({ nativeSchemaAdministrators: 1, membershipRootGroupMembers: 0 });
  expect(traffic.applicationEnvelopeBytesToAdministrator).toBe(0);
  expect(traffic.candidateDescriptorBytes).toBe(0);
  expect(traffic.unexpectedAdministratorRequests).toBe(0);
  await passed('application descriptors and envelopes remain on full peers while participant evidence contains only controls', { small, large, more, traffic });

  await phase('first device authorization and lost approval recovery');
  const prepared = await device({ method: 'prepare', name: 'thin-membership-device' });
  expect(genesis.manifest.initialCapabilities.some(grant => bytesToBase64Url(grant.signingPublicKey) === prepared.signingPublicKey)).toBe(false);
  await device({ method: 'open', name: 'thin-membership-device', bootstrap });
  const applicantInfo = await applicantMembers.info();
  const requestId = applicantInfo.identity.requestPrefix + 'native-browser-qualification';
  const request = await device({ method: 'request', requestId });
  await expect(otherMembers.requestEnrollment(request.signedRequest)).rejects.toMatchObject({ status: 403 });
  const submitted = await applicantMembers.requestEnrollment(request.signedRequest);
  await expect(applicantMembers.history({ after: 0 })).rejects.toMatchObject({ status: 403 });
  await expect(applicantMembers.approve({ operationId: 'self-approve', requestId: submitted.id,
    roles: ['reader', 'writer'], grantFullHistory: true, writerProgram })).rejects.toMatchObject({ status: 403 });

  const approvalDecision = { operationId: 'host-approve-device', requestId: submitted.id,
    roles: ['reader', 'writer'], grantFullHistory: true, writerProgram };
  let dropReply = true;
  const lostReplyOwner = members(page.ownerApi, async (path, response) => {
    if (path === '/members/approve' && response.ok && dropReply) {
      dropReply = false;
      await response.arrayBuffer();
      throw new TypeError('Qualification dropped the committed approval response');
    }
  });
  await expect(decision(lostReplyOwner, 'approve', approvalDecision)).rejects.toThrow('dropped');
  const retained = await applicantMembers.requestStatus(submitted.id);
  expect(retained.status).toBe('approved');
  await page.restart();
  expect((await owner.info()).descriptor).toEqual(configured.descriptor);
  const approval = await decision(owner, 'approve', approvalDecision);
  expect(approval.signedApproval).toBe(retained.signedApproval);
  expect(approval.capabilityIds).toEqual(retained.capabilityIds);
  await expect(owner.approve({ ...approvalDecision, roles: ['reader'] })).rejects.toMatchObject({ status: 409 });
  await passed('host authentication binds device ownership and exact approval survives a lost reply plus real Durable Object eviction');

  await phase('first fresh Worker authenticated history replay');
  const pending = await device({ method: 'approval', requestId, signedApproval: approval.signedApproval });
  expect(pending.enrollment.state).not.toBe('ready');
  const activated = await device({ method: 'history', pages: await history(applicantMembers) });
  expect(activated.grants.filter(grant => grant.active).map(grant => grant.role).sort()).toEqual(['reader', 'writer']);
  expect(activated.availableEpochs.length).toBeGreaterThan(0);
  expect(activated.applicationBlockedOnPayload).toBe(false);
  expect(activated.finalThrough).toBe(0);
  // Compact governance readiness cannot stand in for any application history.
  expect(activated.enrollment.state).not.toBe('ready');
  await device({ method: 'connect' });
  const joined = await until(() => device({ method: 'sync' }), value => value.enrollment.state === 'ready', 'browser enrollment did not become ready');
  expect(joined.value.identity).toBe(prepared.signingPublicKey);
  expect(joined.value.applicationBlockedOnPayload).toBe(false);
  expect((await device({ method: 'events' })).transactions.length).toBe(16);
  expect(joined.value.rtc.receivedBytes).toBeGreaterThan(large.detachedEnvelopeBytes);
  await passed('a fresh OPFS device verifies live approval and HPKE controls, then fetches detached history through authenticated WebRTC in its Worker', { elapsedMs: joined.elapsedMs, rtc: joined.value.rtc });

  await phase('writer revocation and original operation retry');
  const accepted = await device({ method: 'publish', operationId: 'device-before-revocation', text: 'accepted before revocation' });
  await until(() => device({ method: 'operation', operationId: accepted.operationId }), value => value?.final && value.outcome?.outcome === 'accepted', 'device operation did not become final');
  const active = await device({ method: 'status' }), writer = active.grants.find(grant => grant.role === 'writer' && grant.active);
  expect(writer).toBeDefined();
  await device({ method: 'disconnect' });
  const writerDecision = { operationId: 'host-revoke-writer', capabilityIds: [writer.id] };
  const writerRemoved = await decision(owner, 'revoke', writerDecision);
  expect((await applicantMembers.info()).identity.accountId).toBe(applicantInfo.identity.accountId);
  const rejected = await device({ method: 'publish', operationId: 'device-after-writer-revocation', text: 'must fail through direct peer path' });
  await device({ method: 'connect' });
  const finalRejection = await until(() => device({ method: 'operation', operationId: rejected.operationId }),
    value => value?.final && value.outcome?.outcome === 'rejected', 'revoked direct write was not rejected');
  expect((await device({ method: 'publish', operationId: accepted.operationId, text: 'accepted before revocation' })).proposalId).toBe(accepted.proposalId);
  await passed('writer revocation defeats a direct native-path operation while host login survives and an accepted exact retry stays original', finalRejection);

  await phase('abrupt Worker OPFS recovery');
  await fixture('reload-device', { name: 'thin-membership-device', bootstrap, requestId, signedApproval: approval.signedApproval });
  const reopened = await device({ method: 'status' });
  expect(reopened.identity).toBe(prepared.signingPublicKey);
  expect((await device({ method: 'operation', operationId: accepted.operationId })).proposalId).toBe(accepted.proposalId);
  expect((await device({ method: 'operation', operationId: rejected.operationId })).outcome.outcome).toBe('rejected');
  await passed('abrupt Worker replacement reopens OPFS identity, grants and original accepted/rejected operations');

  await phase('reader revocation and key rotation');
  const reader = reopened.grants.find(grant => grant.role === 'reader' && grant.active);
  expect(reader).toBeDefined();
  const readerDecision = { operationId: 'host-revoke-reader', capabilityIds: [reader.id] };
  const removed = await decision(owner, 'revoke', readerDecision);
  await expect(applicantMembers.history({ after: 0 })).rejects.toMatchObject({ status: 403 });
  // An owner can relay public certified controls even when the removed account
  // can no longer bootstrap through its own host membership endpoint.
  const afterRemoval = await device({ method: 'history', pages: await history(owner) });
  expect(afterRemoval.grants.some(grant => grant.role === 'reader' && grant.active)).toBe(false);
  expect(afterRemoval.knownEpochs).toContain(removed.epoch);
  expect(afterRemoval.availableEpochs).not.toContain(removed.epoch);
  await fixture('workload', { namespace: 'after-reader-removal', count: 1, payloadBytes: 4096 });
  expect((await fixture('snapshot')).availableEpochs).toContain(removed.epoch);
  expect((await device({ method: 'events' })).transactions.some(transaction => transaction.events.some(event => event.payload?.id === 'after-reader-removal-0'))).toBe(false);
  await passed('reader revocation rotates future keys without claiming to erase previously decrypted history',
    { identity: prepared.signingPublicKey, removedEpoch: removed.epoch, knownEpochs: afterRemoval.knownEpochs,
      availableEpochs: afterRemoval.availableEpochs, cannotReadPostRevocationEvent: true });

  await phase('administrator restart and retained decisions');
  await owner.sync();
  const controlsBeforeRestore = await history(owner), beforeRestore = await owner.info();
  const entriesBeforeRestore = entries(controlsBeforeRestore);
  const nativeBeforeRestore = (await fixture('snapshot')).head;
  expect(beforeRestore.pendingActions).toBe(0);
  expect(beforeRestore.requests.find(row => row.id === submitted.id).status).toBe('revoked');
  await page.restart();
  const restored = await owner.info();
  expect(restored).toEqual(beforeRestore);
  expect(await decision(owner, 'approve', approvalDecision)).toEqual(approval);
  expect(await decision(owner, 'revoke', writerDecision)).toEqual(writerRemoved);
  expect(await decision(owner, 'revoke', readerDecision)).toEqual(removed);
  await expect(owner.revoke({ operationId: 'host-revoke-reader', capabilityIds: [writer.id] })).rejects.toMatchObject({ status: 409 });
  await expect(applicantMembers.history({ after: 0 })).rejects.toMatchObject({ status: 403 });
  const entriesAfterRestore = entries(await history(owner));
  expect(entriesAfterRestore.slice(0, entriesBeforeRestore.length)).toEqual(entriesBeforeRestore);
  const newReceipts = entriesAfterRestore.slice(entriesBeforeRestore.length);
  expect(newReceipts).toEqual([]);
  const nativeAfterRestore = (await fixture('snapshot')).head;
  expect(nativeAfterRestore.position).toBeGreaterThanOrEqual(nativeBeforeRestore.position);
  await passed('reopened actual Cloudflare metadata retains root, certified descriptor prefix, revoked roster, epoch decisions and exact action receipts without new application or control entries',
    { before: beforeRestore, after: restored, writerRevocation: writerRemoved, readerRevocation: removed,
      nativeBeforeRestore, nativeAfterRestore, retainedReceipts: entriesBeforeRestore.length, newClosureRecords: newReceipts.length });

  await phase('second fresh Worker approval and full retained history');
  const fresh = await fixture('new-device', { name: 'thin-membership-restored-reader', bootstrap });
  expect(fresh.prepared.signingPublicKey).not.toBe(prepared.signingPublicKey);
  const readerInfo = await otherMembers.info(), readerRequestId = readerInfo.identity.requestPrefix + 'after-admin-restart';
  const readerRequest = await device({ method: 'request', requestId: readerRequestId });
  const readerSubmission = await otherMembers.requestEnrollment(readerRequest.signedRequest);
  const readerApproval = await decision(owner, 'approve', { operationId: 'approve-reader-after-admin-restart', requestId: readerSubmission.id,
    roles: ['reader'], grantFullHistory: true });
  await device({ method: 'approval', requestId: readerRequestId, signedApproval: readerApproval.signedApproval });
  const readerActivated = await device({ method: 'history', pages: await history(otherMembers) });
  expect(readerActivated.grants.filter(grant => grant.active).map(grant => grant.role)).toEqual(['reader']);
  expect(readerActivated.availableEpochs).toContain(removed.epoch);
  await device({ method: 'connect' });
  const readerReady = await until(() => device({ method: 'sync' }), value => value.enrollment.state === 'ready', 'reader approved after admin restart did not become ready');
  expect((await device({ method: 'events' })).transactions.some(transaction => transaction.events.some(event => event.payload?.id === 'after-reader-removal-0'))).toBe(true);
  await expect(applicantMembers.history({ after: 0 })).rejects.toMatchObject({ status: 403 });
  await passed('reopened administrator uses restored historical epoch keys to approve a newly keyed read-only device while the removed account stays denied',
    { identity: fresh.prepared.signingPublicKey, accountId: readerInfo.identity.accountId,
      roles: readerReady.value.grants.filter(grant => grant.active).map(grant => grant.role),
      availableEpochs: readerReady.value.availableEpochs, recoveredEpoch: removed.epoch, elapsedMs: readerReady.elapsedMs });

  await phase('final RTC and administrative byte boundaries');
  const final = await fixture('snapshot');
  expect(final.traffic.applicationEnvelopeBytesToAdministrator).toBe(0);
  expect(final.traffic.candidateDescriptorBytes).toBe(0);
  expect(final.traffic.inlineControlDescriptorBytes).toBeGreaterThan(0);
  expect(final.traffic.closureRecordBytes).toBeGreaterThan(0);
  expect(final.traffic.unexpectedAdministratorRequests).toBe(0);
  expect(final.traffic.peerOutboundBytes).toBeGreaterThan(large.detachedEnvelopeBytes);
  expect(final.rtc.transport).toBe('webrtc'); expect(final.rtc.accepted).toBe(3);
  expect(final.traffic.rtcSignalingDescriptions).toBe(6);
  expect(final.traffic.rtcSdpBytes).toBeGreaterThan(0);
  const rtc = await device({ method: 'rtcStats' });
  expect(rtc.transport).toBe('webrtc'); expect(rtc.channelOwner).toBe('DedicatedWorker');
  expect(rtc.introductions).toHaveLength(3);
  expect(rtc.introductions.every(value => value.requests === 1 && value.closed && value.requestBytes > 0 && value.responseBytes > 0)).toBe(true);
  await fixture('complete', { traffic: final.traffic, rtc: { browser: rtc, native: final.rtc }, descriptor: configured.descriptor, requestId: submitted.id });
});
