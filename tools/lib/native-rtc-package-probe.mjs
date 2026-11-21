// Runs from an independent npm consumer; no source/workspace imports.
import assert from 'node:assert/strict';
import console from 'node:console';
import { createNativePeerConnection } from '@chronolog/peer-session/webrtc-native';
import { openWebRtcConnection } from '@chronolog/peer-session/webrtc';
function inbox() {
  const queue = [], waiters = []; let closed = false;
  return { push(value) { if (closed) return; const next = waiters.shift(); if (next) next({ value, done: false }); else queue.push(value); },
    close() { closed = true; for (const next of waiters.splice(0)) next({ done: true }); },
    [Symbol.asyncIterator]() { return { next: () => queue.length ? Promise.resolve({ value: queue.shift(), done: false })
      : closed ? Promise.resolve({ done: true }) : new Promise(resolve => waiters.push(resolve)) }; } };
}
const queues = [inbox(), inbox()], peers = [];
const signaling = queues.map((messages, i) => ({ messages, async send(value) { queues[1-i].push(value); }, close() { messages.close(); } }));
const stop = new globalThis.AbortController(); let pair;
const opening = [0, 1].map(i => openWebRtcConnection({ role: i ? 'answerer' : 'offerer', signaling: signaling[i],
  signal: stop.signal, timeoutMs: 5000, configuration: { iceServers: [] },
  createPeerConnection(configuration) {
    const peer = createNativePeerConnection(configuration, { iceUseIpv6: false, iceAdditionalHostAddresses: ['127.0.0.1'] });
    peers.push(peer); return peer;
  },
}));
try {
  pair = await Promise.all(opening);
  await Promise.all(pair.map(connection => connection.ready));
  const payload = Uint8Array.from({ length: 600_003 }, (_, i) => i % 251);
  const reads = pair.map(connection => connection.frames()[Symbol.asyncIterator]());
  await Promise.all([pair[0].send(payload), pair[1].send(new Uint8Array([7, 8, 9]))]);
  assert.deepEqual((await reads[1].next()).value, payload);
  assert.deepEqual((await reads[0].next()).value, new Uint8Array([7, 8, 9]));
  const live = pair.map(connection => connection.live.frames()[Symbol.asyncIterator]());
  assert.equal(await pair[0].live.trySend(new Uint8Array([4, 5])), true);
  assert.deepEqual((await live[1].next()).value, new Uint8Array([4, 5]));
  await Promise.all(pair.map(connection => connection.close()));
  await Promise.all([...reads, ...live].map(reader => reader.return?.()));
  assert.ok(pair.every(connection => connection.signal.aborted));
  assert.ok(peers.every(peer => peer.connectionState === 'closed'));
  console.log(JSON.stringify({ passed: true, reliableBytes: payload.length, bidirectional: true, liveLane: true, peersClosed: peers.length }));
} finally {
  stop.abort();
  const settled = await Promise.allSettled(opening);
  await Promise.allSettled(settled.filter(value => value.status === 'fulfilled').map(value => value.value.close()));
  await Promise.allSettled(peers.map(peer => peer.close()));
}
// No forced exit: the parent requires this child to exit naturally.
