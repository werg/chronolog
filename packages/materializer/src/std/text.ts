export const STD_TEXT_SOURCE = `
function hasWriter(ctx, author) {
  const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
  if (cfg.allowPublicWrite === true) return true;
  return ctx.can('writer', author);
}

function compareStamp(a, b) {
  if (a.ts !== b.ts) return a.ts < b.ts ? -1 : 1;
  if (a.author !== b.author) return a.author < b.author ? -1 : 1;
  if (a.opId !== b.opId) return a.opId < b.opId ? -1 : 1;
  if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1;
  return 0;
}

/**
 * Linearize RGA character/token nodes deterministically.
 * Each character node has a stable ID "<opId>:<offset>" so concurrent edits merge cleanly
 * without index drift under arbitrary out-of-order replay.
 */
function linearize(nodes) {
  const byParent = {};
  for (const id of Object.keys(nodes)) {
    const n = nodes[id];
    const parent = n.afterId && nodes[n.afterId] ? n.afterId : '__root__';
    if (!byParent[parent]) byParent[parent] = [];
    byParent[parent].push(n);
  }
  for (const key of Object.keys(byParent)) {
    byParent[key].sort((a, b) => compareStamp(b, a));
  }
  const ordered = [];
  const visited = {};
  function walk(parent) {
    const children = byParent[parent];
    if (!children) return;
    for (const child of children) {
      if (visited[child.id]) continue;
      visited[child.id] = true;
      ordered.push(child);
      walk(child.id);
    }
  }
  walk('__root__');
  return ordered;
}

function visibleNodes(nodes) {
  return linearize(nodes).filter(n => !n.deleted);
}

/**
 * Deterministic RGA Collaborative Text CRDT for prose, notes, and code co-editing.
 * Supports stable node-anchored edits (insert/delete) and index convenience helpers (insertAt/deleteRange).
 */
export const collaborativeText = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.nodes && typeof state.nodes === 'object'
      ? state
      : { nodes: {}, anchors: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const action = typeof input.action === 'string' ? input.action : 'insert';
    const nextNodes = { ...cur.nodes };
    const nextAnchors = { ...(cur.anchors || {}) };
    const baseTs = Number(tx.authorTimestampMs || 0);

    if (action === 'insert' || action === 'insertAt') {
      if (typeof input.text !== 'string' || input.text.length === 0) {
        return { ok: false, code: 'text:empty_insert' };
      }
      if (input.text.length > 4096) return { ok: false, code: 'text:insert_too_large' };
      let afterId = null;
      if (action === 'insert') {
        afterId = typeof input.afterId === 'string' && input.afterId.length > 0 ? input.afterId : null;
      } else {
        const vis = visibleNodes(nextNodes);
        const idx = Number.isSafeInteger(input.index) ? Math.max(0, Math.min(input.index, vis.length)) : vis.length;
        afterId = idx === 0 ? null : vis[idx - 1].id;
      }
      const chars = Array.from(input.text);
      let prevId = afterId;
      const insertedIds = [];
      for (let i = 0; i < chars.length; i++) {
        const id = tx.opId + ':' + i;
        nextNodes[id] = {
          id,
          afterId: prevId,
          ch: chars[i],
          deleted: false,
          ts: baseTs,
          author: tx.author,
          opId: tx.opId,
          seq: i,
        };
        insertedIds.push(id);
        prevId = id;
      }
      return {
        ok: true,
        state: { nodes: nextNodes, anchors: nextAnchors },
        events: [{ topic: 'text.insert', payload: { count: chars.length, firstId: insertedIds[0], lastId: insertedIds[insertedIds.length - 1] } }],
      };
    }

    if (action === 'delete') {
      if (!Array.isArray(input.ids) || input.ids.length === 0) return { ok: false, code: 'text:ids_required' };
      let deletedCount = 0;
      for (const id of input.ids) {
        if (typeof id === 'string' && nextNodes[id] && !nextNodes[id].deleted) {
          nextNodes[id] = { ...nextNodes[id], deleted: true };
          deletedCount++;
        }
      }
      return {
        ok: true,
        state: { nodes: nextNodes, anchors: nextAnchors },
        events: [{ topic: 'text.delete', payload: { count: deletedCount } }],
      };
    }

    if (action === 'deleteRange') {
      const vis = visibleNodes(nextNodes);
      const index = Number(input.index);
      const length = Number(input.length);
      if (!Number.isSafeInteger(index) || !Number.isSafeInteger(length) || index < 0 || length < 0) {
        return { ok: false, code: 'text:invalid_range' };
      }
      const slice = vis.slice(index, index + length);
      for (const node of slice) {
        nextNodes[node.id] = { ...node, deleted: true };
      }
      return {
        ok: true,
        state: { nodes: nextNodes, anchors: nextAnchors },
        events: [{ topic: 'text.delete', payload: { count: slice.length } }],
      };
    }

    if (action === 'setAnchor') {
      if (typeof input.name !== 'string' || input.name.length === 0) return { ok: false, code: 'text:invalid_anchor' };
      const nodeId = typeof input.nodeId === 'string' && input.nodeId.length > 0 ? input.nodeId : null;
      nextAnchors[input.name] = { nodeId, updatedBy: tx.author, updatedAtMs: baseTs };
      return { ok: true, state: { nodes: nextNodes, anchors: nextAnchors } };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const nodes = state && state.nodes && typeof state.nodes === 'object' ? state.nodes : {};
    const anchors = state && state.anchors && typeof state.anchors === 'object' ? state.anchors : {};
    const vis = visibleNodes(nodes);
    const kind = input && typeof input === 'object' ? (input.query || input.kind) : 'text';
    if (kind === 'nodes') {
      return { nodes: vis.map(n => ({ id: n.id, ch: n.ch })) };
    }
    if (kind === 'anchors') {
      const idxById = {};
      for (let i = 0; i < vis.length; i++) idxById[vis[i].id] = i;
      const resolved = {};
      for (const name of Object.keys(anchors).sort()) {
        const a = anchors[name];
        resolved[name] = {
          ...a,
          index: a.nodeId && Object.prototype.hasOwnProperty.call(idxById, a.nodeId) ? idxById[a.nodeId] + 1 : 0,
        };
      }
      return { anchors: resolved };
    }
    const text = vis.map(n => n.ch).join('');
    if (kind === 'stats') {
      return { length: vis.length, totalNodes: Object.keys(nodes).length, text };
    }
    return { text, length: vis.length, lastNodeId: vis.length > 0 ? vis[vis.length - 1].id : null };
  },

  describe() {
    const optStr = { anyOf: [{ type: 'string' }, { type: 'null' }] };
    return {
      commands: [
        { name: 'insert', description: 'Insert text anchored after a stable node ID (or null for start).', input: { type: 'object', properties: { afterId: optStr, text: { type: 'string' } }, required: ['text'] } },
        { name: 'insertAt', description: 'Insert text at a character index.', input: { type: 'object', properties: { index: { type: 'integer', minimum: 0 }, text: { type: 'string' } }, required: ['text'] } },
        { name: 'delete', description: 'Delete characters by stable node IDs.', input: { type: 'object', properties: { ids: { type: 'array', items: { type: 'string' } } }, required: ['ids'] } },
        { name: 'deleteRange', description: 'Delete a visible character range.', input: { type: 'object', properties: { index: { type: 'integer', minimum: 0 }, length: { type: 'integer', minimum: 0 } }, required: ['index', 'length'] } },
        { name: 'setAnchor', description: 'Save a named cursor/comment anchor on a stable node ID.', input: { type: 'object', properties: { name: { type: 'string' }, nodeId: optStr }, required: ['name'] } },
      ],
      queries: [
        { name: 'text', description: 'Read the converged string and tail node ID.', input: { type: 'object', properties: {} } },
        { name: 'nodes', description: 'Read visible character nodes with stable IDs.', input: { type: 'object', properties: {} } },
        { name: 'anchors', description: 'Resolve saved anchors to current character indices.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()
