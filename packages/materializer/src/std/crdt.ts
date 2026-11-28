export const STD_CRDT_SOURCE = `
function hasWriter(ctx, author) {
  const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
  if (cfg.allowPublicWrite === true) return true;
  return ctx.can('writer', author);
}

function compareStamp(a, b) {
  if (a.ts !== b.ts) return a.ts < b.ts ? -1 : 1;
  if (a.author !== b.author) return a.author < b.author ? -1 : 1;
  if (a.opId !== b.opId) return a.opId < b.opId ? -1 : 1;
  return 0;
}

/**
 * Out-of-order-safe Last-Write-Wins Map CRDT.
 * Each key resolves deterministically by (authorTimestampMs, author, opId).
 */
export const lwwMap = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.entries && typeof state.entries === 'object'
      ? state
      : { entries: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object' || Array.isArray(input)) return { ok: false, code: 'invalid_input' };
    const stamp = { ts: Number(tx.authorTimestampMs || 0), author: tx.author, opId: tx.opId };
    const nextEntries = { ...cur.entries };
    const action = typeof input.action === 'string' ? input.action : 'set';

    if (action === 'set') {
      if (typeof input.key !== 'string' || input.key.length === 0) return { ok: false, code: 'crdt:invalid_key' };
      const existing = nextEntries[input.key];
      if (!existing || compareStamp(stamp, existing) >= 0) {
        nextEntries[input.key] = { value: input.value === undefined ? null : input.value, deleted: false, ...stamp };
      }
      return { ok: true, state: { entries: nextEntries }, events: [{ topic: 'crdt.map.set', payload: { key: input.key } }] };
    }

    if (action === 'delete') {
      if (typeof input.key !== 'string' || input.key.length === 0) return { ok: false, code: 'crdt:invalid_key' };
      const existing = nextEntries[input.key];
      if (!existing || compareStamp(stamp, existing) >= 0) {
        nextEntries[input.key] = { value: null, deleted: true, ...stamp };
      }
      return { ok: true, state: { entries: nextEntries }, events: [{ topic: 'crdt.map.delete', payload: { key: input.key } }] };
    }

    if (action === 'merge') {
      if (!input.values || typeof input.values !== 'object' || Array.isArray(input.values)) {
        return { ok: false, code: 'crdt:invalid_values' };
      }
      const keys = Object.keys(input.values).sort();
      for (const k of keys) {
        const existing = nextEntries[k];
        if (!existing || compareStamp(stamp, existing) >= 0) {
          nextEntries[k] = { value: input.values[k], deleted: false, ...stamp };
        }
      }
      return { ok: true, state: { entries: nextEntries }, events: [{ topic: 'crdt.map.merge', payload: { keys } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const entries = state && state.entries && typeof state.entries === 'object' ? state.entries : {};
    if (input && typeof input === 'object' && typeof input.key === 'string') {
      const e = entries[input.key];
      return !e || e.deleted ? null : e.value;
    }
    const out = {};
    for (const k of Object.keys(entries).sort()) {
      const e = entries[k];
      if (e && !e.deleted) out[k] = e.value;
    }
    return out;
  },
  describe() {
    const anyScalar = { anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] };
    return {
      commands: [
        { name: 'set', description: 'Set a key in the LWW map.', input: { type: 'object', properties: { key: { type: 'string' }, value: anyScalar }, required: ['key'] } },
        { name: 'delete', description: 'Tombstone a key in the LWW map.', input: { type: 'object', properties: { key: { type: 'string' } }, required: ['key'] } },
        { name: 'merge', description: 'Merge multiple key-value pairs into the LWW map.', input: { type: 'object', properties: { values: { type: 'object', properties: {} } }, required: ['values'] } },
      ],
      queries: [
        { name: 'get', description: 'Read all live entries or a single key.', input: { type: 'object', properties: { key: { type: 'string' } } } },
      ],
    };
  },
};

/**
 * Observed-Remove Set (OR-Set) CRDT.
 * Each add receives a unique opId tag; remove clears either explicitly observed tags or all tags present at replay time.
 */
export const orSet = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.tags && typeof state.tags === 'object'
      ? state
      : { tags: {}, removed: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const action = typeof input.action === 'string' ? input.action : 'add';
    const value = typeof input.value === 'string' ? input.value : null;
    if (value === null || value.length === 0) return { ok: false, code: 'crdt:invalid_value' };

    const nextTags = { ...cur.tags };
    const nextRemoved = { ...cur.removed };

    if (action === 'add') {
      const tag = tx.opId;
      if (!nextRemoved[tag]) {
        const list = Array.isArray(nextTags[value]) ? nextTags[value].slice() : [];
        if (!list.includes(tag)) list.push(tag);
        list.sort();
        nextTags[value] = list;
      }
      return { ok: true, state: { tags: nextTags, removed: nextRemoved }, events: [{ topic: 'crdt.set.add', payload: { value } }] };
    }

    if (action === 'remove') {
      const existing = Array.isArray(nextTags[value]) ? nextTags[value] : [];
      const toRemove = Array.isArray(input.observedTags) ? input.observedTags.filter(t => typeof t === 'string') : existing;
      for (const t of toRemove) nextRemoved[t] = true;
      const remaining = existing.filter(t => !nextRemoved[t]);
      if (remaining.length === 0) delete nextTags[value];
      else nextTags[value] = remaining;
      return { ok: true, state: { tags: nextTags, removed: nextRemoved }, events: [{ topic: 'crdt.set.remove', payload: { value } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state, input) {
    const tags = state && state.tags && typeof state.tags === 'object' ? state.tags : {};
    const values = Object.keys(tags).filter(k => Array.isArray(tags[k]) && tags[k].length > 0).sort();
    if (input && typeof input === 'object' && typeof input.has === 'string') {
      return values.includes(input.has);
    }
    return { values, tags };
  },
  describe() {
    return {
      commands: [
        { name: 'add', description: 'Add a value with a unique op tag.', input: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] } },
        { name: 'remove', description: 'Remove observed tags for a value.', input: { type: 'object', properties: { value: { type: 'string' }, observedTags: { type: 'array', items: { type: 'string' } } }, required: ['value'] } },
      ],
      queries: [
        { name: 'values', description: 'List live set values or check membership.', input: { type: 'object', properties: { has: { type: 'string' } } } },
      ],
    };
  },
};

/**
 * Positive-Negative Counter (PN-Counter) CRDT.
 */
export const pnCounter = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.p && state.n ? state : { p: {}, n: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const action = typeof input.action === 'string' ? input.action : 'add';
    const amount = Number(input.amount === undefined ? 1 : input.amount);
    if (!Number.isSafeInteger(amount) || amount < 0) return { ok: false, code: 'crdt:invalid_amount' };

    const p = { ...cur.p };
    const n = { ...cur.n };
    if (action === 'increment' || action === 'add') {
      p[tx.author] = (Number(p[tx.author]) || 0) + amount;
      return { ok: true, state: { p, n }, events: [{ topic: 'crdt.counter.increment', payload: { amount } }] };
    }
    if (action === 'decrement' || action === 'sub') {
      n[tx.author] = (Number(n[tx.author]) || 0) + amount;
      return { ok: true, state: { p, n }, events: [{ topic: 'crdt.counter.decrement', payload: { amount } }] };
    }
    return { ok: false, code: 'unknown_action' };
  },
  query(state) {
    const p = state && state.p && typeof state.p === 'object' ? state.p : {};
    const n = state && state.n && typeof state.n === 'object' ? state.n : {};
    let total = 0;
    for (const v of Object.values(p)) total += Number(v) || 0;
    for (const v of Object.values(n)) total -= Number(v) || 0;
    return { value: total, p, n };
  },
  describe() {
    return {
      commands: [
        { name: 'increment', description: 'Increment the counter.', input: { type: 'object', properties: { amount: { type: 'integer', minimum: 0 } } } },
        { name: 'decrement', description: 'Decrement the counter.', input: { type: 'object', properties: { amount: { type: 'integer', minimum: 0 } } } },
      ],
      queries: [
        { name: 'value', description: 'Read the converged total and per-author vectors.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};

function linearizeOrderedNodes(nodes) {
  const byParent = {};
  for (const id of Object.keys(nodes)) {
    const node = nodes[id];
    const parentKey = node.afterId && nodes[node.afterId] ? node.afterId : '__root__';
    if (!byParent[parentKey]) byParent[parentKey] = [];
    byParent[parentKey].push(node);
  }
  for (const key of Object.keys(byParent)) {
    // RGA tie-break: newer (higher ts/author/opId) concurrent siblings come FIRST right after their parent
    byParent[key].sort((a, b) => compareStamp(b, a));
  }
  const result = [];
  const visited = {};
  function walk(parentKey) {
    const children = byParent[parentKey];
    if (!children) return;
    for (const child of children) {
      if (visited[child.id]) continue;
      visited[child.id] = true;
      if (!child.deleted) result.push(child);
      walk(child.id);
    }
  }
  walk('__root__');
  return result;
}

/**
 * RGA Ordered List CRDT with deterministic concurrent insert and move support (Kanban / checklists).
 */
export const orderedList = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = state && typeof state === 'object' && state.nodes && typeof state.nodes === 'object'
      ? state
      : { nodes: {} };
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const action = typeof input.action === 'string' ? input.action : 'insert';
    const stamp = { ts: Number(tx.authorTimestampMs || 0), author: tx.author, opId: tx.opId };
    const nextNodes = { ...cur.nodes };

    if (action === 'insert') {
      const id = typeof input.id === 'string' && input.id.length > 0 ? input.id : tx.opId;
      if (nextNodes[id]) return { ok: false, code: 'crdt:duplicate_id' };
      const afterId = typeof input.afterId === 'string' && input.afterId.length > 0 ? input.afterId : null;
      nextNodes[id] = { id, afterId, value: input.value === undefined ? null : input.value, deleted: false, ...stamp };
      return { ok: true, state: { nodes: nextNodes }, events: [{ topic: 'crdt.list.insert', payload: { id } }] };
    }

    if (action === 'move') {
      const id = typeof input.id === 'string' ? input.id : '';
      const existing = nextNodes[id];
      if (!existing || existing.deleted) return { ok: false, code: 'crdt:item_not_found' };
      const afterId = typeof input.afterId === 'string' && input.afterId.length > 0 ? input.afterId : null;
      if (afterId === id) return { ok: false, code: 'crdt:cycle_forbidden' };
      // Prevent cycle by walking ancestors of afterId
      let cursor = afterId;
      let guard = 0;
      while (cursor && nextNodes[cursor] && guard++ < 10000) {
        if (cursor === id) return { ok: false, code: 'crdt:cycle_forbidden' };
        cursor = nextNodes[cursor].afterId;
      }
      nextNodes[id] = { ...existing, afterId, ...stamp };
      return { ok: true, state: { nodes: nextNodes }, events: [{ topic: 'crdt.list.move', payload: { id, afterId } }] };
    }

    if (action === 'update') {
      const id = typeof input.id === 'string' ? input.id : '';
      const existing = nextNodes[id];
      if (!existing || existing.deleted) return { ok: false, code: 'crdt:item_not_found' };
      nextNodes[id] = { ...existing, value: input.value === undefined ? null : input.value };
      return { ok: true, state: { nodes: nextNodes }, events: [{ topic: 'crdt.list.update', payload: { id } }] };
    }

    if (action === 'delete') {
      const id = typeof input.id === 'string' ? input.id : '';
      const existing = nextNodes[id];
      if (!existing) return { ok: false, code: 'crdt:item_not_found' };
      nextNodes[id] = { ...existing, deleted: true };
      return { ok: true, state: { nodes: nextNodes }, events: [{ topic: 'crdt.list.delete', payload: { id } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },
  query(state) {
    const nodes = state && state.nodes && typeof state.nodes === 'object' ? state.nodes : {};
    const items = linearizeOrderedNodes(nodes).map(n => ({ id: n.id, value: n.value }));
    return { items };
  },
  describe() {
    const anyScalar = { anyOf: [{ type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] };
    const optStr = { anyOf: [{ type: 'string' }, { type: 'null' }] };
    return {
      commands: [
        { name: 'insert', description: 'Insert an item after an anchor ID (or null for head).', input: { type: 'object', properties: { id: { type: 'string' }, afterId: optStr, value: anyScalar } } },
        { name: 'move', description: 'Move an existing item after another anchor ID.', input: { type: 'object', properties: { id: { type: 'string' }, afterId: optStr }, required: ['id'] } },
        { name: 'update', description: 'Update an item value.', input: { type: 'object', properties: { id: { type: 'string' }, value: anyScalar }, required: ['id'] } },
        { name: 'delete', description: 'Tombstone an item.', input: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
      ],
      queries: [
        { name: 'items', description: 'Return the converged ordered list.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()
