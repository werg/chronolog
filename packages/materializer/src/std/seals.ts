/**
 * Built-in `chronolog/seals` standard module.
 *
 * Plain-data monotonic immutability controller for `$seals`:
 * - `reducers[topic] = true`: pins the topic's resolved reducer binding & CAS hash forever.
 * - `paths[topic][dotPath] = 'frozen' | 'append-only'`: locks a JSON subtree forever.
 * - By default, sealing any path on topic `T` ALSO seals `reducers[T]` (preventing
 *   leaky data locks via reducer swap) unless `allowMutableReducer: true` is explicit.
 * - Monotonicity (no removal or weakening) and enforcement are guaranteed by TopicKernel itself.
 */
export const STD_SEALS_SOURCE = `
function normalizeSeals(state) {
  const s = state && typeof state === 'object' && !Array.isArray(state) ? state : {};
  const reducers = {};
  if (s.reducers && typeof s.reducers === 'object' && !Array.isArray(s.reducers)) {
    for (const [k, v] of Object.entries(s.reducers)) {
      if (v === true && typeof k === 'string' && k.length > 0) reducers[k] = true;
    }
  }
  const paths = {};
  if (s.paths && typeof s.paths === 'object' && !Array.isArray(s.paths)) {
    for (const [topic, rules] of Object.entries(s.paths)) {
      if (!rules || typeof rules !== 'object' || Array.isArray(rules)) continue;
      const clean = {};
      for (const [p, mode] of Object.entries(rules)) {
        if (typeof p === 'string' && p.length > 0 && (mode === 'frozen' || mode === 'append-only')) {
          clean[p] = mode;
        }
      }
      if (Object.keys(clean).length > 0) paths[topic] = clean;
    }
  }
  return { reducers, paths };
}

function validTopicName(topic) {
  return typeof topic === 'string' && topic.length > 0 && topic.length <= 128;
}

function validPathName(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 256) return false;
  if (path === '*') return true;
  return path.split('.').every(seg => seg.length > 0 && seg !== '__proto__' && seg !== 'constructor' && seg !== 'prototype');
}

function applyPathSeal(reducers, paths, entry) {
  if (!entry || typeof entry !== 'object') return { ok: false, code: 'invalid_seal' };
  const topic = entry.topic;
  const path = entry.path;
  const mode = entry.mode === undefined ? 'frozen' : entry.mode;
  if (!validTopicName(topic) || !validPathName(path) || (mode !== 'frozen' && mode !== 'append-only')) {
    return { ok: false, code: 'invalid_seal' };
  }
  const topicPaths = { ...(paths[topic] || {}) };
  if (topicPaths[path] === 'frozen' && mode === 'append-only') {
    return { ok: false, code: 'seal_cannot_weaken' };
  }
  topicPaths[path] = mode;
  paths[topic] = topicPaths;
  if (entry.allowMutableReducer !== true) {
    reducers[topic] = true;
  }
  return { ok: true };
}

export const monotonicSeals = {
  reduce(state, tx, ctx) {
    if (!ctx.can('administrator')) return { ok: false, code: 'admin_required' };
    const input = tx.payload;
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return { ok: false, code: 'invalid_input' };
    }
    const cur = normalizeSeals(state);
    const reducers = { ...cur.reducers };
    const paths = { ...cur.paths };

    if (input.action === 'sealReducer') {
      const list = Array.isArray(input.topics) ? input.topics : (typeof input.topic === 'string' ? [input.topic] : []);
      if (list.length === 0) return { ok: false, code: 'invalid_seal' };
      for (const t of list) {
        if (!validTopicName(t)) return { ok: false, code: 'invalid_seal' };
        reducers[t] = true;
      }
      return {
        ok: true,
        state: { reducers, paths },
        events: [{ topic: '$seals.updated', payload: { reducers: list } }],
      };
    }

    if (input.action === 'sealPath') {
      const res = applyPathSeal(reducers, paths, input);
      if (!res.ok) return res;
      return {
        ok: true,
        state: { reducers, paths },
        events: [{ topic: '$seals.updated', payload: { topic: input.topic, path: input.path, mode: input.mode || 'frozen' } }],
      };
    }

    if (input.action === 'seal') {
      const rList = Array.isArray(input.reducers) ? input.reducers : [];
      const pList = Array.isArray(input.paths) ? input.paths : [];
      if (rList.length === 0 && pList.length === 0) return { ok: false, code: 'invalid_seal' };
      for (const t of rList) {
        if (!validTopicName(t)) return { ok: false, code: 'invalid_seal' };
        reducers[t] = true;
      }
      for (const p of pList) {
        const res = applyPathSeal(reducers, paths, p);
        if (!res.ok) return res;
      }
      return {
        ok: true,
        state: { reducers, paths },
        events: [{ topic: '$seals.updated', payload: { reducerCount: rList.length, pathCount: pList.length } }],
      };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const cur = normalizeSeals(state);
    if (input && typeof input === 'object' && typeof input.topic === 'string') {
      const reducerSealed = cur.reducers[input.topic] === true;
      const topicPaths = cur.paths[input.topic] || {};
      if (typeof input.path === 'string') {
        return {
          topic: input.topic,
          path: input.path,
          reducerSealed,
          mode: topicPaths[input.path] || topicPaths['*'] || null,
        };
      }
      return { topic: input.topic, reducerSealed, paths: topicPaths };
    }
    return cur;
  },
};

export default monotonicSeals;
`.trimStart()
