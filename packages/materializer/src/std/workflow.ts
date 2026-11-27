export const STD_WORKFLOW_SOURCE = `
function hasCap(ctx, cap, author) {
  const checked = ctx.query('$permissions', { check: cap, actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  if (!perms || !Array.isArray(perms.members)) return false;
  const m = perms.members.find(x => x.publicKey === author);
  if (!m) return false;
  if (cap === 'administrator') return m.administrator === true;
  if (cap === 'writer') return m.writer === true || m.administrator === true;
  return false;
}

function normalizeWorkflow(state, config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const s = state && typeof state === 'object' ? state : {};
  const def = s.definition && typeof s.definition === 'object'
    ? s.definition
    : (cfg.definition && typeof cfg.definition === 'object' ? cfg.definition : {
        initialState: 'proposed',
        states: ['proposed', 'approved', 'rejected', 'expired'],
        transitions: [
          { name: 'approve', from: 'proposed', to: 'approved', roles: ['administrator'], distinctFromCreator: false, requiredApprovals: 1 },
          { name: 'reject', from: 'proposed', to: 'rejected', roles: ['administrator'], distinctFromCreator: false, requiredApprovals: 1 },
        ],
      });
  return {
    definition: def,
    items: s.items && typeof s.items === 'object' ? { ...s.items } : {},
  };
}

/**
 * Deterministic Workflow / State-Machine & Approval Queue Reducer.
 * Supports role guards, separation of duties (reviewer !== creator), M-of-N item sign-offs,
 * SLA expiry, and AI-agent proposal review queues.
 */
export const stateMachine = {
  reduce(state, tx, ctx) {
    const cur = normalizeWorkflow(state, ctx.config);
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const isAdmin = hasCap(ctx, 'administrator', tx.author);
    const isWriter = isAdmin || hasCap(ctx, 'writer', tx.author);
    const nowMs = Number(tx.authorTimestampMs || 0);
    const action = typeof input.action === 'string' ? input.action : 'create';

    if (action === 'configure') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      const def = input.definition;
      if (!def || typeof def !== 'object' || !Array.isArray(def.states) || !Array.isArray(def.transitions) || typeof def.initialState !== 'string') {
        return { ok: false, code: 'workflow:invalid_definition' };
      }
      return { ok: true, state: { ...cur, definition: def }, events: [{ topic: 'workflow.configured', payload: { states: def.states } }] };
    }

    if (action === 'create') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const id = typeof input.id === 'string' && input.id.length > 0 ? input.id : tx.opId;
      if (cur.items[id]) return { ok: false, code: 'workflow:item_exists' };
      const initialState = typeof input.initialState === 'string' ? input.initialState : cur.definition.initialState;
      if (!cur.definition.states.includes(initialState)) return { ok: false, code: 'workflow:invalid_state' };
      cur.items[id] = {
        id,
        title: typeof input.title === 'string' ? input.title : '',
        state: initialState,
        createdBy: tx.author,
        createdAtMs: nowMs,
        enteredAtMs: nowMs,
        payload: input.payload === undefined ? null : input.payload,
        approvals: {},
        history: [{ state: initialState, actor: tx.author, ts: nowMs, opId: tx.opId }],
      };
      return { ok: true, state: cur, events: [{ topic: 'workflow.created', payload: { id, state: initialState } }] };
    }

    if (action === 'transition') {
      const id = typeof input.id === 'string' ? input.id : '';
      const item = cur.items[id];
      if (!item) return { ok: false, code: 'workflow:item_not_found' };
      const tName = typeof input.transition === 'string' ? input.transition : '';
      const rule = cur.definition.transitions.find(r =>
        r.name === tName && (Array.isArray(r.from) ? r.from.includes(item.state) : r.from === item.state),
      );
      if (!rule) return { ok: false, code: 'workflow:transition_not_allowed' };
      if (rule.slaMs !== undefined && rule.slaMs !== null && nowMs > item.enteredAtMs + Number(rule.slaMs)) {
        return { ok: false, code: 'workflow:sla_expired' };
      }
      if (rule.distinctFromCreator === true && tx.author === item.createdBy) {
        return { ok: false, code: 'workflow:separation_of_duties' };
      }
      const roles = Array.isArray(rule.roles) && rule.roles.length > 0 ? rule.roles : ['writer'];
      const authorized = roles.some(role => {
        if (role === 'administrator' || role === 'admin') return isAdmin;
        if (role === 'writer') return isWriter;
        return Boolean(ctx.query('$permissions', { check: 'scope', actor: tx.author, scope: role, atMs: nowMs }));
      });
      if (!authorized) return { ok: false, code: 'workflow:role_required' };

      const required = Number.isSafeInteger(rule.requiredApprovals) && rule.requiredApprovals > 0 ? rule.requiredApprovals : 1;
      const nextApprovals = { ...(item.approvals || {}) };
      const currentSigners = Array.isArray(nextApprovals[tName]) ? nextApprovals[tName].slice() : [];
      if (!currentSigners.includes(tx.author)) currentSigners.push(tx.author);
      currentSigners.sort();
      nextApprovals[tName] = currentSigners;

      if (currentSigners.length < required) {
        cur.items[id] = { ...item, approvals: nextApprovals };
        return {
          ok: true,
          state: cur,
          events: [{ topic: 'workflow.approval_recorded', payload: { id, transition: tName, count: currentSigners.length, required } }],
        };
      }

      const nextHistory = item.history.concat([{
        transition: tName,
        from: item.state,
        state: rule.to,
        actor: tx.author,
        ts: nowMs,
        opId: tx.opId,
        ...(typeof input.note === 'string' && input.note.length > 0 ? { note: input.note } : {}),
      }]);
      cur.items[id] = {
        ...item,
        state: rule.to,
        enteredAtMs: nowMs,
        approvals: {},
        ...(input.payload !== undefined ? { payload: input.payload } : {}),
        history: nextHistory,
      };
      return {
        ok: true,
        state: cur,
        events: [{ topic: 'workflow.transitioned', payload: { id, transition: tName, from: item.state, to: rule.to } }],
      };
    }

    if (action === 'expire') {
      const id = typeof input.id === 'string' ? input.id : '';
      const item = cur.items[id];
      if (!item) return { ok: false, code: 'workflow:item_not_found' };
      const rule = cur.definition.transitions.find(r =>
        r.slaMs !== undefined && r.slaMs !== null && r.expiredTo &&
        (Array.isArray(r.from) ? r.from.includes(item.state) : r.from === item.state),
      );
      if (!rule) return { ok: false, code: 'workflow:no_sla_rule' };
      if (nowMs <= item.enteredAtMs + Number(rule.slaMs)) return { ok: false, code: 'workflow:not_yet_expired' };
      cur.items[id] = {
        ...item,
        state: rule.expiredTo,
        enteredAtMs: nowMs,
        approvals: {},
        history: item.history.concat([{ transition: 'expire', from: item.state, state: rule.expiredTo, actor: tx.author, ts: nowMs, opId: tx.opId }]),
      };
      return { ok: true, state: cur, events: [{ topic: 'workflow.expired', payload: { id, to: rule.expiredTo } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const cur = normalizeWorkflow(state, null);
    const q = input && typeof input === 'object' ? input : {};
    const kind = q.query || q.kind || 'list';
    if (kind === 'config') return cur.definition;
    if (kind === 'item' && typeof q.id === 'string') return cur.items[q.id] || null;
    const all = Object.values(cur.items);
    const filtered = typeof q.state === 'string' ? all.filter(i => i.state === q.state) : all;
    filtered.sort((a, b) => (a.createdAtMs !== b.createdAtMs ? a.createdAtMs - b.createdAtMs : (a.id < b.id ? -1 : 1)));
    return { items: filtered };
  },

  describe() {
    const anyPayload = { anyOf: [{ type: 'object', properties: {} }, { type: 'string' }, { type: 'number' }, { type: 'boolean' }, { type: 'null' }] };
    return {
      commands: [
        { name: 'configure', description: 'Configure states, transitions, role guards, and SLA rules.', input: { type: 'object', properties: { definition: { type: 'object', properties: {} } }, required: ['definition'] } },
        { name: 'create', description: 'Create a workflow item or AI proposal.', input: { type: 'object', properties: { id: { type: 'string' }, title: { type: 'string' }, payload: anyPayload } } },
        { name: 'transition', description: 'Approve or execute a state transition.', input: { type: 'object', properties: { id: { type: 'string' }, transition: { type: 'string' }, note: { type: 'string' } }, required: ['id', 'transition'] } },
        { name: 'expire', description: 'Transition an item past its SLA deadline.', input: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
      ],
      queries: [
        { name: 'list', description: 'List workflow items (optionally filtered by state).', input: { type: 'object', properties: { state: { type: 'string' } } } },
        { name: 'item', description: 'Inspect one workflow item and its history.', input: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
        { name: 'config', description: 'Inspect active state machine definition.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()
