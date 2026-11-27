export const STD_LEDGER_SOURCE = `
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

function normalizeState(state) {
  const s = state && typeof state === 'object' ? state : {};
  return {
    accounts: s.accounts && typeof s.accounts === 'object' ? { ...s.accounts } : {},
    holds: s.holds && typeof s.holds === 'object' ? { ...s.holds } : {},
    allowances: s.allowances && typeof s.allowances === 'object' ? { ...s.allowances } : {},
    entries: Array.isArray(s.entries) ? s.entries.slice() : [],
  };
}

function reservedAmount(state, accountId, nowMs) {
  let reserved = 0;
  for (const h of Object.values(state.holds)) {
    if (h.status === 'active' && h.from === accountId && (h.expiresAtMs === null || nowMs <= h.expiresAtMs)) {
      reserved += h.amount;
    }
  }
  for (const a of Object.values(state.allowances)) {
    if (a.status === 'active' && a.fromAccount === accountId && (a.expiresAtMs === null || nowMs <= a.expiresAtMs)) {
      reserved += a.remaining;
    }
  }
  return reserved;
}

function availableBalance(state, accountId, nowMs) {
  const acct = state.accounts[accountId];
  if (!acct) return 0;
  return acct.balance - reservedAmount(state, accountId, nowMs);
}

/**
 * Deterministic Double-Entry Ledger with:
 * - Balanced integer postings (sum === 0) and per-account non-negative invariants
 * - Expiring holds/escrows (automatically release when authorTimestampMs > expiresAtMs)
 * - Offline Escrow CRDT allowances (grantee spends autonomously offline up to reserved quota)
 */
export const doubleEntryLedger = {
  reduce(state, tx, ctx) {
    const cur = normalizeState(state);
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const isAdmin = hasCap(ctx, 'administrator', tx.author);
    const isWriter = isAdmin || hasCap(ctx, 'writer', tx.author);
    const nowMs = Number(tx.authorTimestampMs || 0);
    const action = typeof input.action === 'string' ? input.action : 'post';

    if (action === 'createAccount') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const id = typeof input.id === 'string' && input.id.length > 0 ? input.id : null;
      if (!id) return { ok: false, code: 'ledger:invalid_account_id' };
      if (cur.accounts[id]) return { ok: false, code: 'ledger:account_exists' };
      const allowNegative = input.allowNegative === true;
      if (allowNegative && !isAdmin) return { ok: false, code: 'admin_required' };
      cur.accounts[id] = {
        id,
        currency: typeof input.currency === 'string' && input.currency.length > 0 ? input.currency : 'USD',
        balance: 0,
        allowNegative,
        owner: typeof input.owner === 'string' ? input.owner : tx.author,
      };
      return { ok: true, state: cur, events: [{ topic: 'ledger.account_created', payload: { id } }] };
    }

    if (action === 'post') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      if (!Array.isArray(input.postings) || input.postings.length < 2) return { ok: false, code: 'ledger:postings_required' };
      let sum = 0;
      const currencies = new Set();
      const deltas = {};
      for (const p of input.postings) {
        if (!p || typeof p.account !== 'string' || !Number.isSafeInteger(p.delta) || p.delta === 0) {
          return { ok: false, code: 'ledger:invalid_posting' };
        }
        const acct = cur.accounts[p.account];
        if (!acct) return { ok: false, code: 'ledger:account_not_found', detail: p.account };
        currencies.add(acct.currency);
        sum += p.delta;
        deltas[p.account] = (deltas[p.account] || 0) + p.delta;
      }
      if (currencies.size !== 1) return { ok: false, code: 'ledger:currency_mismatch' };
      if (sum !== 0) return { ok: false, code: 'ledger:unbalanced' };
      for (const [acctId, delta] of Object.entries(deltas)) {
        const acct = cur.accounts[acctId];
        if (!acct.allowNegative && availableBalance(cur, acctId, nowMs) + delta < 0) {
          return { ok: false, code: 'ledger:insufficient_funds', detail: acctId };
        }
      }
      for (const [acctId, delta] of Object.entries(deltas)) {
        cur.accounts[acctId] = { ...cur.accounts[acctId], balance: cur.accounts[acctId].balance + delta };
      }
      const entry = {
        opId: tx.opId,
        author: tx.author,
        ts: nowMs,
        memo: typeof input.memo === 'string' ? input.memo : '',
        postings: input.postings.map(p => ({ account: p.account, delta: p.delta })),
      };
      cur.entries = cur.entries.concat([entry]).slice(-512);
      return { ok: true, state: cur, events: [{ topic: 'ledger.posted', payload: { opId: tx.opId } }] };
    }

    if (action === 'hold') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const holdId = typeof input.holdId === 'string' && input.holdId.length > 0 ? input.holdId : tx.opId;
      if (cur.holds[holdId]) return { ok: false, code: 'ledger:hold_exists' };
      const amount = Number(input.amount);
      if (!Number.isSafeInteger(amount) || amount <= 0) return { ok: false, code: 'ledger:invalid_amount' };
      const fromAcct = cur.accounts[input.from];
      const toAcct = cur.accounts[input.to];
      if (!fromAcct || !toAcct) return { ok: false, code: 'ledger:account_not_found' };
      if (fromAcct.currency !== toAcct.currency) return { ok: false, code: 'ledger:currency_mismatch' };
      if (!fromAcct.allowNegative && availableBalance(cur, fromAcct.id, nowMs) < amount) {
        return { ok: false, code: 'ledger:insufficient_funds', detail: fromAcct.id };
      }
      const expiresAtMs = input.expiresAtMs === undefined || input.expiresAtMs === null ? null : Number(input.expiresAtMs);
      if (expiresAtMs !== null && !Number.isSafeInteger(expiresAtMs)) return { ok: false, code: 'ledger:invalid_expiry' };
      cur.holds[holdId] = {
        holdId,
        from: fromAcct.id,
        to: toAcct.id,
        amount,
        expiresAtMs,
        status: 'active',
        createdBy: tx.author,
        createdAtMs: nowMs,
      };
      return { ok: true, state: cur, events: [{ topic: 'ledger.hold_created', payload: { holdId, amount } }] };
    }

    if (action === 'captureHold') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const h = cur.holds[input.holdId];
      if (!h || h.status !== 'active') return { ok: false, code: 'ledger:hold_not_active' };
      if (h.expiresAtMs !== null && nowMs > h.expiresAtMs) return { ok: false, code: 'ledger:hold_expired' };
      const captureAmt = input.amount === undefined ? h.amount : Number(input.amount);
      if (!Number.isSafeInteger(captureAmt) || captureAmt <= 0 || captureAmt > h.amount) {
        return { ok: false, code: 'ledger:invalid_amount' };
      }
      cur.accounts[h.from] = { ...cur.accounts[h.from], balance: cur.accounts[h.from].balance - captureAmt };
      cur.accounts[h.to] = { ...cur.accounts[h.to], balance: cur.accounts[h.to].balance + captureAmt };
      cur.holds[h.holdId] = { ...h, status: 'captured', capturedAmount: captureAmt };
      cur.entries = cur.entries.concat([{
        opId: tx.opId,
        author: tx.author,
        ts: nowMs,
        memo: 'capture:' + h.holdId,
        postings: [{ account: h.from, delta: -captureAmt }, { account: h.to, delta: captureAmt }],
      }]).slice(-512);
      return { ok: true, state: cur, events: [{ topic: 'ledger.hold_captured', payload: { holdId: h.holdId, amount: captureAmt } }] };
    }

    if (action === 'releaseHold') {
      if (!isWriter) return { ok: false, code: 'writer_required' };
      const h = cur.holds[input.holdId];
      if (!h || h.status !== 'active') return { ok: false, code: 'ledger:hold_not_active' };
      if (!isAdmin && h.createdBy !== tx.author) return { ok: false, code: 'admin_or_creator_required' };
      cur.holds[h.holdId] = { ...h, status: 'released' };
      return { ok: true, state: cur, events: [{ topic: 'ledger.hold_released', payload: { holdId: h.holdId } }] };
    }

    if (action === 'grantAllowance') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      const allowanceId = typeof input.allowanceId === 'string' && input.allowanceId.length > 0 ? input.allowanceId : tx.opId;
      if (cur.allowances[allowanceId]) return { ok: false, code: 'ledger:allowance_exists' };
      const amount = Number(input.amount);
      if (!Number.isSafeInteger(amount) || amount <= 0) return { ok: false, code: 'ledger:invalid_amount' };
      const fromAcct = cur.accounts[input.fromAccount];
      if (!fromAcct) return { ok: false, code: 'ledger:account_not_found' };
      if (typeof input.grantee !== 'string' || input.grantee.length === 0) return { ok: false, code: 'ledger:invalid_grantee' };
      if (!fromAcct.allowNegative && availableBalance(cur, fromAcct.id, nowMs) < amount) {
        return { ok: false, code: 'ledger:insufficient_funds', detail: fromAcct.id };
      }
      const expiresAtMs = input.expiresAtMs === undefined || input.expiresAtMs === null ? null : Number(input.expiresAtMs);
      cur.allowances[allowanceId] = {
        allowanceId,
        fromAccount: fromAcct.id,
        grantee: input.grantee,
        granted: amount,
        remaining: amount,
        expiresAtMs,
        status: 'active',
        grantedBy: tx.author,
        grantedAtMs: nowMs,
      };
      return { ok: true, state: cur, events: [{ topic: 'ledger.allowance_granted', payload: { allowanceId, grantee: input.grantee, amount } }] };
    }

    if (action === 'spendFromAllowance') {
      const al = cur.allowances[input.allowanceId];
      if (!al || al.status !== 'active') return { ok: false, code: 'ledger:allowance_not_active' };
      if (al.grantee !== tx.author && !isAdmin) return { ok: false, code: 'ledger:grantee_required' };
      if (al.expiresAtMs !== null && nowMs > al.expiresAtMs) return { ok: false, code: 'ledger:allowance_expired' };
      const amount = Number(input.amount);
      if (!Number.isSafeInteger(amount) || amount <= 0 || amount > al.remaining) {
        return { ok: false, code: 'ledger:allowance_exceeded' };
      }
      const toAcct = cur.accounts[input.toAccount];
      const fromAcct = cur.accounts[al.fromAccount];
      if (!toAcct || !fromAcct) return { ok: false, code: 'ledger:account_not_found' };
      if (fromAcct.currency !== toAcct.currency) return { ok: false, code: 'ledger:currency_mismatch' };
      cur.accounts[fromAcct.id] = { ...fromAcct, balance: fromAcct.balance - amount };
      cur.accounts[toAcct.id] = { ...toAcct, balance: toAcct.balance + amount };
      cur.allowances[al.allowanceId] = { ...al, remaining: al.remaining - amount };
      cur.entries = cur.entries.concat([{
        opId: tx.opId,
        author: tx.author,
        ts: nowMs,
        memo: typeof input.memo === 'string' ? input.memo : ('allowance:' + al.allowanceId),
        postings: [{ account: fromAcct.id, delta: -amount }, { account: toAcct.id, delta: amount }],
      }]).slice(-512);
      return { ok: true, state: cur, events: [{ topic: 'ledger.allowance_spent', payload: { allowanceId: al.allowanceId, amount, remaining: al.remaining - amount } }] };
    }

    if (action === 'reclaimAllowance') {
      if (!isAdmin) return { ok: false, code: 'admin_required' };
      const al = cur.allowances[input.allowanceId];
      if (!al || al.status !== 'active') return { ok: false, code: 'ledger:allowance_not_active' };
      cur.allowances[al.allowanceId] = { ...al, status: 'reclaimed', remaining: 0 };
      return { ok: true, state: cur, events: [{ topic: 'ledger.allowance_reclaimed', payload: { allowanceId: al.allowanceId } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const cur = normalizeState(state);
    const q = input && typeof input === 'object' ? input : {};
    const atMs = Number.isSafeInteger(q.atMs) ? q.atMs : 0;
    const kind = q.query || q.kind || 'balances';
    if (kind === 'account' && typeof q.id === 'string') {
      const a = cur.accounts[q.id];
      if (!a) return null;
      return { ...a, available: availableBalance(cur, a.id, atMs) };
    }
    if (kind === 'holds') return { holds: Object.values(cur.holds) };
    if (kind === 'allowances') {
      const list = Object.values(cur.allowances);
      return { allowances: typeof q.grantee === 'string' ? list.filter(a => a.grantee === q.grantee) : list };
    }
    if (kind === 'entries') return { entries: cur.entries };
    const balances = {};
    for (const id of Object.keys(cur.accounts).sort()) {
      const a = cur.accounts[id];
      balances[id] = { currency: a.currency, balance: a.balance, available: availableBalance(cur, id, atMs) };
    }
    return { balances };
  },

  describe() {
    return {
      commands: [
        { name: 'createAccount', description: 'Create a ledger account.', input: { type: 'object', properties: { id: { type: 'string' }, currency: { type: 'string' }, allowNegative: { type: 'boolean' } }, required: ['id'] } },
        { name: 'post', description: 'Submit balanced double-entry postings.', input: { type: 'object', properties: { postings: { type: 'array' }, memo: { type: 'string' } }, required: ['postings'] } },
        { name: 'hold', description: 'Reserve funds in an expiring hold/escrow.', input: { type: 'object', properties: { holdId: { type: 'string' }, from: { type: 'string' }, to: { type: 'string' }, amount: { type: 'integer' }, expiresAtMs: { type: ['integer', 'null'] } }, required: ['from', 'to', 'amount'] } },
        { name: 'captureHold', description: 'Settle an active hold.', input: { type: 'object', properties: { holdId: { type: 'string' }, amount: { type: 'integer' } }, required: ['holdId'] } },
        { name: 'releaseHold', description: 'Release an active hold.', input: { type: 'object', properties: { holdId: { type: 'string' } }, required: ['holdId'] } },
        { name: 'grantAllowance', description: 'Reserve an offline Escrow CRDT spending allowance for a peer or agent.', input: { type: 'object', properties: { allowanceId: { type: 'string' }, fromAccount: { type: 'string' }, grantee: { type: 'string' }, amount: { type: 'integer' }, expiresAtMs: { type: ['integer', 'null'] } }, required: ['fromAccount', 'grantee', 'amount'] } },
        { name: 'spendFromAllowance', description: 'Spend offline from a granted allowance without global consensus.', input: { type: 'object', properties: { allowanceId: { type: 'string' }, toAccount: { type: 'string' }, amount: { type: 'integer' }, memo: { type: 'string' } }, required: ['allowanceId', 'toAccount', 'amount'] } },
        { name: 'reclaimAllowance', description: 'Reclaim unused funds from an allowance.', input: { type: 'object', properties: { allowanceId: { type: 'string' } }, required: ['allowanceId'] } },
      ],
      queries: [
        { name: 'balances', description: 'Read posted and available balances.', input: { type: 'object', properties: { atMs: { type: 'integer' } } } },
        { name: 'allowances', description: 'List active offline spending allowances.', input: { type: 'object', properties: { grantee: { type: 'string' } } } },
        { name: 'holds', description: 'List holds and escrows.', input: { type: 'object', properties: {} } },
        { name: 'entries', description: 'Read ledger entry history.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()
