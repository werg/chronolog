/**
 * Declarative, self-describing JS reducer helper (`chronolog/reducer`):
 * Define `commands` and `queries` once to get automatic `chronolog/schema` input validation,
 * `action` dispatch, `ctx.reject(...)` support, and auto-generated `describe()` schemas
 * for MCP tools, CLIs, and AI agents.
 */
export const STD_REDUCER_SOURCE = `
import { validate } from 'chronolog/schema';

export function defineReducer(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('REDUCER_SPEC_INVALID');
  const initialState = spec.initialState === undefined ? {} : spec.initialState;
  const commands = spec.commands && typeof spec.commands === 'object' ? spec.commands : {};
  const queries = spec.queries && typeof spec.queries === 'object' ? spec.queries : {};
  const pre = Array.isArray(spec.pre) ? spec.pre : (spec.pre ? [spec.pre] : []);
  const post = Array.isArray(spec.post) ? spec.post : (spec.post ? [spec.post] : []);

  return {
    reduce(state, tx, ctx) {
      const cur = state === null || state === undefined ? initialState : state;
      const input = tx.payload;
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return { ok: false, code: 'invalid_input' };
      }
      const action = typeof input.action === 'string' ? input.action : null;
      if (!action || !Object.prototype.hasOwnProperty.call(commands, action)) {
        return { ok: false, code: 'unknown_action', detail: String(action) };
      }
      const entry = commands[action];
      const run = typeof entry === 'function' ? entry : entry.run;
      if (typeof run !== 'function') return { ok: false, code: 'unknown_action' };
      if (entry && entry.input) {
        const v = validate(entry.input, input);
        if (!v.ok) return v;
      }
      if (entry && typeof entry.requiredCapability === 'string') {
        if (!ctx.can(entry.requiredCapability)) {
          return { ok: false, code: entry.requiredCapability + '_required' };
        }
      }
      if (entry && typeof entry.requiredScope === 'string') {
        if (!ctx.can('scope', tx.author, { scope: entry.requiredScope })) {
          return { ok: false, code: 'scope_required', detail: entry.requiredScope };
        }
      }
      const cmdPre = entry && entry.pre ? (Array.isArray(entry.pre) ? entry.pre : [entry.pre]) : [];
      for (const check of pre.concat(cmdPre)) {
        const r = check(cur, input, tx, ctx);
        if (r === false) return { ok: false, code: 'precondition_failed' };
        if (r && r.ok === false) return r;
      }
      const out = run(cur, input, tx, ctx);
      if (out && typeof out === 'object' && out.ok === false) return out;
      const nextState = out && typeof out === 'object' && Object.prototype.hasOwnProperty.call(out, 'state') ? out.state : out;
      const events = out && typeof out === 'object' && Array.isArray(out.events) ? out.events : [];
      const cmdPost = entry && entry.post ? (Array.isArray(entry.post) ? entry.post : [entry.post]) : [];
      for (const check of post.concat(cmdPost)) {
        const r = check(nextState, input, tx, ctx, cur);
        if (r === false) return { ok: false, code: 'postcondition_failed' };
        if (r && r.ok === false) return r;
      }
      return { ok: true, state: nextState, ...(events.length > 0 ? { events } : {}) };
    },
    query(state, input, ctx) {
      const cur = state === null || state === undefined ? initialState : state;
      if (input === null || input === undefined) {
        if (Object.prototype.hasOwnProperty.call(queries, 'default')) {
          const entry = queries.default;
          const run = typeof entry === 'function' ? entry : entry.run;
          return run(cur, {}, ctx);
        }
        return cur;
      }
      const qObj = typeof input === 'object' && !Array.isArray(input) ? input : { query: String(input) };
      const qName = typeof qObj.query === 'string' ? qObj.query : (typeof qObj.kind === 'string' ? qObj.kind : null);
      if (qName && Object.prototype.hasOwnProperty.call(queries, qName)) {
        const entry = queries[qName];
        const run = typeof entry === 'function' ? entry : entry.run;
        return run(cur, qObj, ctx);
      }
      return cur;
    },
    describe() {
      return {
        commands: Object.entries(commands).map(([name, entry]) => ({
          name,
          description: (entry && entry.description) || '',
          input: (entry && entry.input) || { type: 'object', properties: {} },
        })),
        queries: Object.entries(queries).map(([name, entry]) => ({
          name,
          description: (entry && entry.description) || '',
          input: (entry && entry.input) || { type: 'object', properties: {} },
        })),
      };
    },
  };
}

export default defineReducer;
`.trimStart()
