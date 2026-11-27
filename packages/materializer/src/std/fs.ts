export const STD_FS_SOURCE = `
function hasWriter(ctx, author) {
  const cfg = ctx.config && typeof ctx.config === 'object' ? ctx.config : {};
  if (cfg.allowPublicWrite === true) return true;
  const checked = ctx.query('$permissions', { check: 'writer', actor: author });
  if (typeof checked === 'boolean') return checked;
  const perms = ctx.topic('$permissions');
  if (!perms || !Array.isArray(perms.members)) return false;
  return perms.members.some(m => m.publicKey === author && (m.writer === true || m.administrator === true));
}

function normalizePath(raw) {
  if (typeof raw !== 'string') return null;
  const parts = raw.split('/').filter(Boolean);
  if (parts.length === 0) return '/';
  for (const p of parts) {
    if (p === '.' || p === '..' || p.length > 128) return null;
  }
  return '/' + parts.join('/');
}

function parentPath(p) {
  if (p === '/') return null;
  const idx = p.lastIndexOf('/');
  return idx <= 0 ? '/' : p.slice(0, idx);
}

function conflictPathFor(path, author, opId) {
  const slash = path.lastIndexOf('/');
  const dir = path.slice(0, slash + 1);
  const name = path.slice(slash + 1);
  const dot = name.lastIndexOf('.');
  const tag = ' (conflict-' + String(author).slice(0, 8) + '-' + String(opId).slice(0, 6) + ')';
  if (dot > 0) return dir + name.slice(0, dot) + tag + name.slice(dot);
  return dir + name + tag;
}

function normalizeFs(state) {
  const s = state && typeof state === 'object' && state.entries && typeof state.entries === 'object'
    ? { entries: { ...state.entries } }
    : { entries: { '/': { kind: 'dir', path: '/', createdAtMs: 0 } } };
  if (!s.entries['/']) s.entries['/'] = { kind: 'dir', path: '/', createdAtMs: 0 };
  return s;
}

function ensureParents(entries, path, nowMs, author) {
  let cur = parentPath(path);
  const toCreate = [];
  while (cur && !entries[cur]) {
    toCreate.push(cur);
    cur = parentPath(cur);
  }
  for (let i = toCreate.length - 1; i >= 0; i--) {
    const dirPath = toCreate[i];
    entries[dirPath] = { kind: 'dir', path: dirPath, createdBy: author, createdAtMs: nowMs };
  }
}

/**
 * Content-Addressed Virtual Filesystem Reducer.
 * Stores directory tree & metadata in the log while file bodies are lazy-pulled via session.content.
 * Concurrent edits to a file with a mismatched expectedOpId automatically create a non-destructive conflict fork.
 */
export const virtualFs = {
  reduce(state, tx, ctx) {
    if (!hasWriter(ctx, tx.author)) return { ok: false, code: 'writer_required' };
    const cur = normalizeFs(state);
    const input = tx.payload;
    if (!input || typeof input !== 'object') return { ok: false, code: 'invalid_input' };
    const nowMs = Number(tx.authorTimestampMs || 0);
    const action = typeof input.action === 'string' ? input.action : 'writeFile';

    if (action === 'mkdir') {
      const path = normalizePath(input.path);
      if (!path || path === '/') return { ok: false, code: 'fs:invalid_path' };
      if (cur.entries[path] && cur.entries[path].kind !== 'dir') return { ok: false, code: 'fs:path_is_file' };
      ensureParents(cur.entries, path, nowMs, tx.author);
      if (!cur.entries[path]) {
        cur.entries[path] = { kind: 'dir', path, createdBy: tx.author, createdAtMs: nowMs };
      }
      return { ok: true, state: cur, events: [{ topic: 'fs.mkdir', payload: { path } }] };
    }

    if (action === 'writeFile') {
      const path = normalizePath(input.path);
      if (!path || path === '/') return { ok: false, code: 'fs:invalid_path' };
      const existing = cur.entries[path];
      if (existing && existing.kind === 'dir') return { ok: false, code: 'fs:path_is_dir' };
      ensureParents(cur.entries, path, nowMs, tx.author);

      const expectedOpId = input.expectedOpId;
      const isConflict = expectedOpId !== undefined &&
        ((existing && existing.opId !== expectedOpId) || (!existing && expectedOpId !== null));

      if (isConflict && input.onConflict === 'reject') {
        return { ok: false, code: 'fs:version_conflict', detail: path };
      }

      const targetPath = isConflict ? conflictPathFor(path, tx.author, tx.opId) : path;
      const prevVersion = existing && !isConflict ? (Number(existing.version) || 0) : 0;
      const prevHistory = existing && !isConflict && Array.isArray(existing.history) ? existing.history.slice(-15) : [];
      const meta = {
        kind: 'file',
        path: targetPath,
        ...(isConflict ? { conflictOf: path } : {}),
        ref: input.ref === undefined ? null : input.ref,
        sha256: typeof input.sha256 === 'string' ? input.sha256 : null,
        bytes: Number.isSafeInteger(input.bytes) ? input.bytes : 0,
        mediaType: typeof input.mediaType === 'string' ? input.mediaType : 'application/octet-stream',
        version: prevVersion + 1,
        opId: tx.opId,
        updatedBy: tx.author,
        updatedAtMs: nowMs,
        history: prevHistory.concat([{ version: prevVersion + 1, opId: tx.opId, ref: input.ref ?? null, updatedBy: tx.author, updatedAtMs: nowMs }]),
      };
      cur.entries[targetPath] = meta;
      return {
        ok: true,
        state: cur,
        events: [{ topic: isConflict ? 'fs.conflict_fork' : 'fs.write', payload: { path: targetPath, ...(isConflict ? { conflictOf: path } : {}), version: meta.version } }],
      };
    }

    if (action === 'move') {
      const from = normalizePath(input.from);
      const to = normalizePath(input.to);
      if (!from || !to || from === '/' || to === '/') return { ok: false, code: 'fs:invalid_path' };
      const entry = cur.entries[from];
      if (!entry) return { ok: false, code: 'fs:not_found' };
      if (cur.entries[to]) return { ok: false, code: 'fs:destination_exists' };
      ensureParents(cur.entries, to, nowMs, tx.author);
      if (entry.kind === 'file') {
        delete cur.entries[from];
        cur.entries[to] = { ...entry, path: to, updatedBy: tx.author, updatedAtMs: nowMs };
      } else {
        const prefix = from + '/';
        const moved = [];
        for (const p of Object.keys(cur.entries)) {
          if (p === from || p.startsWith(prefix)) moved.push(p);
        }
        for (const p of moved) {
          const nextP = p === from ? to : to + p.slice(from.length);
          cur.entries[nextP] = { ...cur.entries[p], path: nextP };
          delete cur.entries[p];
        }
      }
      return { ok: true, state: cur, events: [{ topic: 'fs.move', payload: { from, to } }] };
    }

    if (action === 'delete') {
      const path = normalizePath(input.path);
      if (!path || path === '/') return { ok: false, code: 'fs:invalid_path' };
      if (!cur.entries[path]) return { ok: false, code: 'fs:not_found' };
      const prefix = path + '/';
      for (const p of Object.keys(cur.entries)) {
        if (p === path || p.startsWith(prefix)) delete cur.entries[p];
      }
      return { ok: true, state: cur, events: [{ topic: 'fs.delete', payload: { path } }] };
    }

    if (action === 'resolveConflict') {
      const conflictPath = normalizePath(input.conflictPath);
      if (!conflictPath || !cur.entries[conflictPath] || !cur.entries[conflictPath].conflictOf) {
        return { ok: false, code: 'fs:conflict_not_found' };
      }
      const conflictEntry = cur.entries[conflictPath];
      const originalPath = conflictEntry.conflictOf;
      const strategy = input.strategy || 'keep_original';
      if (strategy === 'keep_original') {
        delete cur.entries[conflictPath];
      } else if (strategy === 'replace_original') {
        const prev = cur.entries[originalPath];
        const nextVersion = prev ? (Number(prev.version) || 0) + 1 : 1;
        delete cur.entries[conflictPath];
        const { conflictOf: _drop, ...clean } = conflictEntry;
        cur.entries[originalPath] = { ...clean, path: originalPath, version: nextVersion, opId: tx.opId, updatedBy: tx.author, updatedAtMs: nowMs };
      } else if (strategy === 'keep_both') {
        const { conflictOf: _drop, ...clean } = conflictEntry;
        cur.entries[conflictPath] = clean;
      } else {
        return { ok: false, code: 'fs:invalid_strategy' };
      }
      return { ok: true, state: cur, events: [{ topic: 'fs.conflict_resolved', payload: { conflictPath, originalPath, strategy } }] };
    }

    return { ok: false, code: 'unknown_action' };
  },

  query(state, input) {
    const cur = normalizeFs(state);
    const q = input && typeof input === 'object' ? input : {};
    const kind = q.query || q.kind || 'list';
    if (kind === 'stat') {
      const p = normalizePath(q.path || '/');
      return p ? (cur.entries[p] || null) : null;
    }
    if (kind === 'conflicts') {
      const conflicts = Object.values(cur.entries).filter(e => e.kind === 'file' && e.conflictOf);
      conflicts.sort((a, b) => (a.path < b.path ? -1 : 1));
      return { conflicts };
    }
    if (kind === 'tree') {
      const entries = Object.values(cur.entries).sort((a, b) => (a.path < b.path ? -1 : 1));
      return { entries };
    }
    const dir = normalizePath(q.path || '/');
    if (!dir) return { entries: [] };
    const entries = Object.values(cur.entries)
      .filter(e => e.path !== '/' && parentPath(e.path) === dir)
      .sort((a, b) => (a.kind !== b.kind ? (a.kind === 'dir' ? -1 : 1) : (a.path < b.path ? -1 : 1)));
    return { path: dir, entries };
  },

  describe() {
    const optStr = { anyOf: [{ type: 'string' }, { type: 'null' }] };
    const optRef = { anyOf: [{ type: 'object', properties: {} }, { type: 'string' }, { type: 'null' }] };
    return {
      commands: [
        { name: 'mkdir', description: 'Create a directory.', input: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
        { name: 'writeFile', description: 'Write file metadata and content ref (auto-forks on concurrent version mismatch).', input: { type: 'object', properties: { path: { type: 'string' }, ref: optRef, bytes: { type: 'integer' }, mediaType: { type: 'string' }, expectedOpId: optStr }, required: ['path'] } },
        { name: 'move', description: 'Move or rename a file or directory.', input: { type: 'object', properties: { from: { type: 'string' }, to: { type: 'string' } }, required: ['from', 'to'] } },
        { name: 'delete', description: 'Delete a file or directory recursively.', input: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
        { name: 'resolveConflict', description: 'Resolve an auto-forked conflict file.', input: { type: 'object', properties: { conflictPath: { type: 'string' }, strategy: { type: 'string', enum: ['keep_original', 'replace_original', 'keep_both'] } }, required: ['conflictPath'] } },
      ],
      queries: [
        { name: 'list', description: 'List entries in a directory.', input: { type: 'object', properties: { path: { type: 'string' } } } },
        { name: 'stat', description: 'Inspect metadata and history for a path.', input: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
        { name: 'conflicts', description: 'List unresolved conflict forks.', input: { type: 'object', properties: {} } },
        { name: 'tree', description: 'List the entire directory tree.', input: { type: 'object', properties: {} } },
      ],
    };
  },
};
`.trimStart()
