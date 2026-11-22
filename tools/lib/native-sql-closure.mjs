import ts from 'typescript';

/** Cache only a completed root search: cycles cannot make an intermediate node falsely safe. */
export function createNativeSqlClassifier({ read, resolveImport, isNative }) {
  const cache = new Map();
  return function touchesNativeSql(entry) {
    if (cache.has(entry)) return cache.get(entry);
    const pending = [entry], seen = new Set();
    while (pending.length) {
      const file = pending.pop();
      if (seen.has(file)) continue;
      seen.add(file);
      if (isNative(file) || cache.get(file) === true) { cache.set(entry, true); return true; }
      if (cache.get(file) === false) continue;
      for (const imported of ts.preProcessFile(read(file), true, true).importedFiles) {
        const target = resolveImport(imported.fileName, file);
        if (target === 'NATIVE_SQL') { cache.set(entry, true); return true; }
        if (target) pending.push(target);
      }
    }
    cache.set(entry, false); return false;
  };
}
