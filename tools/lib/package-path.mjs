import path from 'node:path';
/** Resolve provenance entries within the installed package on every supported host OS. */
export function checkedPackagePath(root, name, paths = path) {
  const target = paths.resolve(root, name), local = paths.relative(root, target);
  if (!local || paths.isAbsolute(local) || local === '..' || local.startsWith('..' + paths.sep)) throw new Error('Unsafe provenance file path');
  return target;
}
