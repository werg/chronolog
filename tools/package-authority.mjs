import { execNpmSync } from './lib/npm-cli.mjs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import process from 'node:process';
import console from 'node:console';
import { build } from 'esbuild';
import ts from 'typescript';

const root = resolve(import.meta.dirname, '..');
const args = process.argv.slice(2);
const outputFlag = args.indexOf('--output');
const output = resolve(outputFlag >= 0 ? args[outputFlag + 1] : args.find(value => !value.startsWith('--')) ?? join(root, 'artifacts/authority'));
const names = ['index', 'control', 'metadata', 'participant', 'publication', 'finality'];
const authorityRoot = join(root, 'packages/authority');
const workspace = JSON.parse(await readFile(join(authorityRoot, 'package.json'), 'utf8'));
// Bundle exactly the source entry selected by each public workspace export.
const entries = Object.fromEntries(names.map(name => {
  const key = name === 'index' ? '.' : `./${name}`, entry = workspace.exports[key];
  if (typeof entry !== 'string' || !entry.startsWith('./src/') || entry.split('/').includes('..') || !entry.endsWith('.ts'))
    throw new Error(`Invalid authority source export: ${key}`);
  return [name, resolve(authorityRoot, entry)];
}));
await mkdir(output, { recursive: true });
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
const source = git('rev-parse', 'HEAD'), sourceTree = git('rev-parse', 'HEAD^{tree}');
const result = await build({ entryPoints: entries, outdir: output, outExtension: { '.js': '.mjs' }, bundle: true,
  platform: 'browser', format: 'esm', target: 'es2022', metafile: true, logLevel: 'warning', absWorkingDir: root });
for (const module of Object.values(result.metafile.outputs)) {
  if (module.imports.some(value => value.external && /^(?:node:|@chronolog\/)/u.test(value.path)))
    throw new Error('Authority archives must be standalone and portable');
}
const configuration = ts.readConfigFile(join(root, 'tsconfig.base.json'), ts.sys.readFile);
if (configuration.error) throw new Error(ts.flattenDiagnosticMessageText(configuration.error.messageText, '\n'));
const parsed = ts.parseJsonConfigFileContent(configuration.config, ts.sys, root);
const compiler = ts.createProgram(Object.values(entries), { ...parsed.options, noEmit: true });
const typeInputs = compiler.getSourceFiles().filter(file => !file.fileName.includes('/node_modules/') && file.fileName.startsWith(root + '/'))
  .map(file => relative(root, file.fileName).replaceAll('\\', '/'));
const inputs = [...new Set([...Object.keys(result.metafile.inputs), ...typeInputs, 'tools/package-authority.mjs',
  'tools/lib/npm-cli.mjs', 'package.json', 'pnpm-lock.yaml', 'packages/authority/package.json', 'packages/authority/README.md', 'tsconfig.base.json'])].sort();
if (Object.keys(result.metafile.inputs).some(path => /(?:materializer|peer-session|node:)/u.test(path)))
  throw new Error('Portable authority must not import application execution, SQL or native transports');
const changed = git('status', '--porcelain', '--', ...inputs);
if (changed && !args.includes('--allow-dirty')) throw new Error('Commit authority inputs before packaging');
const suffix = `${source.slice(0, 8)}${changed ? '-dirty' : ''}`;
const version = `0.0.0-g${suffix}`;
for (const [name, entry] of Object.entries(entries)) {
  execNpmSync(['exec', '--yes', '--package=dts-bundle-generator@9.5.1', '--package=typescript@5.8.3', '--',
    'dts-bundle-generator', '--project', join(root, 'tsconfig.base.json'), '--out-file', join(output, `${name}.d.ts`),
    '--external-inlines', '@chronolog/canonical', '@chronolog/crypto', '@chronolog/protocol', '@chronolog/authority', '@chronolog/records', '--', entry],
  { cwd: root, stdio: 'inherit' });
  const declarations = await readFile(join(output, `${name}.d.ts`), 'utf8');
  if (/from\s+['"](?:node:|@chronolog\/)|reference\s+types=/u.test(declarations))
    throw new Error('Authority declarations must be portable and self-contained');
}
if (git('rev-parse', 'HEAD') !== source || git('rev-parse', 'HEAD^{tree}') !== sourceTree ||
    git('status', '--porcelain', '--', ...inputs) !== changed)
  throw new Error('Authority source changed during packaging; rebuild from one stable checkpoint');
const exports = Object.fromEntries(names.map(name => [name === 'index' ? '.' : `./${name}`,
  { types: `./${name}.d.ts`, import: `./${name}.mjs` }]));
await writeFile(join(output, 'README.md'), await readFile(join(authorityRoot, 'README.md')));
const files = [...names.flatMap(name => [`${name}.mjs`, `${name}.d.ts`]), 'README.md'];
await writeFile(join(output, 'package.json'), JSON.stringify({ name: '@chronolog/authority', version, type: 'module',
  description: 'Portable signed application authority, publication and optional authored-time finality',
  exports, files: [...files, 'provenance.json'] }, null, 2) + '\n');
const digest = async name => createHash('sha256').update(await readFile(join(output, name))).digest('hex');
const runtimeModules = Object.fromEntries(Object.entries(result.metafile.outputs).map(([path, module]) =>
  [relative(output, resolve(root, path)).replaceAll('\\', '/'), { inputs: Object.keys(module.inputs).sort(), imports: module.imports }]));
await writeFile(join(output, 'provenance.json'), JSON.stringify({ format: 'chronolog-authority-package/v1',
  repository: 'werg/chronolog-db', source, sourceTree, profile: 'chronolog-crdt-v1', dirty: Boolean(changed), inputs, runtimeModules,
  sha256: Object.fromEntries(await Promise.all(files.map(async name => [name, await digest(name)]))) }, null, 2) + '\n');
const packed = JSON.parse(execNpmSync(['pack', '--ignore-scripts', '--json', '--pack-destination', output], {
  cwd: output, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const target = join(output, `chronolog-authority-${suffix}.tgz`);
await rename(join(output, packed.filename), target);
console.log(JSON.stringify({ artifact: target, version, source, sourceTree, dirty: Boolean(changed), runtimeInputs: inputs.length }));
