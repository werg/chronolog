import { createHash } from 'node:crypto';
import process from 'node:process';
import console from 'node:console';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { build } from 'esbuild';

const root = resolve(import.meta.dirname, '..');
const output = resolve(process.argv[2] ?? join(root, 'artifacts/membership'));
const entry = join(root, 'packages/node-core/src/membership.ts');
await mkdir(output, { recursive: true });
const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const result = await build({ entryPoints: [entry], outfile: join(output, 'index.mjs'), bundle: true,
  platform: 'browser', format: 'esm', target: 'es2022', metafile: true, logLevel: 'warning',
  absWorkingDir: root });
const inputs = Object.keys(result.metafile.inputs).sort();
if (inputs.some(path => /(?:materializer|transport-ssb|node-core\/src\/node\.ts|node:)/u.test(path))) {
  throw new Error('Membership package must not load an application engine or native transport');
}
const changed = execFileSync('git', ['status', '--porcelain', '--', ...inputs], { cwd: root, encoding: 'utf8' }).trim();
if (changed && !process.argv.includes('--allow-dirty')) throw new Error('Commit membership package inputs before packaging');
const version = `0.0.0-${source.slice(0, 8)}${changed ? '-dirty' : ''}`;

// Pin the declaration builder and its compiler independently of the host's
// global npm/TypeScript versions. The published package has no dependencies.
execFileSync('npm', ['exec', '--yes', '--package=dts-bundle-generator@9.5.1', '--package=typescript@5.8.3', '--',
  'dts-bundle-generator', '--project', join(root, 'tsconfig.base.json'), '--out-file', join(output, 'index.d.ts'),
  '--external-inlines', '@chronolog/canonical', '@chronolog/capabilities', '@chronolog/crypto', '@chronolog/protocol',
  '@chronolog/records', '@chronolog/node-core', '--', entry], { cwd: root, stdio: 'inherit' });
const declarations = await readFile(join(output, 'index.d.ts'), 'utf8');
if (/from\s+['"](?:node:|@chronolog\/)|reference\s+types=/u.test(declarations)) {
  throw new Error('Membership declarations must be portable and self-contained');
}
const packageJson = { name: '@chronolog/membership', version, type: 'module',
  description: 'Portable signed roster administration over a small certified ledger',
  exports: { '.': { types: './index.d.ts', import: './index.mjs' } },
  files: ['index.mjs', 'index.d.ts', 'provenance.json'] };
await writeFile(join(output, 'package.json'), JSON.stringify(packageJson, null, 2) + '\n');
const digest = async name => createHash('sha256').update(await readFile(join(output, name))).digest('hex');
await writeFile(join(output, 'provenance.json'), JSON.stringify({ repository: 'werg/chronolog-db', source,
  dirty: Boolean(changed), inputs, sha256: { 'index.mjs': await digest('index.mjs'), 'index.d.ts': await digest('index.d.ts') } }, null, 2) + '\n');
const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', output], {
  cwd: output, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const target = join(output, `chronolog-membership-${source.slice(0, 8)}${changed ? '-dirty' : ''}.tgz`);
await rename(join(output, packed.filename), target);
console.log(JSON.stringify({ artifact: target, version, source, dirty: Boolean(changed), runtimeInputs: inputs.length }));
