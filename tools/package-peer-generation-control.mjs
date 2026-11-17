import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import process from 'node:process';
import console from 'node:console';
import { build } from 'esbuild';

const root = resolve(import.meta.dirname, '..');
const output = resolve(process.argv.find((arg, index) => index > 1 && !arg.startsWith('--')) ?? join(root, 'artifacts/peer-generation-control'));
const entry = join(root, 'packages/peer-generation/src/control.ts');
await mkdir(output, { recursive: true });
const source = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const result = await build({ entryPoints: [entry], outfile: join(output, 'control.mjs'), bundle: true,
  platform: 'browser', format: 'esm', target: 'es2022', metafile: true, logLevel: 'warning', absWorkingDir: root });
const inputs = Object.keys(result.metafile.inputs).sort();
if (inputs.some(path => /(?:materializer|transport-ssb|node-core\/src\/node\.ts|peer-session|node:)/u.test(path)))
  throw new Error('The generation control artifact must not import SQL, application sessions or native transports');
const changed = execFileSync('git', ['status', '--porcelain', '--', ...inputs], { cwd: root, encoding: 'utf8' }).trim();
if (changed && !process.argv.includes('--allow-dirty')) throw new Error('Commit generation control inputs before packaging');
const version = `0.0.0-${source.slice(0, 8)}${changed ? '-dirty' : ''}`;
execFileSync('npm', ['exec', '--yes', '--package=dts-bundle-generator@9.5.1', '--package=typescript@5.8.3', '--',
  'dts-bundle-generator', '--project', join(root, 'tsconfig.base.json'), '--out-file', join(output, 'control.d.ts'),
  '--external-inlines', '@chronolog/canonical', '@chronolog/protocol', '@chronolog/peer-generation', '--', entry],
{ cwd: root, stdio: 'inherit' });
const declarations = await readFile(join(output, 'control.d.ts'), 'utf8');
if (/from\s+['"](?:node:|@chronolog\/)|reference\s+types=/u.test(declarations))
  throw new Error('Generation control declarations must be portable and self-contained');
await writeFile(join(output, 'package.json'), JSON.stringify({ name: '@chronolog/peer-generation', version, type: 'module',
  description: 'Portable peer-generation authority verification and durable generation selection',
  exports: { './control': { types: './control.d.ts', import: './control.mjs' } },
  files: ['control.mjs', 'control.d.ts', 'provenance.json'] }, null, 2) + '\n');
const digest = async name => createHash('sha256').update(await readFile(join(output, name))).digest('hex');
await writeFile(join(output, 'provenance.json'), JSON.stringify({ repository: 'werg/chronolog-db', source,
  profile: 'peer-generation-v1', dirty: Boolean(changed), inputs,
  sha256: { 'control.mjs': await digest('control.mjs'), 'control.d.ts': await digest('control.d.ts') } }, null, 2) + '\n');
const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', output], {
  cwd: output, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}))[0];
const target = join(output, `chronolog-peer-generation-control-${source.slice(0, 8)}${changed ? '-dirty' : ''}.tgz`);
await rename(join(output, packed.filename), target);
console.log(JSON.stringify({ artifact: target, version, source, dirty: Boolean(changed), runtimeInputs: inputs.length }));
