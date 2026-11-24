// Source CI consumer pins are separate from immutable qualified release receipts.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath, URL } from 'node:url';
import { select } from '../distribution/select-companion-release.mjs';
const clone = value => JSON.parse(JSON.stringify(value));
const tuple = JSON.parse(readFileSync(new URL('../distribution/companion-release.json', import.meta.url)));
const sourceQualification = JSON.parse(readFileSync(new URL('../distribution/source-qualification.json', import.meta.url)));
test('webrtc consumes reviewed source pins and retains exact checkout checks', () => {
  const selected = select(tuple, 'chronolog', {}, sourceQualification);
  const text = readFileSync(new URL('../.github/workflows/webrtc.yml', import.meta.url), 'utf8');
  assert.ok(Object.values(selected).every(value => /^[a-f0-9]{40}$/.test(value)));
  assert.equal(selected.HOST_REF, tuple.core.source);
  assert.equal(selected.CONTRIB_REF, sourceQualification.contrib.source);
  assert.ok(text.includes('node distribution/select-companion-release.mjs chronolog'));
  assert.doesNotMatch(text, /inputs\.\w+_ref \|\| '[a-f0-9]{40}'/);
  assert.ok(text.includes('node tools/package-peer-session.mjs'));
  assert.ok(text.includes('Build independent host test artifacts (not for deployment)'));
  for (const key of ['HOST_REF', 'CONTRIB_REF']) {
    assert.ok(text.includes('ref: ${{ env.' + key + ' }}'));
    assert.ok(text.includes('= "$' + key + '"'));
  }
});
test('source selection preserves the qualified receipt and explicit overrides take precedence', () => {
  const original = clone(tuple);
  assert.deepEqual(select(tuple, 'chronolog'), { HOST_REF: tuple.core.source, CONTRIB_REF: tuple.contrib.source });
  assert.deepEqual(select(tuple, 'chronolog', { TENDRILLER_REF: tuple.core.source, CONTRIB_REF_INPUT: tuple.contrib.source }, sourceQualification),
    { HOST_REF: tuple.core.source, CONTRIB_REF: tuple.contrib.source });
  assert.deepEqual(select(tuple, 'contrib', {}, sourceQualification),
    { HOST_REF: tuple.core.source, CORE_REF: tuple.core.source, CHRONOLOG_REF: tuple.kernel.source });
  assert.deepEqual(tuple, original);
});
test('source pins and explicit overrides require supported schemas, repository and immutable commits', () => {
  for (const change of [
    pin => { pin.format = 'unsupported'; },
    pin => { pin.contrib.repository = 'other/consumer'; },
    pin => { pin.contrib.source = 'main'; },
    pin => { pin.contrib.source = pin.contrib.source.slice(0, 8); },
    pin => { delete pin.contrib.source; },
  ]) {
    const pin = clone(sourceQualification); change(pin);
    assert.throws(() => select(tuple, 'chronolog', {}, pin));
  }
  for (const env of [{ TENDRILLER_REF: 'main' }, { CONTRIB_REF_INPUT: 'main' }]) {
    assert.throws(() => select(tuple, 'chronolog', env, sourceQualification));
  }
  const changedReceipt = clone(tuple); changedReceipt.stage = `${tuple.stage}-tampered`;
  assert.throws(() => select(changedReceipt, 'chronolog', {}, sourceQualification), /Tuple digest mismatch/);
});
test('the workflow CLI actually loads source qualification defaults and honors dispatch overrides', () => {
  const cli = fileURLToPath(new URL('../distribution/select-companion-release.mjs', import.meta.url));
  const run = env => execFileSync(process.execPath, [cli, 'chronolog'], {
    encoding: 'utf8', env: { ...process.env, TENDRILLER_REF: '', CONTRIB_REF_INPUT: '', ...env },
  });
  assert.equal(run({}), `HOST_REF=${tuple.core.source}\nCONTRIB_REF=${sourceQualification.contrib.source}\n`);
  assert.equal(run({ CONTRIB_REF_INPUT: tuple.contrib.source }), `HOST_REF=${tuple.core.source}\nCONTRIB_REF=${tuple.contrib.source}\n`);
});
