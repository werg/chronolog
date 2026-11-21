// Pins have one source: the content-addressed tuple, not this test.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { URL } from 'node:url';
import { select } from '../distribution/select-companion-release.mjs';
const tuple = JSON.parse(readFileSync(new URL('../distribution/companion-release.json', import.meta.url)));
test('webrtc consumes the canonical tuple and retains exact checkout checks', () => {
  const selected = select(tuple, 'chronolog');
  const text = readFileSync(new URL('../.github/workflows/webrtc.yml', import.meta.url), 'utf8');
  assert.ok(Object.values(selected).every(value => /^[a-f0-9]{40}$/.test(value)));
  assert.ok(text.includes('node distribution/select-companion-release.mjs chronolog'));
  assert.doesNotMatch(text, /inputs\.\w+_ref \|\| '[a-f0-9]{40}'/);
  assert.ok(text.includes('node tools/package-peer-session.mjs'));
  assert.ok(text.includes('Build independent host test artifacts (not for deployment)'));
  for (const key of ['HOST_REF', 'CONTRIB_REF']) {
    assert.ok(text.includes('ref: \u0024{{ env.' + key + ' }}'));
    assert.ok(text.includes('= "$' + key + '"'));
  }
});
