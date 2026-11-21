import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { URL } from 'node:url';

const workflow = await readFile(new URL('../.github/workflows/webrtc.yml', import.meta.url), 'utf8');

// Change these together after qualification. Historical evidence keeps its own
// source tuple; a workflow-only change does not replace the deployed kernel pin.
const companions = {
  host_ref: ['HOST_REF', '726376618060183e448a62043e283f7a74964ebe'],
  contrib_ref: ['CONTRIB_REF', '4e34d310a2b62ba66c98ce59dc18275c9669976a'],
};

for (const [input, [environment, source]] of Object.entries(companions)) {
  test(`${input} selects the qualified fallback and preserves explicit overrides`, () => {
    assert.match(source, /^[a-f0-9]{40}$/u);
    assert.ok(workflow.includes(`${environment}: \${{ inputs.${input} || '${source}' }}`));
    assert.ok(workflow.includes(`ref: \${{ env.${environment} }}`));
    assert.ok(workflow.includes(`= "$${environment}"`), 'Verify the actual companion checkout SHA');
  });
}

test('the workflow packages its own kernel checkout, distinct from the host test build', () => {
  assert.match(workflow, /- uses: actions\/checkout@v6\n {6}- uses: pnpm\/action-setup/u);
  assert.ok(workflow.includes('node tools/package-peer-session.mjs'));
  assert.ok(workflow.includes('node tools/package-peer-session.mjs --sql-native'));
  assert.ok(workflow.includes('Build independent host test artifacts (not for deployment)'));
  assert.ok(workflow.includes('node --test tools/test-companion-workflow-pins.mjs'));
});

test('ordinary PR and main quality checks execute the companion pin guard', async () => {
  const quality = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
  assert.match(quality, /pull_request:/u);
  assert.match(quality, /branches: \[main\]/u);
  assert.ok(quality.includes('run: node --test tools/test-companion-workflow-pins.mjs'));
});
