import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeSqlClassifier } from './lib/native-sql-closure.mjs';
function classifier(files) {
  return createNativeSqlClassifier({ read: file => files[file], resolveImport: name => name === 'native-sql' ? 'NATIVE_SQL' : Object.hasOwn(files, name) ? name : null, isNative: () => false });
}
test('cycle searches never cache an incomplete native-SQL-free result', () => {
  const check = classifier({ a: "import 'b'; import 'native-sql';", b: "import 'a';", safe: "export const value = 1;" });
  assert.equal(check('a'), true); assert.equal(check('b'), true); assert.equal(check('safe'), false);
});
test('literal dynamic imports with comments and reexports enter the closure', () => {
  const check = classifier({ a: "export * from 'b';", b: "const load = () => import(/* comment */ 'native-sql');" });
  assert.equal(check('a'), true);
});
test('comment text is not a runtime import', () => {
  const check = classifier({ safe: "// import 'native-sql';\nexport const safe = true;" }); assert.equal(check('safe'), false);
});
