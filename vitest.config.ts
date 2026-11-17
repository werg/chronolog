import { coverageConfigDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      exclude: [
        ...coverageConfigDefaults.exclude,
        // Generated qualification bundles and vendored WASM sources are not project source.
        'artifacts/**',
        // Release/doc CLI scripts executed by CI jobs; their library logic (tools/lib) stays in coverage.
        'tools/*.ts',
        'tools/*.mjs',
      ],
      thresholds: {
        statements: 70,
        branches: 70,
        functions: 75,
        lines: 70,
      },
    },
    include: ['packages/**/*.test.ts', 'test/**/*.test.ts', 'tools/**/*.test.ts'],
    testTimeout: 30_000,
  },
})
