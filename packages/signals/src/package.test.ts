import { build } from 'esbuild'
import { describe, expect, it } from 'vitest'

describe('standalone signal package boundary', () => {
  it('bundles its public browser entry without database, membership or finality implementation', async () => {
    const result = await build({
      stdin: { contents: "export { SignalChannel, generateSignalIdentity } from '@chronolog/signals'", resolveDir: process.cwd() },
      bundle: true, platform: 'browser', format: 'esm', write: false, metafile: true,
    })
    const inputs = Object.keys(result.metafile.inputs)
    expect(inputs).toContain('packages/signals/src/index.ts')
    expect(inputs).not.toEqual(expect.arrayContaining([expect.stringMatching(/packages\/(?:protocol|materializer|materializer-doltlite|records|peer-generation|peer-session)\//u)]))
    expect(inputs).not.toEqual(expect.arrayContaining([expect.stringMatching(/(?:node:|doltlite|sqlite|\.node$|\.wasm$)/u)]))
    expect(result.outputFiles[0]!.text).toContain('SignalChannel')
  })
})
