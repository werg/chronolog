import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { selectDistributionArtifact, type DistributionIdentity } from './distribution-artifact.js'

const current = { sourceCommit: '1'.repeat(40), platform: process.platform, architecture: process.arch }
const historical = { ...current, sourceCommit: 'f'.repeat(40) }
const foreign = { ...current, architecture: process.arch === 'arm64' ? 'x64' : 'arm64' }
let directory: string

beforeEach(async () => { directory = await mkdtemp(join(tmpdir(), 'chronolog-archive-selection-')) })
afterEach(async () => { await rm(directory, { recursive: true, force: true }) })

async function archive(name: string, identity: DistributionIdentity, format = 'chronolog-native-distribution-v1'): Promise<string> {
  const source = join(directory, name)
  await mkdir(source)
  await writeFile(join(source, 'release-manifest.json'), JSON.stringify({ format, ...identity, files: [] }))
  const path = `${source}.tar.gz`
  execFileSync('tar', ['-czf', path, '-C', directory, name], { stdio: 'pipe' })
  await rm(source, { recursive: true })
  return path
}

function select() {
  return selectDistributionArtifact({ directory, expectedSourceCommit: current.sourceCommit,
    platform: current.platform, architecture: current.architecture })
}

describe('native distribution archive selection', () => {
  it('qualifies the current manifest despite newer-sorting historical and foreign archives', async () => {
    const expected = await archive('chronolog-0.0.0-111-current', current)
    await archive('chronolog-9.0.0-historical', historical)
    await archive('chronolog-9.0.1-foreign', foreign)
    expect(await select()).toEqual({ archive: expected, identity: current })
  })

  it('never substitutes an older or foreign build when the current build is absent', async () => {
    await archive('chronolog-stale', historical)
    await archive('chronolog-current-wrong-platform', foreign)
    await expect(select()).rejects.toThrow('DISTRIBUTION_ARTIFACT_NOT_FOUND')
  })

  it('rejects two archives claiming the current source and platform', async () => {
    await archive('chronolog-current-tagged', current)
    await archive('chronolog-current-untagged', current)
    await expect(select()).rejects.toThrow('DISTRIBUTION_ARTIFACT_AMBIGUOUS')
  })

  it('reports an explicit historical source and enforces an optional source pin', async () => {
    const path = await archive('chronolog-historical', historical)
    const options = { directory, artifact: path, platform: current.platform, architecture: current.architecture }
    expect(await selectDistributionArtifact(options)).toEqual({ archive: path, identity: historical })
    expect(await selectDistributionArtifact({ ...options, expectedSourceCommit: historical.sourceCommit })).toEqual({ archive: path, identity: historical })
    await expect(selectDistributionArtifact({ ...options, expectedSourceCommit: current.sourceCommit })).rejects.toThrow('DISTRIBUTION_SOURCE_MISMATCH')
  })

  it('rejects a foreign explicit artifact before executing anything from it', async () => {
    const path = await archive('chronolog-foreign', foreign)
    await expect(selectDistributionArtifact({ directory, artifact: path, platform: current.platform, architecture: current.architecture }))
      .rejects.toThrow('DISTRIBUTION_PLATFORM_MISMATCH')
  })

  it('does not select a manifest with an unknown format', async () => {
    await archive('chronolog-invalid', current, 'unknown-format')
    await expect(select()).rejects.toThrow('DISTRIBUTION_MANIFEST_INVALID')
  })
})
