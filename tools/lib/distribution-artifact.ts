import { execFileSync } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'

export interface DistributionIdentity {
  readonly sourceCommit: string
  readonly platform: string
  readonly architecture: string
}

export interface DistributionArtifact {
  readonly archive: string
  readonly identity: DistributionIdentity
}

/** Select by the archive's recorded identity, never by filename ordering. */
export async function selectDistributionArtifact(options: {
  readonly directory: string
  readonly artifact?: string
  readonly expectedSourceCommit?: string
  readonly platform: string
  readonly architecture: string
}): Promise<DistributionArtifact> {
  if (options.artifact !== undefined) {
    const archive = resolve(options.artifact)
    const identity = readDistributionIdentity(archive)
    if (options.expectedSourceCommit !== undefined && identity.sourceCommit !== options.expectedSourceCommit) {
      throw new Error(`DISTRIBUTION_SOURCE_MISMATCH: expected ${options.expectedSourceCommit}, found ${identity.sourceCommit}`)
    }
    if (identity.platform !== options.platform || identity.architecture !== options.architecture) {
      throw new Error(`DISTRIBUTION_PLATFORM_MISMATCH: expected ${options.platform}-${options.architecture}, found ${identity.platform}-${identity.architecture}`)
    }
    return { archive, identity }
  }
  if (options.expectedSourceCommit === undefined) throw new Error('DISTRIBUTION_EXPECTED_SOURCE_REQUIRED')
  const matches: DistributionArtifact[] = []
  for (const name of await readdir(options.directory)) {
    if (!name.startsWith('chronolog-') || !name.endsWith('.tar.gz')) continue
    const archive = resolve(join(options.directory, name))
    const identity = readDistributionIdentity(archive)
    if (identity.sourceCommit === options.expectedSourceCommit && identity.platform === options.platform && identity.architecture === options.architecture) {
      matches.push({ archive, identity })
    }
  }
  const target = `${options.expectedSourceCommit} ${options.platform}-${options.architecture}`
  if (matches.length === 0) throw new Error(`DISTRIBUTION_ARTIFACT_NOT_FOUND: ${target}`)
  if (matches.length > 1) throw new Error(`DISTRIBUTION_ARTIFACT_AMBIGUOUS: ${target}: ${matches.map(match => basename(match.archive)).join(', ')}`)
  return matches[0]!
}

function readDistributionIdentity(archive: string): DistributionIdentity {
  const name = basename(archive, '.tar.gz')
  const manifest = execFileSync('tar', ['-xOzf', archive, `${name}/release-manifest.json`], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024,
  })
  const parsed: unknown = JSON.parse(manifest)
  if (parsed === null || typeof parsed !== 'object' || !('format' in parsed) || parsed.format !== 'chronolog-native-distribution-v1'
    || !('sourceCommit' in parsed) || typeof parsed.sourceCommit !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(parsed.sourceCommit)
    || !('platform' in parsed) || typeof parsed.platform !== 'string'
    || !('architecture' in parsed) || typeof parsed.architecture !== 'string') {
    throw new Error(`DISTRIBUTION_MANIFEST_INVALID: ${archive}`)
  }
  return { sourceCommit: parsed.sourceCommit, platform: parsed.platform, architecture: parsed.architecture }
}
