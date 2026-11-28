import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import {
  normalizePosixPath,
  putTreeDag,
  type CasPartition,
  type ChronologTreeNode,
  type ContentAddressedStore,
} from '@chronolog/records'

export interface TarEntry {
  readonly path: string
  readonly bytes: Uint8Array
}

function readCString(buf: Uint8Array, start: number, len: number): string {
  let end = start
  const max = start + len
  while (end < max && buf[end] !== 0) end++
  return new TextDecoder().decode(buf.subarray(start, end))
}

function parseOctal(buf: Uint8Array, start: number, len: number): number {
  const str = readCString(buf, start, len).trim()
  if (str.length === 0) return 0
  return Number.parseInt(str, 8)
}

/**
 * Deterministically parse a POSIX USTAR/PAX tar (or .tgz/.tar.gz) archive into sorted file entries,
 * stripping all non-deterministic tar metadata (mtime, uid, gid, permissions, uname/gname).
 */
export function parseCanonicalTarball(
  archiveBytes: Uint8Array,
  options: { readonly stripPrefix?: string; readonly integrity?: string } = {},
): readonly TarEntry[] {
  if (options.integrity !== undefined) {
    const match = /^(sha512|sha256)-(.+)$/u.exec(options.integrity)
    if (match === null) throw new Error(`TARBALL_INTEGRITY_FORMAT_INVALID:${options.integrity}`)
    const algo = match[1]!
    const expected = match[2]!
    const actualBase64 = createHash(algo).update(archiveBytes).digest('base64')
    const actualHex = createHash(algo).update(archiveBytes).digest('hex')
    if (actualBase64 !== expected && actualHex !== expected) {
      throw new Error(`TARBALL_INTEGRITY_MISMATCH: expected ${options.integrity}`)
    }
  }

  // Auto-detect gzip header (1f 8b)
  const tar = (archiveBytes.byteLength >= 2 && archiveBytes[0] === 0x1f && archiveBytes[1] === 0x8b)
    ? new Uint8Array(gunzipSync(archiveBytes))
    : archiveBytes

  const stripPrefix = options.stripPrefix ?? 'package/'
  const entries = new Map<string, Uint8Array>()
  let offset = 0
  let paxPath: string | null = null

  while (offset + 512 <= tar.byteLength) {
    const header = tar.subarray(offset, offset + 512)
    let allZero = true
    for (let i = 0; i < 512; i++) {
      if (header[i] !== 0) { allZero = false; break }
    }
    if (allZero) break

    const name = readCString(header, 0, 100)
    const prefix = readCString(header, 345, 155)
    const size = parseOctal(header, 124, 12)
    const typeFlag = header[156] ?? 0
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    if (dataEnd > tar.byteLength) throw new Error('TARBALL_TRUNCATED')
    const data = tar.subarray(dataStart, dataEnd)

    // Advance to next 512-byte boundary
    offset = dataStart + Math.ceil(size / 512) * 512

    // PAX extended header ('x')
    if (typeFlag === 0x78) {
      const text = new TextDecoder().decode(data)
      for (const line of text.split('\n')) {
        const sp = line.indexOf(' ')
        if (sp > 0) {
          const kv = line.slice(sp + 1)
          if (kv.startsWith('path=')) paxPath = kv.slice(5)
        }
      }
      continue
    }

    // GNU LongName ('L')
    if (typeFlag === 0x4c) {
      paxPath = new TextDecoder().decode(data).replace(/\0+$/u, '')
      continue
    }

    let fullPath = paxPath ?? (prefix.length > 0 ? `${prefix}/${name}` : name)
    paxPath = null

    // Regular file ('0' = 0x30 or NUL = 0x00)
    if (typeFlag !== 0x30 && typeFlag !== 0x00) continue

    fullPath = fullPath.replace(/^\.\//u, '')
    if (stripPrefix.length > 0 && fullPath.startsWith(stripPrefix)) {
      fullPath = fullPath.slice(stripPrefix.length)
    }
    if (fullPath.length === 0) continue
    const norm = normalizePosixPath(fullPath)
    entries.set(norm, data.slice())
  }

  return [...entries.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([path, bytes]) => ({ path, bytes }))
}

/**
 * Ingest an npm/JSR tarball (or uncompressed tar) into CAS as a canonical, reproducible `chronolog-tree/v1`.
 * Identical file contents always produce the exact same `cas:sha256-...` hash regardless of tar timestamps.
 */
export async function ingestTarballToCas(
  cas: ContentAddressedStore,
  archiveBytes: Uint8Array,
  options: { readonly stripPrefix?: string; readonly integrity?: string; readonly partition?: CasPartition } = {},
): Promise<{ readonly hash: string; readonly ref: string; readonly tree: ChronologTreeNode; readonly fileCount: number }> {
  const entries = parseCanonicalTarball(archiveBytes, options)
  const files: Record<string, Uint8Array> = {}
  for (const e of entries) files[e.path] = e.bytes
  const placed = await putTreeDag(cas, files, options.partition ?? 'public')
  return { ...placed, fileCount: entries.length }
}

/** Helper to construct a deterministic POSIX tar archive from a map of files (useful for tests & packaging). */
export function createDeterministicTar(
  files: Readonly<Record<string, string | Uint8Array>>,
  prefix = 'package/',
): Uint8Array {
  const enc = new TextEncoder()
  const blocks: Uint8Array[] = []
  for (const [rawPath, content] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
    const fullPath = `${prefix}${normalizePosixPath(rawPath)}`
    const data = typeof content === 'string' ? enc.encode(content) : content
    const header = new Uint8Array(512)
    header.set(enc.encode(fullPath.slice(0, 100)), 0)
    header.set(enc.encode('0000644\0'), 100) // mode
    header.set(enc.encode('0000000\0'), 108) // uid
    header.set(enc.encode('0000000\0'), 116) // gid
    header.set(enc.encode(`${data.byteLength.toString(8).padStart(11, '0')}\0`), 124) // size
    header.set(enc.encode('00000000000\0'), 136) // deterministic zero mtime
    header.fill(0x20, 148, 156) // checksum placeholder
    header[156] = 0x30 // regular file '0'
    header.set(enc.encode('ustar\0'), 257)
    header.set(enc.encode('00'), 263)
    let sum = 0
    for (let i = 0; i < 512; i++) sum += header[i]!
    header.set(enc.encode(`${sum.toString(8).padStart(6, '0')}\0 `), 148)
    blocks.push(header)
    if (data.byteLength > 0) {
      const padded = new Uint8Array(Math.ceil(data.byteLength / 512) * 512)
      padded.set(data, 0)
      blocks.push(padded)
    }
  }
  blocks.push(new Uint8Array(1024)) // end-of-archive zero blocks
  const total = blocks.reduce((acc, b) => acc + b.byteLength, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const b of blocks) {
    out.set(b, pos)
    pos += b.byteLength
  }
  return out
}
