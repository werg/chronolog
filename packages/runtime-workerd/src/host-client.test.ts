import { describe, expect, it } from 'vitest'

import { DEFAULT_REDUCER_COMMIT, resolveReducerCommitOptions } from './host-client.js'

describe('reducer commit options', () => {
  it('defaults to a fixed non-zero commit instant', () => {
    expect(resolveReducerCommitOptions()).toBe(DEFAULT_REDUCER_COMMIT)
    expect(DEFAULT_REDUCER_COMMIT.timestamp).not.toBe('1970-01-01T00:00:00')
  })

  it('rejects the epoch, which DoltLite replaces with wall-clock time', () => {
    for (const timestamp of ['1970-01-01T00:00:00', '1970-01-01 00:00:00', '1969-12-31T23:59:59']) {
      expect(() => resolveReducerCommitOptions({ ...DEFAULT_REDUCER_COMMIT, timestamp }))
        .toThrow('WORKERD_COMMIT_TIMESTAMP_NOT_REPRODUCIBLE')
    }
  })

  it('rejects dates DoltLite cannot parse exactly', () => {
    for (const timestamp of ['2000-01-01', '2000-02-30T00:00:00', '2000-01-01T24:00:00', '2000-01-01T00:00:00Z', '']) {
      expect(() => resolveReducerCommitOptions({ ...DEFAULT_REDUCER_COMMIT, timestamp }))
        .toThrow('WORKERD_COMMIT_TIMESTAMP_INVALID')
    }
  })

  it('accepts explicit reproducible instants', () => {
    const commit = { ...DEFAULT_REDUCER_COMMIT, timestamp: '1970-01-01T00:00:01' }
    expect(resolveReducerCommitOptions(commit)).toBe(commit)
  })
})
