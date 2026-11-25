import { expect, it } from 'vitest'
import { canonicalJson, type EventPayload } from '@chronolog/protocol'
import { recordDigest } from './codec.js'
import { applicationDescriptionDigest, parseApplicationInput, validateApplicationDescription, type ApplicationDescription } from './definition.js'

const description: ApplicationDescription = {
  id: 'fractional-input', version: '1',
  commands: [{ name: 'adjust', description: 'Bounded fractional input', input: { type: 'number', minimum: 0.25, maximum: 1.75 } }],
  queries: [],
}
it('digests validated fractional bounds using domain-separated canonical description JSON', async () => {
  const validated = validateApplicationDescription(description), schema = validated.commands[0]!.input
  expect(parseApplicationInput(schema, 0.25)).toBe(0.25); expect(parseApplicationInput(schema, 1.75)).toBe(1.75)
  expect(() => parseApplicationInput(schema, 0.24)).toThrow('APPLICATION_INPUT_INVALID')
  expect(() => parseApplicationInput(schema, 1.76)).toThrow('APPLICATION_INPUT_INVALID')
  const digest = await applicationDescriptionDigest(description)
  expect(digest).toMatch(/^[0-9a-f]{64}$/u)
  expect(digest).toBe(await recordDigest(['application-description/v1', canonicalJson(validated as unknown as EventPayload, { maxBytes: 262_144, maxNodes: 65_536, maxDepth: 32 })]))
  const reordered: ApplicationDescription = { queries: [], commands: [{ input: { maximum: 1.75, minimum: 0.25, type: 'number' }, description: 'Bounded fractional input', name: 'adjust' }], version: '1', id: 'fractional-input' }
  expect(await applicationDescriptionDigest(reordered)).toBe(digest)
  await expect(recordDigest({ minimum: 0.25 })).rejects.toThrow()
})
it('still rejects reversed or nonfinite bounds before hashing public descriptions', async () => {
  const changed = (minimum: number, maximum: number): ApplicationDescription => ({ ...description, commands: [{ ...description.commands[0]!, input: { type: 'number', minimum, maximum } }] })
  await expect(applicationDescriptionDigest(changed(1.75, 0.25))).rejects.toThrow('APPLICATION_SCHEMA_INVALID')
  await expect(applicationDescriptionDigest(changed(Number.NaN, 1.75))).rejects.toThrow()
  await expect(applicationDescriptionDigest(changed(0.25, Number.POSITIVE_INFINITY))).rejects.toThrow()
})
