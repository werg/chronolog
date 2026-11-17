import { describe, expect, it } from 'vitest'
import { emit, program } from '@chronolog/protocol'
import { applicationDescriptionDigest, validateApplicationDescription } from '@chronolog/peer-generation/control'

import { applicationDefinitionDigest, defineApplication, defineCommand, defineQuery, describeApplication, parseApplicationInput, type ApplicationInputSchema } from './definition.js'

const move = defineCommand({
  description: 'Move a task at the observed version',
  input: { type: 'object', properties: { task: { type: 'string', minLength: 1 }, version: { type: 'integer', minimum: 0 },
    column: { type: 'string', enum: ['todo', 'done'] } }, required: ['task', 'version', 'column'] },
  prepare(input) {
    // These assignments also qualify inference from the same published schema.
    const task: string = input.task, version: number = input.version, column: 'todo' | 'done' = input.column
    return program(emit('task.moved', { task, version, column }))
  },
})

describe('application definitions', () => {
  it('uses the same authenticated public description in the host and executing peer', async () => {
    const board = defineApplication({ id: 'board', version: '1', commands: { move }, queries: {} })
    const description = describeApplication(board)
    expect(await applicationDescriptionDigest(description)).toBe(await applicationDefinitionDigest(board))
    const changed = { ...description, version: '2' }
    expect(await applicationDescriptionDigest(changed)).not.toBe(await applicationDefinitionDigest(board))
    expect(() => validateApplicationDescription({ ...description, commands: [...description.commands, ...description.commands] })).toThrow('APPLICATION_DEFINITION_NAME_INVALID')
    expect(() => validateApplicationDescription({ ...description, commands: [{ ...description.commands[0]!, input: { type: 'object', properties: {} } }] })).toThrow('APPLICATION_SCHEMA_NOT_CANONICAL')
  })
  it('validates domain input, preserves types, and publishes the same closed schema to agents', () => {
    const board = defineApplication({ id: 'board', version: '1', commands: { move }, queries: {
      task: defineQuery({ description: 'Read a task', input: { type: 'string' },
        read: (view: { readonly tasks: Readonly<Record<string, string>> }, id) => view.tasks[id] ?? null }),
    } })
    expect(board.commands.move.prepare({ task: 'T1', version: 0, column: 'done' }).steps).toEqual([
      emit('task.moved', { task: 'T1', version: 0, column: 'done' }),
    ])
    expect(board.queries.task.read({ tasks: { T1: 'done' } }, 'T1')).toBe('done')
    const description = describeApplication(board)
    expect(description.commands[0]?.input).toMatchObject({ additionalProperties: false, required: ['task', 'version', 'column'] })
    expect(description.queries[0]?.name).toBe('task')
    expect(() => move.prepare({ task: 'T1', version: 0, column: 'done', admin: true } as never)).toThrow('APPLICATION_INPUT_INVALID')
    expect(() => move.prepare({ task: 'T1', version: -1, column: 'done' })).toThrow('APPLICATION_INPUT_INVALID')
    expect(() => move.prepare({ task: 'T1', version: 0 } as never)).toThrow('APPLICATION_INPUT_INVALID')
  })

  it('copies and freezes input and schema before preparation', () => {
    const schema: ApplicationInputSchema = { type: 'object', properties: { item: { type: 'string' } }, required: ['item'] }
    const command = defineCommand({ description: 'Copy', input: schema, prepare(input) {
      expect(Object.isFrozen(input)).toBe(true)
      return program(emit('copied', { item: (input as { item: string }).item }))
    } })
    const input = { item: 'original' }
    const result = command.prepare(input)
    input.item = 'changed'
    expect(result.steps).toEqual([emit('copied', { item: 'original' })])
    expect(Object.isFrozen(command.input)).toBe(true)
  })

  it('rejects unsupported schema constructs rather than advertising validation it does not perform', () => {
    for (const input of [{ type: 'string', pattern: '^x' }, { $ref: '#/defs/x' }, { type: 'object', properties: {}, additionalProperties: true },
      { type: 'integer', minimum: 5, maximum: 2 }, { anyOf: [] }, { type: 'object', properties: {}, required: ['missing'] }]) {
      expect(() => defineCommand({ description: '', input: input as ApplicationInputSchema, prepare: () => program(emit('valid', true)) })).toThrow('APPLICATION_SCHEMA_')
    }
  })

  it('validates nullable arrays and rejects non-JSON values before user code runs', () => {
    const input = { anyOf: [{ type: 'null' }, { type: 'array', items: { type: 'integer' }, maxItems: 2 }] } as const
    expect(parseApplicationInput(input, [1, 2])).toEqual([1, 2])
    expect(parseApplicationInput(input, null)).toBeNull()
    for (const value of [[1, 2, 3], [1.1], [Number.NaN], [undefined], new Date(), { get value() { throw new Error('must not run') } }]) {
      expect(() => parseApplicationInput(input, value)).toThrow()
    }
  })
})
