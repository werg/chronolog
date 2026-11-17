import { canonicalEventPayload, canonicalJson, decodeChangeProgram, type EventPayload } from '@chronolog/protocol'
import { bytesDigest, hexToBytes, object, check, isArray } from './codec.js'

/** The deliberately small JSON Schema subset accepted by application tools. */
export type ApplicationInputSchema = (
  | { readonly type: 'string'; readonly minLength?: number; readonly maxLength?: number; readonly enum?: readonly string[] }
  | { readonly type: 'number' | 'integer'; readonly minimum?: number; readonly maximum?: number }
  | { readonly type: 'boolean' | 'null' }
  | { readonly type: 'array'; readonly items: ApplicationInputSchema; readonly minItems?: number; readonly maxItems?: number }
  | { readonly type: 'object'; readonly properties: Readonly<Record<string, ApplicationInputSchema>>; readonly required?: readonly string[]; readonly additionalProperties?: false }
  | { readonly anyOf: readonly ApplicationInputSchema[] }
) & { readonly description?: string }

export type ApplicationInput<S extends ApplicationInputSchema> =
  ApplicationInputSchema extends S ? EventPayload :
  S extends { readonly anyOf: readonly (infer T extends ApplicationInputSchema)[] } ? ApplicationInput<T> :
  S extends { readonly type: 'string'; readonly enum: readonly (infer T extends string)[] } ? T :
  S extends { readonly type: 'string' } ? string :
  S extends { readonly type: 'number' | 'integer' } ? number :
  S extends { readonly type: 'boolean' } ? boolean :
  S extends { readonly type: 'null' } ? null :
  S extends { readonly type: 'array'; readonly items: infer T extends ApplicationInputSchema } ? readonly ApplicationInput<T>[] :
  S extends { readonly type: 'object'; readonly properties: infer P extends Readonly<Record<string, ApplicationInputSchema>> } ?
    { readonly [K in keyof P as K extends RequiredInputKeys<S> ? K : never]: ApplicationInput<P[K]> } &
    { readonly [K in keyof P as K extends RequiredInputKeys<S> ? never : K]?: ApplicationInput<P[K]> } : never

type RequiredInputKeys<S> = S extends { readonly required: readonly (infer K extends string)[] } ? K : never

/** Validate, copy and freeze JSON. Accessors, prototypes, undefined, NaN and sparse arrays fail. */
export function parseApplicationInput(schema: ApplicationInputSchema, value: unknown): EventPayload {
  const copy = JSON.parse(canonicalEventPayload(value as EventPayload)) as EventPayload
  const visit = (spec: ApplicationInputSchema, item: EventPayload, path: string): void => {
    const invalid = (): never => { throw new Error(`APPLICATION_INPUT_INVALID:${path}`) }
    if ('anyOf' in spec) {
      for (const option of spec.anyOf) { try { visit(option, item, path); return } catch { /* Try the next declared alternative. */ } }
      invalid()
    } else if (spec.type === 'null') { if (item !== null) invalid() }
    else if (spec.type === 'boolean') { if (typeof item !== 'boolean') invalid() }
    else if (spec.type === 'string') {
      if (typeof item !== 'string') return invalid()
      const length = [...item].length
      if (length < (spec.minLength ?? 0) || length > (spec.maxLength ?? 16_384) || spec.enum !== undefined && !spec.enum.includes(item)) invalid()
    } else if (spec.type === 'number' || spec.type === 'integer') {
      if (typeof item !== 'number' || spec.type === 'integer' && !Number.isSafeInteger(item) ||
          item < (spec.minimum ?? -Infinity) || item > (spec.maximum ?? Infinity)) invalid()
    } else if (spec.type === 'array') {
      if (!Array.isArray(item) || item.length < (spec.minItems ?? 0) || item.length > (spec.maxItems ?? 4096)) return invalid()
      const items = item as readonly EventPayload[]
      items.forEach((child, index) => visit(spec.items, child, `${path}[${index}]`))
    } else if (spec.type === 'object') {
      if (item === null || typeof item !== 'object' || Array.isArray(item)) return invalid()
      const object = item as Readonly<Record<string, EventPayload>>
      for (const name of spec.required ?? []) if (!Object.hasOwn(object, name)) invalid()
      for (const [name, child] of Object.entries(object)) {
        if (!Object.hasOwn(spec.properties, name)) invalid()
        visit(spec.properties[name]!, child, `${path}.${name}`)
      }
    }
  }
  visit(schema, copy, '$')
  return freeze(copy)
}

export function checkedApplicationInputSchema(value: ApplicationInputSchema): ApplicationInputSchema {
  const copy = JSON.parse(canonicalEventPayload(value)) as ApplicationInputSchema
  let nodes = 0
  const visit = (schema: ApplicationInputSchema, depth: number): void => {
    if (++nodes > 256 || depth > 16 || schema === null || typeof schema !== 'object' || Array.isArray(schema)) throw new Error('APPLICATION_SCHEMA_INVALID')
    const keys = new Set(['description'])
    const allow = (...names: string[]): void => { for (const name of names) keys.add(name) }
    const bound = (value: number | undefined, max: number): void => {
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 0 || value > max)) throw new Error('APPLICATION_SCHEMA_INVALID')
    }
    if (schema.description !== undefined && typeof schema.description !== 'string') throw new Error('APPLICATION_SCHEMA_INVALID')
    if ('anyOf' in schema) {
      allow('anyOf')
      if (!Array.isArray(schema.anyOf) || schema.anyOf.length < 1 || schema.anyOf.length > 16) throw new Error('APPLICATION_SCHEMA_INVALID')
      const alternatives = schema.anyOf as readonly ApplicationInputSchema[]
      alternatives.forEach(option => visit(option, depth + 1))
    } else {
      allow('type')
      switch (schema.type) {
        case 'string':
          allow('minLength', 'maxLength', 'enum'); bound(schema.minLength, 16_384); bound(schema.maxLength, 16_384)
          if ((schema.minLength ?? 0) > (schema.maxLength ?? 16_384) || schema.enum !== undefined &&
            (!Array.isArray(schema.enum) || schema.enum.length === 0 || schema.enum.length > 256 || schema.enum.some(item => typeof item !== 'string'))) throw new Error('APPLICATION_SCHEMA_INVALID')
          break
        case 'number': case 'integer':
          allow('minimum', 'maximum')
          if ([schema.minimum, schema.maximum].some(value => value !== undefined && !Number.isFinite(value)) ||
              (schema.minimum ?? -Infinity) > (schema.maximum ?? Infinity)) throw new Error('APPLICATION_SCHEMA_INVALID')
          break
        case 'boolean': case 'null': break
        case 'array':
          allow('items', 'minItems', 'maxItems'); bound(schema.minItems, 4096); bound(schema.maxItems, 4096)
          if ((schema.minItems ?? 0) > (schema.maxItems ?? 4096)) throw new Error('APPLICATION_SCHEMA_INVALID')
          visit(schema.items, depth + 1); break
        case 'object':
          allow('properties', 'required', 'additionalProperties')
          if (schema.properties === null || typeof schema.properties !== 'object' || Array.isArray(schema.properties) ||
              schema.additionalProperties !== undefined && schema.additionalProperties !== false) throw new Error('APPLICATION_SCHEMA_INVALID')
          for (const child of Object.values(schema.properties)) visit(child, depth + 1)
          if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.some(name => typeof name !== 'string' || !Object.hasOwn(schema.properties, name)) || new Set(schema.required).size !== schema.required.length)) {
            throw new Error('APPLICATION_SCHEMA_INVALID')
          }
          // Tool consumers must apply the same closed-object rule as this parser.
          Object.assign(schema, { additionalProperties: false })
          break
        default: throw new Error('APPLICATION_SCHEMA_UNSUPPORTED')
      }
    }
    if (Object.keys(schema).some(key => !keys.has(key))) throw new Error('APPLICATION_SCHEMA_UNSUPPORTED')
  }
  visit(copy, 0)
  return freeze(copy)
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child)
    Object.freeze(value)
  }
  return value
}


export interface ApplicationDescription {
  readonly id: string
  readonly version: string
  readonly schema: string | null
  readonly commands: readonly ApplicationEntryDescription[]
  readonly queries: readonly ApplicationEntryDescription[]
}
export interface ApplicationEntryDescription {
  readonly name: string
  readonly description: string
  readonly input: ApplicationInputSchema
}

/** One bounded, executable schema contract is used by peers, host metadata, and tools. */
export function validateApplicationDescription(value: ApplicationDescription): ApplicationDescription {
  const bytes = descriptionJson(value)
  check(new TextEncoder().encode(bytes).length <= 262_144, 'APPLICATION_DESCRIPTION_TOO_LARGE')
  const copy = JSON.parse(bytes) as ApplicationDescription
  object(copy, ['id', 'version', 'schema', 'commands', 'queries'])
  for (const text of [copy.id, copy.version]) check(typeof text === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(text), 'APPLICATION_DEFINITION_ID_INVALID')
  if (copy.schema !== null) {
    check(typeof copy.schema === 'string' && /^(?:[0-9a-f]{2})+$/u.test(copy.schema), 'APPLICATION_SCHEMA_PROGRAM_INVALID')
    decodeChangeProgram(hexToBytes(copy.schema))
  }
  for (const entries of [copy.commands, copy.queries]) {
    check(isArray(entries) && entries.length <= 128, 'APPLICATION_DEFINITION_TOO_LARGE')
    let previous = ''
    for (const entry of entries) {
      object(entry, ['name', 'description', 'input'])
      check(typeof entry.name === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(entry.name) && !['__proto__', 'constructor', 'prototype'].includes(entry.name) && entry.name > previous, 'APPLICATION_DEFINITION_NAME_INVALID')
      previous = entry.name
      check(typeof entry.description === 'string' && entry.description.length <= 4096, 'APPLICATION_DESCRIPTION_INVALID')
      const checked = checkedApplicationInputSchema(entry.input)
      check(canonicalEventPayload(entry.input) === canonicalEventPayload(checked), 'APPLICATION_SCHEMA_NOT_CANONICAL')
    }
  }
  return freeze(copy)
}

/** Authenticates published schemas and semantic version without executable application code. */
export async function applicationDescriptionDigest(value: ApplicationDescription): Promise<string> {
  const description = validateApplicationDescription(value)
  return bytesDigest(new TextEncoder().encode(descriptionJson(description)))
}

function descriptionJson(value: ApplicationDescription): string {
  return canonicalJson(value as unknown as EventPayload, { maxBytes: 262_144, maxNodes: 65_536, maxDepth: 32 })
}
