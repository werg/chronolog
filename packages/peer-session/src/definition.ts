import { bytesToHex, canonicalEventPayload, encodeChangeProgram, type ChangeProgram, type EventPayload } from '@chronolog/protocol'

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

export interface ApplicationCommand<Input = never> {
  readonly description: string
  readonly input: ApplicationInputSchema
  prepare(input: Input): ChangeProgram
}

export interface ApplicationQuery<Input = never, Result = unknown, View = unknown> {
  readonly description: string
  readonly input: ApplicationInputSchema
  read(view: View, input: Input): Result | Promise<Result>
}

export interface ApplicationDefinition<
  Commands extends Readonly<Record<string, ApplicationCommand>> = Readonly<Record<string, ApplicationCommand>>,
  Queries extends Readonly<Record<string, ApplicationQuery<never, unknown, never>>> = Readonly<Record<string, ApplicationQuery<never, unknown, never>>>,
> {
  readonly id: string
  /** Changes to command preparation or query semantics require a new version. */
  readonly version: string
  /** Literal schema setup is authenticated separately and executes before application history. */
  readonly schema?: ChangeProgram
  readonly commands: Commands
  readonly queries: Queries
}

export function defineCommand<const S extends ApplicationInputSchema>(options: {
  readonly description: string
  readonly input: S
  readonly prepare: (input: ApplicationInput<S>) => ChangeProgram
}): ApplicationCommand<ApplicationInput<S>> {
  const input = checkedSchema(options.input)
  if (typeof options.description !== 'string' || options.description.length > 4096 || typeof options.prepare !== 'function') {
    throw new Error('APPLICATION_COMMAND_INVALID')
  }
  return Object.freeze({ description: options.description, input,
    prepare(value: ApplicationInput<S>) {
      const validated = parseApplicationInput(input, value) as ApplicationInput<S>
      const program = options.prepare(validated)
      // Reject malformed or oversized programs before saving/signing an attempt.
      encodeChangeProgram(program)
      return program
    },
  })
}

export function defineQuery<const S extends ApplicationInputSchema, Result, View>(options: {
  readonly description: string
  readonly input: S
  readonly read: (view: View, input: ApplicationInput<S>) => Result | Promise<Result>
}): ApplicationQuery<ApplicationInput<S>, Result, View> {
  const input = checkedSchema(options.input)
  if (typeof options.description !== 'string' || options.description.length > 4096 || typeof options.read !== 'function') {
    throw new Error('APPLICATION_QUERY_INVALID')
  }
  return Object.freeze({ description: options.description, input,
    read(view: View, value: ApplicationInput<S>) { return options.read(view, parseApplicationInput(input, value) as ApplicationInput<S>) },
  })
}

export function defineApplication<
  const Commands extends Readonly<Record<string, ApplicationCommand>>,
  const Queries extends Readonly<Record<string, ApplicationQuery<never, unknown, never>>>,
>(definition: ApplicationDefinition<Commands, Queries>): ApplicationDefinition<Commands, Queries> {
  for (const value of [definition.id, definition.version]) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u.test(value)) throw new Error('APPLICATION_DEFINITION_ID_INVALID')
  }
  if (definition.schema !== undefined) encodeChangeProgram(definition.schema)
  for (const entries of [definition.commands, definition.queries]) {
    const names = Object.keys(entries)
    if (names.length > 128) throw new Error('APPLICATION_DEFINITION_TOO_LARGE')
    for (const name of names) {
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
        throw new Error('APPLICATION_DEFINITION_NAME_INVALID')
      }
      checkedSchema(entries[name]!.input)
    }
  }
  return Object.freeze({ ...definition, commands: Object.freeze({ ...definition.commands }), queries: Object.freeze({ ...definition.queries }) })
}

/** Descriptions and tool schemas come from the same definition that executes commands. */
export function describeApplication(definition: ApplicationDefinition): {
  readonly id: string
  readonly version: string
  readonly schema: string | null
  readonly commands: readonly { readonly name: string; readonly description: string; readonly input: ApplicationInputSchema }[]
  readonly queries: readonly { readonly name: string; readonly description: string; readonly input: ApplicationInputSchema }[]
} {
  const describe = (entries: Readonly<Record<string, { readonly description: string; readonly input: ApplicationInputSchema }>>) =>
    Object.keys(entries).sort().map(name => ({ name, description: entries[name]!.description, input: entries[name]!.input }))
  return { id: definition.id, version: definition.version, schema: definition.schema === undefined ? null : bytesToHex(encodeChangeProgram(definition.schema)), commands: describe(definition.commands), queries: describe(definition.queries) }
}

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

function checkedSchema(value: ApplicationInputSchema): ApplicationInputSchema {
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

/** Authenticates the published command/query schemas and their explicit semantic version. */
export async function applicationDefinitionDigest(definition: ApplicationDefinition): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalEventPayload(describeApplication(definition)))
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return [...hash].map(byte => byte.toString(16).padStart(2, '0')).join('')
}
