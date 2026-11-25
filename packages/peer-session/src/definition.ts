import { encodeChangeProgram, type ChangeProgram } from '@chronolog/protocol'
import { applicationDescriptionDigest, checkedApplicationInputSchema, parseApplicationInput, validateApplicationDescription, type ApplicationDescription, type ApplicationInput, type ApplicationInputSchema } from '@chronolog/authority'
export { parseApplicationInput, type ApplicationDescription, type ApplicationInput, type ApplicationInputSchema } from '@chronolog/authority'

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
  readonly commands: Commands
  readonly queries: Queries
}

export function defineCommand<const S extends ApplicationInputSchema>(options: {
  readonly description: string
  readonly input: S
  readonly prepare: (input: ApplicationInput<S>) => ChangeProgram
}): ApplicationCommand<ApplicationInput<S>> {
  const input = checkedApplicationInputSchema(options.input)
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
  const input = checkedApplicationInputSchema(options.input)
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
  for (const entries of [definition.commands, definition.queries]) {
    const names = Object.keys(entries)
    if (names.length > 128) throw new Error('APPLICATION_DEFINITION_TOO_LARGE')
    for (const name of names) {
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(name) || ['__proto__', 'constructor', 'prototype'].includes(name)) {
        throw new Error('APPLICATION_DEFINITION_NAME_INVALID')
      }
      checkedApplicationInputSchema(entries[name]!.input)
    }
  }
  return Object.freeze({ ...definition, commands: Object.freeze({ ...definition.commands }), queries: Object.freeze({ ...definition.queries }) })
}

/** Descriptions and tool schemas come from the same definition that executes commands. */
export function describeApplication(definition: ApplicationDefinition): ApplicationDescription {
  const describe = (entries: Readonly<Record<string, { readonly description: string; readonly input: ApplicationInputSchema }>>) =>
    Object.keys(entries).sort().map(name => ({ name, description: entries[name]!.description, input: entries[name]!.input }))
  return validateApplicationDescription({ id: definition.id, version: definition.version, commands: describe(definition.commands), queries: describe(definition.queries) })
}

/** Authenticates the same public description used by bootstrap and local tools. */
export async function applicationDefinitionDigest(definition: ApplicationDefinition): Promise<string> {
  return applicationDescriptionDigest(describeApplication(definition))
}
