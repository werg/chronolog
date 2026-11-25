import type { ApplicationSubmission } from './operation.js'
import type { ApplicationOperation } from './operation.js'
import type { CommandOptions } from './session-types.js'
export interface LocalAuthoringSession { submit(input: ApplicationSubmission): Promise<ApplicationOperation>; command(name: string, input: unknown, options?: CommandOptions): Promise<ApplicationOperation> }
export async function submitBatch(session: LocalAuthoringSession, submissions: readonly ApplicationSubmission[]): Promise<readonly ApplicationOperation[]> { const operations: ApplicationOperation[] = []; for (const submission of submissions) operations.push(await session.submit(submission)); return operations }
export function createAppClient(session: LocalAuthoringSession) { return { command: (name: string, input: unknown, options?: CommandOptions) => session.command(name, input, options), submit: (input: ApplicationSubmission) => session.submit(input), batch: (input: readonly ApplicationSubmission[]) => submitBatch(session, input) } }
