import type { ApplicationReadView } from './session-types.js'
import { createLiveView, type LiveView, type ReactiveSession } from './live-view.js'
export interface ApplicationProjectionDefinition<Value> { readonly name: string; readonly version: string; derive(view: ApplicationReadView): Value | Promise<Value> }
export function defineProjection<Value>(definition: ApplicationProjectionDefinition<Value>): ApplicationProjectionDefinition<Value> { if (!definition.name || !definition.version || typeof definition.derive !== 'function') throw new Error('PROJECTION_INVALID'); return Object.freeze({ ...definition }) }
export function createProjection<Value>(session: ReactiveSession, definition: ApplicationProjectionDefinition<Value>): LiveView<Value> { return createLiveView(session, view => definition.derive(view)) }
