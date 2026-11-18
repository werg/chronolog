/** The Worker owns the immediate protocol participant and its lazy durable facet. */
export { openBrowserDevice } from './browser-device.js'
export { openPeerApplication as openBrowserApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { serveApplicationWorker } from './worker-application-server.js'

import type { BrowserCapabilityReport } from './browser-capabilities.js'
export type { BrowserCapabilityReport } from './browser-capabilities.js'
export async function probeBrowserCapabilities(): Promise<BrowserCapabilityReport> {
  return (await import('./browser-capabilities.js')).probeBrowserCapabilities()
}
