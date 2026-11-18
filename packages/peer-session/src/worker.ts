/** The Worker owns the immediate protocol participant and its lazy durable facet. */
export { openBrowserDevice } from './browser-device.js'
export { openPeerApplication as openBrowserApplication } from './runtime.js'
export type { OpenPeerApplicationOptions } from './runtime.js'
export { serveApplicationWorker } from './worker-application-server.js'

export type { BrowserCapabilityReport } from './browser-capabilities.js'
export async function probeBrowserCapabilities(): Promise<import('./browser-capabilities.js').BrowserCapabilityReport> {
  return (await import('./browser-capabilities.js')).probeBrowserCapabilities()
}
