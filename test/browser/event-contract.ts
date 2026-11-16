/** Only public enrollment keys cross from a browser Worker into this fixture. */
export interface BrowserEventIdentity {
  readonly identity: string
  readonly readerKey: string
  readonly transportAuthor: string
}

export interface BrowserEventBootstrap {
  readonly genesis: string
  readonly groupRoute: string
  readonly epochContentKey: string
  readonly executionManifest: string
  readonly nativeIdentity: string
  readonly peerUrl: string
  readonly peerToken: string
  readonly connection?: { readonly url: string; readonly route: 'direct' | 'relay'; readonly relayHandshake: boolean }
}
