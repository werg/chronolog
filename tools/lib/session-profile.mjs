/** Keep adapter/profile versions distinct even when built into the same directory. */
export function sqlProfileSuffix({ native = false, browser = false, wasmNode = false } = {}) {
  return `${native ? '-sql' : ''}${browser && wasmNode ? '-wasm-browser-node' : browser ? '-wasm-browser' : wasmNode ? '-wasm-node' : ''}`;
}
