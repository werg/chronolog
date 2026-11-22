import { execFileSync } from 'node:child_process';
import { win32 } from 'node:path';
import process from 'node:process';

/** Windows .cmd launchers require a shell; invoke npm's JS entry with Node instead. */
export function npmInvocation(args, { platform = process.platform, execPath = process.execPath } = {}) {
  return platform === 'win32'
    ? { file: execPath, args: [win32.join(win32.dirname(execPath), 'node_modules/npm/bin/npm-cli.js'), ...args] }
    : { file: 'npm', args: [...args] };
}
export function execNpmSync(args, options = {}) {
  const invocation = npmInvocation(args);
  return execFileSync(invocation.file, invocation.args, { ...options, shell: false });
}
