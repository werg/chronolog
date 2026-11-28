import type { ChronologBuiltinName } from '@chronolog/records'

export interface DeterminismDiagnostic {
  readonly code:
    | 'nondeterministic:date'
    | 'nondeterministic:random'
    | 'nondeterministic:intl'
    | 'nondeterministic:clock'
    | 'forbidden:host-io'
    | 'forbidden:async-reducer'
  readonly file: string
  readonly line: number
  readonly column: number
  readonly message: string
  readonly suggestion: string
}

interface LintRule {
  readonly code: DeterminismDiagnostic['code']
  readonly pattern: RegExp
  readonly message: string
  readonly suggestion: string
}

const LINT_RULES: readonly LintRule[] = [
  {
    code: 'nondeterministic:date',
    pattern: /\b(?:new\s+Date\b|Date\.(?:now|parse|UTC)\b)/gu,
    message: 'Wall-clock Date API is forbidden in deterministic reducers.',
    suggestion: 'Use tx.authorTimestampMs instead.',
  },
  {
    code: 'nondeterministic:random',
    pattern: /\b(?:Math\.random\b|crypto\.(?:getRandomValues|randomUUID)\b)/gu,
    message: 'Randomness APIs are forbidden in deterministic reducers.',
    suggestion: 'Derive deterministic entropy via sha256(tx.opId + ...) from chronolog:crypto.',
  },
  {
    code: 'nondeterministic:intl',
    pattern: /\bIntl\./gu,
    message: 'Locale-dependent Intl APIs are stripped in Chronolog.',
    suggestion: 'Use explicit UTC/ASCII formatting or pure deterministic helpers.',
  },
  {
    code: 'nondeterministic:clock',
    pattern: /\b(?:performance\.now\b|setTimeout\b|setInterval\b|setImmediate\b)/gu,
    message: 'Timers and high-resolution clocks are forbidden in deterministic reducers.',
    suggestion: 'Model time explicitly using tx.authorTimestampMs.',
  },
  {
    code: 'forbidden:host-io',
    pattern: /\b(?:fetch\s*\(|XMLHttpRequest\b|WebSocket\b|from\s+['"]node:|import\s*\(\s*['"]node:)/gu,
    message: 'Host I/O, network, and Node builtins are unavailable inside the Chronolog sandbox.',
    suggestion: 'Move I/O outside reducers and pass verified data via operation payloads or CAS.',
  },
  {
    code: 'forbidden:async-reducer',
    pattern: /\basync\s+(?:function\s+)?(?:reduce|query|describe|onConflict)\s*\(/gu,
    message: 'Chronolog reducer hooks (reduce, query, describe, onConflict) must be synchronous.',
    suggestion: 'Remove async/await from reducer methods.',
  },
]

/** Strip comments and string literals (preserving line/column layout) so the linter avoids false positives. */
function maskCommentsAndStrings(source: string): string {
  const chars = [...source]
  let i = 0
  while (i < chars.length) {
    const c = chars[i]!
    const next = chars[i + 1]
    // Single-line comment
    if (c === '/' && next === '/') {
      while (i < chars.length && chars[i] !== '\n') {
        chars[i] = ' '
        i++
      }
      continue
    }
    // Block comment
    if (c === '/' && next === '*') {
      chars[i] = ' '
      chars[i + 1] = ' '
      i += 2
      while (i < chars.length && !(chars[i] === '*' && chars[i + 1] === '/')) {
        if (chars[i] !== '\n') chars[i] = ' '
        i++
      }
      if (i + 1 < chars.length) {
        chars[i] = ' '
        chars[i + 1] = ' '
        i += 2
      }
      continue
    }
    // Single/double-quoted strings (keep `from 'node:...` readable by only blanking non-import strings)
    if (c === '"' || c === "'" || c === '`') {
      const quote = c
      // Preserve import specifiers after `from ` or `import(`
      const prefix = source.slice(Math.max(0, i - 16), i)
      const isImportSpec = /(?:from\s+|import\s*\(\s*)$/u.test(prefix)
      i++
      while (i < chars.length) {
        if (chars[i] === '\\') {
          if (!isImportSpec) {
            chars[i] = ' '
            if (i + 1 < chars.length && chars[i + 1] !== '\n') chars[i + 1] = ' '
          }
          i += 2
          continue
        }
        if (chars[i] === quote) {
          i++
          break
        }
        if (!isImportSpec && chars[i] !== '\n') chars[i] = ' '
        i++
      }
      continue
    }
    i++
  }
  return chars.join('')
}

function lineColAt(source: string, index: number): { readonly line: number; readonly column: number } {
  let line = 1
  let lastNl = -1
  for (let i = 0; i < index; i++) {
    if (source.charCodeAt(i) === 10) {
      line++
      lastNl = i
    }
  }
  return { line, column: index - lastNl }
}

/** Statically lint JS/TS source for non-deterministic or sandbox-forbidden constructs. */
export function lintDeterminism(source: string, file = 'index.js'): readonly DeterminismDiagnostic[] {
  const masked = maskCommentsAndStrings(source)
  const diagnostics: DeterminismDiagnostic[] = []
  for (const rule of LINT_RULES) {
    rule.pattern.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = rule.pattern.exec(masked)) !== null) {
      const { line, column } = lineColAt(source, match.index)
      diagnostics.push({
        code: rule.code,
        file,
        line,
        column,
        message: rule.message,
        suggestion: rule.suggestion,
      })
    }
  }
  diagnostics.sort((a, b) => a.line - b.line || a.column - b.column || a.code.localeCompare(b.code))
  return diagnostics
}

const BUILTIN_IMPORT_RE = /(?:from\s*['"]|import\s*['"]|import\s*\(\s*['"])(chronolog:(?:crypto|cas|sqlite|wasm))['"]/gu

/** Auto-detect minimal chronolog:* builtins imported by JS/TS source files. */
export function detectRequiredBuiltins(sources: Iterable<string>): readonly ChronologBuiltinName[] {
  const found = new Set<ChronologBuiltinName>()
  for (const src of sources) {
    BUILTIN_IMPORT_RE.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = BUILTIN_IMPORT_RE.exec(src)) !== null) {
      found.add(match[1] as ChronologBuiltinName)
    }
  }
  return [...found].sort()
}
