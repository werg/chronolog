/**
 * Pure GF(256) Shamir's Secret Sharing (AES irreducible polynomial x^8 + x^4 + x^3 + x + 1 = 0x11b).
 * Used for threshold social recovery so guardians hold encrypted recovery shares without ever
 * being able to decrypt page content unless threshold shares are combined for a recovering device.
 */

export interface ShamirShare {
  /** Non-zero x-coordinate in 1..255. */
  readonly index: number
  /** Share payload bytes (same length as original secret). */
  readonly bytes: Uint8Array
}

function gfMul(a: number, b: number): number {
  let x = a & 0xff
  let y = b & 0xff
  let out = 0
  for (let i = 0; i < 8; i++) {
    if ((y & 1) !== 0) out ^= x
    const hi = x & 0x80
    x = (x << 1) & 0xff
    if (hi !== 0) x ^= 0x1b
    y >>>= 1
  }
  return out
}

function gfPow(base: number, exp: number): number {
  let result = 1
  let b = base & 0xff
  let e = exp
  while (e > 0) {
    if ((e & 1) !== 0) result = gfMul(result, b)
    b = gfMul(b, b)
    e >>>= 1
  }
  return result
}

function gfInv(a: number): number {
  if ((a & 0xff) === 0) throw new Error('SHAMIR_ZERO_INVERSE')
  // Fermat's little theorem in GF(2^8): a^(254) = a^(-1)
  return gfPow(a, 254)
}

/**
 * Split a secret byte array into `totalShares` shares such that any `threshold` shares
 * reconstruct the exact secret, while fewer than `threshold` shares reveal zero information.
 */
export function splitSecret(secret: Uint8Array, threshold: number, totalShares: number): ShamirShare[] {
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new Error('SHAMIR_SECRET_EMPTY')
  }
  if (!Number.isSafeInteger(threshold) || !Number.isSafeInteger(totalShares) || threshold < 1 || totalShares < threshold || totalShares > 255) {
    throw new Error('SHAMIR_INVALID_THRESHOLD')
  }
  const len = secret.length
  // Random polynomial coefficients c_1..c_{threshold-1} for each byte position
  const coeffs = new Uint8Array((threshold - 1) * len)
  if (coeffs.length > 0) crypto.getRandomValues(coeffs)

  const shares: ShamirShare[] = []
  for (let i = 1; i <= totalShares; i++) {
    const out = new Uint8Array(len)
    for (let pos = 0; pos < len; pos++) {
      // Evaluate P(i) = secret[pos] + c_1*i + c_2*i^2 + ... via Horner's method
      let acc = 0
      for (let d = threshold - 1; d >= 1; d--) {
        acc = gfMul(acc, i) ^ coeffs[(d - 1) * len + pos]!
      }
      acc = gfMul(acc, i) ^ secret[pos]!
      out[pos] = acc
    }
    shares.push({ index: i, bytes: out })
  }
  return shares
}

/**
 * Reconstruct a secret from `threshold` or more Shamir shares via Lagrange interpolation at x = 0.
 */
export function combineShares(shares: readonly ShamirShare[]): Uint8Array {
  if (shares.length === 0) {
    throw new Error('SHAMIR_SHARES_EMPTY')
  }
  const len = shares[0]!.bytes.length
  if (len === 0) throw new Error('SHAMIR_SHARE_EMPTY')
  const seen = new Set<number>()
  for (const s of shares) {
    if (!Number.isSafeInteger(s.index) || s.index < 1 || s.index > 255) {
      throw new Error('SHAMIR_INVALID_INDEX')
    }
    if (seen.has(s.index)) throw new Error('SHAMIR_DUPLICATE_INDEX')
    seen.add(s.index)
    if (!(s.bytes instanceof Uint8Array) || s.bytes.length !== len) {
      throw new Error('SHAMIR_SHARE_LENGTH_MISMATCH')
    }
  }

  // Precompute Lagrange basis coefficients L_j(0) = prod_{m != j} (x_m / (x_m ^ x_j))
  const lambdas = new Uint8Array(shares.length)
  for (let j = 0; j < shares.length; j++) {
    const xj = shares[j]!.index
    let num = 1
    let den = 1
    for (let m = 0; m < shares.length; m++) {
      if (m === j) continue
      const xm = shares[m]!.index
      num = gfMul(num, xm)
      den = gfMul(den, xm ^ xj)
    }
    lambdas[j] = gfMul(num, gfInv(den))
  }

  const secret = new Uint8Array(len)
  for (let pos = 0; pos < len; pos++) {
    let val = 0
    for (let j = 0; j < shares.length; j++) {
      val ^= gfMul(shares[j]!.bytes[pos]!, lambdas[j]!)
    }
    secret[pos] = val
  }
  return secret
}
