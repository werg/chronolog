/**
 * Standard `chronolog/keybox` module: the one shared definition of HPKE lockbox suites and lockbox
 * validation used by `chronolog/keys` (`$keys`) and `chronolog/vaults`.
 *
 * - Flat lockbox suites: `hpke-x25519-aes256gcm` (RFC 9180 DHKEM(X25519)) and `hpke-xwing-aes256gcm`
 *   (RFC 9180 with the X-Wing KEM 0x647a). A box without `suite` is X25519; X-Wing boxes always name
 *   their suite. Encapsulated key length must match the suite (32 / 1120 bytes).
 * - Tree suites (`hpke-tree-*`) describe `$keys` tree epochs and are never valid for a single box.
 * - `validateBoxesMap` enforces that every recipient is eligible (callback) and holds a wrap key of
 *   the box's suite, so writers cannot address lockboxes to non-members.
 */
export const STD_KEYBOX_SOURCE = `
export const HEX32 = /^[0-9a-f]{64}$/;
export const CAS_REF = /^cas:sha256-[0-9a-f]{64}$/;
const HEX_DATA = /^(?:[0-9a-f]{2})+$/;

export const SUITE_X25519 = 'hpke-x25519-aes256gcm';
export const SUITE_XWING = 'hpke-xwing-aes256gcm';
export const TREE_SUITE_X25519 = 'hpke-tree-x25519-aes256gcm';
export const TREE_SUITE_XWING = 'hpke-tree-xwing-aes256gcm';
export const FLAT_SUITES = [SUITE_X25519, SUITE_XWING];
export const TREE_SUITES = [TREE_SUITE_X25519, TREE_SUITE_XWING];
export const SUITE_RANK = {
  [SUITE_X25519]: 1,
  [TREE_SUITE_X25519]: 1,
  [SUITE_XWING]: 2,
  [TREE_SUITE_XWING]: 2,
};
const ENC_HEX_LENGTH = { [SUITE_X25519]: 64, [SUITE_XWING]: 2240 };

export function isTreeSuite(suite) {
  return TREE_SUITES.includes(suite);
}

/** Normalize an optional suite name: undefined/null -> fallback; unknown -> null. */
export function normalizeSuite(raw, fallback) {
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw === 'string' && Object.prototype.hasOwnProperty.call(SUITE_RANK, raw)) return raw;
  return null;
}

export function suiteAtLeast(suite, minSuite) {
  return SUITE_RANK[suite] >= SUITE_RANK[minSuite || SUITE_X25519];
}

/**
 * Validate one flat lockbox. Returns { ok: true, box, suite } with the canonical stored form
 * (suite omitted for X25519) or { ok: false, code }.
 */
export function validateBox(box, minSuite) {
  if (!box || typeof box !== 'object' || Array.isArray(box)) return { ok: false, code: 'box_invalid' };
  const suite = box.suite === undefined || box.suite === null ? SUITE_X25519 : box.suite;
  if (!FLAT_SUITES.includes(suite)) return { ok: false, code: 'box_invalid' };
  if (typeof box.encapsulatedKey !== 'string' || box.encapsulatedKey.length !== ENC_HEX_LENGTH[suite] || !HEX_DATA.test(box.encapsulatedKey)) {
    return { ok: false, code: 'box_invalid' };
  }
  if (typeof box.ciphertext !== 'string' || box.ciphertext.length < 32 || box.ciphertext.length > 8192 || !HEX_DATA.test(box.ciphertext)) {
    return { ok: false, code: 'box_invalid' };
  }
  if (!suiteAtLeast(suite, minSuite)) return { ok: false, code: 'suite_below_minimum' };
  return {
    ok: true,
    suite,
    box: { ...(suite !== SUITE_X25519 ? { suite } : {}), encapsulatedKey: box.encapsulatedKey, ciphertext: box.ciphertext },
  };
}

/** A recipient must hold a wrap key of the box's suite (when its member record is known). */
export function recipientHoldsSuiteKey(member, suite) {
  if (!member) return true;
  return suite === SUITE_XWING ? typeof member.pqWrapKey === 'string' : typeof member.wrapKey === 'string';
}

/**
 * Validate a { [recipientPk]: box } map. \`recipient(pk)\` returns the recipient's member record,
 * \`true\` (eligible, record unknown), or a falsy value (not eligible -> 'box_recipient_not_eligible').
 */
export function validateBoxesMap(raw, options) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, code: 'boxes_invalid' };
  const minSuite = options && options.minSuite;
  const recipient = options && typeof options.recipient === 'function' ? options.recipient : () => true;
  const out = {};
  for (const [pk, rawBox] of Object.entries(raw)) {
    if (!HEX32.test(pk)) return { ok: false, code: 'boxes_invalid' };
    const res = validateBox(rawBox, minSuite);
    if (!res.ok) return res;
    const rec = recipient(pk);
    if (!rec) return { ok: false, code: 'box_recipient_not_eligible', detail: pk };
    if (!recipientHoldsSuiteKey(rec === true ? null : rec, res.suite)) return { ok: false, code: 'box_recipient_key_missing', detail: pk };
    out[pk] = res.box;
  }
  return { ok: true, boxes: out };
}

/** Decode hex-encoded ASCII bytes (as returned by \`chronolog:cas\` get) and parse them as JSON, or null. */
export function parseHexJson(bytesHex) {
  if (typeof bytesHex !== 'string' || bytesHex.length % 2 !== 0) return null;
  let text = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytesHex.length; i += CHUNK) {
    const end = Math.min(bytesHex.length, i + CHUNK);
    const codes = [];
    for (let j = i; j < end; j += 2) {
      const c = parseInt(bytesHex.substr(j, 2), 16);
      if (!(c >= 0x20 && c < 0x7f)) return null;
      codes.push(c);
    }
    text += String.fromCharCode.apply(null, codes);
  }
  try { return JSON.parse(text); } catch { return null; }
}
`.trimStart()
