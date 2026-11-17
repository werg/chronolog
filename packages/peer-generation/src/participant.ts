/** Delivery interests are separate from signed authority and application history. */
export const PARTICIPANT_PROTOCOL = 'chronolog-participant-v1' as const
export type ParticipantFacet = 'control' | 'publication' | 'discovery' | 'ephemeral' | 'database' | 'content'
export interface ParticipantInterest { readonly facet: ParticipantFacet; readonly action: string }
export interface ParticipantPolicy {
  readonly role: 'control' | 'peer'
  readonly interests: readonly ParticipantInterest[]
}
export interface ParticipantRequest extends ParticipantInterest {
  readonly protocol: typeof PARTICIPANT_PROTOCOL
  readonly applicationId: string
  readonly requestId: string
  readonly payload: unknown
}
export type ParticipantResponse = ParticipantRequest
export interface ParticipantExchangeOptions { readonly signal?: AbortSignal }
export interface ParticipantTransport {
  readonly applicationId: string
  readonly policy: ParticipantPolicy
  exchange(request: ParticipantRequest, options?: ParticipantExchangeOptions): Promise<ParticipantResponse>
  request<T = unknown>(facet: ParticipantFacet, action: string, payload: unknown, options?: ParticipantExchangeOptions): Promise<T>
}

export const PARTICIPANT_LIMITS = Object.freeze({
  pending: 4, depth: 32,
  bytes: Object.freeze({ control: 16 * 1024 * 1024, publication: 12 * 1024 * 1024,
    discovery: 256 * 1024, ephemeral: 64 * 1024, database: 32 * 1024 * 1024, content: 512 * 1024 }),
})

function policy(role: ParticipantPolicy['role'], actions: Readonly<Record<string, readonly string[]>>): ParticipantPolicy {
  return Object.freeze({ role, interests: Object.freeze(Object.entries(actions).flatMap(([facet, names]) =>
    names.map(action => Object.freeze({ facet: facet as ParticipantFacet, action })))) })
}

/** The host receives lifecycle/control traffic; ordinary data and live UI activity are excluded. */
export const CONTROL_PARTICIPANT_POLICY = policy('control', {
  control: ['read', 'configure', 'select', 'administer'],
  publication: ['definition', 'read', 'publish'],
  discovery: ['read', 'advertise', 'withdraw'],
  ephemeral: ['invite'],
})
export const PEER_PARTICIPANT_POLICY = policy('peer', {
  control: ['state', 'keyShare'], publication: ['definition', 'read'],
  database: ['submit', 'range', 'coverage'], content: ['manifest', 'chunk', 'retained', 'observeRetention'], ephemeral: ['signal', 'hint'],
})

export class ParticipantProtocolError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'ParticipantProtocolError' }
}
function requireParticipant(condition: unknown, code: string): asserts condition {
  if (!condition) throw new ParticipantProtocolError(code)
}
function applicationId(value: unknown): asserts value is string {
  requireParticipant(typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value), 'PEER_PARTICIPANT_SCOPE_INVALID')
}
function jsonValue(value: unknown, depth = 0): void {
  requireParticipant(depth <= PARTICIPANT_LIMITS.depth, 'PEER_PARTICIPANT_DEPTH_LIMIT')
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number') { requireParticipant(Number.isFinite(value), 'PEER_PARTICIPANT_PAYLOAD_INVALID'); return }
  if (Array.isArray(value)) { for (const item of value) jsonValue(item, depth + 1); return }
  requireParticipant(value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype,
    'PEER_PARTICIPANT_PAYLOAD_INVALID')
  for (const item of Object.values(value)) jsonValue(item, depth + 1)
}
export function participantAccepts(policy: ParticipantPolicy, interest: ParticipantInterest): boolean {
  return policy.interests.some(value => value.facet === interest.facet && value.action === interest.action)
}

/** Validate before routing or dispatch. A transport policy does not confer author permissions. */
export function validateParticipantRequest(value: unknown, selected: ParticipantPolicy = CONTROL_PARTICIPANT_POLICY): ParticipantRequest {
  requireParticipant(value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype,
    'PEER_PARTICIPANT_ENVELOPE_INVALID')
  const request = value as ParticipantRequest
  const fields = ['protocol', 'applicationId', 'requestId', 'facet', 'action', 'payload']
  requireParticipant(Object.keys(request).length === fields.length && fields.every(key => Object.hasOwn(request, key)),
    'PEER_PARTICIPANT_ENVELOPE_INVALID')
  requireParticipant(request.protocol === PARTICIPANT_PROTOCOL, 'PEER_PARTICIPANT_PROTOCOL_UNSUPPORTED')
  applicationId(request.applicationId)
  requireParticipant(typeof request.requestId === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/u.test(request.requestId),
    'PEER_PARTICIPANT_REQUEST_INVALID')
  requireParticipant(typeof request.facet === 'string' && Object.hasOwn(PARTICIPANT_LIMITS.bytes, request.facet) &&
    typeof request.action === 'string' && /^[a-z][A-Za-z-]{0,47}$/u.test(request.action), 'PEER_PARTICIPANT_INTEREST_INVALID')
  requireParticipant(participantAccepts(selected, request), 'PEER_PARTICIPANT_FACET_FORBIDDEN')
  jsonValue(request.payload)
  requireParticipant(new TextEncoder().encode(JSON.stringify(request)).length <= PARTICIPANT_LIMITS.bytes[request.facet],
    'PEER_PARTICIPANT_SIZE_LIMIT')
  return structuredClone(request)
}

export function createParticipantRequest(input: Omit<ParticipantRequest, 'protocol' | 'requestId'> & { readonly requestId?: string },
  selected: ParticipantPolicy = CONTROL_PARTICIPANT_POLICY): ParticipantRequest {
  return validateParticipantRequest({ protocol: PARTICIPANT_PROTOCOL, applicationId: input.applicationId,
    requestId: input.requestId ?? crypto.randomUUID(), facet: input.facet, action: input.action, payload: input.payload }, selected)
}
export function createParticipantResponse(request: ParticipantRequest, payload: unknown,
  selected: ParticipantPolicy = CONTROL_PARTICIPANT_POLICY): ParticipantResponse {
  return validateParticipantRequest({ ...validateParticipantRequest(request, selected), payload }, selected)
}
export function validateParticipantResponse(value: unknown, request: ParticipantRequest,
  selected: ParticipantPolicy = CONTROL_PARTICIPANT_POLICY): ParticipantResponse {
  const response = validateParticipantRequest(value, selected)
  requireParticipant(response.applicationId === request.applicationId && response.requestId === request.requestId &&
    response.facet === request.facet && response.action === request.action, 'PEER_PARTICIPANT_RESPONSE_MISMATCH')
  return response
}

/** One bounded request transport. It never polls or substitutes a data-plane fallback. */
export function createParticipantTransport(options: {
  readonly applicationId: string
  readonly policy?: ParticipantPolicy
  readonly exchange: (request: ParticipantRequest, options: ParticipantExchangeOptions) => Promise<unknown>
}): ParticipantTransport {
  applicationId(options.applicationId)
  const scope = options.applicationId, dispatch = options.exchange
  const selected = structuredClone(options.policy ?? CONTROL_PARTICIPANT_POLICY)
  let pending = 0
  const exchange = async (input: ParticipantRequest, inputOptions: ParticipantExchangeOptions = {}): Promise<ParticipantResponse> => {
    const request = validateParticipantRequest(input, selected)
    requireParticipant(request.applicationId === scope, 'PEER_PARTICIPANT_SCOPE_MISMATCH')
    inputOptions.signal?.throwIfAborted()
    requireParticipant(pending < PARTICIPANT_LIMITS.pending, 'PEER_PARTICIPANT_BUSY')
    pending++
    try {
      const response = await dispatch(request, inputOptions)
      inputOptions.signal?.throwIfAborted()
      return validateParticipantResponse(response, request, selected)
    } finally { pending-- }
  }
  return Object.freeze({ applicationId: scope, policy: policy(selected.role,
    Object.fromEntries([...new Set(selected.interests.map(value => value.facet))].map(facet =>
      [facet, selected.interests.filter(value => value.facet === facet).map(value => value.action)]))), exchange,
  async request<T = unknown>(facet: ParticipantFacet, action: string, payload: unknown, inputOptions: ParticipantExchangeOptions = {}): Promise<T> {
    return (await exchange(createParticipantRequest({ applicationId: scope, facet, action, payload }, selected), inputOptions)).payload as T
  } })
}
