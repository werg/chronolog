import { useEffect, useMemo, useState } from 'react'
import {
  ownershipQueries,
  type ChronologClient,
  type Grant,
  type OwnershipQuery,
  type TeamMember,
  type TeamMembership,
  type TransferOffer,
} from '@chronolog/client'

import { useChronologClient } from './context.js'
import { useChronologQuery, type UseResourceOptions } from './hooks.js'

export type IdentityState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly key: Uint8Array }
  | { readonly status: 'error'; readonly error: unknown }

/** This node's signing key: the owner of the rows it inserts. */
export function useChronologIdentity(clientOverride?: ChronologClient): IdentityState {
  const client = useChronologClient(clientOverride)
  const [state, setState] = useState<{ readonly client: ChronologClient; readonly value: IdentityState }>()
  useEffect(() => {
    let live = true
    client.identity().then(
      (key) => { if (live) setState({ client, value: { status: 'ready', key } }) },
      (error: unknown) => { if (live) setState({ client, value: { status: 'error', error } }) },
    )
    return () => { live = false }
  }, [client])
  return state?.client === client ? state.value : { status: 'loading' }
}

export type OwnershipListState<T> =
  | { readonly status: 'loading'; readonly rows: readonly T[] }
  | { readonly status: 'ready'; readonly rows: readonly T[] }
  | { readonly status: 'error'; readonly rows: readonly T[]; readonly error: unknown }
  | { readonly status: 'disabled'; readonly rows: readonly T[] }

/**
 * Live rows of an ownership query (see `ownershipQueries`). `rows` keeps the
 * last value while reloading or after a transport error.
 */
export function useOwnershipQuery<T>(query: OwnershipQuery<T> | undefined, options: UseResourceOptions = {}): OwnershipListState<T> {
  const state = useChronologQuery(query?.sql ?? '', query?.parameters ?? [], {
    ...(options.client === undefined ? {} : { client: options.client }),
    enabled: query !== undefined && options.enabled !== false,
  })
  const value = state.status === 'value' || state.status === 'reset'
    ? state.value
    : state.status === 'disabled' ? undefined : state.previous
  const rows = useMemo(
    () => value?.result === undefined || query === undefined ? [] : query.decode(value.result),
    // `value` changes with every new result; `decode` is fixed per query kind.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [value],
  )
  switch (state.status) {
    case 'value':
    case 'reset': return { status: 'ready', rows }
    case 'disabled': return { status: 'disabled', rows }
    case 'transport_error':
    case 'query_error': return { status: 'error', rows, error: state.error }
    case 'loading': return { status: 'loading', rows }
  }
}

/** Runs `build` with this node's key once it is known. */
function useMine<T>(build: (key: Uint8Array) => OwnershipQuery<T>, options: UseResourceOptions): OwnershipListState<T> {
  const identity = useChronologIdentity(options.client)
  const key = identity.status === 'ready' ? identity.key : undefined
  // The key's bytes identify the query; `build` is a fixed function per hook.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const query = useMemo(() => key === undefined ? undefined : build(key), [key])
  const state = useOwnershipQuery(query, options)
  if (identity.status === 'error') return { status: 'error', rows: [], error: identity.error }
  if (query === undefined && options.enabled !== false) return { status: 'loading', rows: [] }
  return state
}

/** Teams this node is an active member of. */
export function useMyTeams(options: UseResourceOptions = {}): OwnershipListState<TeamMembership> {
  return useMine(ownershipQueries.teams, options)
}

/** Teams that invited this node and await its acceptance. */
export function useTeamInvitations(options: UseResourceOptions = {}): OwnershipListState<TeamMembership> {
  return useMine(ownershipQueries.invitations, options)
}

/** Live grants this node has received. */
export function useGrantsReceived(options: UseResourceOptions = {}): OwnershipListState<Grant> {
  return useMine(ownershipQueries.grantsReceived, options)
}

/** Live grants on this node's own rows. */
export function useGrantsGiven(options: UseResourceOptions = {}): OwnershipListState<Grant> {
  return useMine(ownershipQueries.grantsGiven, options)
}

/** Open transfer offers this node may accept (to it, or to a team it administers). */
export function useIncomingOffers(options: UseResourceOptions = {}): OwnershipListState<TransferOffer> {
  return useMine(ownershipQueries.incomingOffers, options)
}

/** Open transfer offers of this node's own rows. */
export function useOutgoingOffers(options: UseResourceOptions = {}): OwnershipListState<TransferOffer> {
  return useMine(ownershipQueries.outgoingOffers, options)
}

/** Current and invited members of a team; pass undefined to wait for an id. */
export function useTeamMembers(teamId: Uint8Array | undefined, options: UseResourceOptions = {}): OwnershipListState<TeamMember> {
  const hex = teamId === undefined ? undefined : Buffer.from(teamId).toString('hex')
  // The id's bytes, not the array's identity, select the query.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const query = useMemo(() => teamId === undefined ? undefined : ownershipQueries.members(teamId), [hex])
  return useOwnershipQuery(query, options)
}
