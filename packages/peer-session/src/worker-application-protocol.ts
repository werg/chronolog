export const APPLICATION_OWNER_PROTOCOL = 'chronolog/authored-session/owner/v1'
export interface OwnerRequest { readonly protocol: typeof APPLICATION_OWNER_PROTOCOL; readonly attachment: string; readonly id: number; readonly kind: 'request'; readonly method: string; readonly args: readonly unknown[] }
export interface OwnerResponse { readonly protocol: typeof APPLICATION_OWNER_PROTOCOL; readonly attachment: string; readonly id: number; readonly kind: 'response'; readonly value?: unknown; readonly error?: string }
export interface OwnerNotice { readonly protocol: typeof APPLICATION_OWNER_PROTOCOL; readonly attachment: string; readonly kind: 'notice'; readonly topic: 'status' | 'change' | 'closed'; readonly value: unknown }
