# `@chronolog/authority`

Portable, zero-native cryptographic record helpers, canonical application input schemas, and Chronolog v2 finality verification. Runs identically in Node.js, browsers, and Cloudflare Workers without importing materializers, SQLite, or storage.

## Exports

- **Signed records (`codec.ts`):** `createSigningIdentity`, `signRecord`, `verifyRecord`, `encodeRecord`, `decodeRecord`, `recordDigest`, `equalRecord`.
- **Application descriptions (`definition.ts`):** `validateApplicationDescription`, `applicationDescriptionDigest`, `checkedApplicationInputSchema`, `parseApplicationInput`.
- **Chronolog v2 Finality (`finality-v2.ts`):** `parseFinalitySchedule`, `policyScopeId`, `computeIncludedSetDigest`, `signFinalityCheckpoint`, `verifyFinalityV2`, `signHostAttestationV2`, `verifyHostAttestationV2`.
