# `@chronolog/authority`

Portable, zero-native cryptographic record helpers, canonical application input schemas, and protocol-agnostic `$admission` evidence evaluation. Runs identically in Node.js, browsers, and Cloudflare Workers without importing materializers, SQLite, or storage.

## Exports

- **Signed records (`codec.ts`):** `createSigningIdentity`, `signRecord`, `verifyRecord`, `encodeRecord`, `decodeRecord`, `recordDigest`, `equalRecord`.
- **Application descriptions (`definition.ts`):** `validateApplicationDescription`, `applicationDescriptionDigest`, `checkedApplicationInputSchema`, `parseApplicationInput`.
- **Protocol-Agnostic Admission (`admission.ts`):** `evaluateAdmission`, `computeAdmissionScopeId`, `canonicalAdmissionCheckpointMessage`, `checkpointPayloadToJson`, `signAdmissionCheckpoint`, `signAdmissionMessage`, `computeIncludedSetDigest`, `evidenceDigest`, `signHostAttestationV2`, `verifyHostAttestationV2`, `AdmissionEvidence`, `PinnedFrontier`, `AdmissionDecision`.
