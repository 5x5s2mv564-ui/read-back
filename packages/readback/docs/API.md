# API

## `src/gate.mjs`

- `isGateEnabled(valueOrEnv, key?)`: returns true only for the exact string
  `"true"`.

## `src/ledger.mjs`

- `canonicalJson(value)`: stable serialization.
- `sha256(value)`: `sha256:<hex>` hash of a string or buffer.
- `generateEphemeralKeypair()`: returns PEM encoded Ed25519 keys.
- `appendEvent({ ledgerPath, eventType, payload, privateKeyPem, publicKeyPem, now })`
- `verifyLedger({ ledgerPath, entries, publicKeyPem, headSnapshot })`
- `verifyAnchoredStore({ entries, publicKeyPem })`
- `exportProofBundle({ ledgerPath, publicKeyPem, privateKeyPem, outPath })`
- `verifyProofBundle(bundleOrPath)`
- `verifyEventSemantics({ entries, readbacks })`

`verifyProofBundle` performs cryptographic checks and semantic checks. It rejects
validly signed but impossible histories, such as orphan executions, expired
approval executions, and single-use replay forgeries.

## `bin/verify-bundle.mjs`

- `verifyBundleIndependent(bundleOrPath, { publicKeyPem? })`: standalone
  zero-trust proof-bundle verifier.
- CLI: `node bin/verify-bundle.mjs --bundle <path> --json`

The independent verifier does not import `src/ledger.mjs`.

## `src/proposals.mjs`

- `propose({ ledgerPath, privateKeyPem, publicKeyPem, specPath, inputPaths, now })`
- `reject({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, now })`
- `proposalState({ ledgerPath })`

## `src/approvals.mjs`

- `approve({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, now, expiryHours })`

Refuses rejected, drifted, missing, or already approved proposals.

## `src/execute.mjs`

- `execute({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, outputDir, now, timeoutMs })`
- `writeOutputAtomic({ outputDir, fileName, content, maxBytes })`

Jobs return content. The runner writes content through the validated output API.

## `src/readback.mjs`

- `interrogate(query, { ledgerPath })`: returns `{ claim, evidence, answer_text }`
  using ledger evidence only.

Fake-success wording is refused unless matching signed evidence is cited.
