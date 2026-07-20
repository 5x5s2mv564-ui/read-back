# readback

`readback` is a portable trust layer so an AI agent can only claim what it can prove. It governs not only what an agent may do, but what it may say it did.

The package demonstrates three properties:

- A tamper-evident signed append-only ledger, with previous-hash chaining and a signed export-head snapshot so deletion, tail truncation, and reordering inside an exported bundle are detectable.
- A propose, approve, execute separation with single-use, expiring, hash-bound approvals. Conversation may propose work; it must never self-approve or self-execute.
- A readback contract: claims are answered only from signed ledger evidence, and fake-success wording is guarded.

## Quickstart

Requires Node.js 20 or newer.

```bash
npm test
node demo/run-demo.mjs
node demo/run-demo.mjs --record
```

The demo prints a numbered transcript. It proposes a synthetic hash-manifest job, refuses simulated conversational approval, records a human approval, executes once, refuses replay with `approval_consumed`, answers three readback questions from ledger evidence, demonstrates byte-flip tampering and chain-deletion tampering, restores the ledger, exports a proof bundle, and verifies that bundle offline.

## Third-Party Verification

After running the demo, use the printed proof-bundle path:

```bash
node bin/verify-bundle.mjs --bundle /path/to/proof-bundle.json --json
```

The bundle contains the ledger, signed head snapshot, and public key needed to verify
the claim history offline. `bin/verify-bundle.mjs` is intentionally separate
from the package verifier in `src/ledger.mjs`; it re-implements the checks so a
bug in the package verifier cannot hide inside the independent proof.

That default check proves internal integrity, not signer identity. For trusted
verification, supply the expected public key from a separate trusted location:

```bash
node bin/verify-bundle.mjs \
  --bundle /path/to/proof-bundle.json \
  --public-key /trusted/path/runner-public.pem \
  --json
```

An agent must not establish trust by including a new key in its own bundle.
Money Penny pins the full SHA-256 fingerprint of approved runner keys in local
configuration before reviewing evidence.

## Verify My Claims Yourself

Run the negative-control suite:

```bash
node --test test/adversarial.test.mjs
```

It starts from valid signed bundles, forges fifteen different invalid histories,
and requires both the package verifier and the independent verifier to reject
each one with the expected first-failure reason. The demo also ends by deleting a
middle event from a copied bundle and showing the independent verifier catch the
chain break.

## Vocabulary

This package is an implementation of verifiability-first agent control ideas:
attestation, provenance, non-repudiation, fail-closed routing, and single-use
capabilities. It does not claim novelty over research work in those areas; it is
a small working artifact that makes the ideas concrete.

## Scope

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). In short: this package proves
what the runner recorded, binds approvals to hashed inputs, and limits readback
claims to signed evidence. Signature verification alone does not establish that
the signer is trusted; embedders must pin a key or full key fingerprint outside
the submitted bundle. It does not sandbox job code at the operating-system
level, defend a compromised host, protect a stolen signing key, or verify the
semantic truth of job outputs.

The signed head snapshot commits to the bundle at export time. It detects a
bundle that is shortened or whose declared head is rewritten after export, but
without an external transparency log or timestamp it cannot prove that the
signer never created later history outside the submitted bundle.

See [docs/PROVENANCE.md](docs/PROVENANCE.md) for the project provenance note and
[docs/CHANGELOG.md](docs/CHANGELOG.md) for version history.
