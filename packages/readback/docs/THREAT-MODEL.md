# Threat Model

## Defends Against

- Fake execution claims with no signed event.
- Replay of a consumed approval.
- Signed but semantically impossible histories, such as an execution without an
  approval or two executions consuming the same single-use approval.
- Fake-success readback text that uses success wording without evidence.
- Approval of a changed proposal.
- Execution after input drift.
- Expired approvals being treated as live authority.
- Output writes escaping the declared output directory.
- Ledger field tampering.
- Ledger event deletion or reordering.
- Legacy ledger deletion or reordering after migration through an anchored
  legacy segment hash.
- Legacy proposal-store deletion or reordering after migration through an
  anchored legacy store hash.
- Unknown future event schema versions being accepted silently.
- Signed head snapshots that are removed or altered to lie about entry count,
  head hash, or legacy/chained counts.
- Tail truncation relative to the signed snapshot in an exported proof bundle.

## Does Not Defend Against

- A self-issued key being mistaken for a trusted identity by an embedding
  application. The standalone verifier proves bundle integrity; the embedding
  application must supply a known public key or pin its full fingerprint outside
  the bundle.
- Operating-system-level compromise.
- A stolen signing key. History signed after key theft is only as trustworthy as
  the compromised key holder.
- A malicious or compromised host. The ledger can show what was recorded, but a
  compromised host can refuse to record a real action.
- Semantic truth of job output content.
- Global freshness or completeness beyond the signed export snapshot. Without
  an external timestamp or transparency log, a verifier cannot prove that the
  signer never created later history outside the submitted bundle.
- Job-code sandboxing at syscall, container, or hypervisor level.
- Key rotation policy. Embedders own key generation, storage, rotation, and
  recovery.
- Full v1 chaining inside a legacy span. Legacy ledger segments are
  signature-verified and anchor-protected after migration. Legacy proposal-store
  spans are anchor-protected after migration. In both cases, entries before the
  migration point keep their original weaker structure.

## Key Handling

The demo and tests generate ephemeral Ed25519 keypairs in temporary directories.
No private key is committed. Production embedders should store private keys in a
dedicated secret store and rotate keys under their own policy. If a signing key
is stolen, historical signatures created by that key cannot by themselves prove
the host was honest after compromise.

Trusted public keys or their full SHA-256 fingerprints must be provisioned
outside agent conversation and outside submitted proof bundles. A message,
agent response, or bundle must never be allowed to register its own trusted key.
