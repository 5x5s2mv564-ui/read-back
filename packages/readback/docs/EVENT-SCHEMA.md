# Event Schema

All events use `schema_version: 1`. Unknown schema versions fail verification.

Canonical serialization uses stable object key order, exact array order, JSON
strings for primitive values, no undefined values, and no non-finite numbers.
The signature envelope covers every event field except `signature` and
`entry_hash`. The `entry_hash` covers the full event including the signature but
excluding `entry_hash` itself.

Every event includes:

- `schema_version`
- `event_id`
- `event_type`
- `timestamp`
- `prev_hash`
- `payload`
- `signature`
- `entry_hash`

`prev_hash` is the previous event's `entry_hash`, or `null` for the first entry.
Verification checks signatures, entry hashes, and the previous-hash chain.
Proof-bundle verification also checks semantic consistency: approvals must refer
to existing proposals, executions must refer to prior unexpired approvals, and a
single-use approval can be consumed exactly once.

Head snapshots include:

- `entry_count`
- `ledger_head_hash`
- `legacy_entry_count`
- `chained_entry_count`
- `signed_entry_count`
- an Ed25519 `signature` over the complete snapshot in proof bundles

Proof-bundle verification requires that signature. The signed head and counts
make middle deletion and tail truncation detectable relative to the exported
bundle.

## Event Types

- `proposal_recorded`
- `proposal_rejected`
- `sidecar_job_approved`
- `sidecar_job_refused`
- `sidecar_job_executed`
- `ledger_schema_migrated`
- `proposal_store_migrated`
- `ledger_head_snapshot`

## Legacy Segment Migration

`ledger_schema_migrated` anchors an immutable pre-v1 segment without rewriting
it. The migration event payload includes:

- `schema_version: 1`
- `legacy_entry_count`
- `legacy_head_hash`
- `migrated_at`

Verification checks the exact legacy segment hash before validating the v1 chain
from the migration event forward. A deleted or reordered legacy entry changes
the legacy segment hash and fails verification with `legacy_anchor_mismatch`.
Post-migration entries continue to use `prev_hash` chaining.

## Proposal Store Anchor Migration

`proposal_store_migrated` anchors an append-only proposal store that existed
before the public schema. Its payload includes:

- `schema_version: 1`
- `legacy_row_count`
- `legacy_store_hash`
- `migrated_at`

Verification recomputes the hash over the exact legacy store rows before the
marker, then validates the signed v1 chain from the marker forward. A deleted,
reordered, or edited legacy store row changes the anchor hash and fails with
`store_anchor_mismatch`. A changed post-anchor store event fails normal v1
entry or chain verification.

## Refusal Reasons

`sidecar_job_refused` uses an enumerated `payload.refusal_reason`:

- `approval_expired`
- `approval_consumed`
- `proposal_tampered`
- `spec_tampered`
- `input_drift`
- `proposal_rejected`
- `approval_missing`
- `unapproved`
- `timeout`
- `output_path_refused`
- `job_failed`
- `single_use_violated`
- `orphan_execution`
- `expired_at_execution`
- `absent_proposal`
- `fake_success_without_evidence`

The fixed execution refusal ladder is:

1. proposal exists
2. rejected after approval
3. proposal record hash intact
4. spec hash match
5. every input hash match
6. approval expired
7. approval consumed

Missing execution approval records use the Stage 7D-compatible
`approval_missing` refusal reason. The broader `unapproved` status remains
available for approval-layer refusals that do not create `sidecar_job_refused`
events.

The first failure wins. Integrity failures must not be hidden by softer status
wording in later stages.

## Independent Verification

`bin/verify-bundle.mjs` is a standalone verifier. It does not import
`src/ledger.mjs`; it re-implements canonical serialization, signature
verification, entry hashing, legacy anchors, head snapshot checks, and semantic
consistency checks. A disagreement between the package verifier and independent
verifier is a finding, not a tie.
