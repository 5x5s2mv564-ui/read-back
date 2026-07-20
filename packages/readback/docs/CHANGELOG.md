# Changelog

## 0.2.1

- Added a standalone independent proof-bundle verifier.
- Added an adversarial negative-control suite covering signature, chain,
  anchor, approval, replay, expiry, snapshot, schema, and fake-success forgeries.
- Added a recorded demo transcript sample and a live independent-verifier catch
  segment.
- Signed proof-bundle head snapshots and added tail-truncation rejection.

## 0.2.0

- Added legacy-segment verification and anchor protection for migrated ledgers.
- Added proposal-store anchor verification support.

## 0.1.0

- Extracted the zero-dependency claim-governance package.
- Added signed append-only ledger, fail-closed gate, proposal/approval/execute
  separation, readback guard, demo, tests, and clean export pipeline support.
