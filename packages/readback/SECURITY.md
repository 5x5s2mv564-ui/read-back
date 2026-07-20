# Security

Report vulnerabilities to `<SECURITY_CONTACT>`.

This package is deliberately fail-closed: actions require explicit, signed,
hash-bound evidence before the readback layer may confirm that anything
happened. Missing evidence is treated as no evidence. Unknown event schema
versions, invalid signatures, hash-chain gaps, stale approvals, replay attempts,
and output path escapes all fail verification.
