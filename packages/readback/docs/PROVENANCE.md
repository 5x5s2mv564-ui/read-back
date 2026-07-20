# Provenance

`readback` is a working implementation of verifiability-first agent control
ideas: signed attestations, provenance, non-repudiation, fail-closed execution,
single-use approvals, and evidence-bound claim readback.

Those ideas are convergent with recent research and engineering work around
verifiable agent systems. This package does not claim priority over that work.
Its purpose is narrower: provide a small, zero-dependency artifact that a
skeptic can run locally to see proposal, approval, execution, replay refusal,
tamper detection, and offline proof verification without trusting the producer.
