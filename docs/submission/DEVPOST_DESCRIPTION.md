## Inspiration

I built Money Penny because I wanted a personal AI chief of staff I could actually trust. Her existing workflow covers inbox attention, Calendar, reminders, memory, open loops, and briefings. As she gained context, the hardest problem changed: not only what an AI may do, but what it may claim it did.

An agent can confidently say "I sent it," "the repository is clean," or "the task is complete" when the action failed, remains pending, or never happened. During Build Week, I turned that problem into Readback: Money Penny's Honesty Filter.

## What It Does

Money Penny is the personal product. Readback is the trust capability that makes her different.

She reviews another agent's report and asks: **what does the evidence actually support?** Missing evidence is held; altered or contradictory evidence is blocked. The agent's text cannot approve itself, register a signing key, choose a command, redirect a source check, or turn confidence into proof.

The key discovery was that an AI can sign a false story. A valid signature proves that a key signed something; it does not prove the signer deserves trust. Money Penny accepts signed Readback only from a runner trusted beforehand, or checks a bounded source directly.

## Live Demo

In the public demo, a synthetic coding agent lies about a real public GitHub repository. Money Penny checks GitHub's current metadata and exact default-branch reference, catches the mismatch, and blocks the claim. When the report matches, she supports only the facts she observed. **Nothing is changed.**

The workspace also demonstrates missing evidence, trusted proof, unknown signers, tampering, and prompt attacks. It needs no login, API key, personal data, or cloud-model call at runtime.

## How It Works

Think of Readback as a receipt checker plus an independent spot-check:

1. **Authority:** Was the evidence issued by a runner trusted before the conversation?
2. **Integrity:** Was it altered, replayed, or expired?
3. **Binding:** Does it match the exact approval, operation, and output?
4. **Reality:** When a source can be checked directly, does it agree?

The zero-dependency package uses single-use approvals and signed, chained proof bundles that can be verified offline. The Git connector uses fixed read-only operations. The hosted GitHub connector makes two fixed metadata requests and accepts no credential, command, path, file request, arbitrary destination, or write method.

A review receipt proves Money Penny completed the review. It does not automatically prove the outside action happened.

## What I Built During Build Week

Money Penny's personal-assistant foundation existed before the event. The meaningful Build Week extension includes:

- The Readback package, independent verifier, and claim-level Honesty Filter.
- Trusted-runner pinning that reviewed content cannot change.
- Defences against forged, altered, replayed, expired, self-issued, or instruction-bearing evidence.
- Fixed read-only Git and public GitHub source adapters.
- A responsive no-login demo and sanitized release pipeline with CI, privacy scanning, and hash verification.

The public repository passes 20 tests and verifies all 62 release files with zero dependencies.

## Challenges

The hardest distinction was between proving a review ran and proving the reviewed action happened. Browser testing found wording that blurred those meanings, so I changed the interface and tests.

The deeper problem was trust: any agent can generate a key and sign an internally consistent lie. Money Penny treats valid proof from an unknown signer as **HOLD**, never **SUPPORTED**. Signed evidence still depends on its runner, so I added direct adapters that ask a bounded read-only source what is true.

The private assistant contains personal connectors and data. The judging edition is generated from an explicit allowlist, privacy-scanned, tested, and hash-verified.

## How Codex and GPT-5.6 Helped

**Codex** was my primary engineering partner. It audited the assistant, traced completion claims, implemented and attacked the proof system, added the GitHub connector, corrected wording through browser testing, extracted a privacy-safe release, and verified the judge flow.

**GPT-5.6** contributed product judgment, claim classification, threat analysis, UX decisions, and the central correction: governing what an agent may do is not enough; a trustworthy assistant must also govern what it may claim it did.

The public runtime makes no cloud-model call. Codex and GPT-5.6 shaped the system; the safety-critical demo remains deterministic and reproducible without credentials.

## Potential Impact

People should not need to understand signatures or provenance chains. They care whether "I sent it," "I changed it," or "the task is complete" is true.

Money Penny protects that trust across AI tools: authority before action, evidence or a source check afterward, and a clear next step when reality disagrees with the claim.

## Honest Limits

Readback is not a magic truth machine. A signature proves integrity and signer possession, not trustworthiness. It cannot defend a compromised host or stolen key.

Local Git verifies only bounded revision and worktree claims. Public GitHub verifies repository identity, default branch, current HEAD, visibility, and archive state. It cannot inspect private repositories, files, tests, or arbitrary outcomes. Every new destination needs its own read-only connector.

Those limits are part of the product: Money Penny should say what she knows, what she does not know, and whether anything changed.
