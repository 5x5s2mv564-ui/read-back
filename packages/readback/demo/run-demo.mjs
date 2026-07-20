#!/usr/bin/env node
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { approve } from '../src/approvals.mjs'
import { execute } from '../src/execute.mjs'
import {
  canonicalJson,
  exportProofBundle,
  generateEphemeralKeypair,
  hashObject,
  readLedgerEntries,
  verifyLedger,
  verifyProofBundle,
} from '../src/ledger.mjs'
import { buildSpec, propose } from '../src/proposals.mjs'
import { interrogate } from '../src/readback.mjs'
import { verifyBundleIndependent } from '../bin/verify-bundle.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SAMPLE_TRANSCRIPT_PATH = join(__dirname, 'transcript.sample.txt')

function redact(text = '') {
  return String(text)
    .replace(/sha256:[a-f0-9]{64}/g, 'sha256:<redacted>')
    .replace(/approval_proposal_demo_manifest_[0-9]+/g, 'approval_proposal_demo_manifest_<redacted>')
    .replace(/evt_[A-Za-z0-9_]+_[0-9]+_[a-f0-9]+/g, 'evt_<redacted>')
    .replace(/\/var\/folders\/[^\s",]+/g, '<temp-path>')
    .replace(/\/tmp\/readback-demo-[^\s",]+/g, '<temp-path>')
}

function log(lines, payload, jsonMode, humanLines) {
  humanLines.push(redact(lines))
  if (jsonMode) return
  console.log(lines)
  if (payload) {
    const body = JSON.stringify(payload, null, 2)
    humanLines.push(redact(body))
    console.log(body)
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function writeSpec(path) {
  const spec = buildSpec()
  writeFileSync(path, `${JSON.stringify(spec, null, 2)}\n`, 'utf8')
  return spec
}

function writeLedger(path, entries) {
  writeFileSync(path, entries.map(canonicalJson).join('\n') + '\n', 'utf8')
}

async function main() {
  const jsonMode = process.argv.includes('--json')
  const recordMode = process.argv.includes('--record')
  const keep = process.argv.includes('--keep')
  const transcript = []
  const humanLines = []
  const tempRoot = mkdtempSync(join(tmpdir(), 'readback-demo-'))
  try {
    const keys = generateEphemeralKeypair()
    const ledgerPath = join(tempRoot, 'ledger.jsonl')
    const outputDir = join(tempRoot, 'runner-output')
    const proofBundlePath = join(tempRoot, 'proof-bundle.json')
    const fixtures = join(tempRoot, 'demo/fixtures')
    mkdirSync(fixtures, { recursive: true })
    writeFileSync(join(fixtures, 'quarterly-widgets.json'), `${JSON.stringify({
      fixture: 'quarterly-widgets',
      owner: 'Ada Lovelace',
      count: 8,
    }, null, 2)}\n`, 'utf8')
    const specPath = join(fixtures, 'hash-manifest-spec.json')
    const spec = writeSpec(specPath)
    transcript.push({ step: 1, outcome: 'ephemeral keypair generated' })
    log('1. Generated ephemeral Ed25519 keypair.', null, jsonMode, humanLines)

    const proposed = propose({
      ledgerPath,
      ...keys,
      specPath,
      inputPaths: spec.input_paths,
      baseDir: tempRoot,
      now: '2026-01-01T00:00:00.000Z',
      proposalId: 'proposal_demo_manifest',
    })
    transcript.push({ step: 2, proposal_id: proposed.proposal.proposal_id, spec_hash: proposed.proposal.spec_hash, input_hashes: proposed.proposal.input_hashes })
    log('2. Proposed hash-manifest job.', transcript.at(-1), jsonMode, humanLines)

    const simulatedConversationApproval = { ok: false, status: 'conversational_approval_refused', reason: 'cli_only' }
    assert(!readLedgerEntries(ledgerPath).some((entry) => entry.event_type === 'sidecar_job_approved'), 'conversation created approval event')
    transcript.push({ step: 3, ...simulatedConversationApproval })
    log('3. Simulated conversational self-approval refused; no approval event exists.', simulatedConversationApproval, jsonMode, humanLines)

    const approved = approve({
      ledgerPath,
      ...keys,
      proposalId: proposed.proposal.proposal_id,
      baseDir: tempRoot,
      now: '2026-01-01T00:01:00.000Z',
    })
    assert(approved.ok, `approval failed: ${JSON.stringify(approved)}`)
    transcript.push({ step: 4, approval_id: approved.approval.approval_id, expires_at: approved.approval.expires_at, single_use: approved.approval.single_use })
    log('4. Human approval recorded through CLI path.', transcript.at(-1), jsonMode, humanLines)

    const executed = execute({
      ledgerPath,
      ...keys,
      proposalId: proposed.proposal.proposal_id,
      baseDir: tempRoot,
      outputDir,
      now: '2026-01-01T00:02:00.000Z',
    })
    assert(executed.ok, `execution failed: ${JSON.stringify(executed)}`)
    transcript.push({ step: 5, output_hash: executed.output_hash, approval_consumed: executed.event.payload.approval_consumed })
    log('5. Executed once; output hash recorded and approval consumed.', transcript.at(-1), jsonMode, humanLines)

    const replay = execute({
      ledgerPath,
      ...keys,
      proposalId: proposed.proposal.proposal_id,
      baseDir: tempRoot,
      outputDir,
      now: '2026-01-01T00:03:00.000Z',
    })
    assert(replay.refusal_reason === 'approval_consumed', `replay did not refuse approval_consumed: ${JSON.stringify(replay)}`)
    transcript.push({ step: 6, replay_refusal: replay.refusal_reason })
    log('6. Replay refused with approval_consumed.', transcript.at(-1), jsonMode, humanLines)

    const q1 = interrogate('manifest_job_ran', { ledgerPath })
    const q2 = interrogate('email_sent', { ledgerPath })
    const q3 = interrogate('second_job_approved', { ledgerPath })
    transcript.push({ step: 7, answers: [q1, q2, q3] })
    log('7. Interrogation answers from ledger evidence only.', transcript.at(-1), jsonMode, humanLines)
    assert(q1.evidence.length === 1, 'manifest readback missing evidence')
    assert(q2.evidence.length === 0 && q3.evidence.length === 0, 'negative readback produced evidence')

    const originalEntries = readLedgerEntries(ledgerPath)
    const headSnapshot = { ledger_head_hash: originalEntries.at(-1).entry_hash, entry_count: originalEntries.length }
    const byteTampered = JSON.parse(JSON.stringify(originalEntries))
    byteTampered[0].payload.proposal.spec_hash = 'sha256:0000'
    const byteTamperResult = verifyLedger({ entries: byteTampered, publicKeyPem: keys.publicKeyPem, headSnapshot })
    assert(!byteTamperResult.ok, 'byte tamper unexpectedly verified')
    writeLedger(ledgerPath, originalEntries)
    const byteRestore = verifyLedger({ ledgerPath, publicKeyPem: keys.publicKeyPem, headSnapshot })
    assert(byteRestore.ok, 'restore after byte tamper failed')
    const chainTampered = originalEntries.filter((_, index) => index !== 2)
    const chainTamperResult = verifyLedger({ entries: chainTampered, publicKeyPem: keys.publicKeyPem, headSnapshot })
    assert(!chainTamperResult.ok, 'chain deletion unexpectedly verified')
    writeLedger(ledgerPath, originalEntries)
    const chainRestore = verifyLedger({ ledgerPath, publicKeyPem: keys.publicKeyPem, headSnapshot })
    assert(chainRestore.ok, 'restore after chain tamper failed')
    transcript.push({
      step: 8,
      byte_flip_failure: byteTamperResult,
      byte_restore: byteRestore,
      chain_deletion_failure: chainTamperResult,
      chain_restore: chainRestore,
    })
    if (!jsonMode) {
      const tamperLine = `TAMPER DETECTED - entry ${byteTamperResult.index} was modified after signing. Its content no longer matches its signed hash (${byteTamperResult.reason}). Every claim depending on this entry is now unverifiable.`
      const chainLine = `CHAIN BROKEN - entry ${chainTamperResult.index} expects a predecessor that no longer exists (${chainTamperResult.reason}). An event has been deleted from history.`
      humanLines.push(tamperLine, chainLine)
      console.log(tamperLine)
      console.log(chainLine)
    }
    log('8. Tamper checks failed loudly, then restored verification passed.', transcript.at(-1), jsonMode, humanLines)

    exportProofBundle({
      ledgerPath,
      publicKeyPem: keys.publicKeyPem,
      privateKeyPem: keys.privateKeyPem,
      outPath: proofBundlePath,
      now: '2026-01-01T00:04:00.000Z',
    })
    const proofVerify = verifyProofBundle(proofBundlePath)
    assert(proofVerify.ok, 'proof bundle verification failed')
    const independentVerify = verifyBundleIndependent(proofBundlePath)
    assert(independentVerify.ok, 'independent proof bundle verification failed')
    const forgedBundle = JSON.parse(readFileSync(proofBundlePath, 'utf8'))
    const deleteIndex = forgedBundle.ledger.findIndex((entry) => entry.event_type === 'sidecar_job_approved')
    forgedBundle.ledger.splice(deleteIndex, 1)
    const independentCatch = verifyBundleIndependent(forgedBundle)
    assert(!independentCatch.ok && independentCatch.first_failure?.reason === 'prev_hash_mismatch', 'independent verifier did not catch chain deletion')
    transcript.push({ step: 9, proof_bundle: proofBundlePath, package_verify: proofVerify, independent_verify: independentVerify, independent_chain_deletion_catch: independentCatch })
    if (!jsonMode) {
      const independentLine = `INDEPENDENT VERIFIER - valid bundle accepted with ${independentVerify.checks.length} checks.`
      const catchLine = `INDEPENDENT VERIFIER CATCH - forged chain deletion refused (${independentCatch.first_failure.reason}).`
      humanLines.push(independentLine, catchLine)
      console.log(independentLine)
      console.log(catchLine)
    }
    log('9. Exported proof bundle; package and independent verifiers passed; independent verifier caught a chain-deletion forgery.', transcript.at(-1), jsonMode, humanLines)

    if (recordMode) {
      writeFileSync(SAMPLE_TRANSCRIPT_PATH, `${humanLines.join('\n')}\n`, 'utf8')
    }

    const final = { ok: true, temp_root: tempRoot, transcript }
    if (jsonMode) console.log(JSON.stringify(final, null, 2))
    else console.log(JSON.stringify({ ok: true, proof_bundle: proofBundlePath }, null, 2))
  } catch (error) {
    if (jsonMode) console.log(JSON.stringify({ ok: false, error: error.message, transcript }, null, 2))
    else console.error(`demo failed: ${error.message}`)
    process.exitCode = 1
  } finally {
    if (!keep) rmSync(tempRoot, { recursive: true, force: true })
  }
}

main()
