import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  canonicalJson,
  contentHashForRecord,
  createHeadSnapshot,
  exportProofBundle,
  generateEphemeralKeypair,
  hashObject,
  legacySegmentHash,
  ledgerHead,
  readLedgerEntries,
  signEvent,
  verifyProofBundle,
  withoutKeys,
} from '../src/ledger.mjs'
import { approve } from '../src/approvals.mjs'
import { execute } from '../src/execute.mjs'
import { buildSpec, propose, reject } from '../src/proposals.mjs'
import { verifyBundleIndependent } from '../bin/verify-bundle.mjs'

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'readback-adv-'))
  const keys = generateEphemeralKeypair()
  const fixtures = join(root, 'demo/fixtures')
  const outputDir = join(root, 'runner-output')
  const ledgerPath = join(root, 'ledger.jsonl')
  mkdirSync(fixtures, { recursive: true })
  writeFileSync(join(fixtures, 'quarterly-widgets.json'), `${JSON.stringify({ fixture: 'quarterly-widgets', owner: 'Ada Lovelace', count: 8 }, null, 2)}\n`)
  const spec = buildSpec()
  const specPath = join(fixtures, 'hash-manifest-spec.json')
  writeFileSync(specPath, `${JSON.stringify(spec, null, 2)}\n`)
  return { root, keys, fixtures, outputDir, ledgerPath, spec, specPath }
}

function writeLedger(path, entries) {
  writeFileSync(path, `${entries.map(canonicalJson).join('\n')}\n`, 'utf8')
}

function addLegacyAnchor(ctx) {
  const legacyOne = signEvent({
    event_id: 'legacy_one',
    event_type: 'proposal_recorded',
    timestamp: '2026-01-01T00:00:00.000Z',
    payload: { status: 'legacy_needs_approval' },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  const legacyTwo = signEvent({
    event_id: 'legacy_two',
    event_type: 'sidecar_job_refused',
    timestamp: '2026-01-01T00:00:30.000Z',
    payload: { refusal_reason: 'approval_missing' },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  const migration = signEvent({
    schema_version: 1,
    event_id: 'migration_one',
    event_type: 'ledger_schema_migrated',
    timestamp: '2026-01-01T00:00:59.000Z',
    prev_hash: null,
    payload: {
      schema_version: 1,
      legacy_entry_count: 2,
      legacy_head_hash: legacySegmentHash([legacyOne, legacyTwo]),
      migrated_at: '2026-01-01T00:00:59.000Z',
    },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  writeLedger(ctx.ledgerPath, [legacyOne, legacyTwo, migration])
}

function validBundle() {
  const ctx = setup()
  addLegacyAnchor(ctx)
  const proposed = propose({
    ledgerPath: ctx.ledgerPath,
    ...ctx.keys,
    specPath: ctx.specPath,
    inputPaths: ctx.spec.input_paths,
    baseDir: ctx.root,
    now: '2026-01-01T00:01:00.000Z',
    proposalId: 'proposal_attack_base',
  })
  approve({
    ledgerPath: ctx.ledgerPath,
    ...ctx.keys,
    proposalId: proposed.proposal.proposal_id,
    baseDir: ctx.root,
    now: '2026-01-01T00:02:00.000Z',
  })
  execute({
    ledgerPath: ctx.ledgerPath,
    ...ctx.keys,
    proposalId: proposed.proposal.proposal_id,
    baseDir: ctx.root,
    outputDir: ctx.outputDir,
    now: '2026-01-01T00:03:00.000Z',
  })
  const proofPath = join(ctx.root, 'proof-bundle.json')
  const bundle = exportProofBundle({
    ledgerPath: ctx.ledgerPath,
    publicKeyPem: ctx.keys.publicKeyPem,
    privateKeyPem: ctx.keys.privateKeyPem,
    outPath: proofPath,
    now: '2026-01-01T00:04:00.000Z',
  })
  assert.equal(verifyProofBundle(bundle).ok, true)
  assert.equal(verifyBundleIndependent(bundle).ok, true)
  return { ...ctx, bundle }
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function withSnapshot(bundle, keys) {
  return {
    ...bundle,
    head_snapshot: createHeadSnapshot({
      entries: bundle.ledger,
      publicKeyPem: bundle.public_key_pem,
      privateKeyPem: keys.privateKeyPem,
      now: '2026-01-01T00:10:00.000Z',
    }),
  }
}

function entryHash(entry) {
  return hashObject(withoutKeys(entry, ['entry_hash']))
}

function appendSigned(bundle, keys, eventType, payload, timestamp, eventId) {
  const next = clone(bundle)
  const entry = signEvent({
    schema_version: 1,
    event_id: eventId,
    event_type: eventType,
    timestamp,
    prev_hash: ledgerHead(next.ledger),
    payload,
  }, keys.privateKeyPem, keys.publicKeyPem)
  next.ledger.push(entry)
  return withSnapshot(next, keys)
}

function firstEvent(bundle, eventType) {
  return bundle.ledger.find((entry) => entry.event_type === eventType)
}

function lastEvent(bundle, eventType) {
  return bundle.ledger.filter((entry) => entry.event_type === eventType).at(-1)
}

function reasonOfPackage(result) {
  return result.reason || result.first_failure?.reason || null
}

function reasonOfIndependent(result) {
  return result.first_failure?.reason || result.reason || null
}

function assertBothReject(name, bundle, expectedReason) {
  const packageResult = verifyProofBundle(bundle)
  const independentResult = verifyBundleIndependent(bundle)
  assert.equal(packageResult.ok, false, `${name}: package verifier accepted forged bundle`)
  assert.equal(independentResult.ok, false, `${name}: independent verifier accepted forged bundle`)
  assert.equal(reasonOfPackage(packageResult), expectedReason, `${name}: package reason`)
  assert.equal(reasonOfIndependent(independentResult), expectedReason, `${name}: independent reason`)
}

function tamperSignature(bundle) {
  const forged = clone(bundle)
  const index = forged.ledger.findIndex((entry) => entry.event_type === 'proposal_recorded' && entry.payload?.proposal)
  forged.ledger[index].signature.value = Buffer.from('wrong signature').toString('base64')
  forged.ledger[index].entry_hash = entryHash(forged.ledger[index])
  return forged
}

function wrongKeySubstitution(bundle) {
  const forged = clone(bundle)
  forged.public_key_pem = generateEphemeralKeypair().publicKeyPem
  return forged
}

function mutateExecutedOutputHash(bundle) {
  const forged = clone(bundle)
  const executed = forged.ledger.find((entry) => entry.event_type === 'sidecar_job_executed')
  executed.payload.output_hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
  return forged
}

function deleteMiddleChainedEntry(bundle) {
  const forged = clone(bundle)
  const index = forged.ledger.findIndex((entry) => entry.event_type === 'sidecar_job_approved')
  forged.ledger.splice(index, 1)
  return forged
}

function reorderChainedEntries(bundle) {
  const forged = clone(bundle)
  const index = forged.ledger.findIndex((entry) => entry.event_type === 'proposal_recorded' && entry.payload?.proposal)
  const tmp = forged.ledger[index]
  forged.ledger[index] = forged.ledger[index + 1]
  forged.ledger[index + 1] = tmp
  return forged
}

function tamperLegacy(bundle) {
  const forged = clone(bundle)
  forged.ledger[0].payload.status = 'changed'
  return forged
}

function insertLegacy(bundle, keys) {
  const forged = clone(bundle)
  const inserted = signEvent({
    event_id: 'legacy_inserted',
    event_type: 'proposal_recorded',
    timestamp: '2026-01-01T00:00:45.000Z',
    payload: { status: 'fake_legacy' },
  }, keys.privateKeyPem, keys.publicKeyPem)
  forged.ledger.splice(2, 0, inserted)
  return forged
}

function forgedApprovalAfterReject(ctx) {
  const proposed = ctx.bundle.ledger.find((entry) => entry.event_type === 'proposal_recorded' && entry.payload?.proposal)?.payload.proposal
  let forged = appendSigned(ctx.bundle, ctx.keys, 'proposal_rejected', {
    proposal_id: proposed.proposal_id,
    status: 'rejected',
    rejected_at: '2026-01-01T00:05:00.000Z',
    proposal_hash: proposed.record_hash,
    spec_hash: proposed.spec_hash,
    input_hashes: proposed.input_hashes,
  }, '2026-01-01T00:05:00.000Z', 'evt_reject_before_forged_approval')
  forged = appendSigned(forged, ctx.keys, 'sidecar_job_approved', {
    approval_id: 'approval_forged_after_reject',
    proposal_id: proposed.proposal_id,
    proposal_hash: proposed.record_hash,
    spec_hash: proposed.spec_hash,
    input_hashes: proposed.input_hashes,
    approved_at: '2026-01-01T00:06:00.000Z',
    expires_at: '2026-01-02T00:06:00.000Z',
    single_use: true,
  }, '2026-01-01T00:06:00.000Z', 'evt_forged_approval_after_reject')
  return forged
}

function replayExecution(ctx, timestamp = '2026-01-01T00:04:00.000Z') {
  const executed = lastEvent(ctx.bundle, 'sidecar_job_executed').payload
  return appendSigned(ctx.bundle, ctx.keys, 'sidecar_job_executed', {
    ...executed,
    output_hash: 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
  }, timestamp, `evt_replay_${timestamp}`)
}

function orphanExecution(ctx) {
  const executed = lastEvent(ctx.bundle, 'sidecar_job_executed').payload
  return appendSigned(ctx.bundle, ctx.keys, 'sidecar_job_executed', {
    ...executed,
    approval_id: 'approval_missing_for_orphan',
  }, '2026-01-01T00:04:00.000Z', 'evt_orphan_execution')
}

function schemaDowngrade(bundle) {
  const forged = clone(bundle)
  const index = forged.ledger.findIndex((entry) => entry.event_type === 'proposal_recorded' && entry.payload?.proposal)
  forged.ledger[index].schema_version = 0
  return forged
}

function fakeSuccessText(bundle) {
  const forged = clone(bundle)
  forged.readbacks = [{
    claim: 'fake_execution',
    evidence: [],
    answer_text: 'The job executed.',
  }]
  return forged
}

function truncateLedgerTail(bundle) {
  const forged = clone(bundle)
  forged.ledger.pop()
  return forged
}

test('adversarial proof suite rejects all forged bundles in both verifiers', () => {
  const ctx = validBundle()
  const attacks = [
    ['signature forgery', tamperSignature(ctx.bundle), 'bad_signature'],
    ['wrong-key substitution', wrongKeySubstitution(ctx.bundle), 'head_snapshot_key_mismatch'],
    ['field mutation under intact signature', mutateExecutedOutputHash(ctx.bundle), 'entry_hash_mismatch'],
    ['chain deletion', deleteMiddleChainedEntry(ctx.bundle), 'prev_hash_mismatch'],
    ['chain reorder', reorderChainedEntries(ctx.bundle), 'prev_hash_mismatch'],
    ['legacy tamper', tamperLegacy(ctx.bundle), 'legacy_anchor_mismatch'],
    ['legacy insertion', insertLegacy(ctx.bundle, ctx.keys), 'legacy_entry_count_mismatch'],
    ['approval forgery for rejected proposal', forgedApprovalAfterReject(ctx), 'proposal_rejected'],
    ['replay forgery', replayExecution(ctx), 'single_use_violated'],
    ['orphan execution', orphanExecution(ctx), 'orphan_execution'],
    ['expiry bypass', replayExecution(ctx, '2026-01-03T00:04:00.000Z'), 'expired_at_execution'],
    ['head snapshot lie', { ...clone(ctx.bundle), head_snapshot: { ...ctx.bundle.head_snapshot, entry_count: ctx.bundle.head_snapshot.entry_count + 1 } }, 'head_snapshot_bad_signature'],
    ['ledger tail truncation', truncateLedgerTail(ctx.bundle), 'head_snapshot_mismatch'],
    ['schema downgrade', schemaDowngrade(ctx.bundle), 'unknown_schema_version'],
    ['fake-success text', fakeSuccessText(ctx.bundle), 'fake_success_without_evidence'],
  ]
  const matrix = []
  for (const [name, forged, expected] of attacks) {
    const packageResult = verifyProofBundle(forged)
    const independentResult = verifyBundleIndependent(forged)
    assert.equal(packageResult.ok, false, `${name}: package verifier accepted forged bundle`)
    assert.equal(independentResult.ok, false, `${name}: independent verifier accepted forged bundle`)
    assert.equal(reasonOfPackage(packageResult), expected, `${name}: package reason`)
    assert.equal(reasonOfIndependent(independentResult), expected, `${name}: independent reason`)
    matrix.push({
      attack: name,
      package_verifier: { ok: packageResult.ok, reason: reasonOfPackage(packageResult) },
      independent_verifier: { ok: independentResult.ok, reason: reasonOfIndependent(independentResult) },
      expected_reason: expected,
    })
  }
  console.log(`ADVERSARIAL_MATRIX ${JSON.stringify(matrix)}`)
  rmSync(ctx.root, { recursive: true, force: true })
})
