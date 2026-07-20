import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { approve } from '../src/approvals.mjs'
import { execute, writeOutputAtomic } from '../src/execute.mjs'
import { isGateEnabled } from '../src/gate.mjs'
import {
  appendEvent,
  canonicalJson,
  exportProofBundle,
  generateEphemeralKeypair,
  legacySegmentHash,
  readLedgerEntries,
  signEvent,
  verifyAnchoredStore,
  verifyLedger,
  verifyProofBundle,
} from '../src/ledger.mjs'
import { buildSpec, propose, reject } from '../src/proposals.mjs'
import { enforceFakeSuccessLexicon, interrogate } from '../src/readback.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const packageRoot = join(__dirname, '..')

function tempPackage() {
  const root = mkdtempSync(join(tmpdir(), 'readback-test-'))
  const fixtures = join(root, 'demo/fixtures')
  const output = join(root, 'runner-output')
  const runtime = join(root, 'runtime-inputs')
  const ledger = join(root, 'ledger.jsonl')
  return { root, fixtures, output, runtime, ledger }
}

function setup() {
  const t = tempPackage()
  const keys = generateEphemeralKeypair()
  mkdirSync(t.fixtures, { recursive: true })
  mkdirSync(t.runtime, { recursive: true })
  writeFileSync(join(t.fixtures, 'quarterly-widgets.json'), JSON.stringify({ fixture: 'quarterly-widgets', owner: 'Ada Lovelace', count: 8 }, null, 2))
  const spec = buildSpec()
  writeFileSync(join(t.fixtures, 'hash-manifest-spec.json'), JSON.stringify(spec, null, 2))
  return { ...t, keys, specPath: join(t.fixtures, 'hash-manifest-spec.json'), inputPath: 'demo/fixtures/quarterly-widgets.json' }
}

function makeProposal(t, id = 'proposal_test') {
  return propose({
    ledgerPath: t.ledger,
    ...t.keys,
    specPath: t.specPath,
    inputPaths: [t.inputPath],
    baseDir: t.root,
    proposalId: id,
    now: '2026-01-01T00:00:00.000Z',
  }).proposal
}

function ledgerCount(t) {
  return readLedgerEntries(t.ledger).length
}

function assertGrowth(t, before, expected, label) {
  assert.equal(ledgerCount(t), before + expected, label)
}

test('gate truth table is exact true only', () => {
  for (const value of [undefined, '', ' ', '1', 'yes', 'on', 'TRUE', ' true ', 'junk']) assert.equal(isGateEnabled(value), false)
  assert.equal(isGateEnabled('true'), true)
})

test('ledger verifies, detects mutation, deletion, reorder, and unknown schema', () => {
  const t = setup()
  const p = makeProposal(t)
  const a = approve({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, now: '2026-01-01T00:01:00.000Z' })
  assert.equal(a.ok, true)
  execute({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, outputDir: t.output, now: '2026-01-01T00:02:00.000Z' })
  execute({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, outputDir: t.output, now: '2026-01-01T00:03:00.000Z' })
  const entries = readLedgerEntries(t.ledger)
  const snapshot = { ledger_head_hash: entries.at(-1).entry_hash, entry_count: entries.length }
  assert.equal(verifyLedger({ ledgerPath: t.ledger, publicKeyPem: t.keys.publicKeyPem, headSnapshot: snapshot }).ok, true)
  for (const key of Object.keys(entries[0]).filter((field) => !['signature', 'entry_hash'].includes(field))) {
    const copy = JSON.parse(JSON.stringify(entries))
    copy[0][key] = typeof copy[0][key] === 'object' && copy[0][key] !== null ? { changed: true } : `${copy[0][key]}x`
    assert.equal(verifyLedger({ entries: copy, publicKeyPem: t.keys.publicKeyPem, headSnapshot: snapshot }).ok, false, `mutating signed field should fail: ${key}`)
  }
  const deleted = entries.filter((_, index) => index !== 1)
  assert.equal(verifyLedger({ entries: deleted, publicKeyPem: t.keys.publicKeyPem, headSnapshot: snapshot }).ok, false)
  const reordered = [entries[0], entries[2], entries[1], ...entries.slice(3)]
  assert.equal(verifyLedger({ entries: reordered, publicKeyPem: t.keys.publicKeyPem, headSnapshot: snapshot }).ok, false)
  const unknown = JSON.parse(JSON.stringify(entries))
  unknown[0].schema_version = 999
  assert.equal(verifyLedger({ entries: unknown, publicKeyPem: t.keys.publicKeyPem }).reason, 'unknown_schema_version')
  rmSync(t.root, { recursive: true, force: true })
})

test('ledger verifies legacy segment migration anchors and post-migration chain', (t) => {
  const ctx = setup()
  const legacyOne = signEvent({
    event_id: 'legacy_one',
    event_type: 'proposal_recorded',
    timestamp: '2026-01-01T00:00:00.000Z',
    payload: { status: 'needs_approval' },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  const legacyTwo = signEvent({
    event_id: 'legacy_two',
    event_type: 'sidecar_job_approved',
    timestamp: '2026-01-01T00:01:00.000Z',
    payload: { status: 'approved' },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  const migration = signEvent({
    schema_version: 1,
    event_id: 'migration_one',
    event_type: 'ledger_schema_migrated',
    timestamp: '2026-01-01T00:02:00.000Z',
    prev_hash: null,
    payload: {
      schema_version: 1,
      legacy_entry_count: 2,
      legacy_head_hash: legacySegmentHash([legacyOne, legacyTwo]),
      migrated_at: '2026-01-01T00:02:00.000Z',
    },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  writeFileSync(ctx.ledger, `${canonicalJson(legacyOne)}\n${canonicalJson(legacyTwo)}\n${canonicalJson(migration)}\n`, 'utf8')
  appendEvent({
    ledgerPath: ctx.ledger,
    eventType: 'sidecar_job_refused',
    privateKeyPem: ctx.keys.privateKeyPem,
    publicKeyPem: ctx.keys.publicKeyPem,
    now: '2026-01-01T00:03:00.000Z',
    payload: { proposal_id: 'proposal_legacy', refusal_reason: 'approval_missing' },
  })
  const clean = verifyLedger({ ledgerPath: ctx.ledger, publicKeyPem: ctx.keys.publicKeyPem })
  assert.equal(clean.ok, true)
  assert.equal(clean.legacy_entry_count, 2)

  const tamperedLegacy = readLedgerEntries(ctx.ledger)
  tamperedLegacy[0].payload.status = 'tampered'
  const legacyTamper = verifyLedger({ entries: tamperedLegacy, publicKeyPem: ctx.keys.publicKeyPem })
  assert.equal(legacyTamper.ok, false)
  assert.equal(legacyTamper.reason, 'legacy_anchor_mismatch')

  const tamperedPostMigration = readLedgerEntries(ctx.ledger)
  tamperedPostMigration[3].payload.refusal_reason = 'approval_expired'
  const postTamper = verifyLedger({ entries: tamperedPostMigration, publicKeyPem: ctx.keys.publicKeyPem })
  assert.equal(postTamper.ok, false)
  assert.equal(postTamper.reason, 'entry_hash_mismatch')
  rmSync(ctx.root, { recursive: true, force: true })
})

test('store anchor verifies legacy rows and chained post-anchor records', () => {
  const ctx = setup()
  const legacyOne = {
    proposal_id: 'proposal_legacy_one',
    status: 'needs_approval',
    content_hash: 'sha256:legacy-one',
  }
  const legacyTwo = {
    proposal_id: 'proposal_legacy_one',
    status: 'rejected',
    content_hash: 'sha256:legacy-two',
  }
  const marker = signEvent({
    schema_version: 1,
    event_id: 'store_migration_one',
    event_type: 'proposal_store_migrated',
    timestamp: '2026-01-01T00:02:00.000Z',
    prev_hash: null,
    payload: {
      schema_version: 1,
      legacy_row_count: 2,
      legacy_store_hash: legacySegmentHash([legacyOne, legacyTwo]),
      migrated_at: '2026-01-01T00:02:00.000Z',
    },
  }, ctx.keys.privateKeyPem, ctx.keys.publicKeyPem)
  writeFileSync(ctx.ledger, `${canonicalJson(legacyOne)}\n${canonicalJson(legacyTwo)}\n${canonicalJson(marker)}\n`, 'utf8')
  appendEvent({
    ledgerPath: ctx.ledger,
    eventType: 'proposal_recorded',
    privateKeyPem: ctx.keys.privateKeyPem,
    publicKeyPem: ctx.keys.publicKeyPem,
    now: '2026-01-01T00:03:00.000Z',
    payload: {
      proposal_id: 'proposal_after_anchor',
      proposal: { proposal_id: 'proposal_after_anchor', status: 'needs_approval', record_hash: 'sha256:after-anchor' },
    },
  })

  const clean = verifyAnchoredStore({ entries: readLedgerEntries(ctx.ledger), publicKeyPem: ctx.keys.publicKeyPem })
  assert.equal(clean.ok, true)
  assert.equal(clean.legacy_entry_count, 2)

  const legacyTamper = readLedgerEntries(ctx.ledger)
  legacyTamper[0].status = 'tampered'
  assert.equal(verifyAnchoredStore({ entries: legacyTamper, publicKeyPem: ctx.keys.publicKeyPem }).reason, 'store_anchor_mismatch')

  const postTamper = readLedgerEntries(ctx.ledger)
  postTamper[3].payload.proposal.status = 'tampered'
  assert.equal(verifyAnchoredStore({ entries: postTamper, publicKeyPem: ctx.keys.publicKeyPem }).reason, 'entry_hash_mismatch')
  rmSync(ctx.root, { recursive: true, force: true })
})

test('proposal, reject, approval, drift, expiry, and replay contracts hold', () => {
  const t = setup()
  let before = ledgerCount(t)
  const p = makeProposal(t)
  assertGrowth(t, before, 1, 'proposal should append one event')
  assert.equal(p.status, 'needs_approval')
  assert.equal(p.spec_hash.startsWith('sha256:'), true)
  assert.equal(p.input_hashes[0].sha256.startsWith('sha256:'), true)
  before = ledgerCount(t)
  const rejected = reject({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, now: '2026-01-01T00:01:00.000Z' })
  assert.equal(rejected.ok, true)
  assertGrowth(t, before, 1, 'reject should append one tombstone event')
  assert.equal(approve({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root }).refusal_reason, 'proposal_rejected')

  const t2 = setup()
  before = ledgerCount(t2)
  const p2 = makeProposal(t2, 'proposal_approve_execute')
  assertGrowth(t2, before, 1, 'proposal should append one event')
  before = ledgerCount(t2)
  const approved = approve({ ledgerPath: t2.ledger, ...t2.keys, proposalId: p2.proposal_id, baseDir: t2.root, now: '2026-01-01T00:01:00.000Z' })
  assert.equal(approved.ok, true)
  assert.equal(approved.approval.single_use, true)
  assertGrowth(t2, before, 1, 'approval should append one event')
  assert.equal(approve({ ledgerPath: t2.ledger, ...t2.keys, proposalId: p2.proposal_id, baseDir: t2.root, now: '2026-01-01T00:01:30.000Z' }).reason, 'already_approved')
  before = ledgerCount(t2)
  const executed = execute({ ledgerPath: t2.ledger, ...t2.keys, proposalId: p2.proposal_id, baseDir: t2.root, outputDir: t2.output, now: '2026-01-01T00:02:00.000Z' })
  assert.equal(executed.ok, true)
  assertGrowth(t2, before, 1, 'execute should append one event')
  before = ledgerCount(t2)
  assert.equal(execute({ ledgerPath: t2.ledger, ...t2.keys, proposalId: p2.proposal_id, baseDir: t2.root, outputDir: t2.output, now: '2026-01-01T00:03:00.000Z' }).refusal_reason, 'approval_consumed')
  assertGrowth(t2, before, 1, 'replay refusal should append one event')

  const t3 = setup()
  const p3 = makeProposal(t3, 'proposal_expired')
  approve({ ledgerPath: t3.ledger, ...t3.keys, proposalId: p3.proposal_id, baseDir: t3.root, now: '2026-01-01T00:00:00.000Z' })
  assert.equal(execute({ ledgerPath: t3.ledger, ...t3.keys, proposalId: p3.proposal_id, baseDir: t3.root, outputDir: t3.output, now: '2026-01-03T00:00:00.000Z' }).refusal_reason, 'approval_expired')

  const t4 = setup()
  const p4 = makeProposal(t4, 'proposal_drift')
  writeFileSync(join(t4.fixtures, 'quarterly-widgets.json'), JSON.stringify({ changed: true }))
  assert.equal(approve({ ledgerPath: t4.ledger, ...t4.keys, proposalId: p4.proposal_id, baseDir: t4.root }).refusal_reason, 'input_drift')

  for (const x of [t, t2, t3, t4]) rmSync(x.root, { recursive: true, force: true })
})

test('execute refusal ladder exposes every distinct refusal reason', () => {
  const unapproved = setup()
  const p0 = makeProposal(unapproved, 'proposal_unapproved')
  assert.equal(execute({ ledgerPath: unapproved.ledger, ...unapproved.keys, proposalId: p0.proposal_id, baseDir: unapproved.root, outputDir: unapproved.output }).refusal_reason, 'approval_missing')

  const rejected = setup()
  const p1 = makeProposal(rejected, 'proposal_rejected_after_approval')
  approve({ ledgerPath: rejected.ledger, ...rejected.keys, proposalId: p1.proposal_id, baseDir: rejected.root })
  reject({ ledgerPath: rejected.ledger, ...rejected.keys, proposalId: p1.proposal_id })
  assert.equal(execute({ ledgerPath: rejected.ledger, ...rejected.keys, proposalId: p1.proposal_id, baseDir: rejected.root, outputDir: rejected.output }).refusal_reason, 'proposal_rejected')

  const expired = setup()
  const p2 = makeProposal(expired, 'proposal_expired_rung')
  approve({ ledgerPath: expired.ledger, ...expired.keys, proposalId: p2.proposal_id, baseDir: expired.root, now: '2026-01-01T00:00:00.000Z' })
  assert.equal(execute({ ledgerPath: expired.ledger, ...expired.keys, proposalId: p2.proposal_id, baseDir: expired.root, outputDir: expired.output, now: '2026-01-03T00:00:00.000Z' }).refusal_reason, 'approval_expired')

  const consumed = setup()
  const p3 = makeProposal(consumed, 'proposal_consumed_rung')
  approve({ ledgerPath: consumed.ledger, ...consumed.keys, proposalId: p3.proposal_id, baseDir: consumed.root, now: '2026-01-01T00:00:00.000Z' })
  execute({ ledgerPath: consumed.ledger, ...consumed.keys, proposalId: p3.proposal_id, baseDir: consumed.root, outputDir: consumed.output, now: '2026-01-01T00:01:00.000Z' })
  assert.equal(execute({ ledgerPath: consumed.ledger, ...consumed.keys, proposalId: p3.proposal_id, baseDir: consumed.root, outputDir: consumed.output, now: '2026-01-01T00:02:00.000Z' }).refusal_reason, 'approval_consumed')

  const proposalTampered = setup()
  const p4 = makeProposal(proposalTampered, 'proposal_tampered_rung')
  approve({ ledgerPath: proposalTampered.ledger, ...proposalTampered.keys, proposalId: p4.proposal_id, baseDir: proposalTampered.root })
  const tamperedEntries = readLedgerEntries(proposalTampered.ledger)
  tamperedEntries[0].payload.proposal.job_type = 'tampered'
  writeFileSync(proposalTampered.ledger, tamperedEntries.map(canonicalJson).join('\n') + '\n')
  assert.equal(execute({ ledgerPath: proposalTampered.ledger, ...proposalTampered.keys, proposalId: p4.proposal_id, baseDir: proposalTampered.root, outputDir: proposalTampered.output }).refusal_reason, 'proposal_tampered')

  const specTampered = setup()
  const p5 = makeProposal(specTampered, 'proposal_spec_tampered_rung')
  approve({ ledgerPath: specTampered.ledger, ...specTampered.keys, proposalId: p5.proposal_id, baseDir: specTampered.root })
  const changedSpec = buildSpec()
  changedSpec.output_filename = 'changed.json'
  writeFileSync(specTampered.specPath, JSON.stringify(changedSpec, null, 2))
  assert.equal(execute({ ledgerPath: specTampered.ledger, ...specTampered.keys, proposalId: p5.proposal_id, baseDir: specTampered.root, outputDir: specTampered.output }).refusal_reason, 'spec_tampered')

  const inputDrift = setup()
  const p6 = makeProposal(inputDrift, 'proposal_input_drift_rung')
  approve({ ledgerPath: inputDrift.ledger, ...inputDrift.keys, proposalId: p6.proposal_id, baseDir: inputDrift.root })
  writeFileSync(join(inputDrift.fixtures, 'quarterly-widgets.json'), JSON.stringify({ changed: true }))
  assert.equal(execute({ ledgerPath: inputDrift.ledger, ...inputDrift.keys, proposalId: p6.proposal_id, baseDir: inputDrift.root, outputDir: inputDrift.output }).refusal_reason, 'input_drift')

  for (const x of [unapproved, rejected, expired, consumed, proposalTampered, specTampered, inputDrift]) rmSync(x.root, { recursive: true, force: true })
})

test('execution refusal ladder uses tamper before expiry when multiple failures exist', () => {
  const t = setup()
  const p = makeProposal(t)
  approve({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, now: '2026-01-01T00:00:00.000Z' })
  const entries = readLedgerEntries(t.ledger)
  entries[0].payload.proposal.spec_hash = 'sha256:tampered'
  writeFileSync(t.ledger, entries.map(canonicalJson).join('\n') + '\n')
  const refused = execute({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, outputDir: t.output, now: '2026-01-03T00:00:00.000Z' })
  assert.equal(refused.refusal_reason, 'proposal_tampered')
  rmSync(t.root, { recursive: true, force: true })
})

test('output API refuses path traversal and symlink escape', () => {
  const t = setup()
  assert.throws(() => writeOutputAtomic({ outputDir: t.output, fileName: '../escape.json', content: '{}' }), /output_path_refused/)
  mkdirSync(t.output, { recursive: true })
  symlinkSync(join(t.root, 'outside.json'), join(t.output, 'linked.json'))
  assert.equal(lstatSync(join(t.output, 'linked.json')).isSymbolicLink(), true)
  assert.throws(() => writeOutputAtomic({ outputDir: t.output, fileName: 'linked.json', content: '{}' }), /output_path_refused/)
  assert.equal(existsSync(join(t.root, 'outside.json')), false)
  const written = writeOutputAtomic({ outputDir: t.output, fileName: 'inside.json', content: '{}' })
  assert.equal(written.startsWith(realpathSync(t.output)), true)
  assert.equal(existsSync(written), true)
  rmSync(t.root, { recursive: true, force: true })
})

test('job modules have no fs write, network, or process calls', () => {
  for (const rel of ['src/jobs/hash-manifest.mjs', 'src/jobs/noop.mjs']) {
    const source = readFileSync(join(packageRoot, rel), 'utf8')
    assert.equal(/\b(writeFile|appendFile|rename|rmSync|mkdir|node:fs)\b/.test(source), false, `${rel} must not write files`)
    assert.equal(/\b(fetch|node:http|node:https|node:net|child_process)\b/.test(source), false, `${rel} must not call network or process APIs`)
  }
})

test('timeout produces no finalized output', () => {
  const t = setup()
  const spec = buildSpec()
  spec.parameters.test_delay_ms = 50_000
  writeFileSync(t.specPath, JSON.stringify(spec, null, 2))
  const p = makeProposal(t)
  approve({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root })
  const result = execute({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, outputDir: t.output, timeoutMs: 10 })
  assert.equal(result.refusal_reason, 'timeout')
  assert.equal(existsSync(join(t.output, 'manifest.json')), false)
  rmSync(t.root, { recursive: true, force: true })
})

test('readback and proof bundle are evidence-bound', () => {
  const t = setup()
  const p = makeProposal(t)
  approve({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, now: '2026-01-01T00:01:00.000Z' })
  execute({ ledgerPath: t.ledger, ...t.keys, proposalId: p.proposal_id, baseDir: t.root, outputDir: t.output, now: '2026-01-01T00:02:00.000Z' })
  const positive = interrogate('manifest_job_ran', { ledgerPath: t.ledger })
  assert.equal(positive.evidence.length, 1)
  assert.equal(readLedgerEntries(t.ledger).some((entry) => entry.event_id === positive.evidence[0].event_id), true)
  const negative = interrogate('email_sent', { ledgerPath: t.ledger })
  assert.equal(negative.evidence.length, 0)
  for (const word of ['done', 'sent', 'approved', 'executed', 'scheduled', 'will run', 'completed']) {
    assert.throws(() => enforceFakeSuccessLexicon(`The task is ${word}.`, []), /fake_success/)
  }
  const bundle = join(t.root, 'proof-bundle.json')
  exportProofBundle({
    ledgerPath: t.ledger,
    publicKeyPem: t.keys.publicKeyPem,
    privateKeyPem: t.keys.privateKeyPem,
    outPath: bundle,
  })
  assert.equal(verifyProofBundle(bundle).ok, true)
  const parsed = JSON.parse(readFileSync(bundle, 'utf8'))
  parsed.ledger[0].payload.proposal.job_type = 'changed'
  assert.equal(verifyProofBundle(parsed).ok, false)
  rmSync(t.root, { recursive: true, force: true })
})
