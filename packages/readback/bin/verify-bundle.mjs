#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { createHash, verify as cryptoVerify } from 'node:crypto'

const EVENT_SCHEMA_VERSION = 1
const EVENT_TYPES = Object.freeze([
  'proposal_recorded',
  'proposal_rejected',
  'sidecar_job_approved',
  'sidecar_job_refused',
  'sidecar_job_executed',
  'ledger_schema_migrated',
  'proposal_store_migrated',
  'ledger_head_snapshot',
])
const REFUSAL_REASONS = Object.freeze([
  'approval_expired',
  'approval_consumed',
  'proposal_tampered',
  'spec_tampered',
  'input_drift',
  'proposal_rejected',
  'approval_missing',
  'unapproved',
  'timeout',
  'output_path_refused',
  'job_failed',
  'single_use_violated',
  'orphan_execution',
  'expired_at_execution',
  'absent_proposal',
  'fake_success_without_evidence',
])

function canonicalJson(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite number rejected')
    return JSON.stringify(value)
  }
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((key) => value[key] !== undefined).sort()
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
  }
  throw new Error(`unsupported canonical type: ${typeof value}`)
}

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function hashObject(value) {
  return sha256(canonicalJson(value))
}

function withoutKeys(object, keys) {
  const copy = JSON.parse(JSON.stringify(object))
  for (const key of keys) delete copy[key]
  return copy
}

function publicKeyFingerprint(publicKeyPem) {
  return sha256(publicKeyPem).slice(0, 24)
}

function entryHash(entry) {
  return hashObject(withoutKeys(entry, ['entry_hash']))
}

function signingPayload(entry) {
  return withoutKeys(entry, ['signature', 'entry_hash'])
}

function verifySignature(entry, publicKeyPem) {
  const message = canonicalJson(signingPayload(entry))
  return cryptoVerify(null, Buffer.from(message), publicKeyPem, Buffer.from(entry.signature?.value || '', 'base64'))
}

function eventPayload(event = {}) {
  return event.payload || event
}

function ledgerHead(entries = []) {
  return entries.length ? entries.at(-1).entry_hash : null
}

function legacySegmentHash(entries = []) {
  return hashObject(entries)
}

function failure(index, reason, event = null, detail = {}) {
  return { ok: false, index, reason, event_id: event?.event_id || event?.ledger_id || null, ...detail }
}

function parseTime(value) {
  const parsed = Date.parse(String(value || ''))
  return Number.isFinite(parsed) ? parsed : null
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right)
}

function contentHashForRecord(record) {
  return hashObject(withoutKeys(record, ['record_hash']))
}

function verifyV1Entry(entry, { index, previous, publicKeyPem }) {
  if (entry.schema_version !== EVENT_SCHEMA_VERSION) return failure(index, 'unknown_schema_version', entry)
  if (!EVENT_TYPES.includes(entry.event_type)) return failure(index, 'unknown_event_type', entry)
  if (entry.prev_hash !== previous) return failure(index, 'prev_hash_mismatch', entry, { expected: previous, actual: entry.prev_hash })
  if (entry.entry_hash !== entryHash(entry)) return failure(index, 'entry_hash_mismatch', entry, { expected: entryHash(entry), actual: entry.entry_hash })
  if (entry.signature?.public_key_fingerprint && entry.signature.public_key_fingerprint !== publicKeyFingerprint(publicKeyPem)) {
    return failure(index, 'public_key_fingerprint_mismatch', entry)
  }
  if (!verifySignature(entry, publicKeyPem)) return failure(index, 'bad_signature', entry)
  return { ok: true }
}

function verifyLegacyEntry(entry, { index, publicKeyPem }) {
  if (!entry.signature?.value) return failure(index, 'legacy_signature_missing', entry)
  if (entry.signature?.public_key_fingerprint && entry.signature.public_key_fingerprint !== publicKeyFingerprint(publicKeyPem)) {
    return failure(index, 'legacy_public_key_fingerprint_mismatch', entry)
  }
  if (!verifySignature(entry, publicKeyPem)) return failure(index, 'legacy_bad_signature', entry)
  return { ok: true }
}

function verifyLedgerEntries(entries = [], { publicKeyPem, headSnapshot = null } = {}) {
  const snapshotSignatureStatus = verifyHeadSnapshotSignature(headSnapshot, publicKeyPem, entries.length)
  if (!snapshotSignatureStatus.ok) return snapshotSignatureStatus
  const migrationIndex = entries.findIndex((entry) => entry.event_type === 'ledger_schema_migrated')
  if (migrationIndex > 0) {
    const legacyEntries = entries.slice(0, migrationIndex)
    const migration = entries[migrationIndex]
    const payload = eventPayload(migration)
    if (payload.legacy_entry_count !== legacyEntries.length) {
      return failure(migrationIndex, 'legacy_entry_count_mismatch', migration, { expected: legacyEntries.length, actual: payload.legacy_entry_count })
    }
    const legacyHash = legacySegmentHash(legacyEntries)
    if (payload.legacy_head_hash !== legacyHash) {
      return failure(migrationIndex, 'legacy_anchor_mismatch', migration, { expected: legacyHash, actual: payload.legacy_head_hash })
    }
    for (let index = 0; index < legacyEntries.length; index += 1) {
      const status = verifyLegacyEntry(legacyEntries[index], { index, publicKeyPem })
      if (!status.ok) return status
    }
    let previous = null
    for (let index = migrationIndex; index < entries.length; index += 1) {
      const status = verifyV1Entry(entries[index], { index, previous, publicKeyPem })
      if (!status.ok) return status
      previous = entries[index].entry_hash
    }
    return verifyHeadSnapshot(entries, headSnapshot, {
      legacyEntryCount: legacyEntries.length,
      chainedEntryCount: entries.length - migrationIndex,
      publicKeyPem,
    })
  }

  let previous = null
  for (let index = 0; index < entries.length; index += 1) {
    const status = verifyV1Entry(entries[index], { index, previous, publicKeyPem })
    if (!status.ok) return status
    previous = entries[index].entry_hash
  }
  return verifyHeadSnapshot(entries, headSnapshot, {
    legacyEntryCount: 0,
    chainedEntryCount: entries.length,
    publicKeyPem,
  })
}

function verifyHeadSnapshot(entries, headSnapshot, { legacyEntryCount, chainedEntryCount, publicKeyPem }) {
  const index = Math.max(entries.length - 1, 0)
  const signatureStatus = verifyHeadSnapshotSignature(headSnapshot, publicKeyPem, entries.length)
  if (!signatureStatus.ok) return signatureStatus
  if (headSnapshot.ledger_head_hash !== ledgerHead(entries)) return failure(index, 'head_snapshot_mismatch', null, { expected: headSnapshot.ledger_head_hash, actual: ledgerHead(entries) })
  if (headSnapshot.entry_count !== entries.length) return failure(index, 'entry_count_mismatch', null, { expected: headSnapshot.entry_count, actual: entries.length })
  if (headSnapshot.legacy_entry_count !== undefined && headSnapshot.legacy_entry_count !== legacyEntryCount) {
    return failure(index, 'legacy_count_mismatch', null, { expected: headSnapshot.legacy_entry_count, actual: legacyEntryCount })
  }
  if (headSnapshot.chained_entry_count !== undefined && headSnapshot.chained_entry_count !== chainedEntryCount) {
    return failure(index, 'chained_count_mismatch', null, { expected: headSnapshot.chained_entry_count, actual: chainedEntryCount })
  }
  if (headSnapshot.signed_entry_count !== undefined && headSnapshot.signed_entry_count !== entries.length) {
    return failure(index, 'signed_count_mismatch', null, { expected: headSnapshot.signed_entry_count, actual: entries.length })
  }
  return { ok: true }
}

function verifyHeadSnapshotSignature(headSnapshot, publicKeyPem, entryCount) {
  const index = Math.max(entryCount - 1, 0)
  if (!headSnapshot) return failure(index, 'head_snapshot_missing')
  if (!headSnapshot.signature?.value) return failure(index, 'head_snapshot_signature_missing')
  if (headSnapshot.signature.algorithm !== 'ed25519') return failure(index, 'head_snapshot_algorithm_invalid')
  const expectedFingerprint = publicKeyFingerprint(publicKeyPem)
  if (headSnapshot.public_key_fingerprint !== expectedFingerprint
    || headSnapshot.signature.public_key_fingerprint !== expectedFingerprint) {
    return failure(index, 'head_snapshot_key_mismatch')
  }
  try {
    const message = canonicalJson(withoutKeys(headSnapshot, ['signature']))
    if (!cryptoVerify(null, Buffer.from(message), publicKeyPem, Buffer.from(headSnapshot.signature.value, 'base64'))) {
      return failure(index, 'head_snapshot_bad_signature')
    }
  } catch {
    return failure(index, 'head_snapshot_bad_signature')
  }
  return { ok: true }
}

function verifyStoreEntries(entries = [], { publicKeyPem }) {
  if (!entries.length) return { ok: true }
  const markerIndex = entries.findIndex((entry) => entry.event_type === 'proposal_store_migrated')
  if (markerIndex < 0) return failure(-1, 'store_anchor_missing')
  const legacyEntries = entries.slice(0, markerIndex)
  const marker = entries[markerIndex]
  const payload = eventPayload(marker)
  if (payload.legacy_row_count !== legacyEntries.length) return failure(markerIndex, 'store_legacy_count_mismatch', marker)
  const legacyHash = legacySegmentHash(legacyEntries)
  if (payload.legacy_store_hash !== legacyHash) return failure(markerIndex, 'store_anchor_mismatch', marker, { expected: legacyHash, actual: payload.legacy_store_hash })
  let previous = null
  for (let index = markerIndex; index < entries.length; index += 1) {
    const status = verifyV1Entry(entries[index], { index, previous, publicKeyPem })
    if (!status.ok) return status
    previous = entries[index].entry_hash
  }
  return { ok: true }
}

function verifySemantics(entries = [], readbacks = []) {
  const migrationIndex = entries.findIndex((entry) => entry.event_type === 'ledger_schema_migrated')
  const startIndex = migrationIndex > 0 ? migrationIndex : 0
  const proposals = new Map()
  const rejections = new Map()
  const approvals = new Map()
  const consumed = new Set()
  for (let index = startIndex; index < entries.length; index += 1) {
    const entry = entries[index]
    const payload = eventPayload(entry)
    if (entry.event_type === 'proposal_recorded') {
      const proposal = payload.proposal
      if (!proposal?.proposal_id) return failure(index, 'absent_proposal', entry)
      if (contentHashForRecord(proposal) !== proposal.record_hash) return failure(index, 'proposal_tampered', entry)
      proposals.set(proposal.proposal_id, proposal)
    } else if (entry.event_type === 'proposal_rejected') {
      if (!proposals.has(payload.proposal_id)) return failure(index, 'absent_proposal', entry)
      rejections.set(payload.proposal_id, entry)
    } else if (entry.event_type === 'sidecar_job_approved') {
      const proposal = proposals.get(payload.proposal_id)
      if (!proposal) return failure(index, 'absent_proposal', entry)
      if (rejections.has(payload.proposal_id)) return failure(index, 'proposal_rejected', entry)
      if (payload.single_use !== true) return failure(index, 'single_use_required', entry)
      if (payload.proposal_hash !== proposal.record_hash) return failure(index, 'proposal_tampered', entry)
      if (payload.spec_hash !== proposal.spec_hash) return failure(index, 'spec_tampered', entry)
      if (!sameJson(payload.input_hashes || [], proposal.input_hashes || [])) return failure(index, 'input_drift', entry)
      approvals.set(payload.approval_id, payload)
    } else if (entry.event_type === 'sidecar_job_refused') {
      if (payload.refusal_reason && !REFUSAL_REASONS.includes(payload.refusal_reason)) return failure(index, 'unknown_refusal_reason', entry)
    } else if (entry.event_type === 'sidecar_job_executed') {
      const approval = approvals.get(payload.approval_id)
      if (!approval) return failure(index, 'orphan_execution', entry)
      if (rejections.has(payload.proposal_id)) return failure(index, 'proposal_rejected', entry)
      if (payload.proposal_id !== approval.proposal_id) return failure(index, 'approval_mismatch', entry)
      if (payload.proposal_hash !== approval.proposal_hash) return failure(index, 'proposal_tampered', entry)
      if (payload.spec_hash !== approval.spec_hash) return failure(index, 'spec_tampered', entry)
      if (!sameJson(payload.input_hashes || [], approval.input_hashes || [])) return failure(index, 'input_drift', entry)
      if (parseTime(approval.expires_at) <= parseTime(entry.timestamp)) return failure(index, 'expired_at_execution', entry)
      if (consumed.has(payload.approval_id)) return failure(index, 'single_use_violated', entry)
      if (payload.approval_consumed !== true) return failure(index, 'approval_not_consumed', entry)
      if (!String(payload.output_hash || '').startsWith('sha256:')) return failure(index, 'output_hash_missing', entry)
      consumed.add(payload.approval_id)
    }
  }
  return verifyReadbacks(readbacks, entries)
}

function verifyReadbacks(readbacks = [], entries = []) {
  const eventIds = new Set(entries.map((entry) => entry.event_id).filter(Boolean))
  const eventHashes = new Set(entries.map((entry) => entry.entry_hash).filter(Boolean))
  const fakeSuccessRe = /\b(done|sent|approved|executed|scheduled|completed|will run)\b/i
  for (let index = 0; index < readbacks.length; index += 1) {
    const readback = readbacks[index] || {}
    const evidence = Array.isArray(readback.evidence) ? readback.evidence : []
    if (fakeSuccessRe.test(String(readback.answer_text || '')) && evidence.length === 0) return failure(index, 'fake_success_without_evidence')
    for (const ref of evidence) {
      const eventId = typeof ref === 'string' ? ref : ref?.event_id
      const entryHash = typeof ref === 'string' ? '' : ref?.entry_hash
      if ((eventId && eventIds.has(eventId)) || (entryHash && eventHashes.has(entryHash))) continue
      return failure(index, 'evidence_ref_missing', null, { evidence: ref })
    }
  }
  return { ok: true }
}

export function verifyBundleIndependent(bundleOrPath, { publicKeyPem = '' } = {}) {
  const bundle = typeof bundleOrPath === 'string'
    ? JSON.parse(readFileSync(bundleOrPath, 'utf8'))
    : bundleOrPath
  const checks = []
  function add(name, status) {
    const pass = Boolean(status.ok)
    checks.push({ name, pass, detail: pass ? 'ok' : status.reason })
    if (!pass) return { ok: false, checks, first_failure: { index: status.index ?? null, reason: status.reason, event_id: status.event_id || null } }
    return null
  }

  if (bundle?.bundle_version !== 'readback-proof-bundle.v0.1') {
    const failed = { ok: false, index: null, reason: 'invalid_bundle_version' }
    return { ok: false, checks: [{ name: 'bundle version', pass: false, detail: failed.reason }], first_failure: failed }
  }
  const key = publicKeyPem || bundle.public_key_pem
  const ledgerStatus = verifyLedgerEntries(bundle.ledger || [], { publicKeyPem: key, headSnapshot: bundle.head_snapshot })
  let early = add('ledger cryptographic structure', ledgerStatus)
  if (early) return early
  const storeStatus = verifyStoreEntries(bundle.proposal_store || [], { publicKeyPem: key })
  early = add('proposal store anchor', storeStatus)
  if (early) return early
  const semanticStatus = verifySemantics(bundle.ledger || [], bundle.readbacks || [])
  early = add('event semantic consistency', semanticStatus)
  if (early) return early
  return { ok: true, checks, first_failure: null }
}

function parseArgs(argv = process.argv.slice(2)) {
  const opts = { json: false, bundle: '', publicKey: '', publicKeyPem: '' }
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index]
    if (item === '--json') opts.json = true
    else if (item === '--bundle' || item === '--proof-bundle') {
      opts.bundle = argv[index + 1] || ''
      index += 1
    } else if (item === '--public-key') {
      opts.publicKey = argv[index + 1] || ''
      index += 1
    } else if (item === '--public-key-pem') {
      opts.publicKeyPem = argv[index + 1] || ''
      index += 1
    } else if (!opts.bundle) {
      opts.bundle = item
    } else {
      throw new Error(`unknown argument: ${item}`)
    }
  }
  return opts
}

function main() {
  try {
    const opts = parseArgs()
    if (!opts.bundle) throw new Error('missing --bundle')
    const publicKeyPem = opts.publicKeyPem || (opts.publicKey ? readFileSync(opts.publicKey, 'utf8') : '')
    const verdict = verifyBundleIndependent(opts.bundle, { publicKeyPem })
    if (opts.json) console.log(JSON.stringify(verdict, null, 2))
    else {
      console.log(verdict.ok ? 'OK: proof bundle verified' : `FAIL: ${verdict.first_failure?.reason || 'unknown'}`)
      console.log(JSON.stringify(verdict, null, 2))
    }
    process.exitCode = verdict.ok ? 0 : 1
  } catch (error) {
    const verdict = { ok: false, checks: [], first_failure: { index: null, reason: error.message } }
    console.log(JSON.stringify(verdict, null, 2))
    process.exitCode = 1
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main()
