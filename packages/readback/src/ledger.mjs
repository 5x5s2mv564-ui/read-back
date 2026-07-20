import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto'
import { EVENT_SCHEMA_VERSION, EVENT_TYPES, REFUSAL_REASONS } from './config.mjs'

export function canonicalJson(value) {
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

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8')
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

export function sha256File(path) {
  return sha256(readFileSync(path))
}

export function hashObject(value) {
  return sha256(canonicalJson(value))
}

export function withoutKeys(object, keys) {
  const copy = JSON.parse(JSON.stringify(object))
  for (const key of keys) delete copy[key]
  return copy
}

export function contentHashForRecord(record) {
  return hashObject(withoutKeys(record, ['record_hash']))
}

function signingPayload(entry) {
  return withoutKeys(entry, ['signature', 'entry_hash'])
}

function entryHashPayload(entry) {
  return withoutKeys(entry, ['entry_hash'])
}

export function generateEphemeralKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }
}

export function publicKeyFingerprint(publicKeyPem) {
  return sha256(publicKeyPem).slice(0, 24)
}

export function readLedgerEntries(ledgerPath) {
  if (!existsSync(ledgerPath)) return []
  return readFileSync(ledgerPath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line))
}

export function ledgerHead(entriesOrPath) {
  const entries = Array.isArray(entriesOrPath) ? entriesOrPath : readLedgerEntries(entriesOrPath)
  return entries.length ? entries.at(-1).entry_hash : null
}

export function legacySegmentHash(entries = []) {
  return hashObject(entries)
}

export function verifyAnchoredStore({ entries = [], publicKeyPem } = {}) {
  const markerIndex = entries.findIndex((entry) => entry.event_type === 'proposal_store_migrated')
  if (markerIndex < 0) return { ok: false, index: -1, reason: 'store_anchor_missing' }
  const legacyEntries = entries.slice(0, markerIndex)
  const marker = entries[markerIndex]
  const payload = migrationPayload(marker)
  if (payload.legacy_row_count !== legacyEntries.length) {
    return {
      ok: false,
      index: markerIndex,
      reason: 'store_legacy_count_mismatch',
      expected: legacyEntries.length,
      actual: payload.legacy_row_count,
      event_id: marker.event_id || marker.ledger_id || null,
    }
  }
  const legacyHash = legacySegmentHash(legacyEntries)
  if (payload.legacy_store_hash !== legacyHash) {
    return {
      ok: false,
      index: markerIndex,
      reason: 'store_anchor_mismatch',
      expected: legacyHash,
      actual: payload.legacy_store_hash,
      event_id: marker.event_id || marker.ledger_id || null,
    }
  }
  let previous = null
  for (let index = markerIndex; index < entries.length; index += 1) {
    const status = verifySchemaV1Entry(entries[index], { index, previous, publicKeyPem })
    if (!status.ok) return status
    previous = entries[index].entry_hash
  }
  return {
    ok: true,
    entry_count: entries.length,
    legacy_entry_count: legacyEntries.length,
    legacy_store_hash: legacyHash,
    store_head_hash: entries.at(-1)?.entry_hash || null,
    marker_event_id: marker.event_id || null,
  }
}

export function signEvent(entry, privateKeyPem, publicKeyPem) {
  const message = canonicalJson(signingPayload(entry))
  const signature = sign(null, Buffer.from(message), privateKeyPem).toString('base64')
  const signed = {
    ...entry,
    signature: {
      algorithm: 'ed25519',
      public_key_fingerprint: publicKeyFingerprint(publicKeyPem),
      value: signature,
    },
  }
  return {
    ...signed,
    entry_hash: hashObject(entryHashPayload(signed)),
  }
}

function verifyEntrySignature(entry, publicKeyPem) {
  const message = canonicalJson(signingPayload(entry))
  return verify(null, Buffer.from(message), publicKeyPem, Buffer.from(entry.signature?.value || '', 'base64'))
}

function verifySchemaV1Entry(entry, { index, previous, publicKeyPem }) {
  if (entry.schema_version !== EVENT_SCHEMA_VERSION) {
    return { ok: false, index, reason: 'unknown_schema_version', event_id: entry.event_id || null }
  }
  if (!EVENT_TYPES.includes(entry.event_type)) {
    return { ok: false, index, reason: 'unknown_event_type', event_id: entry.event_id || null }
  }
  if (entry.prev_hash !== previous) {
    return {
      ok: false,
      index,
      reason: 'prev_hash_mismatch',
      expected: previous,
      actual: entry.prev_hash,
      event_id: entry.event_id || null,
    }
  }
  const expectedEntryHash = hashObject(entryHashPayload(entry))
  if (entry.entry_hash !== expectedEntryHash) {
    return {
      ok: false,
      index,
      reason: 'entry_hash_mismatch',
      expected: expectedEntryHash,
      actual: entry.entry_hash,
      event_id: entry.event_id || null,
    }
  }
  if (entry.signature?.public_key_fingerprint && entry.signature.public_key_fingerprint !== publicKeyFingerprint(publicKeyPem)) {
    return { ok: false, index, reason: 'public_key_fingerprint_mismatch', event_id: entry.event_id || null }
  }
  if (!verifyEntrySignature(entry, publicKeyPem)) {
    return { ok: false, index, reason: 'bad_signature', event_id: entry.event_id || null }
  }
  return { ok: true }
}

function verifyLegacyEntry(entry, { index, publicKeyPem }) {
  if (!entry.signature?.value) return { ok: false, index, reason: 'legacy_signature_missing', event_id: entry.event_id || null }
  if (entry.signature?.public_key_fingerprint && entry.signature.public_key_fingerprint !== publicKeyFingerprint(publicKeyPem)) {
    return { ok: false, index, reason: 'legacy_public_key_fingerprint_mismatch', event_id: entry.event_id || null }
  }
  if (!verifyEntrySignature(entry, publicKeyPem)) return { ok: false, index, reason: 'legacy_bad_signature', event_id: entry.event_id || null }
  return { ok: true }
}

function migrationPayload(entry) {
  return entry.payload || entry
}

export function appendEvent({
  ledgerPath,
  eventType,
  payload = {},
  privateKeyPem,
  publicKeyPem,
  now = new Date().toISOString(),
}) {
  if (!EVENT_TYPES.includes(eventType)) throw new Error(`unknown event type: ${eventType}`)
  const entries = readLedgerEntries(ledgerPath)
  const entry = signEvent({
    schema_version: EVENT_SCHEMA_VERSION,
    event_id: `evt_${eventType}_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`,
    event_type: eventType,
    timestamp: now,
    prev_hash: ledgerHead(entries),
    payload,
  }, privateKeyPem, publicKeyPem)
  mkdirSync(dirname(ledgerPath), { recursive: true })
  appendFileSync(ledgerPath, `${canonicalJson(entry)}\n`, 'utf8')
  return entry
}

export function verifyLedger({
  ledgerPath = '',
  entries = null,
  publicKeyPem,
  headSnapshot = null,
  requireSignedHeadSnapshot = false,
} = {}) {
  const ledgerEntries = entries || readLedgerEntries(ledgerPath)
  const snapshotSignatureStatus = verifyHeadSnapshotSignature(headSnapshot, publicKeyPem, {
    required: requireSignedHeadSnapshot,
  })
  if (!snapshotSignatureStatus.ok) return snapshotSignatureStatus
  const migrationIndex = ledgerEntries.findIndex((entry) => entry.event_type === 'ledger_schema_migrated')
  if (migrationIndex > 0) {
    const legacyEntries = ledgerEntries.slice(0, migrationIndex)
    const migration = ledgerEntries[migrationIndex]
    const payload = migrationPayload(migration)
    if (payload.legacy_entry_count !== legacyEntries.length) {
      return {
        ok: false,
        index: migrationIndex,
        reason: 'legacy_entry_count_mismatch',
        expected: legacyEntries.length,
        actual: payload.legacy_entry_count,
        event_id: migration.event_id || null,
      }
    }
    const legacyHash = legacySegmentHash(legacyEntries)
    if (payload.legacy_head_hash !== legacyHash) {
      return {
        ok: false,
        index: migrationIndex,
        reason: 'legacy_anchor_mismatch',
        expected: legacyHash,
        actual: payload.legacy_head_hash,
        event_id: migration.event_id || null,
      }
    }
    for (let index = 0; index < legacyEntries.length; index += 1) {
      const signatureStatus = verifyLegacyEntry(legacyEntries[index], { index, publicKeyPem })
      if (!signatureStatus.ok) return signatureStatus
    }
    let previous = null
    for (let index = migrationIndex; index < ledgerEntries.length; index += 1) {
      const entry = ledgerEntries[index]
      const status = verifySchemaV1Entry(entry, { index, previous, publicKeyPem })
      if (!status.ok) return status
      previous = entry.entry_hash
    }
    const headHash = ledgerHead(ledgerEntries.slice(migrationIndex))
    if (headSnapshot) {
      if (headSnapshot.ledger_head_hash !== headHash) {
        return { ok: false, index: ledgerEntries.length - 1, reason: 'head_snapshot_mismatch', expected: headSnapshot.ledger_head_hash, actual: headHash }
      }
      if (headSnapshot.entry_count !== ledgerEntries.length) {
        return { ok: false, index: ledgerEntries.length - 1, reason: 'entry_count_mismatch', expected: headSnapshot.entry_count, actual: ledgerEntries.length }
      }
      if (headSnapshot.legacy_entry_count !== undefined && headSnapshot.legacy_entry_count !== legacyEntries.length) {
        return { ok: false, index: ledgerEntries.length - 1, reason: 'legacy_count_mismatch', expected: headSnapshot.legacy_entry_count, actual: legacyEntries.length }
      }
      if (headSnapshot.chained_entry_count !== undefined && headSnapshot.chained_entry_count !== ledgerEntries.length - migrationIndex) {
        return { ok: false, index: ledgerEntries.length - 1, reason: 'chained_count_mismatch', expected: headSnapshot.chained_entry_count, actual: ledgerEntries.length - migrationIndex }
      }
      if (headSnapshot.signed_entry_count !== undefined && headSnapshot.signed_entry_count !== ledgerEntries.length) {
        return { ok: false, index: ledgerEntries.length - 1, reason: 'signed_count_mismatch', expected: headSnapshot.signed_entry_count, actual: ledgerEntries.length }
      }
    }
    return {
      ok: true,
      entry_count: ledgerEntries.length,
      ledger_head_hash: headHash,
      legacy_entry_count: legacyEntries.length,
      legacy_head_hash: legacyHash,
      migration_event_id: migration.event_id,
    }
  }
  let previous = null
  for (let index = 0; index < ledgerEntries.length; index += 1) {
    const entry = ledgerEntries[index]
    const status = verifySchemaV1Entry(entry, { index, previous, publicKeyPem })
    if (!status.ok) return status
    previous = entry.entry_hash
  }
  const headHash = ledgerHead(ledgerEntries)
  if (headSnapshot) {
    if (headSnapshot.ledger_head_hash !== headHash) {
      return { ok: false, index: ledgerEntries.length - 1, reason: 'head_snapshot_mismatch', expected: headSnapshot.ledger_head_hash, actual: headHash }
    }
    if (headSnapshot.entry_count !== ledgerEntries.length) {
      return { ok: false, index: ledgerEntries.length - 1, reason: 'entry_count_mismatch', expected: headSnapshot.entry_count, actual: ledgerEntries.length }
    }
    if (headSnapshot.legacy_entry_count !== undefined && headSnapshot.legacy_entry_count !== 0) {
      return { ok: false, index: ledgerEntries.length - 1, reason: 'legacy_count_mismatch', expected: headSnapshot.legacy_entry_count, actual: 0 }
    }
    if (headSnapshot.chained_entry_count !== undefined && headSnapshot.chained_entry_count !== ledgerEntries.length) {
      return { ok: false, index: ledgerEntries.length - 1, reason: 'chained_count_mismatch', expected: headSnapshot.chained_entry_count, actual: ledgerEntries.length }
    }
    if (headSnapshot.signed_entry_count !== undefined && headSnapshot.signed_entry_count !== ledgerEntries.length) {
      return { ok: false, index: ledgerEntries.length - 1, reason: 'signed_count_mismatch', expected: headSnapshot.signed_entry_count, actual: ledgerEntries.length }
    }
  }
  return { ok: true, entry_count: ledgerEntries.length, ledger_head_hash: headHash }
}

export function createHeadSnapshot({ entries, publicKeyPem, privateKeyPem = null, now = new Date().toISOString() }) {
  const migrationIndex = entries.findIndex((entry) => entry.event_type === 'ledger_schema_migrated')
  const legacyEntryCount = migrationIndex > 0 ? migrationIndex : 0
  const chainedEntryCount = migrationIndex >= 0 ? entries.length - migrationIndex : entries.length
  const snapshot = {
    schema_version: EVENT_SCHEMA_VERSION,
    event_type: 'ledger_head_snapshot',
    generated_at: now,
    entry_count: entries.length,
    ledger_head_hash: ledgerHead(entries),
    legacy_entry_count: legacyEntryCount,
    chained_entry_count: chainedEntryCount,
    signed_entry_count: entries.length,
    public_key_fingerprint: publicKeyFingerprint(publicKeyPem),
  }
  if (!privateKeyPem) return snapshot
  const message = canonicalJson(snapshot)
  return {
    ...snapshot,
    signature: {
      algorithm: 'ed25519',
      public_key_fingerprint: publicKeyFingerprint(publicKeyPem),
      value: sign(null, Buffer.from(message), privateKeyPem).toString('base64'),
    },
  }
}

export function verifyHeadSnapshotSignature(snapshot, publicKeyPem, { required = false } = {}) {
  if (!snapshot) return required ? { ok: false, reason: 'head_snapshot_missing' } : { ok: true }
  if (!snapshot.signature?.value) {
    return required ? { ok: false, reason: 'head_snapshot_signature_missing' } : { ok: true }
  }
  if (snapshot.signature.algorithm !== 'ed25519') return { ok: false, reason: 'head_snapshot_algorithm_invalid' }
  const expectedFingerprint = publicKeyFingerprint(publicKeyPem)
  if (snapshot.public_key_fingerprint !== expectedFingerprint
    || snapshot.signature.public_key_fingerprint !== expectedFingerprint) {
    return { ok: false, reason: 'head_snapshot_key_mismatch' }
  }
  try {
    const message = canonicalJson(withoutKeys(snapshot, ['signature']))
    const valid = verify(null, Buffer.from(message), publicKeyPem, Buffer.from(snapshot.signature.value, 'base64'))
    return valid ? { ok: true } : { ok: false, reason: 'head_snapshot_bad_signature' }
  } catch {
    return { ok: false, reason: 'head_snapshot_bad_signature' }
  }
}

export function exportProofBundle({
  ledgerPath,
  publicKeyPem,
  privateKeyPem,
  outPath,
  now = new Date().toISOString(),
}) {
  if (!privateKeyPem) throw new Error('proof_bundle_private_key_required')
  const entries = readLedgerEntries(ledgerPath)
  const bundle = {
    bundle_version: 'readback-proof-bundle.v0.1',
    exported_at: now,
    public_key_pem: publicKeyPem,
    ledger: entries,
    head_snapshot: createHeadSnapshot({ entries, publicKeyPem, privateKeyPem, now }),
  }
  writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8')
  return bundle
}

function eventPayload(event = {}) {
  return event.payload || event
}

function parseTime(value) {
  const parsed = Date.parse(String(value || ''))
  return Number.isFinite(parsed) ? parsed : null
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right)
}

function semanticFailure(index, reason, event = null, detail = {}) {
  return { ok: false, index, reason, event_id: event?.event_id || null, ...detail }
}

function verifyReadbackClaims(readbacks = [], events = []) {
  const eventIds = new Set(events.map((event) => event.event_id).filter(Boolean))
  const eventHashes = new Set(events.map((event) => event.entry_hash).filter(Boolean))
  const fakeSuccessRe = /\b(done|sent|approved|executed|scheduled|completed|will run)\b/i
  for (let index = 0; index < readbacks.length; index += 1) {
    const readback = readbacks[index] || {}
    const evidence = Array.isArray(readback.evidence) ? readback.evidence : []
    if (fakeSuccessRe.test(String(readback.answer_text || '')) && evidence.length === 0) {
      return { ok: false, index, reason: 'fake_success_without_evidence' }
    }
    for (const ref of evidence) {
      const id = typeof ref === 'string' ? ref : ref?.event_id
      const hash = typeof ref === 'string' ? '' : ref?.entry_hash
      if ((id && eventIds.has(id)) || (hash && eventHashes.has(hash))) continue
      return { ok: false, index, reason: 'evidence_ref_missing', evidence: ref }
    }
  }
  return { ok: true }
}

export function verifyEventSemantics({ entries = [], readbacks = [] } = {}) {
  const migrationIndex = entries.findIndex((entry) => entry.event_type === 'ledger_schema_migrated')
  const startIndex = migrationIndex > 0 ? migrationIndex : 0
  const proposals = new Map()
  const rejections = new Map()
  const approvals = new Map()
  const consumedApprovals = new Set()

  for (let index = startIndex; index < entries.length; index += 1) {
    const entry = entries[index]
    const payload = eventPayload(entry)
    if (entry.event_type === 'proposal_recorded') {
      const proposal = payload.proposal
      if (!proposal?.proposal_id) return semanticFailure(index, 'absent_proposal', entry)
      if (contentHashForRecord(proposal) !== proposal.record_hash) return semanticFailure(index, 'proposal_tampered', entry)
      proposals.set(proposal.proposal_id, proposal)
    } else if (entry.event_type === 'proposal_rejected') {
      if (!proposals.has(payload.proposal_id)) return semanticFailure(index, 'absent_proposal', entry)
      rejections.set(payload.proposal_id, entry)
    } else if (entry.event_type === 'sidecar_job_approved') {
      const proposal = proposals.get(payload.proposal_id)
      if (!proposal) return semanticFailure(index, 'absent_proposal', entry)
      if (rejections.has(payload.proposal_id)) return semanticFailure(index, 'proposal_rejected', entry)
      if (payload.single_use !== true) return semanticFailure(index, 'single_use_required', entry)
      if (payload.proposal_hash !== proposal.record_hash) return semanticFailure(index, 'proposal_tampered', entry)
      if (payload.spec_hash !== proposal.spec_hash) return semanticFailure(index, 'spec_tampered', entry)
      if (!sameJson(payload.input_hashes || [], proposal.input_hashes || [])) return semanticFailure(index, 'input_drift', entry)
      if (approvals.has(payload.approval_id)) return semanticFailure(index, 'approval_duplicate', entry)
      approvals.set(payload.approval_id, payload)
    } else if (entry.event_type === 'sidecar_job_refused') {
      if (payload.refusal_reason && !REFUSAL_REASONS.includes(payload.refusal_reason)) {
        return semanticFailure(index, 'unknown_refusal_reason', entry)
      }
    } else if (entry.event_type === 'sidecar_job_executed') {
      const approval = approvals.get(payload.approval_id)
      if (!approval) return semanticFailure(index, 'orphan_execution', entry)
      if (rejections.has(payload.proposal_id)) return semanticFailure(index, 'proposal_rejected', entry)
      if (payload.proposal_id !== approval.proposal_id) return semanticFailure(index, 'approval_mismatch', entry)
      if (payload.proposal_hash !== approval.proposal_hash) return semanticFailure(index, 'proposal_tampered', entry)
      if (payload.spec_hash !== approval.spec_hash) return semanticFailure(index, 'spec_tampered', entry)
      if (!sameJson(payload.input_hashes || [], approval.input_hashes || [])) return semanticFailure(index, 'input_drift', entry)
      if (parseTime(approval.expires_at) <= parseTime(entry.timestamp)) return semanticFailure(index, 'expired_at_execution', entry)
      if (consumedApprovals.has(payload.approval_id)) return semanticFailure(index, 'single_use_violated', entry)
      if (payload.approval_consumed !== true) return semanticFailure(index, 'approval_not_consumed', entry)
      if (!String(payload.output_hash || '').startsWith('sha256:')) return semanticFailure(index, 'output_hash_missing', entry)
      consumedApprovals.add(payload.approval_id)
    }
  }

  const readbackStatus = verifyReadbackClaims(readbacks, entries)
  if (!readbackStatus.ok) return readbackStatus
  return { ok: true }
}

export function verifyProofBundle(bundleOrPath) {
  const bundle = typeof bundleOrPath === 'string'
    ? JSON.parse(readFileSync(bundleOrPath, 'utf8'))
    : bundleOrPath
  if (bundle?.bundle_version !== 'readback-proof-bundle.v0.1') return { ok: false, reason: 'invalid_bundle_version' }
  const ledgerStatus = verifyLedger({
    entries: bundle.ledger || [],
    publicKeyPem: bundle.public_key_pem,
    headSnapshot: bundle.head_snapshot,
    requireSignedHeadSnapshot: true,
  })
  if (!ledgerStatus.ok) return ledgerStatus
  if (Array.isArray(bundle.proposal_store) && bundle.proposal_store.length) {
    const storeStatus = verifyAnchoredStore({ entries: bundle.proposal_store, publicKeyPem: bundle.public_key_pem })
    if (!storeStatus.ok) return storeStatus
  }
  const semanticStatus = verifyEventSemantics({ entries: bundle.ledger || [], readbacks: bundle.readbacks || [] })
  if (!semanticStatus.ok) return semanticStatus
  return { ...ledgerStatus, semantic_ok: true }
}
