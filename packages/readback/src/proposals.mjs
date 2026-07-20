import { existsSync, readFileSync } from 'node:fs'
import { realpathSync } from 'node:fs'
import { relative, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { appendEvent, contentHashForRecord, hashObject, readLedgerEntries, sha256File } from './ledger.mjs'

const ALLOWED_INPUT_ROOTS = Object.freeze([
  'demo/fixtures',
  'runtime-inputs',
])

function cleanId(id = '') {
  return String(id || '').trim()
}

function safeRelative(path) {
  return String(path || '').replace(/\\/g, '/').replace(/^\.\//, '')
}

export function assertInsideRoots(filePath, { baseDir = process.cwd(), roots = ALLOWED_INPUT_ROOTS } = {}) {
  const relativePath = safeRelative(filePath)
  if (!relativePath || relativePath.startsWith('/') || relativePath.includes('\0')) throw new Error(`input path rejected: ${filePath}`)
  const absolute = resolve(baseDir, relativePath)
  if (!existsSync(absolute)) throw new Error(`input path missing: ${filePath}`)
  const realFile = realpathSync(absolute)
  const allowed = roots.some((root) => {
    const rootPath = resolve(baseDir, root)
    if (!existsSync(rootPath)) return false
    const realRoot = realpathSync(rootPath)
    return realFile === realRoot || realFile.startsWith(`${realRoot}/`)
  })
  if (!allowed) throw new Error(`input path outside allowed roots: ${filePath}`)
  return { declared_path: relativePath, absolute_path: absolute, real_path: realFile }
}

export function hashInputs(inputPaths = [], options = {}) {
  return inputPaths.map((inputPath) => {
    const resolved = assertInsideRoots(inputPath, options)
    return {
      declared_path: resolved.declared_path,
      sha256: sha256File(resolved.real_path),
      size_bytes: readFileSync(resolved.real_path).length,
    }
  })
}

export function proposalState({ ledgerPath }) {
  const events = readLedgerEntries(ledgerPath)
  const proposals = new Map()
  const rejections = new Map()
  const approvals = []
  const executions = []
  const refusals = []
  for (const event of events) {
    if (event.event_type === 'proposal_recorded') proposals.set(event.payload.proposal_id, event.payload.proposal)
    if (event.event_type === 'proposal_rejected') rejections.set(event.payload.proposal_id, event.payload)
    if (event.event_type === 'sidecar_job_approved') approvals.push(event.payload)
    if (event.event_type === 'sidecar_job_executed') executions.push(event.payload)
    if (event.event_type === 'sidecar_job_refused') refusals.push(event.payload)
  }
  return { proposals, rejections, approvals, executions, refusals, events }
}

export function getProposal({ ledgerPath, proposalId }) {
  return proposalState({ ledgerPath }).proposals.get(proposalId) || null
}

export function hasRejection({ ledgerPath, proposalId }) {
  return proposalState({ ledgerPath }).rejections.has(proposalId)
}

export function propose({
  ledgerPath,
  privateKeyPem,
  publicKeyPem,
  specPath,
  inputPaths,
  baseDir = process.cwd(),
  now = new Date().toISOString(),
  proposalId = `proposal_${randomUUID()}`,
}) {
  const specDeclared = safeRelative(relative(baseDir, resolve(baseDir, specPath)))
  const specResolved = assertInsideRoots(specDeclared, { baseDir, roots: ['demo/fixtures', 'runtime-inputs'] })
  const specText = readFileSync(specResolved.real_path, 'utf8')
  const parsedSpec = JSON.parse(specText)
  const declaredInputs = inputPaths?.length ? inputPaths : parsedSpec.input_paths || []
  const inputs = hashInputs(declaredInputs, { baseDir })
  const proposal = {
    proposal_id: cleanId(proposalId),
    status: 'needs_approval',
    job_type: parsedSpec.job_type,
    spec_path: specDeclared,
    spec_hash: sha256File(specResolved.real_path),
    input_hashes: inputs,
    created_at: now,
    single_use_required: true,
  }
  proposal.record_hash = contentHashForRecord(proposal)
  const event = appendEvent({
    ledgerPath,
    eventType: 'proposal_recorded',
    privateKeyPem,
    publicKeyPem,
    now,
    payload: { proposal_id: proposal.proposal_id, proposal },
  })
  return { proposal, event }
}

export function reject({
  ledgerPath,
  privateKeyPem,
  publicKeyPem,
  proposalId,
  now = new Date().toISOString(),
}) {
  const state = proposalState({ ledgerPath })
  const proposal = state.proposals.get(proposalId)
  if (!proposal) return { ok: false, status: 'not_found', proposal_id: proposalId }
  const tombstone = {
    proposal_id: proposalId,
    status: 'rejected',
    rejected_at: now,
    proposal_hash: proposal.record_hash,
    spec_hash: proposal.spec_hash,
    input_hashes: proposal.input_hashes,
  }
  const event = appendEvent({
    ledgerPath,
    eventType: 'proposal_rejected',
    privateKeyPem,
    publicKeyPem,
    now,
    payload: tombstone,
  })
  return { ok: true, status: 'rejected', tombstone, event }
}

export function buildSpec({ jobType = 'hash_manifest_v0', jobId = 'job_synthetic_manifest', inputPaths = ['demo/fixtures/quarterly-widgets.json'], output = 'manifest.json', fixedTimestamp = '2026-01-01T00:00:00.000Z' } = {}) {
  const spec = {
    spec_version: 'readback-job-spec.v0.1',
    job_id: jobId,
    job_type: jobType,
    input_paths: inputPaths,
    output_filename: output,
    parameters: {
      fixed_timestamp: fixedTimestamp,
    },
  }
  return {
    ...spec,
    spec_hash: hashObject(spec),
  }
}
