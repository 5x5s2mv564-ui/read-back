import { appendEvent, contentHashForRecord, sha256File } from './ledger.mjs'
import { DEFAULT_APPROVAL_EXPIRY_HOURS } from './config.mjs'
import { getProposal, hasRejection, hashInputs, proposalState } from './proposals.mjs'
import { resolve } from 'node:path'

export function approvalExpiresAt({ now = new Date().toISOString(), hours = DEFAULT_APPROVAL_EXPIRY_HOURS } = {}) {
  return addHours(now, hours)
}

function addHours(iso, hours) {
  return new Date(Date.parse(iso) + hours * 60 * 60 * 1000).toISOString()
}

function refusal(status, details = {}) {
  return { ok: false, status, refusal_reason: status, ...details }
}

export function approve({
  ledgerPath,
  privateKeyPem,
  publicKeyPem,
  proposalId,
  baseDir = process.cwd(),
  now = new Date().toISOString(),
  expiryHours = DEFAULT_APPROVAL_EXPIRY_HOURS,
}) {
  const proposal = getProposal({ ledgerPath, proposalId })
  if (!proposal) return refusal('unapproved', { reason: 'proposal_missing' })
  if (hasRejection({ ledgerPath, proposalId })) return refusal('proposal_rejected')
  const state = proposalState({ ledgerPath })
  if (state.approvals.some((approval) => approval.proposal_id === proposalId)) return refusal('unapproved', { reason: 'already_approved' })
  if (contentHashForRecord(proposal) !== proposal.record_hash) return refusal('proposal_tampered')
  const specHash = sha256File(resolve(baseDir, proposal.spec_path))
  if (specHash !== proposal.spec_hash) return refusal('spec_tampered', { expected: proposal.spec_hash, actual: specHash })
  const currentInputs = hashInputs(proposal.input_hashes.map((input) => input.declared_path), { baseDir })
  if (JSON.stringify(currentInputs) !== JSON.stringify(proposal.input_hashes)) return refusal('input_drift', { expected: proposal.input_hashes, actual: currentInputs })
  const approval = {
    approval_id: `approval_${proposalId}_${Date.now()}`,
    proposal_id: proposalId,
    proposal_hash: proposal.record_hash,
    spec_hash: proposal.spec_hash,
    input_hashes: proposal.input_hashes,
    approved_at: now,
    expires_at: approvalExpiresAt({ now, hours: expiryHours }),
    single_use: true,
  }
  const event = appendEvent({
    ledgerPath,
    eventType: 'sidecar_job_approved',
    privateKeyPem,
    publicKeyPem,
    now,
    payload: approval,
  })
  return { ok: true, status: 'approved', approval, event }
}
