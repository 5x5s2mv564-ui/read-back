import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { basename, resolve } from 'node:path'
import { appendEvent, contentHashForRecord, ledgerHead, readLedgerEntries, sha256, sha256File } from './ledger.mjs'
import { getProposal, hasRejection, hashInputs, proposalState } from './proposals.mjs'
import { runHashManifestJob, HASH_MANIFEST_JOB_TYPE } from './jobs/hash-manifest.mjs'
import { runNoopJob, NOOP_JOB_TYPE } from './jobs/noop.mjs'

export const RUNNER_VERSION = 'readback-runner-v0.1'

function parseTime(value) {
  const parsed = Date.parse(String(value || ''))
  return Number.isFinite(parsed) ? parsed : null
}

function refusalResult(reason, event = null) {
  return { ok: false, status: 'refused', refusal_reason: reason, event }
}

function assertInside(child, parent, label) {
  const c = resolve(child)
  const p = resolve(parent)
  if (c !== p && !c.startsWith(`${p}/`)) throw new Error(`${label} escapes output directory`)
}

export function writeOutputAtomic({ outputDir, fileName, content, maxBytes = 100_000 }) {
  if (String(fileName || '') !== basename(String(fileName || ''))) throw new Error('output_path_refused')
  if (!/^[A-Za-z0-9._-]+$/.test(String(fileName || ''))) throw new Error('output_path_refused')
  mkdirSync(outputDir, { recursive: true })
  const base = realpathSync(outputDir)
  const finalPath = resolve(base, basename(fileName))
  assertInside(finalPath, base, 'output path')
  try {
    if (lstatSync(finalPath).isSymbolicLink()) throw new Error('output_path_refused')
  } catch (error) {
    if (error.message === 'output_path_refused') throw error
    if (error.code !== 'ENOENT') throw error
  }
  const body = String(content)
  if (Buffer.byteLength(body, 'utf8') > maxBytes) throw new Error('output too large')
  const tempPath = resolve(base, `.${basename(fileName)}.${process.pid}.${Date.now()}.tmp`)
  assertInside(tempPath, base, 'temp output path')
  writeFileSync(tempPath, body.endsWith('\n') ? body : `${body}\n`, 'utf8')
  renameSync(tempPath, finalPath)
  return finalPath
}

function latestApproval(state, proposalId) {
  return state.approvals.filter((approval) => approval.proposal_id === proposalId).at(-1) || null
}

function consumed(state, approvalId) {
  return state.executions.some((execution) => execution.approval_id === approvalId && execution.approval_consumed === true)
}

function proposalEvidence(proposal = null) {
  if (!proposal) return {}
  return {
    proposal_hash: proposal.record_hash,
    spec_hash: proposal.spec_hash,
    input_hashes: proposal.input_hashes,
  }
}

function appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal = null, approval, reason, now }) {
  const event = appendEvent({
    ledgerPath,
    eventType: 'sidecar_job_refused',
    privateKeyPem,
    publicKeyPem,
    now,
    payload: {
      proposal_id: proposalId,
      approval_id: approval?.approval_id || null,
      refusal_reason: reason,
      ...proposalEvidence(proposal),
    },
  })
  return event
}

function loadSpec(path) {
  const spec = JSON.parse(readFileSync(path, 'utf8'))
  return spec
}

function jobContent({ spec, inputs, ledgerHeadAtStart }) {
  if (spec.job_type === HASH_MANIFEST_JOB_TYPE) return runHashManifestJob({ spec, inputs, ledgerHeadAtStart, runnerVersion: RUNNER_VERSION })
  if (spec.job_type === NOOP_JOB_TYPE) return runNoopJob({ spec })
  throw new Error('job_failed')
}

export function execute({
  ledgerPath,
  privateKeyPem,
  publicKeyPem,
  proposalId,
  baseDir = process.cwd(),
  outputDir,
  now = new Date().toISOString(),
  timeoutMs = 30_000,
}) {
  const state = proposalState({ ledgerPath })
  const proposal = getProposal({ ledgerPath, proposalId })
  if (!proposal) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, approval: null, reason: 'approval_missing', now })
    return refusalResult('approval_missing', event)
  }
  const approval = latestApproval(state, proposalId)
  if (!approval) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval: null, reason: 'approval_missing', now })
    return refusalResult('approval_missing', event)
  }
  if (hasRejection({ ledgerPath, proposalId })) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'proposal_rejected', now })
    return refusalResult('proposal_rejected', event)
  }
  if (contentHashForRecord(proposal) !== proposal.record_hash || approval.proposal_hash !== proposal.record_hash) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'proposal_tampered', now })
    return refusalResult('proposal_tampered', event)
  }
  const currentSpecHash = sha256File(resolve(baseDir, proposal.spec_path))
  if (currentSpecHash !== proposal.spec_hash || approval.spec_hash !== proposal.spec_hash) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'spec_tampered', now })
    return refusalResult('spec_tampered', event)
  }
  const currentInputs = hashInputs(proposal.input_hashes.map((input) => input.declared_path), { baseDir })
  if (JSON.stringify(currentInputs) !== JSON.stringify(proposal.input_hashes)) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'input_drift', now })
    return refusalResult('input_drift', event)
  }
  if (parseTime(approval.expires_at) <= parseTime(now)) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'approval_expired', now })
    return refusalResult('approval_expired', event)
  }
  if (consumed(state, approval.approval_id)) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'approval_consumed', now })
    return refusalResult('approval_consumed', event)
  }
  const spec = loadSpec(resolve(baseDir, proposal.spec_path))
  const delay = Number(spec.parameters?.test_delay_ms || 0)
  if (delay > timeoutMs) {
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason: 'timeout', now })
    return refusalResult('timeout', event)
  }
  const headAtStart = ledgerHead(readLedgerEntries(ledgerPath))
  let outputPath = null
  try {
    const content = jobContent({ spec, inputs: currentInputs, ledgerHeadAtStart: headAtStart })
    outputPath = writeOutputAtomic({ outputDir, fileName: spec.output_filename, content })
  } catch (error) {
    if (outputPath) rmSync(outputPath, { force: true })
    const reason = error.message === 'output_path_refused' ? 'output_path_refused' : 'job_failed'
    const event = appendRefusal({ ledgerPath, privateKeyPem, publicKeyPem, proposalId, proposal, approval, reason, now })
    return refusalResult(reason, event)
  }
  const outputHash = sha256(readFileSync(outputPath))
  const event = appendEvent({
    ledgerPath,
    eventType: 'sidecar_job_executed',
    privateKeyPem,
    publicKeyPem,
    now,
    payload: {
      proposal_id: proposalId,
      approval_id: approval.approval_id,
      job_type: proposal.job_type,
      proposal_hash: proposal.record_hash,
      spec_hash: proposal.spec_hash,
      input_hashes: proposal.input_hashes,
      output_path: outputPath,
      output_hash: outputHash,
      approval_consumed: true,
      runner_version: RUNNER_VERSION,
    },
  })
  return { ok: true, status: 'executed', output_path: outputPath, output_hash: outputHash, event }
}
