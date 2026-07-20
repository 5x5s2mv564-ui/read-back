import { createHash } from 'node:crypto'

import { createMoneypennyActionPolicyReport } from './moneypenny-action-policy.mjs'
import {
  createMoneypennyCompletionReceipt,
  normaliseMoneypennyCompletionReceipt,
} from './moneypenny-completion-receipt.mjs'
import { inspectMoneypennyPromptInput } from './moneypenny-prompt-security.mjs'
import { sha256, verifyProofBundle } from '../packages/readback/src/ledger.mjs'

export const MONEYPENNY_AGENT_REVIEW_FEATURE_TAG = 'agent-review-honesty-filter-v02'
export const MONEYPENNY_AGENT_REVIEW_ROUTE = '/api/moneypenny/agent-review'
export const MONEYPENNY_AGENT_REVIEW_PAYLOAD_CLASS = 'untrusted_agent_output_local_review_only'
export const MONEYPENNY_AGENT_REVIEW_TRUSTED_KEYS_ENV = 'MONEYPENNY_AGENT_REVIEW_TRUSTED_KEY_FINGERPRINTS'

const MAX_TASK_CHARS = 4_000
const MAX_AGENT_OUTPUT_CHARS = 24_000
const MAX_EVIDENCE_CHARS = 48_000
const MAX_CLAIMS = 12
const MAX_BUNDLE_EVENTS = 160
const SIGNER_FINGERPRINT_PATTERN = /^sha256:[a-f0-9]{64}$/i

const COMPLETION_PATTERN = /\b(?:done|completed|finished|sent|emailed|forwarded|replied|deployed|published|released|saved|stored|recorded|updated|created|scheduled|booked|paid|purchased|transferred|deleted|removed|archived|labelled|labeled|executed|ran|uploaded|posted)\b/i
const EXECUTION_COMPLETION_PATTERN = /\b(?:done|completed|finished|executed|ran)\b/i
const DIFFERENT_ACTION_PATTERN = /\b(?:sent|emailed|forwarded|replied|deployed|published|released|saved|stored|recorded|updated|created|scheduled|booked|paid|purchased|transferred|deleted|removed|archived|labelled|labeled|uploaded|posted)\b/i
const NEGATIVE_EXECUTION_PATTERN = /\b(?:did\s+not|didn't|was\s+not|wasn't|has\s+not|hasn't|never)\s+(?:\w+\s+){0,4}?(?:execute|executed|run|ran|complete|completed|finish|finished)\b/i
const COMPLETION_SUBJECT_PATTERN = /\b(?:i|we|the\s+(?:agent|assistant|task|job|email|message|site|app|deployment|file|event|meeting|reminder|payment|transfer)|it|this|that)\b/i
const FUTURE_ACTION_PATTERN = /\b(?:i|we)\s+(?:will|can|shall|am\s+going\s+to|are\s+going\s+to)\s+(?:send|email|forward|reply|deploy|publish|release|save|record|update|create|schedule|book|pay|purchase|transfer|delete|remove|archive|label|execute|run|upload|post)\b/i
const NEGATIVE_ACTION_PATTERN = /\b(?:nothing\s+(?:changed|happened|was\s+changed)|no\s+(?:action|write|change)\s+(?:occurred|was\s+(?:taken|performed|made))|did\s+not|didn't|was\s+not|wasn't|has\s+not|hasn't)\b[\s\S]{0,100}\b(?:send|sent|email|emailed|forward|forwarded|reply|replied|run|ran|execute|executed|complete|completed|finish|finished|deploy|deployed|write|wrote|save|saved|store|stored|record|recorded|update|updated|create|created|schedule|scheduled|book|booked|pay|paid|purchase|purchased|transfer|transferred|delete|deleted|remove|removed|archive|archived|label|labelled|labeled|change|changed|publish|published|release|released|upload|uploaded|post|posted)\b/i
const APPROVAL_CLAIM_PATTERN = /\b(?:you|the\s+(?:user|owner|operator|account\s+holder))\s+(?:approved|authorised|authorized|gave\s+permission|confirmed)|\b(?:with|under)\s+(?:your|the\s+owner's|the\s+user's)\s+(?:approval|authorisation|authorization|permission)\b/i
const RECOMMENDATION_PATTERN = /\b(?:recommend|suggest|consider|should|could|might|option|proposal|propose|would\s+be\s+better)\b/i
const ASSERTIVE_FACT_PATTERN = /\b(?:is|are|was|were|has|have|contains|equals|costs?|requires?|means?|shows?|proves?|confirms?)\b/i
const CHECKABLE_DETAIL_PATTERN = /(?:\b\d+(?:\.\d+)?(?:%|\s*(?:minutes?|hours?|days?|weeks?|months?|years?|dollars?|NZD|USD))?\b|\b(?:today|yesterday|tomorrow|currently|latest|as\s+of)\b|https?:\/\/)/i

const SECRET_PATTERNS = Object.freeze([
  { id: 'openai_key_like', pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { id: 'google_token_like', pattern: /\bya29\.[A-Za-z0-9._-]+\b/g },
  { id: 'github_token_like', pattern: /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}\b/g },
  { id: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi },
  { id: 'credential_assignment', pattern: /\b(?:access[_ -]?token|refresh[_ -]?token|client[_ -]?secret|password|session[_ -]?cookie)\s*[:=]\s*\S+/gi },
])

const VERDICT_CONTRACT = Object.freeze({
  prompt_attack_detected: {
    label: 'Instruction attack detected',
    decision: 'blocked',
    confidence: 'high',
    summary: 'The reviewed output contains instruction-like content that is not allowed to gain authority.',
    next_action: 'Ignore the embedded instructions. Ask the other agent for a clean answer with evidence only.',
  },
  sensitive_data_detected: {
    label: 'Sensitive data detected',
    decision: 'blocked',
    confidence: 'high',
    summary: 'The review input appears to contain a credential or private-key value.',
    next_action: 'Remove or rotate the sensitive value before sharing or relying on this material.',
  },
  evidence_tampered: {
    label: 'Evidence failed verification',
    decision: 'blocked',
    confidence: 'high',
    summary: 'The supplied Readback proof bundle failed integrity or semantic verification.',
    next_action: 'Do not rely on the claimed action. Export a fresh proof bundle from the trusted source.',
  },
  evidence_signer_untrusted: {
    label: 'Signer not trusted',
    decision: 'hold',
    confidence: 'high',
    summary: 'The proof is internally valid, but it was signed by a runner Money Penny does not trust.',
    next_action: 'Use proof from a runner the owner trusted beforehand. A reviewed agent cannot register its own signing key.',
  },
  contradicted: {
    label: 'Claim contradicted',
    decision: 'blocked',
    confidence: 'high',
    summary: 'At least one important claim conflicts with independently verified evidence.',
    next_action: 'Stop and resolve the contradiction before taking another action.',
  },
  unverified_completion: {
    label: 'Completion unverified',
    decision: 'hold',
    confidence: 'high',
    summary: 'The other agent says work happened, but no independently verified readback proves the exact claim.',
    next_action: 'Check the destination or request a signed Readback proof bundle tied to the exact operation.',
  },
  approval_required: {
    label: 'Approval required',
    decision: 'hold',
    confidence: 'high',
    summary: 'The output proposes a real-world action without a recorded owner approval.',
    next_action: 'Review the exact target, scope, and consequences before granting separate approval.',
  },
  evidence_missing: {
    label: 'Evidence missing',
    decision: 'review',
    confidence: 'medium',
    summary: 'The output includes checkable claims that the supplied material does not independently verify.',
    next_action: 'Ask for the source, receipt, or destination readback behind the important claim.',
  },
  supported: {
    label: 'Supported by trusted evidence',
    decision: 'supported',
    confidence: 'high',
    summary: 'The important claim is bound to a Readback bundle from a trusted runner that passed signature, chain, and semantic verification.',
    next_action: 'The recorded claim is supported. Any new action still requires its own authority and approval.',
  },
  advisory_only: {
    label: 'Judgement, not proof',
    decision: 'informational',
    confidence: 'medium',
    summary: 'The output is advice or interpretation rather than a verified factual or completion claim.',
    next_action: 'Use it as advice and verify any factual premise before acting.',
  },
})

function cleanMultiline(value = '', maxChars = MAX_AGENT_OUTPUT_CHARS) {
  return String(value ?? '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .slice(0, maxChars)
    .trim()
}

function cleanInline(value = '', maxChars = 240) {
  return cleanMultiline(value, maxChars).replace(/\s+/g, ' ').trim()
}

function fingerprint(value = '') {
  return `sha256:${createHash('sha256').update(String(value), 'utf8').digest('hex')}`
}

function safeIdentifier(value = '', fallback = '') {
  const clean = cleanInline(value, 120).toLowerCase().replace(/[^a-z0-9._:-]+/g, '_').replace(/^_+|_+$/g, '')
  return clean || fallback
}

function safeReason(value = '', fallback = 'verification_failed') {
  return safeIdentifier(value, fallback).slice(0, 120)
}

export function normaliseMoneypennyTrustedKeyFingerprints(value = process.env[MONEYPENNY_AGENT_REVIEW_TRUSTED_KEYS_ENV]) {
  const candidates = value instanceof Set
    ? [...value]
    : Array.isArray(value)
      ? value
      : String(value || '').split(/[\s,]+/)
  return [...new Set(candidates
    .map((item) => String(item || '').trim().toLowerCase())
    .filter((item) => SIGNER_FINGERPRINT_PATTERN.test(item)))]
}

function sensitiveFindings(...values) {
  const findings = []
  for (const value of values) {
    const text = String(value ?? '')
    for (const rule of SECRET_PATTERNS) {
      rule.pattern.lastIndex = 0
      if (rule.pattern.test(text) && !findings.includes(rule.id)) findings.push(rule.id)
    }
  }
  return findings
}

function evidenceObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value
  const text = cleanMultiline(value, MAX_EVIDENCE_CHARS)
  if (!text || !text.startsWith('{')) return null
  try {
    const parsed = JSON.parse(text)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null
  } catch {
    return null
  }
}

function eventPayload(event = {}) {
  return event?.payload && typeof event.payload === 'object' ? event.payload : event
}

function safeEventReference(event = {}) {
  const payload = eventPayload(event)
  const proposal = payload.proposal && typeof payload.proposal === 'object' ? payload.proposal : {}
  return {
    event_type: safeIdentifier(event.event_type, 'unknown'),
    event_id: cleanInline(event.event_id || event.ledger_id, 160),
    proposal_id: cleanInline(payload.proposal_id || proposal.proposal_id, 160),
    approval_id: cleanInline(payload.approval_id, 160),
    job_type: safeIdentifier(payload.job_type || proposal.job_type, ''),
    output_hash: /^sha256:[a-f0-9]{64}$/i.test(String(payload.output_hash || '')) ? String(payload.output_hash).toLowerCase() : '',
    entry_hash: /^sha256:[a-f0-9]{64}$/i.test(String(event.entry_hash || '')) ? String(event.entry_hash).toLowerCase() : '',
  }
}

function inspectProofBundle(bundle = {}, options = {}) {
  const ledger = Array.isArray(bundle.ledger) ? bundle.ledger : []
  const trustedKeyFingerprints = new Set(normaliseMoneypennyTrustedKeyFingerprints(
    options.trustedKeyFingerprints ?? process.env[MONEYPENNY_AGENT_REVIEW_TRUSTED_KEYS_ENV],
  ))
  const signerFingerprint = typeof bundle.public_key_pem === 'string' && bundle.public_key_pem.trim()
    ? sha256(bundle.public_key_pem).toLowerCase()
    : ''
  if (ledger.length > MAX_BUNDLE_EVENTS) {
    return {
      kind: 'readback_proof_bundle',
      supplied: true,
      independently_verified: false,
      cryptographically_verified: false,
      trusted_signer_required: true,
      signer_trusted: false,
      untrusted_signer: false,
      signer_fingerprint: signerFingerprint,
      tamper_detected: false,
      invalid: true,
      reason: 'bundle_event_limit_exceeded',
      event_count: ledger.length,
      proposals: [],
      executions: [],
      approvals: [],
      refusals: [],
    }
  }

  let verification
  try {
    verification = verifyProofBundle(bundle)
  } catch {
    verification = { ok: false, reason: 'bundle_verifier_rejected_input' }
  }
  const cryptographicallyVerified = verification?.ok === true
  const signerTrusted = cryptographicallyVerified && trustedKeyFingerprints.has(signerFingerprint)
  const independentlyVerified = cryptographicallyVerified && signerTrusted
  const safeEvents = independentlyVerified ? ledger.map(safeEventReference) : []
  return {
    kind: 'readback_proof_bundle',
    supplied: true,
    independently_verified: independentlyVerified,
    cryptographically_verified: cryptographicallyVerified,
    trusted_signer_required: true,
    signer_trusted: signerTrusted,
    untrusted_signer: cryptographicallyVerified && !signerTrusted,
    signer_fingerprint: signerFingerprint,
    tamper_detected: !cryptographicallyVerified,
    invalid: !cryptographicallyVerified,
    reason: independentlyVerified
      ? ''
      : cryptographicallyVerified
        ? trustedKeyFingerprints.size > 0 ? 'signer_not_trusted' : 'trusted_signer_not_configured'
        : safeReason(verification?.reason || verification?.first_failure?.reason),
    event_count: ledger.length,
    proposals: safeEvents.filter((event) => event.event_type === 'proposal_recorded'),
    executions: safeEvents.filter((event) => event.event_type === 'sidecar_job_executed'),
    approvals: safeEvents.filter((event) => event.event_type === 'sidecar_job_approved'),
    refusals: safeEvents.filter((event) => event.event_type === 'sidecar_job_refused'),
    signature_verified: cryptographicallyVerified,
    chain_verified: cryptographicallyVerified,
    semantics_verified: cryptographicallyVerified && verification.semantic_ok === true,
    raw_evidence_returned: false,
  }
}

export function inspectMoneypennyAgentEvidence(value = '', options = {}) {
  const text = typeof value === 'string' ? cleanMultiline(value, MAX_EVIDENCE_CHARS) : ''
  const parsed = evidenceObject(value)
  if (!text && !parsed) {
    return {
      kind: 'none',
      supplied: false,
      independently_verified: false,
      tamper_detected: false,
      invalid: false,
      reason: 'no_evidence_supplied',
      event_count: 0,
      proposals: [],
      executions: [],
      approvals: [],
      refusals: [],
      raw_evidence_returned: false,
    }
  }

  if (parsed?.bundle_version === 'readback-proof-bundle.v0.1') return inspectProofBundle(parsed, options)

  if (parsed?.version === 'moneypenny-completion-receipt-v0.1') {
    const receipt = normaliseMoneypennyCompletionReceipt(parsed)
    return {
      kind: 'moneypenny_completion_receipt',
      supplied: true,
      independently_verified: false,
      tamper_detected: false,
      invalid: !receipt,
      reason: receipt ? 'receipt_structure_valid_but_not_independently_signed' : 'receipt_structure_invalid_or_expired',
      event_count: 0,
      proposals: [],
      executions: [],
      approvals: [],
      refusals: [],
      receipt: receipt ? {
        operation_id: receipt.operation_id,
        operation_type: receipt.operation_type,
        outcome: receipt.outcome,
        changed: receipt.changed,
        readback_verified: receipt.readback_verified,
        external_action_performed: receipt.external_action_performed,
      } : null,
      raw_evidence_returned: false,
    }
  }

  return {
    kind: parsed ? 'unverified_structured_evidence' : 'unverified_text_evidence',
    supplied: true,
    independently_verified: false,
    tamper_detected: false,
    invalid: false,
    reason: parsed ? 'structured_evidence_has_no_supported_verifier' : 'text_evidence_is_claimant_supplied',
    event_count: 0,
    proposals: [],
    executions: [],
    approvals: [],
    refusals: [],
    raw_evidence_returned: false,
  }
}

function candidateStatements(output = '') {
  return cleanMultiline(output)
    .split(/(?<=[.!?])\s+|\n+/)
    .map((item) => cleanInline(item.replace(/^\s*(?:[-*]|\d+[.)])\s*/, ''), 420))
    .filter((item) => item.length >= 4)
    .slice(0, MAX_CLAIMS)
}

export function classifyMoneypennyAgentReviewClaim(statement = '') {
  const text = cleanInline(statement, 420)
  if (!text) return { type: 'empty', checkable: false, action_policy: null }
  const actionPolicy = createMoneypennyActionPolicyReport({ text })
  const actionDetected = actionPolicy.status === 'BLOCKED'

  if (NEGATIVE_ACTION_PATTERN.test(text)) return { type: 'negative_completion', checkable: true, action_policy: actionPolicy }
  if (APPROVAL_CLAIM_PATTERN.test(text)) return { type: 'approval_claim', checkable: true, action_policy: actionPolicy }
  if (FUTURE_ACTION_PATTERN.test(text) || (actionDetected && RECOMMENDATION_PATTERN.test(text))) {
    return { type: 'action_proposal', checkable: true, action_policy: actionPolicy }
  }
  if (COMPLETION_PATTERN.test(text) && COMPLETION_SUBJECT_PATTERN.test(text) && !RECOMMENDATION_PATTERN.test(text)) {
    return { type: 'completion_claim', checkable: true, action_policy: actionPolicy }
  }
  if (actionDetected) return { type: 'action_proposal', checkable: true, action_policy: actionPolicy }
  if (RECOMMENDATION_PATTERN.test(text)) return { type: 'advisory', checkable: false, action_policy: actionPolicy }
  if (CHECKABLE_DETAIL_PATTERN.test(text) || ASSERTIVE_FACT_PATTERN.test(text)) {
    return { type: 'factual_claim', checkable: true, action_policy: actionPolicy }
  }
  return { type: 'statement', checkable: false, action_policy: actionPolicy }
}

function claimReferences(text = '') {
  const proposalIds = cleanInline(text, 600).match(/\bproposal_[a-z0-9_-]+\b/gi) || []
  const approvalIds = cleanInline(text, 600).match(/\bapproval_[a-z0-9_-]+\b/gi) || []
  const hashes = cleanInline(text, 600).match(/\bsha256:[a-f0-9]{64}\b/gi) || []
  return {
    proposal_ids: proposalIds.map((item) => item.toLowerCase()),
    approval_ids: approvalIds.map((item) => item.toLowerCase()),
    hashes: hashes.map((item) => item.toLowerCase()),
  }
}

function eventReferenceMatchesClaim(event = {}, statement = '') {
  const text = cleanInline(statement, 600).toLowerCase()
  const refs = claimReferences(text)
  if (refs.proposal_ids.length && refs.proposal_ids.includes(String(event.proposal_id || '').toLowerCase())) return true
  if (refs.approval_ids.length && refs.approval_ids.includes(String(event.approval_id || '').toLowerCase())) return true
  if (refs.hashes.length && refs.hashes.some((hash) => hash === event.output_hash || hash === event.entry_hash)) return true
  return false
}

function executionEventMatchesClaim(event = {}, statement = '') {
  const text = cleanInline(statement, 600)
  return eventReferenceMatchesClaim(event, text)
    && EXECUTION_COMPLETION_PATTERN.test(text)
    && !DIFFERENT_ACTION_PATTERN.test(text)
}

function claimView(statement, classification, sensitive = false) {
  return {
    id: `claim_${fingerprint(statement).slice(7, 19)}`,
    type: classification.type,
    text: sensitive ? 'Sensitive content was redacted from this claim.' : cleanInline(statement, 260),
    checkable: classification.checkable,
    matched_actions: classification.action_policy?.matched_actions || [],
  }
}

function assessClaim(claim, evidence, priorApprovalAsserted) {
  const proposals = evidence.proposals || []
  const executions = evidence.executions || []
  const approvals = evidence.approvals || []
  const referencedExecutions = executions.filter((event) => eventReferenceMatchesClaim(event, claim.text))
  const exactExecutions = executions.filter((event) => executionEventMatchesClaim(event, claim.text))
  const exactProposals = proposals.filter((event) => eventReferenceMatchesClaim(event, claim.text))
  const exactApprovals = approvals.filter((event) => eventReferenceMatchesClaim(event, claim.text))
  const references = claimReferences(claim.text)
  const hasExactReference = references.proposal_ids.length > 0 || references.approval_ids.length > 0 || references.hashes.length > 0
  const negativeExecutionClaim = NEGATIVE_EXECUTION_PATTERN.test(claim.text)

  if (claim.type === 'negative_completion') {
    if (evidence.independently_verified && negativeExecutionClaim && referencedExecutions.length) {
      return { ...claim, assessment: 'contradicted', reason: 'Trusted signed execution evidence conflicts with the no-action claim.', evidence_level: 'independently_verified' }
    }
    if (evidence.independently_verified && negativeExecutionClaim && hasExactReference && exactProposals.length && referencedExecutions.length === 0) {
      return { ...claim, assessment: 'supported', reason: 'The trusted signed ledger records the referenced proposal and no execution for it.', evidence_level: 'independently_verified' }
    }
    return { ...claim, assessment: 'uncertain', reason: 'No independently verified action history establishes the negative claim.', evidence_level: 'missing' }
  }

  if (claim.type === 'completion_claim') {
    if (evidence.independently_verified && exactExecutions.length) {
      return { ...claim, assessment: 'supported', reason: 'The claim is bound to a trusted signed execution event.', evidence_level: 'independently_verified' }
    }
    if (evidence.independently_verified && hasExactReference && referencedExecutions.length === 0) {
      return { ...claim, assessment: 'contradicted', reason: 'The verified bundle contains no execution event for the referenced operation.', evidence_level: 'independently_verified' }
    }
    return {
      ...claim,
      assessment: 'unverified_completion',
      reason: evidence.independently_verified && referencedExecutions.length
        ? 'The bundle proves the referenced operation ran, but it does not prove the different action described in this claim.'
        : evidence.independently_verified && executions.length
          ? 'The bundle verifies other work, but it does not bind this exact completion claim.'
        : 'No independently verified destination or execution readback supports this claim.',
      evidence_level: evidence.independently_verified ? 'not_bound_to_claim' : evidence.supplied ? 'claimant_supplied_only' : 'missing',
    }
  }

  if (claim.type === 'approval_claim') {
    if (evidence.independently_verified && exactApprovals.length) {
      return { ...claim, assessment: 'supported', reason: 'A trusted signed approval event matches the claim.', evidence_level: 'independently_verified' }
    }
    if (evidence.independently_verified && hasExactReference && exactApprovals.length === 0) {
      return { ...claim, assessment: 'contradicted', reason: 'No matching approval exists in the verified bundle.', evidence_level: 'independently_verified' }
    }
    return { ...claim, assessment: 'uncertain', reason: 'The other agent cannot prove owner authority by saying it had permission.', evidence_level: 'missing' }
  }

  if (claim.type === 'action_proposal') {
    return {
      ...claim,
      assessment: 'approval_required',
      reason: priorApprovalAsserted
        ? 'The owner reports prior approval, but this review cannot verify or reuse that authority and performs no action.'
        : 'The proposed real-world action needs separate explicit owner approval.',
      evidence_level: priorApprovalAsserted ? 'owner_assertion_only' : 'missing',
    }
  }

  if (claim.type === 'factual_claim') {
    return {
      ...claim,
      assessment: 'uncertain',
      reason: evidence.supplied
        ? 'Supplied material is not independently verified against this factual claim.'
        : 'No source was supplied for this checkable claim.',
      evidence_level: evidence.supplied ? 'claimant_supplied_only' : 'missing',
    }
  }

  return {
    ...claim,
    assessment: 'advisory',
    reason: 'This is advice or context, not a proved action or factual result.',
    evidence_level: 'not_applicable',
  }
}

function verdictFor({ promptSecurity, evidenceSecurity, sensitive, evidence, claims }) {
  const securityFindings = [
    ...(promptSecurity?.finding_ids || []),
    ...(evidenceSecurity?.finding_ids || []),
  ]
  if (promptSecurity?.blocked || evidenceSecurity?.blocked || securityFindings.length > 0) return 'prompt_attack_detected'
  if (sensitive.length) return 'sensitive_data_detected'
  if (evidence.kind === 'readback_proof_bundle' && evidence.invalid) return 'evidence_tampered'
  if (evidence.kind === 'readback_proof_bundle' && evidence.untrusted_signer) return 'evidence_signer_untrusted'
  if (claims.some((claim) => claim.assessment === 'contradicted')) return 'contradicted'
  if (claims.some((claim) => claim.assessment === 'unverified_completion')) return 'unverified_completion'
  if (claims.some((claim) => claim.assessment === 'approval_required')) return 'approval_required'
  if (claims.some((claim) => claim.checkable && claim.assessment !== 'supported')) return 'evidence_missing'
  if (claims.some((claim) => claim.checkable && claim.assessment === 'supported')) return 'supported'
  return 'advisory_only'
}

function verdictReply(verdict) {
  return [
    `Honesty review: ${verdict.label}.`,
    verdict.summary,
    verdict.next_action,
    'Review boundary: local and read-only. No provider, tool, write, or external action was used.',
    'Action: Nothing changed.',
  ].join(' ')
}

export function reviewMoneypennyAgentOutput(input = {}, options = {}) {
  const task = cleanMultiline(input?.task || input?.request || input?.goal, MAX_TASK_CHARS)
  const agentOutputOriginal = String(input?.agent_output ?? input?.agentOutput ?? input?.output ?? '')
  const agentOutput = cleanMultiline(agentOutputOriginal, MAX_AGENT_OUTPUT_CHARS)
  const sourceLabel = cleanInline(input?.source_label || input?.sourceLabel || input?.source || 'Other AI', 80)
  const evidenceInput = input?.evidence ?? input?.receipt ?? input?.proof_bundle ?? input?.proofBundle ?? ''
  const evidenceText = typeof evidenceInput === 'string'
    ? evidenceInput
    : evidenceInput && typeof evidenceInput === 'object'
      ? JSON.stringify(evidenceInput)
      : ''
  const priorApprovalAsserted = input?.prior_approval === true || input?.priorApproval === true

  if (!agentOutput) {
    return {
      ok: false,
      status: 'agent_review_input_required',
      feature_tag: MONEYPENNY_AGENT_REVIEW_FEATURE_TAG,
      route: MONEYPENNY_AGENT_REVIEW_ROUTE,
      reply: 'Paste the other agent output before running an honesty review. Action: Nothing changed.',
      write_action_performed: false,
      external_action_performed: false,
      provider_call_performed: false,
      proofEvents: ['Agent review input checked', 'No review performed', 'No external action taken'],
    }
  }

  const promptSecurity = inspectMoneypennyPromptInput(agentOutputOriginal, {
    sourceType: 'external_agent_output',
    trust: 'untrusted_data',
  })
  const evidenceSecurity = inspectMoneypennyPromptInput(evidenceText, {
    sourceType: 'external_agent_evidence',
    trust: 'untrusted_data',
  })
  const sensitive = sensitiveFindings(agentOutputOriginal, evidenceText)
  const evidence = inspectMoneypennyAgentEvidence(evidenceInput, options)
  const redactClaimText = sensitive.length > 0 || promptSecurity.finding_ids.length > 0
  const securityIsolationRequired = sensitive.length > 0
    || promptSecurity.blocked
    || evidenceSecurity.blocked
    || promptSecurity.finding_ids.length > 0
    || evidenceSecurity.finding_ids.length > 0
  const claims = candidateStatements(agentOutput)
    .map((statement) => {
      const classification = classifyMoneypennyAgentReviewClaim(statement)
      return claimView(statement, classification, redactClaimText)
    })
    .map((claim) => assessClaim(claim, evidence, priorApprovalAsserted))

  if (!claims.length) {
    claims.push({
      id: `claim_${fingerprint(agentOutput).slice(7, 19)}`,
      type: 'statement',
      text: redactClaimText ? 'Reviewed content was isolated.' : cleanInline(agentOutput, 260),
      checkable: false,
      matched_actions: [],
      assessment: 'advisory',
      reason: 'No checkable completion, authority, action, or factual claim was detected.',
      evidence_level: 'not_applicable',
    })
  }

  if (securityIsolationRequired) {
    claims.forEach((claim) => {
      claim.assessment = 'blocked'
      claim.reason = sensitive.length
        ? 'Sensitive content was isolated and cannot be treated as evidence or authority.'
        : 'Instruction-like content was isolated and cannot be treated as evidence or authority.'
      claim.evidence_level = 'blocked_untrusted_content'
    })
  } else if (evidence.kind === 'readback_proof_bundle' && evidence.invalid) {
    claims.forEach((claim) => {
      if (!claim.checkable) return
      claim.assessment = 'blocked'
      claim.reason = 'The supplied Readback bundle failed verification and cannot support this claim.'
      claim.evidence_level = 'tampered_or_invalid'
    })
  } else if (evidence.kind === 'readback_proof_bundle' && evidence.untrusted_signer) {
    claims.forEach((claim) => {
      if (!claim.checkable) return
      claim.assessment = 'signer_untrusted'
      claim.reason = 'The bundle is internally valid, but its signer is not on Money Penny\'s trusted-runner list.'
      claim.evidence_level = 'cryptographically_valid_untrusted_signer'
    })
  }

  const verdictCode = verdictFor({ promptSecurity, evidenceSecurity, sensitive, evidence, claims })
  const verdict = { code: verdictCode, ...VERDICT_CONTRACT[verdictCode] }
  const reviewId = `review_${fingerprint([sourceLabel, task, agentOutput, fingerprint(evidenceText)].join('\n')).slice(7, 23)}`
  const reviewReceipt = createMoneypennyCompletionReceipt({
    operation_id: reviewId,
    operation_type: 'agent_honesty_review',
    outcome: 'completed',
    source: 'local_agent_review',
    changed: false,
    persisted: false,
    readback_verified: true,
    approval_required: verdictCode === 'approval_required',
    external_action_performed: false,
  })

  return {
    ok: true,
    status: 'agent_review_complete',
    feature_tag: MONEYPENNY_AGENT_REVIEW_FEATURE_TAG,
    route: MONEYPENNY_AGENT_REVIEW_ROUTE,
    payload_class: MONEYPENNY_AGENT_REVIEW_PAYLOAD_CLASS,
    review_id: reviewId,
    source_label: sourceLabel,
    verdict,
    reply: verdictReply(verdict),
    claims,
    evidence,
    security: {
      output_status: promptSecurity.status,
      evidence_status: evidenceSecurity.status,
      finding_ids: [...new Set([...(promptSecurity.finding_ids || []), ...(evidenceSecurity.finding_ids || [])])],
      max_severity: promptSecurity.max_severity === 'critical' || evidenceSecurity.max_severity === 'critical'
        ? 'critical'
        : promptSecurity.max_severity === 'high' || evidenceSecurity.max_severity === 'high'
          ? 'high'
          : promptSecurity.max_severity === 'medium' || evidenceSecurity.max_severity === 'medium'
            ? 'medium'
            : 'none',
      sensitive_value_findings: sensitive,
      untrusted_content_isolated: true,
      raw_attack_content_returned: false,
    },
    authority: {
      prior_owner_approval_asserted: priorApprovalAsserted,
      prior_owner_approval_independently_verified: claims.some((claim) => (
        claim.type === 'approval_claim' && claim.assessment === 'supported'
      )),
      untrusted_content_can_authorize: false,
      review_grants_new_authority: false,
    },
    completion: {
      review_completed: true,
      reviewed_action_completed: claims.some((claim) => claim.type === 'completion_claim' && claim.assessment === 'supported'),
      reviewed_action_verified: claims.some((claim) => claim.type === 'completion_claim' && claim.assessment === 'supported'),
      review_receipt: reviewReceipt,
    },
    fingerprints: {
      task: fingerprint(task),
      agent_output: fingerprint(agentOutput),
      evidence: fingerprint(evidenceText),
    },
    provider_call_performed: false,
    cloud_used: false,
    network_egress: false,
    private_context_used: false,
    conversation_context_used: false,
    write_action_performed: false,
    external_action_performed: false,
    current_request_changed_state: false,
    raw_agent_output_persisted: false,
    raw_evidence_persisted: false,
    proofEvents: [
      'External agent output treated as untrusted data',
      'Claim and authority review completed locally',
      evidence.independently_verified
        ? 'Trusted signer and Readback evidence independently verified'
        : evidence.untrusted_signer
          ? 'Valid self-issued or unknown signature denied authority'
          : 'Unverified evidence did not gain authority',
      promptSecurity.finding_ids.length || evidenceSecurity.finding_ids.length ? 'Instruction-like content isolated' : 'Prompt security boundary checked',
      'Review completion receipt created',
      'No provider, tool, write, or external action used',
    ],
  }
}

export function moneypennyAgentReviewRuntimeStatus(options = {}) {
  const trustedKeyFingerprints = normaliseMoneypennyTrustedKeyFingerprints(
    options.trustedKeyFingerprints ?? process.env[MONEYPENNY_AGENT_REVIEW_TRUSTED_KEYS_ENV],
  )
  return {
    ok: true,
    feature_tag: MONEYPENNY_AGENT_REVIEW_FEATURE_TAG,
    route: MONEYPENNY_AGENT_REVIEW_ROUTE,
    payload_class: MONEYPENNY_AGENT_REVIEW_PAYLOAD_CLASS,
    external_agent_output_trusted: false,
    signed_readback_bundle_verification: true,
    trusted_signer_pinning: true,
    trusted_signer_count: trustedKeyFingerprints.length,
    self_issued_signatures_can_prove_claims: false,
    conversational_trust_registration: false,
    unverified_text_can_prove_claims: false,
    review_can_authorize_actions: false,
    provider_calls_enabled: false,
    tool_calls_enabled: false,
    writes_enabled: false,
    external_actions_enabled: false,
    raw_content_persisted: false,
  }
}
