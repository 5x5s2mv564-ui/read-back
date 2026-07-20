import { createHash } from 'node:crypto'

export const MONEYPENNY_COMPLETION_RECEIPT_VERSION = 'moneypenny-completion-receipt-v0.1'

const DEFAULT_RECEIPT_TTL_MS = 15 * 60 * 1000
const MAX_RECEIPT_TTL_MS = 30 * 60 * 1000
const RECEIPT_OUTCOMES = new Set([
  'blocked',
  'completed',
  'failed_safely',
  'needs_approval',
  'observed',
  'prepared',
  'unverified',
])
const CHANGED_RESOURCES = new Set([
  'apple_reminders',
  'memory',
  'project_ledger',
  'reminder_store',
])

function cleanText(value = '', maxLength = 160) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, maxLength)
}

function cleanIdentifier(value = '', fallback = '') {
  const clean = cleanText(value, 180)
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return clean || fallback
}

function validDate(value, fallback = null) {
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value || '')
  return Number.isNaN(date.getTime()) ? fallback : date
}

function boundedTtl(value) {
  const requested = Number(value)
  if (!Number.isFinite(requested) || requested <= 0) return DEFAULT_RECEIPT_TTL_MS
  return Math.min(MAX_RECEIPT_TTL_MS, Math.max(60_000, Math.round(requested)))
}

function contextFingerprint(parts = []) {
  return createHash('sha256')
    .update(parts.map((part) => cleanText(part, 500)).join('|'))
    .digest('hex')
    .slice(0, 20)
}

function normaliseChangedResources(values = []) {
  return [...new Set((Array.isArray(values) ? values : [])
    .map((value) => cleanIdentifier(value))
    .filter((value) => CHANGED_RESOURCES.has(value)))]
}

export function createMoneypennyCompletionReceipt(input = {}) {
  const outcomeCandidate = cleanIdentifier(input.outcome, 'observed')
  const outcome = RECEIPT_OUTCOMES.has(outcomeCandidate) ? outcomeCandidate : 'observed'
  const now = validDate(input.now, new Date())
  const createdAt = validDate(input.created_at || input.createdAt, now)
  const requestedExpiresAt = validDate(
    input.expires_at || input.expiresAt,
    new Date(createdAt.getTime() + boundedTtl(input.ttl_ms || input.ttlMs)),
  )
  const expiresAt = new Date(Math.min(
    requestedExpiresAt.getTime(),
    createdAt.getTime() + MAX_RECEIPT_TTL_MS,
  ))
  const changedResources = normaliseChangedResources(input.changed_resources || input.changedResources)
  const changed = input.changed === true && changedResources.length > 0
  const operationType = cleanIdentifier(input.operation_type || input.operationType, 'source_check')
  const source = cleanIdentifier(input.source, 'local_runtime')
  const operationId = cleanIdentifier(input.operation_id || input.operationId)
    || `${operationType}:${contextFingerprint([operationType, source, outcome, createdAt.toISOString()])}`
  return {
    version: MONEYPENNY_COMPLETION_RECEIPT_VERSION,
    operation_id: operationId,
    operation_type: operationType,
    outcome,
    source,
    changed,
    changed_resources: changed ? changedResources : [],
    persisted: input.persisted === true,
    readback_verified: input.readback_verified === true || input.readbackVerified === true,
    approval_required: input.approval_required === true || input.approvalRequired === true,
    external_action_performed: input.external_action_performed === true || input.externalActionPerformed === true,
    session_id: cleanIdentifier(input.session_id || input.sessionId),
    user_id: cleanIdentifier(input.user_id || input.userId),
    created_at: createdAt.toISOString(),
    expires_at: expiresAt.toISOString(),
    private_payload_included: false,
    raw_content_included: false,
  }
}

export function normaliseMoneypennyCompletionReceipt(value, options = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  if (value.version !== MONEYPENNY_COMPLETION_RECEIPT_VERSION) return null
  if (value.private_payload_included !== false || value.raw_content_included !== false) return null
  const outcome = cleanIdentifier(value.outcome)
  if (!RECEIPT_OUTCOMES.has(outcome)) return null
  const createdAt = validDate(value.created_at || value.createdAt)
  const expiresAt = validDate(value.expires_at || value.expiresAt)
  const now = validDate(options.now, new Date())
  if (!createdAt || !expiresAt) return null
  if (createdAt.getTime() > now.getTime() + 60_000) return null
  if (expiresAt.getTime() <= createdAt.getTime()) return null
  if (expiresAt.getTime() - createdAt.getTime() > MAX_RECEIPT_TTL_MS) return null
  const changedResources = normaliseChangedResources(value.changed_resources || value.changedResources)
  if ((value.changed === true) !== (changedResources.length > 0)) return null
  const mustNotChange = ['blocked', 'failed_safely', 'needs_approval', 'observed', 'prepared'].includes(outcome)
  if (mustNotChange && (value.changed === true || value.persisted === true || value.external_action_performed === true || value.externalActionPerformed === true)) return null
  if ((value.external_action_performed === true || value.externalActionPerformed === true) && (value.changed !== true || value.persisted !== true)) return null
  const receipt = createMoneypennyCompletionReceipt(value)
  if (new Date(receipt.expires_at).getTime() <= now.getTime()) return null
  const expectedSessionId = cleanIdentifier(options.session_id || options.sessionId)
  const expectedUserId = cleanIdentifier(options.user_id || options.userId)
  if (expectedSessionId && receipt.session_id !== expectedSessionId) return null
  if (expectedUserId && receipt.user_id !== expectedUserId) return null
  if (receipt.private_payload_included || receipt.raw_content_included) return null
  return receipt
}
