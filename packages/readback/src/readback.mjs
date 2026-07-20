import { readLedgerEntries } from './ledger.mjs'

const FAKE_SUCCESS_RE = /\b(done|sent|approved|executed|scheduled|completed|will run)\b/i

function evidenceRef(event) {
  return {
    event_id: event.event_id || event.ledger_id,
    event_type: event.event_type,
    entry_hash: event.entry_hash || event.content_hash,
    timestamp: event.timestamp,
  }
}

function eventPayload(event = {}) {
  return event.payload || event
}

function proposalMatches(event = {}, proposalId = '') {
  return !proposalId || eventPayload(event).proposal_id === proposalId
}

function executedEvent(events = [], proposalId = '') {
  return events.find((event) => event.event_type === 'sidecar_job_executed' && proposalMatches(event, proposalId))
}

function approvedEvent(events = [], proposalId = '') {
  return events.find((event) => event.event_type === 'sidecar_job_approved' && proposalMatches(event, proposalId))
}

export function enforceFakeSuccessLexicon(answerText, evidence = []) {
  if (!FAKE_SUCCESS_RE.test(answerText)) return answerText
  if (evidence.length > 0) return answerText
  throw new Error('fake_success_lexicon_without_evidence')
}

export function interrogate(query, { ledgerPath }) {
  const key = typeof query === 'string' ? query : query?.claim
  const proposalId = typeof query === 'string' ? '' : String(query?.proposal_id || '')
  const events = readLedgerEntries(ledgerPath)
  let result
  if (key === 'manifest_job_ran') {
    const execution = events.find((event) => {
      const payload = eventPayload(event)
      return event.event_type === 'sidecar_job_executed' && payload.job_type === 'hash_manifest_v0'
    })
    if (execution) {
      const payload = eventPayload(execution)
      result = {
        claim: key,
        evidence: [evidenceRef(execution)],
        answer_text: `Yes. Proposal ${payload.proposal_id} has execution ledger evidence for ${payload.job_type}: output ${payload.output_hash}.`,
      }
    } else {
      result = { claim: key, evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
    }
  } else if (key === 'job_ran') {
    const execution = executedEvent(events, proposalId)
    if (execution) {
      const payload = eventPayload(execution)
      result = {
        claim: key,
        evidence: [evidenceRef(execution)],
        answer_text: `Yes. Proposal ${payload.proposal_id} has execution ledger evidence for ${payload.job_type}: output ${payload.output_hash}.`,
      }
    } else {
      result = { claim: key, evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
    }
  } else if (key === 'job_approved') {
    const approval = approvedEvent(events, proposalId)
    if (approval) {
      const payload = eventPayload(approval)
      result = {
        claim: key,
        evidence: [evidenceRef(approval)],
        answer_text: `Yes. Proposal ${payload.proposal_id} has a CLI approval record ${payload.approval_id}. It still needs separate CLI execution evidence before I can say it ran.`,
      }
    } else {
      result = { claim: key, evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
    }
  } else if (key === 'email_sent') {
    result = { claim: key, evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
  } else if (key === 'second_job_approved') {
    result = { claim: key, evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
  } else {
    result = { claim: key || 'unknown', evidence: [], answer_text: 'No signed ledger evidence supports that claim.' }
  }
  result.answer_text = enforceFakeSuccessLexicon(result.answer_text, result.evidence)
  return result
}
