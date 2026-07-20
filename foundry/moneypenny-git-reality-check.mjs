import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, realpathSync, statSync } from 'node:fs'

import { createMoneypennyCompletionReceipt } from './moneypenny-completion-receipt.mjs'
import { reviewMoneypennyAgentOutput } from './moneypenny-agent-review.mjs'

export const MONEYPENNY_GIT_REALITY_CHECK_FEATURE_TAG = 'git-reality-check-v01'
export const MONEYPENNY_GIT_REALITY_CHECK_ROUTE = '/api/moneypenny/git-reality-check'

const MAX_AGENT_OUTPUT_CHARS = 24_000
const MAX_GIT_OUTPUT_BYTES = 512_000
const GIT_TIMEOUT_MS = 3_000
const GIT_BINARY = existsSync('/usr/bin/git') ? '/usr/bin/git' : 'git'
const BLOCKED_PREFLIGHT_VERDICTS = new Set(['prompt_attack_detected', 'sensitive_data_detected'])
const HASH_PATTERN = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i

const FIXED_GIT_OPERATIONS = Object.freeze({
  inside_worktree: Object.freeze(['rev-parse', '--is-inside-work-tree']),
  bare_repository: Object.freeze(['rev-parse', '--is-bare-repository']),
  top_level: Object.freeze(['rev-parse', '--show-toplevel']),
  head: Object.freeze(['rev-parse', '--verify', 'HEAD']),
  status: Object.freeze(['status', '--porcelain=v1', '-z', '--untracked-files=normal', '--no-renames']),
})

function fingerprint(value = '') {
  return `sha256:${createHash('sha256').update(String(value), 'utf8').digest('hex')}`
}

function cleanInline(value = '', maxChars = 260) {
  return String(value ?? '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, maxChars)
    .trim()
}

function safeGitEnvironment() {
  const env = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('GIT_')) env[key] = value
  }
  return {
    ...env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    LC_ALL: 'C',
  }
}

function runFixedGitOperation({ operation, repoRoot }) {
  const operationArgs = FIXED_GIT_OPERATIONS[operation]
  if (!operationArgs) return Promise.reject(new Error('git_operation_not_allowlisted'))
  const args = [
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.untrackedCache=false',
    '-C', repoRoot,
    ...operationArgs,
  ]
  return new Promise((resolve, reject) => {
    execFile(GIT_BINARY, args, {
      cwd: repoRoot,
      encoding: 'utf8',
      env: safeGitEnvironment(),
      maxBuffer: MAX_GIT_OUTPUT_BYTES,
      timeout: GIT_TIMEOUT_MS,
      windowsHide: true,
    }, (error, stdout) => {
      if (error) {
        reject(new Error(`git_${operation}_failed`))
        return
      }
      resolve(String(stdout || ''))
    })
  })
}

function canonicalRepositoryRoot(repoRoot) {
  const candidate = realpathSync(String(repoRoot || ''))
  if (!statSync(candidate).isDirectory()) throw new Error('git_repository_root_invalid')
  return candidate
}

function statusEntryCount(statusText = '') {
  return String(statusText).split('\0').filter(Boolean).length
}

export async function observeMoneypennyGitRepository(options = {}) {
  const repoRoot = canonicalRepositoryRoot(options.repoRoot)
  const runGit = typeof options.runGit === 'function' ? options.runGit : runFixedGitOperation
  const execute = async (operation) => String(await runGit({
    operation,
    repoRoot,
    args: FIXED_GIT_OPERATIONS[operation],
  }) || '').trim()

  const insideWorktree = await execute('inside_worktree')
  const bareRepository = await execute('bare_repository')
  const observedTopLevel = await execute('top_level')
  if (insideWorktree !== 'true' || bareRepository !== 'false') throw new Error('git_repository_boundary_rejected')
  if (canonicalRepositoryRoot(observedTopLevel) !== repoRoot) throw new Error('git_repository_scope_mismatch')

  const headBefore = (await execute('head')).toLowerCase()
  if (!HASH_PATTERN.test(headBefore)) throw new Error('git_head_invalid')
  const rawStatus = await execute('status')
  const headAfter = (await execute('head')).toLowerCase()
  if (headAfter !== headBefore) throw new Error('git_head_changed_during_readback')

  const changedEntryCount = statusEntryCount(rawStatus)
  const worktreeState = changedEntryCount === 0 ? 'clean' : 'dirty'
  const observedAt = new Date(options.now || Date.now()).toISOString()
  return {
    ok: true,
    source: options.observationSource || 'git',
    source_scope: options.sourceScope || 'canonical_repository_only',
    source_label: options.observationLabel || 'Live Git',
    direct_program_used: options.directProgramUsed !== false,
    observed_at: observedAt,
    observation_id: `git_${fingerprint([headBefore, worktreeState, changedEntryCount, observedAt].join(':')).slice(7, 23)}`,
    head_full: headBefore,
    head_short: headBefore.slice(0, 12),
    worktree_state: worktreeState,
    changed_entry_count: changedEntryCount,
    consistent_head_readback: true,
    raw_status_returned: false,
    file_names_returned: false,
    file_contents_returned: false,
    repository_path_returned: false,
    network_egress: false,
    write_action_performed: false,
  }
}

function addClaim(claims, claim) {
  const key = `${claim.fact}:${claim.claimed}`
  if (!claims.some((item) => `${item.fact}:${item.claimed}` === key)) claims.push(claim)
}

function parseMoneypennyGitClaimMatches(value = '') {
  const text = String(value ?? '').normalize('NFKC').slice(0, MAX_AGENT_OUTPUT_CHARS)
  const claims = []
  const ranges = []

  function record(match, claim) {
    addClaim(claims, claim)
    ranges.push([match.index, match.index + match[0].length])
  }

  const headPattern = /\b(?:git\s+)?(?:head|commit)(?:\s+(?:hash|sha))?\s*(?:is|=|:)\s*([a-f0-9]{7,64})\b/gi
  for (const match of text.matchAll(headPattern)) {
    record(match, { fact: 'head', claimed: match[1].toLowerCase() })
  }

  const statePattern = /\b(?:git\s+)?(?:worktree|working\s+(?:tree|directory)|repo(?:sitory)?)\s+(?:(?:status|state)\s+)?(?:is|was|=|:)?\s*(?:currently\s+)?(not\s+)?(clean|dirty)\b/gi
  for (const match of text.matchAll(statePattern)) {
    const stated = match[2].toLowerCase()
    const claimed = match[1] ? (stated === 'clean' ? 'dirty' : 'clean') : stated
    record(match, { fact: 'worktree_state', claimed })
  }

  const countPatterns = [
    /\b(?:changed|dirty|modified|uncommitted)\s+(?:path|file|entry|item)\s+count\s*(?:is|=|:)\s*(\d{1,7})\b/gi,
    /\b(\d{1,7})\s+(?:changed|dirty|modified|uncommitted)\s+(?:paths?|files?|entries|items?)\b/gi,
  ]
  for (const pattern of countPatterns) {
    for (const match of text.matchAll(pattern)) {
      record(match, { fact: 'changed_entry_count', claimed: Number.parseInt(match[1], 10) })
    }
  }

  return { text, claims, ranges }
}

export function parseMoneypennyGitClaims(value = '') {
  return parseMoneypennyGitClaimMatches(value).claims
}

function unmatchedCheckableClaims(details, input = {}) {
  let residual = details.text
  for (const [start, end] of [...details.ranges].sort((left, right) => right[0] - left[0])) {
    residual = `${residual.slice(0, start)}${' '.repeat(end - start)}${residual.slice(end)}`
  }
  if (!/[a-z0-9]/i.test(residual)) return []
  const review = reviewMoneypennyAgentOutput({
    source_label: input?.source_label || input?.sourceLabel || 'Outside agent',
    task: input?.task || 'Check repository claims against live Git.',
    agent_output: residual,
  })
  return (review.claims || []).filter((claim) => claim.checkable)
}

function assessGitClaim(claim, observation) {
  const sourceLabel = observation.source_label || 'Live Git'
  const evidenceLevel = observation.direct_program_used === false ? 'synthetic_fixture_readback' : 'direct_source_readback'
  if (claim.fact === 'head') {
    const supported = observation.head_full.startsWith(claim.claimed)
    return {
      id: `git_head_${fingerprint(claim.claimed).slice(7, 15)}`,
      type: 'factual_claim',
      text: `Git HEAD is ${claim.claimed.slice(0, 12)}.`,
      checkable: true,
      matched_actions: [],
      assessment: supported ? 'supported' : 'contradicted',
      reason: supported
        ? `${sourceLabel} confirms HEAD ${observation.head_short}.`
        : `${sourceLabel} reports HEAD ${observation.head_short}, not the claimed revision.`,
      evidence_level: evidenceLevel,
    }
  }
  if (claim.fact === 'worktree_state') {
    const supported = claim.claimed === observation.worktree_state
    return {
      id: `git_state_${claim.claimed}`,
      type: 'factual_claim',
      text: `Git worktree is ${claim.claimed}.`,
      checkable: true,
      matched_actions: [],
      assessment: supported ? 'supported' : 'contradicted',
      reason: supported
        ? `${sourceLabel} confirms the worktree is ${observation.worktree_state}.`
        : `${sourceLabel} reports the worktree is ${observation.worktree_state}.`,
      evidence_level: evidenceLevel,
    }
  }

  const supported = claim.claimed === observation.changed_entry_count
  return {
    id: `git_count_${claim.claimed}`,
    type: 'factual_claim',
    text: `Git changed-item count is ${claim.claimed}.`,
    checkable: true,
    matched_actions: [],
    assessment: supported ? 'supported' : 'contradicted',
    reason: supported
      ? `${sourceLabel} confirms ${observation.changed_entry_count} changed item${observation.changed_entry_count === 1 ? '' : 's'}.`
      : `${sourceLabel} reports ${observation.changed_entry_count} changed item${observation.changed_entry_count === 1 ? '' : 's'}.`,
    evidence_level: evidenceLevel,
  }
}

function gitVerdict(sourceClaims, unmatchedClaims, observation) {
  const sourceLabel = observation.source_label || 'Live Git'
  const syntheticFixture = observation.direct_program_used === false
  if (sourceClaims.some((claim) => claim.assessment === 'contradicted')) {
    return {
      code: 'contradicted',
      label: syntheticFixture ? 'Contradicted by demo snapshot' : 'Contradicted by live Git',
      decision: 'blocked',
      confidence: 'high',
      summary: `At least one recognised repository claim conflicts with Money Penny's ${sourceLabel.toLowerCase()} check.`,
      next_action: syntheticFixture
        ? 'Do not rely on the agent report. Use the local edition when a live repository check is required.'
        : 'Do not rely on the agent report until its repository claim matches the live source.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.assessment === 'unverified_completion')) {
    return {
      code: 'unverified_completion',
      label: 'Other completion unverified',
      decision: 'hold',
      confidence: 'high',
      summary: 'The listed Git facts may match, but another completion claim in the same report was not established by Git.',
      next_action: 'Verify the additional action at its real destination before relying on the report.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.assessment === 'approval_required')) {
    return {
      code: 'approval_required',
      label: 'Separate approval required',
      decision: 'hold',
      confidence: 'high',
      summary: 'The report includes a proposed action that the Git check cannot authorize.',
      next_action: 'Review that action separately and grant explicit approval only through its controlled workflow.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.checkable && claim.assessment !== 'supported')) {
    return {
      code: 'evidence_missing',
      label: 'Other claim needs evidence',
      decision: 'review',
      confidence: 'high',
      summary: 'The listed Git facts may match, but another checkable claim in the report remains unsupported.',
      next_action: 'Request a source check for the unmatched claim before relying on the complete report.',
    }
  }
  if (!sourceClaims.length) {
    return {
      code: 'evidence_missing',
      label: syntheticFixture ? 'No snapshot fact found' : 'No Git fact found',
      decision: 'review',
      confidence: 'high',
      summary: syntheticFixture
        ? 'The demo snapshot was checked, but the agent output did not contain a recognised revision, worktree-state, or changed-item claim.'
        : 'Git was reached, but the agent output did not contain a recognised revision, worktree-state, or changed-item claim.',
      next_action: 'Ask the agent to state the Git revision, clean or dirty state, or changed-item count explicitly.',
    }
  }
  return {
    code: 'supported',
    label: syntheticFixture ? 'Confirmed in demo snapshot' : 'Confirmed by live Git',
    decision: 'supported',
    confidence: 'high',
    summary: `Every recognised repository fact matches Money Penny's ${sourceLabel.toLowerCase()} check.`,
    next_action: syntheticFixture
      ? 'Treat this as a demonstration of the judgment flow. Use the local edition for a live repository check.'
      : 'Treat only the listed Git facts as supported. Any other claim still needs its own source check.',
  }
}

function blockedBeforeGit(preflight, options = {}) {
  const directProgramUsed = options.directProgramUsed !== false
  return {
    ...preflight,
    status: 'moneypenny_git_reality_check_blocked',
    feature_tag: MONEYPENNY_GIT_REALITY_CHECK_FEATURE_TAG,
    route: MONEYPENNY_GIT_REALITY_CHECK_ROUTE,
    connector: {
      program: directProgramUsed ? 'git' : 'synthetic_git_snapshot',
      invoked: false,
      reason: 'untrusted_input_blocked_before_tool_use',
      claimant_supplied_commands_allowed: false,
      claimant_supplied_paths_allowed: false,
    },
    provider_call_performed: false,
    tool_call_performed: false,
    external_program_call_performed: false,
    network_egress: false,
    write_action_performed: false,
    repository_write_performed: false,
    proofEvents: [
      ...(preflight.proofEvents || []),
      directProgramUsed
        ? 'Git connector not invoked because untrusted input was blocked'
        : 'Synthetic snapshot adapter not invoked because untrusted input was blocked',
    ],
  }
}

async function reviewWithObservation(input, observation) {
  const agentOutput = String(input?.agent_output ?? input?.agentOutput ?? input?.output ?? '')
  const preflight = reviewMoneypennyAgentOutput({
    source_label: input?.source_label || input?.sourceLabel || 'Outside agent',
    task: input?.task || 'Check repository claims against live Git.',
    agent_output: agentOutput,
  })
  if (!preflight.ok || BLOCKED_PREFLIGHT_VERDICTS.has(preflight.verdict?.code)) {
    return blockedBeforeGit(preflight, { directProgramUsed: observation.direct_program_used })
  }

  const parsedClaims = parseMoneypennyGitClaimMatches(agentOutput)
  const sourceClaims = parsedClaims.claims.map((claim) => assessGitClaim(claim, observation))
  const unmatchedClaims = unmatchedCheckableClaims(parsedClaims, input)
  const claims = [...sourceClaims, ...unmatchedClaims]
  const verdict = gitVerdict(sourceClaims, unmatchedClaims, observation)
  const directProgramUsed = observation.direct_program_used !== false
  const sourceLabel = observation.source_label || 'Live Git'
  const reviewId = `git_review_${fingerprint([
    preflight.source_label,
    preflight.fingerprints?.agent_output,
    observation.observation_id,
  ].join(':')).slice(7, 23)}`
  const reviewReceipt = createMoneypennyCompletionReceipt({
    operation_id: reviewId,
    operation_type: 'git_reality_check',
    outcome: 'completed',
    source: directProgramUsed ? 'local_git_readback' : 'bundled_synthetic_git_snapshot',
    changed: false,
    persisted: false,
    readback_verified: true,
    approval_required: verdict.code === 'approval_required',
    external_action_performed: false,
  })

  return {
    ok: true,
    status: 'moneypenny_git_reality_check_complete',
    feature_tag: MONEYPENNY_GIT_REALITY_CHECK_FEATURE_TAG,
    route: MONEYPENNY_GIT_REALITY_CHECK_ROUTE,
    payload_class: 'untrusted_agent_output_fixed_git_readback',
    review_id: reviewId,
    source_label: preflight.source_label,
    verdict,
    reply: [
      `Git reality check: ${verdict.label}.`,
      verdict.summary,
      verdict.next_action,
      directProgramUsed
        ? 'Readback boundary: fixed canonical repository, local Git, and no claimant-supplied command or path.'
        : 'Demo boundary: bundled synthetic snapshot and no claimant-supplied command or repository path.',
      'Action: Repository unchanged.',
    ].join(' '),
    claims,
    evidence: {
      kind: directProgramUsed ? 'moneypenny_git_readback' : 'moneypenny_synthetic_git_snapshot',
      supplied: false,
      independently_verified: true,
      source: 'git',
      source_scope: observation.source_scope,
      observed_at: observation.observed_at,
      observation_id: observation.observation_id,
      safe_facts: {
        head_short: observation.head_short,
        worktree_state: observation.worktree_state,
        changed_entry_count: observation.changed_entry_count,
      },
      event_count: claims.length,
      raw_status_returned: false,
      file_names_returned: false,
      file_contents_returned: false,
      repository_path_returned: false,
    },
    security: preflight.security,
    authority: {
      prior_owner_approval_asserted: false,
      prior_owner_approval_independently_verified: false,
      untrusted_content_can_authorize: false,
      review_grants_new_authority: false,
    },
    completion: {
      review_completed: true,
      reviewed_action_completed: false,
      reviewed_action_verified: false,
      review_receipt: reviewReceipt,
    },
    fingerprints: preflight.fingerprints,
    connector: {
      program: directProgramUsed ? 'git' : 'synthetic_git_snapshot',
      invoked: true,
      operation_scope: directProgramUsed ? 'fixed_read_only' : 'fixed_synthetic_fixture',
      claimant_supplied_commands_allowed: false,
      claimant_supplied_paths_allowed: false,
      shell_used: false,
      network_used: false,
      repository_changed: false,
      raw_status_returned: false,
    },
    provider_call_performed: false,
    cloud_used: false,
    tool_call_performed: true,
    external_program_call_performed: directProgramUsed,
    network_egress: false,
    private_context_used: false,
    conversation_context_used: false,
    write_action_performed: false,
    repository_write_performed: false,
    external_action_performed: false,
    current_request_changed_state: false,
    raw_agent_output_persisted: false,
    raw_git_output_persisted: false,
    proofEvents: [
      'External agent output treated as untrusted data',
      'Prompt security boundary checked before tool use',
      directProgramUsed ? 'Fixed read-only Git connector invoked' : 'Bundled synthetic Git snapshot checked',
      sourceClaims.length ? 'Recognised Git claims compared with direct source readback' : 'No recognised Git claim found',
      unmatchedClaims.length ? 'Unmatched checkable claims retained for separate verification' : '',
      verdict.code === 'contradicted' ? 'Conflicting agent claim blocked' : '',
      'No file names, file contents, repository path, or raw Git status returned',
      'No network, repository write, or external action used',
      `${sourceLabel} reality-check receipt created`,
    ].filter(Boolean),
  }
}

export async function reviewMoneypennyGitClaim(input = {}, options = {}) {
  const agentOutput = String(input?.agent_output ?? input?.agentOutput ?? input?.output ?? '')
  const preflight = reviewMoneypennyAgentOutput({
    source_label: input?.source_label || input?.sourceLabel || 'Outside agent',
    task: input?.task || 'Check repository claims against live Git.',
    agent_output: agentOutput,
  })
  if (!preflight.ok || BLOCKED_PREFLIGHT_VERDICTS.has(preflight.verdict?.code)) {
    return blockedBeforeGit(preflight, options)
  }
  const observation = await observeMoneypennyGitRepository(options)
  return reviewWithObservation(input, observation)
}

export async function runMoneypennyGitConnectionTest(options = {}) {
  const observation = await observeMoneypennyGitRepository(options)
  const changedLabel = observation.changed_entry_count === 1 ? 'changed item' : 'changed items'
  const testClaim = `Git HEAD is ${observation.head_short}. The worktree is ${observation.worktree_state}. Git reports ${observation.changed_entry_count} ${changedLabel}.`
  const result = await reviewWithObservation({
    source_label: 'Connector self-test',
    task: 'Prove Money Penny can compare an agent claim with a live outside program.',
    agent_output: testClaim,
  }, observation)
  return {
    ...result,
    connection_test: {
      synthetic_agent_claim: true,
      live_git_readback: true,
      test_claim: testClaim,
    },
  }
}

export function moneypennyGitRealityCheckRuntimeStatus() {
  return {
    ok: true,
    feature_tag: MONEYPENNY_GIT_REALITY_CHECK_FEATURE_TAG,
    route: MONEYPENNY_GIT_REALITY_CHECK_ROUTE,
    program: 'git',
    source_scope: 'canonical_repository_only',
    operation_scope: 'fixed_read_only',
    claimant_supplied_commands_allowed: false,
    claimant_supplied_paths_allowed: false,
    shell_enabled: false,
    network_enabled: false,
    repository_writes_enabled: false,
    raw_status_returned: false,
    file_names_returned: false,
    file_contents_returned: false,
  }
}
