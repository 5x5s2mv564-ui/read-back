import { createHash } from 'node:crypto'

import { createMoneypennyCompletionReceipt } from './moneypenny-completion-receipt.mjs'
import { reviewMoneypennyAgentOutput } from './moneypenny-agent-review.mjs'

export const MONEYPENNY_PUBLIC_GITHUB_FEATURE_TAG = 'public-github-reality-check-v01'
export const MONEYPENNY_PUBLIC_GITHUB_ROUTE = '/api/github-review'

const GITHUB_API_ORIGIN = 'https://api.github.com'
const GITHUB_API_VERSION = '2026-03-10'
const GITHUB_USER_AGENT = 'Money-Penny-Readback-Public-Demo'
const MAX_AGENT_OUTPUT_CHARS = 24_000
const MAX_REPOSITORY_INPUT_CHARS = 220
const MAX_RESPONSE_BYTES = 192 * 1024
const DEFAULT_TIMEOUT_MS = 3_500
const DEFAULT_CACHE_TTL_MS = 30_000
const MAX_CACHE_ENTRIES = 32
const BLOCKED_PREFLIGHT_VERDICTS = new Set(['prompt_attack_detected', 'sensitive_data_detected'])
const HASH_PATTERN = /^[a-f0-9]{40}(?:[a-f0-9]{24})?$/i
const OWNER_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/i
const REPOSITORY_PATTERN = /^[a-z0-9._-]{1,100}$/i
const BRANCH_PATTERN = /^[a-z0-9._/-]{1,255}$/i

function publicError(message, statusCode) {
  return Object.assign(new Error(message), { statusCode })
}

function fingerprint(value = '') {
  return `sha256:${createHash('sha256').update(String(value), 'utf8').digest('hex')}`
}

function normalizedInput(value = '') {
  return String(value ?? '')
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
    .trim()
}

function validOwner(owner) {
  return OWNER_PATTERN.test(owner) && !owner.includes('--')
}

function validRepositoryName(repository) {
  return REPOSITORY_PATTERN.test(repository)
    && repository !== '.'
    && repository !== '..'
    && !repository.endsWith('.')
}

export function parsePublicGitHubRepository(value = '') {
  const input = normalizedInput(value)
  if (!input || input.length > MAX_REPOSITORY_INPUT_CHARS || /[\u0000-\u001F\u007F]/.test(input)) {
    throw publicError('github_repository_invalid', 400)
  }

  let owner
  let repository
  const looksLikeUrl = /^https?:\/\//i.test(input) || /^github\.com\//i.test(input)
  if (looksLikeUrl) {
    let parsed
    try {
      parsed = new URL(/^github\.com\//i.test(input) ? `https://${input}` : input)
    } catch {
      throw publicError('github_repository_invalid', 400)
    }
    if (parsed.protocol !== 'https:'
      || parsed.hostname.toLowerCase() !== 'github.com'
      || parsed.port
      || parsed.username
      || parsed.password
      || parsed.search
      || parsed.hash
      || parsed.pathname.includes('%')) {
      throw publicError('github_repository_must_be_public_github', 400)
    }
    const segments = parsed.pathname.split('/').filter(Boolean)
    if (segments.length !== 2) throw publicError('github_repository_invalid', 400)
    ;[owner, repository] = segments
  } else {
    if (/[\\@:#?]/.test(input)) throw publicError('github_repository_invalid', 400)
    const segments = input.split('/')
    if (segments.length !== 2) throw publicError('github_repository_invalid', 400)
    ;[owner, repository] = segments
  }

  repository = repository.replace(/\.git$/i, '')
  if (!validOwner(owner) || !validRepositoryName(repository)) {
    throw publicError('github_repository_invalid', 400)
  }
  return {
    owner,
    repository,
    full_name: `${owner}/${repository}`,
    html_url: `https://github.com/${owner}/${repository}`,
  }
}

function safeBranch(value = '') {
  const branch = normalizedInput(value)
  if (!BRANCH_PATTERN.test(branch)
    || branch.startsWith('/')
    || branch.endsWith('/')
    || branch.endsWith('.')
    || branch.includes('..')
    || branch.includes('//')) {
    throw publicError('github_default_branch_unsupported', 422)
  }
  return branch
}

function nowMilliseconds(value) {
  const candidate = typeof value === 'function' ? value() : value
  const milliseconds = candidate === undefined ? Date.now() : new Date(candidate).getTime()
  if (!Number.isFinite(milliseconds)) throw new Error('github_observation_time_invalid')
  return milliseconds
}

function cacheKey(repository) {
  return repository.full_name.toLowerCase()
}

function trimCache(cache) {
  while (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value)
}

async function boundedJson(response) {
  const declaredLength = Number.parseInt(response.headers.get('content-length') || '0', 10)
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw publicError('github_response_too_large', 502)
  }
  if (!String(response.headers.get('content-type') || '').toLowerCase().includes('json')) {
    throw publicError('github_response_invalid', 502)
  }

  const chunks = []
  let bytes = 0
  if (response.body) {
    const reader = response.body.getReader()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > MAX_RESPONSE_BYTES) {
        await reader.cancel()
        throw publicError('github_response_too_large', 502)
      }
      chunks.push(Buffer.from(value))
    }
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw publicError('github_response_invalid', 502)
  }
}

async function githubGet(pathname, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch
  if (typeof fetchImpl !== 'function') throw publicError('github_source_unavailable', 503)
  const url = new URL(pathname, GITHUB_API_ORIGIN)
  if (url.origin !== GITHUB_API_ORIGIN) throw new Error('github_destination_not_allowlisted')

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || DEFAULT_TIMEOUT_MS)
  try {
    const response = await fetchImpl(url, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': GITHUB_USER_AGENT,
        'X-GitHub-Api-Version': GITHUB_API_VERSION,
      },
      redirect: 'error',
      cache: 'no-store',
      signal: controller.signal,
    })
    if (response.status === 404) throw publicError('github_repository_not_found_or_private', 404)
    if (response.status === 409) throw publicError('github_repository_has_no_default_branch_head', 409)
    if (response.status === 403 || response.status === 429) throw publicError('github_read_limit_reached', 429)
    if (!response.ok) throw publicError('github_source_unavailable', 502)
    return await boundedJson(response)
  } catch (error) {
    if (error?.statusCode) throw error
    if (controller.signal.aborted || error?.name === 'AbortError') throw publicError('github_source_timeout', 504)
    throw publicError('github_source_unavailable', 502)
  } finally {
    clearTimeout(timeout)
  }
}

function encodedPathSegment(value) {
  return encodeURIComponent(value)
}

function encodedBranchPath(branch) {
  return branch.split('/').map(encodedPathSegment).join('/')
}

export async function observeMoneypennyPublicGitHubRepository(repositoryInput, options = {}) {
  const requested = parsePublicGitHubRepository(repositoryInput)
  const observedNow = nowMilliseconds(options.now)
  const cache = options.cache instanceof Map ? options.cache : null
  const ttl = Number.isFinite(options.cacheTtlMs) ? Math.max(0, options.cacheTtlMs) : DEFAULT_CACHE_TTL_MS
  const key = cacheKey(requested)
  const cached = cache?.get(key)
  if (cached && observedNow - cached.cached_at_ms <= ttl) {
    return {
      ...cached.observation,
      cache_hit: true,
      cache_age_ms: Math.max(0, observedNow - cached.cached_at_ms),
      network_request_count: 0,
    }
  }

  const repositoryPath = `/repos/${encodedPathSegment(requested.owner)}/${encodedPathSegment(requested.repository)}`
  const metadata = await githubGet(repositoryPath, options)
  const canonical = parsePublicGitHubRepository(metadata?.full_name || '')
  if (canonical.full_name.toLowerCase() !== requested.full_name.toLowerCase()
    || metadata?.private !== false
    || (metadata?.visibility !== undefined && metadata.visibility !== 'public')) {
    throw publicError('github_repository_not_public', 422)
  }

  const defaultBranch = safeBranch(metadata.default_branch)
  const reference = await githubGet(
    `${repositoryPath}/git/ref/heads/${encodedBranchPath(defaultBranch)}`,
    options,
  )
  const expectedRef = `refs/heads/${defaultBranch}`
  const head = String(reference?.object?.sha || '').toLowerCase()
  if (reference?.ref !== expectedRef || reference?.object?.type !== 'commit' || !HASH_PATTERN.test(head)) {
    throw publicError('github_reference_invalid', 502)
  }

  const observedAt = new Date(observedNow).toISOString()
  const observation = {
    ok: true,
    source: 'github_rest_api',
    source_scope: 'selected_public_repository_metadata_and_default_branch_ref',
    source_label: 'Live GitHub',
    observed_at: observedAt,
    observation_id: `github_${fingerprint([
      canonical.full_name.toLowerCase(),
      defaultBranch,
      head,
      observedAt,
    ].join(':')).slice(7, 23)}`,
    repository_full_name: canonical.full_name,
    repository_url: canonical.html_url,
    default_branch: defaultBranch,
    head_full: head,
    head_short: head.slice(0, 12),
    visibility: 'public',
    archived: metadata.archived === true,
    cache_hit: false,
    cache_age_ms: 0,
    network_request_count: 2,
    credentials_used: false,
    raw_response_returned: false,
    file_names_requested: false,
    file_names_returned: false,
    file_contents_requested: false,
    file_contents_returned: false,
    commit_details_requested: false,
    repository_write_performed: false,
    external_action_performed: false,
  }
  if (cache) {
    trimCache(cache)
    cache.set(key, { cached_at_ms: observedNow, observation })
  }
  return observation
}

function addClaim(claims, claim) {
  const key = `${claim.fact}:${String(claim.claimed).toLowerCase()}`
  if (!claims.some((candidate) => `${candidate.fact}:${String(candidate.claimed).toLowerCase()}` === key)) {
    claims.push(claim)
  }
}

function trimClaimToken(value = '') {
  return String(value).replace(/[.,;:!?]+$/g, '')
}

function parseMoneypennyPublicGitHubClaimMatches(value = '') {
  const text = normalizedInput(value).slice(0, MAX_AGENT_OUTPUT_CHARS)
  const claims = []
  const ranges = []

  function record(match, claim) {
    addClaim(claims, claim)
    ranges.push([match.index, match.index + match[0].length])
  }

  const repositoryPattern = /\b(?:github\s+)?repository\s*(?:is|=|:)\s*([a-z0-9][a-z0-9-]{0,38}\/[a-z0-9._-]{1,100})\b/gi
  for (const match of text.matchAll(repositoryPattern)) {
    try {
      record(match, { fact: 'repository', claimed: parsePublicGitHubRepository(match[1]).full_name })
    } catch {
      // Unparseable repository-shaped text is not treated as evidence.
    }
  }

  const branchPattern = /\b(?:github\s+)?default\s+branch\s*(?:is|=|:)\s*["'`]?([a-z0-9][a-z0-9._/-]{0,254})/gi
  for (const match of text.matchAll(branchPattern)) {
    const claimed = trimClaimToken(match[1])
    if (BRANCH_PATTERN.test(claimed)) record(match, { fact: 'default_branch', claimed })
  }

  const headPattern = /\b(?:git(?:hub)?\s+)?(?:head|commit)(?:\s+(?:hash|sha))?\s*(?:is|=|:)\s*([a-f0-9]{7,64})\b/gi
  for (const match of text.matchAll(headPattern)) {
    record(match, { fact: 'head', claimed: match[1].toLowerCase() })
  }

  const visibilityPattern = /\b(?:github\s+)?repository\s+(?:visibility\s+)?(?:is|=|:)\s*(public|private)\b/gi
  for (const match of text.matchAll(visibilityPattern)) {
    record(match, { fact: 'visibility', claimed: match[1].toLowerCase() })
  }

  const archivedPattern = /\b(?:github\s+)?repository\s+(?:is\s+)?(not\s+)?archived\b/gi
  for (const match of text.matchAll(archivedPattern)) {
    record(match, { fact: 'archived', claimed: !match[1] })
  }

  return { text, claims, ranges }
}

export function parseMoneypennyPublicGitHubClaims(value = '') {
  return parseMoneypennyPublicGitHubClaimMatches(value).claims
}

function unmatchedCheckableClaims(details, input = {}) {
  let residual = details.text
  for (const [start, end] of [...details.ranges].sort((left, right) => right[0] - left[0])) {
    residual = `${residual.slice(0, start)}${' '.repeat(end - start)}${residual.slice(end)}`
  }
  if (!/[a-z0-9]/i.test(residual)) return []
  const review = reviewMoneypennyAgentOutput({
    source_label: input?.source_label || input?.sourceLabel || 'Outside coding agent',
    task: input?.task || 'Check repository claims against live public GitHub.',
    agent_output: residual,
  })
  return (review.claims || []).filter((claim) => claim.checkable)
}

function assessedClaim(claim, observation) {
  let supported = false
  let text
  let reason
  if (claim.fact === 'repository') {
    supported = claim.claimed.toLowerCase() === observation.repository_full_name.toLowerCase()
    text = `GitHub repository is ${claim.claimed}.`
    reason = supported
      ? `Live GitHub confirms the selected repository is ${observation.repository_full_name}.`
      : `Live GitHub checked ${observation.repository_full_name}, not ${claim.claimed}.`
  } else if (claim.fact === 'default_branch') {
    supported = claim.claimed === observation.default_branch
    text = `GitHub default branch is ${claim.claimed}.`
    reason = supported
      ? `Live GitHub confirms the default branch is ${observation.default_branch}.`
      : `Live GitHub reports the default branch is ${observation.default_branch}.`
  } else if (claim.fact === 'head') {
    supported = observation.head_full.startsWith(claim.claimed)
    text = `GitHub default-branch HEAD is ${claim.claimed.slice(0, 12)}.`
    reason = supported
      ? `Live GitHub confirms HEAD ${observation.head_short}.`
      : `Live GitHub reports HEAD ${observation.head_short}, not the claimed revision.`
  } else if (claim.fact === 'visibility') {
    supported = claim.claimed === observation.visibility
    text = `GitHub repository visibility is ${claim.claimed}.`
    reason = supported
      ? 'Live GitHub confirms the repository is public.'
      : 'Live GitHub confirms the selected repository is public.'
  } else {
    supported = claim.claimed === observation.archived
    text = `GitHub repository is ${claim.claimed ? '' : 'not '}archived.`
    reason = supported
      ? `Live GitHub confirms the repository is ${observation.archived ? '' : 'not '}archived.`
      : `Live GitHub reports the repository is ${observation.archived ? '' : 'not '}archived.`
  }
  return {
    id: `github_${claim.fact}_${fingerprint(String(claim.claimed)).slice(7, 15)}`,
    type: 'factual_claim',
    text,
    checkable: true,
    matched_actions: [],
    assessment: supported ? 'supported' : 'contradicted',
    reason,
    evidence_level: 'direct_public_source_readback',
  }
}

function githubVerdict(sourceClaims, unmatchedClaims) {
  if (sourceClaims.some((claim) => claim.assessment === 'contradicted')) {
    return {
      code: 'contradicted',
      label: 'Contradicted by live GitHub',
      decision: 'blocked',
      confidence: 'high',
      summary: 'At least one recognised repository claim conflicts with GitHub\'s current public metadata or default-branch reference.',
      next_action: 'Do not rely on the report until its repository facts match the live public source.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.assessment === 'unverified_completion')) {
    return {
      code: 'unverified_completion',
      label: 'Other completion unverified',
      decision: 'hold',
      confidence: 'high',
      summary: 'The listed GitHub facts may match, but another completion claim in the same report was not established by GitHub.',
      next_action: 'Verify the additional action at its real destination before relying on the report.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.assessment === 'approval_required')) {
    return {
      code: 'approval_required',
      label: 'Separate approval required',
      decision: 'hold',
      confidence: 'high',
      summary: 'The report includes a proposed action that the GitHub check cannot authorize.',
      next_action: 'Review that action separately and grant explicit approval only through its controlled workflow.',
    }
  }
  if (unmatchedClaims.some((claim) => claim.checkable && claim.assessment !== 'supported')) {
    return {
      code: 'evidence_missing',
      label: 'Other claim needs evidence',
      decision: 'review',
      confidence: 'high',
      summary: 'The listed GitHub facts may match, but another checkable claim in the report remains unsupported.',
      next_action: 'Request a source check for the unmatched claim before relying on the complete report.',
    }
  }
  if (!sourceClaims.length) {
    return {
      code: 'evidence_missing',
      label: 'No GitHub fact found',
      decision: 'review',
      confidence: 'high',
      summary: 'The public repository was reached, but the report contained no recognised repository, default-branch, revision, visibility, or archive-state claim.',
      next_action: 'Ask the agent to state one of the supported GitHub facts explicitly.',
    }
  }
  return {
    code: 'supported',
    label: 'Confirmed by live GitHub',
    decision: 'supported',
    confidence: 'high',
    summary: 'Every recognised repository fact matches GitHub\'s current public metadata and default-branch reference.',
    next_action: 'Treat only the listed public GitHub facts as supported. Other claims still need their own source check.',
  }
}

function blockedBeforeGitHub(preflight) {
  return {
    ...preflight,
    status: 'moneypenny_public_github_reality_check_blocked',
    feature_tag: MONEYPENNY_PUBLIC_GITHUB_FEATURE_TAG,
    route: MONEYPENNY_PUBLIC_GITHUB_ROUTE,
    connector: {
      program: 'github_rest_api',
      invoked: false,
      reason: 'untrusted_input_blocked_before_network_use',
      destination_allowlist: ['api.github.com'],
      credentials_allowed: false,
      arbitrary_urls_allowed: false,
      write_methods_allowed: false,
    },
    cloud_model_used: false,
    source_api_call_performed: false,
    network_egress: false,
    write_action_performed: false,
    repository_write_performed: false,
    external_action_performed: false,
    proofEvents: [
      ...(preflight.proofEvents || []),
      'GitHub connector not invoked because untrusted input was blocked',
    ],
  }
}

function preflightReview(input = {}) {
  return reviewMoneypennyAgentOutput({
    source_label: input?.source_label || input?.sourceLabel || 'Outside coding agent',
    task: input?.task || 'Check repository claims against live public GitHub.',
    agent_output: String(input?.agent_output ?? input?.agentOutput ?? input?.output ?? ''),
  })
}

function reviewWithObservation(input, preflight, observation) {
  const agentOutput = String(input?.agent_output ?? input?.agentOutput ?? input?.output ?? '')
  const parsedClaims = parseMoneypennyPublicGitHubClaimMatches(agentOutput)
  const sourceClaims = parsedClaims.claims.map((claim) => assessedClaim(claim, observation))
  const unmatchedClaims = unmatchedCheckableClaims(parsedClaims, input)
  const claims = [...sourceClaims, ...unmatchedClaims]
  const verdict = githubVerdict(sourceClaims, unmatchedClaims)
  const reviewId = `github_review_${fingerprint([
    preflight.source_label,
    preflight.fingerprints?.agent_output,
    observation.observation_id,
  ].join(':')).slice(7, 23)}`
  const reviewReceipt = createMoneypennyCompletionReceipt({
    operation_id: reviewId,
    operation_type: 'public_github_reality_check',
    outcome: 'completed',
    source: 'public_github_readback',
    changed: false,
    persisted: false,
    readback_verified: true,
    approval_required: verdict.code === 'approval_required',
    external_action_performed: false,
  })
  const networkRequestPerformed = observation.network_request_count > 0

  return {
    ok: true,
    status: 'moneypenny_public_github_reality_check_complete',
    feature_tag: MONEYPENNY_PUBLIC_GITHUB_FEATURE_TAG,
    route: MONEYPENNY_PUBLIC_GITHUB_ROUTE,
    payload_class: 'untrusted_agent_output_fixed_public_github_readback',
    review_id: reviewId,
    source_label: preflight.source_label,
    verdict,
    reply: [
      `Public GitHub reality check: ${verdict.label}.`,
      verdict.summary,
      verdict.next_action,
      `Readback boundary: ${observation.repository_full_name}, public metadata and default-branch reference only.`,
      'Action: Repository unchanged.',
    ].join(' '),
    claims,
    evidence: {
      kind: 'moneypenny_public_github_readback',
      supplied: false,
      independently_verified: true,
      source: 'github_rest_api',
      source_scope: observation.source_scope,
      observed_at: observation.observed_at,
      observation_id: observation.observation_id,
      cache_hit: observation.cache_hit,
      cache_age_ms: observation.cache_age_ms,
      safe_facts: {
        repository: observation.repository_full_name,
        repository_url: observation.repository_url,
        default_branch: observation.default_branch,
        head_short: observation.head_short,
        visibility: observation.visibility,
        archived: observation.archived,
      },
      event_count: claims.length,
      raw_response_returned: false,
      file_names_requested: false,
      file_names_returned: false,
      file_contents_requested: false,
      file_contents_returned: false,
      commit_details_requested: false,
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
      program: 'github_rest_api',
      invoked: true,
      operation_scope: 'fixed_public_metadata_and_default_branch_ref',
      destination_allowlist: ['api.github.com'],
      request_method: 'GET',
      network_request_count: observation.network_request_count,
      credentials_used: false,
      public_repositories_only: true,
      claimant_supplied_arbitrary_urls_allowed: false,
      claimant_supplied_commands_allowed: false,
      shell_used: false,
      repository_changed: false,
      raw_response_returned: false,
    },
    cloud_model_used: false,
    model_provider_call_performed: false,
    source_api_call_performed: networkRequestPerformed,
    tool_call_performed: true,
    external_program_call_performed: false,
    network_egress: networkRequestPerformed,
    private_context_used: false,
    conversation_context_used: false,
    write_action_performed: false,
    repository_write_performed: false,
    external_action_performed: false,
    current_request_changed_state: false,
    raw_agent_output_persisted: false,
    raw_github_response_persisted: false,
    proofEvents: [
      'External agent output treated as untrusted data',
      'Prompt security boundary checked before network use',
      observation.cache_hit ? 'Recent bounded GitHub observation reused from memory cache' : 'Fixed read-only GitHub API connector invoked',
      'Public repository metadata and exact default-branch reference checked',
      sourceClaims.length ? 'Recognised GitHub claims compared with direct source readback' : 'No recognised GitHub claim found',
      unmatchedClaims.length ? 'Unmatched checkable claims retained for separate verification' : '',
      verdict.code === 'contradicted' ? 'Conflicting agent claim blocked' : '',
      'No credentials, file names, file contents, commit details, or raw GitHub response requested',
      'No repository write or external action used',
      'Public GitHub reality-check receipt created',
    ].filter(Boolean),
  }
}

export async function reviewMoneypennyPublicGitHubClaim(input = {}, options = {}) {
  const preflight = preflightReview(input)
  if (!preflight.ok || BLOCKED_PREFLIGHT_VERDICTS.has(preflight.verdict?.code)) {
    return blockedBeforeGitHub(preflight)
  }
  const observation = await observeMoneypennyPublicGitHubRepository(options.repository, options)
  return reviewWithObservation(input, preflight, observation)
}

function alternateHash(hash) {
  return `${hash[0] === '0' ? '1' : '0'}${hash.slice(1)}`
}

export function publicGitHubScenarioClaim(observation, mode = 'confirmed') {
  if (mode !== 'confirmed' && mode !== 'contradicted') throw publicError('github_demo_mode_unknown', 400)
  const head = mode === 'confirmed' ? observation.head_short : alternateHash(observation.head_short)
  return [
    `GitHub repository is ${observation.repository_full_name}.`,
    `The default branch is ${observation.default_branch}.`,
    `Git HEAD is ${head}.`,
    'The repository is public.',
    `The repository is ${observation.archived ? '' : 'not '}archived.`,
  ].join(' ')
}

export async function runMoneypennyPublicGitHubDemo({ repository, mode } = {}, options = {}) {
  if (mode !== 'confirmed' && mode !== 'contradicted') throw publicError('github_demo_mode_unknown', 400)
  const observation = await observeMoneypennyPublicGitHubRepository(repository, options)
  const agentOutput = publicGitHubScenarioClaim(observation, mode)
  const input = {
    source_label: 'Synthetic outside coding agent',
    task: 'Check a generated coding-agent report against a real public GitHub repository.',
    agent_output: agentOutput,
  }
  const preflight = preflightReview(input)
  const result = reviewWithObservation(input, preflight, observation)
  return {
    ...result,
    demo: {
      synthetic_claim: true,
      real_public_source: true,
      agent_output: agentOutput,
      mode,
      repository: observation.repository_full_name,
    },
  }
}

export function moneypennyPublicGitHubRuntimeStatus() {
  return {
    ok: true,
    feature_tag: MONEYPENNY_PUBLIC_GITHUB_FEATURE_TAG,
    route: MONEYPENNY_PUBLIC_GITHUB_ROUTE,
    enabled: true,
    program: 'github_rest_api',
    destination_allowlist: ['api.github.com'],
    operation_scope: 'fixed_public_metadata_and_default_branch_ref',
    request_method: 'GET',
    public_repositories_only: true,
    credentials_enabled: false,
    arbitrary_urls_allowed: false,
    redirects_allowed: false,
    file_names_requested: false,
    file_contents_requested: false,
    commit_details_requested: false,
    repository_writes_enabled: false,
    cache_ttl_seconds: DEFAULT_CACHE_TTL_MS / 1000,
  }
}
