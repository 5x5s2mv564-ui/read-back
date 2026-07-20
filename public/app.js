const elements = {
  tabs: Array.from(document.querySelectorAll('[data-tab]')),
  panels: Array.from(document.querySelectorAll('[data-panel]')),
  scenarios: Array.from(document.querySelectorAll('[data-scenario]')),
  gitDemos: Array.from(document.querySelectorAll('[data-git-demo]')),
  gitForm: document.querySelector('[data-git-form]'),
  gitReport: document.querySelector('[data-git-form] [name="agent_output"]'),
  reviewForm: document.querySelector('[data-review-form]'),
  runtime: document.querySelector('.runtime-state'),
  runtimeLabel: document.querySelector('[data-runtime-label]'),
  runtimeScope: document.querySelector('[data-runtime-scope]'),
  gitSource: document.querySelector('[data-git-source]'),
  gitTab: document.querySelector('[data-git-tab]'),
  gitHeading: document.querySelector('[data-git-heading]'),
  gitConfirmLabel: document.querySelector('[data-git-confirm-label]'),
  gitConfirmNote: document.querySelector('[data-git-confirm-note]'),
  gitContradictNote: document.querySelector('[data-git-contradict-note]'),
  gitFieldNote: document.querySelector('[data-git-field-note]'),
  gitSubmit: document.querySelector('[data-git-submit]'),
  githubControls: document.querySelector('[data-github-controls]'),
  githubRepository: document.querySelector('[name="repository"]'),
  contractCommands: document.querySelector('[data-contract-commands]'),
  contractNetwork: document.querySelector('[data-contract-network]'),
  contractFiles: document.querySelector('[data-contract-files]'),
  editionLabel: document.querySelector('[data-edition-label]'),
  reviewBoundary: document.querySelector('[data-review-boundary]'),
  resultPane: document.querySelector('.result-pane'),
  resultEmpty: document.querySelector('[data-result-empty]'),
  result: document.querySelector('[data-result]'),
  verdictLabel: document.querySelector('[data-verdict-label]'),
  verdictDecision: document.querySelector('[data-verdict-decision]'),
  verdictSummary: document.querySelector('[data-verdict-summary]'),
  factEvidence: document.querySelector('[data-fact-evidence]'),
  factAuthority: document.querySelector('[data-fact-authority]'),
  factCompletion: document.querySelector('[data-fact-completion]'),
  factSecurity: document.querySelector('[data-fact-security]'),
  claimCount: document.querySelector('[data-claim-count]'),
  claims: document.querySelector('[data-claims]'),
  nextAction: document.querySelector('[data-next-action]'),
  receipt: document.querySelector('[data-receipt]'),
  technicalRecord: document.querySelector('[data-technical-record]'),
}

let gitReviewTask = 'Check this repository claim against live Git.'
let hostedGithubMode = false

function resetResult() {
  elements.result.hidden = true
  elements.resultEmpty.hidden = false
  elements.result.removeAttribute('data-verdict')
  elements.claims.replaceChildren()
  elements.claimCount.textContent = '0'
  elements.technicalRecord.textContent = ''
}

function setTab(id, { focus = false } = {}) {
  const selectedTab = elements.tabs.find((tab) => tab.dataset.tab === id)
  if (!selectedTab) return

  const changed = selectedTab.getAttribute('aria-selected') !== 'true'
  for (const tab of elements.tabs) {
    const selected = tab === selectedTab
    tab.setAttribute('aria-selected', String(selected))
    tab.tabIndex = selected ? 0 : -1
  }
  if (changed) {
    for (const panel of elements.panels) panel.hidden = panel.dataset.panel !== id
    for (const scenario of elements.scenarios) scenario.setAttribute('aria-pressed', 'false')
    resetResult()
  }
  if (focus) selectedTab.focus()
}

function handleTabKeydown(event) {
  const currentIndex = elements.tabs.indexOf(event.currentTarget)
  let nextIndex
  if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % elements.tabs.length
  else if (event.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + elements.tabs.length) % elements.tabs.length
  else if (event.key === 'Home') nextIndex = 0
  else if (event.key === 'End') nextIndex = elements.tabs.length - 1
  else return

  event.preventDefault()
  setTab(elements.tabs[nextIndex].dataset.tab, { focus: true })
}

function setBusy(busy) {
  elements.resultPane.setAttribute('aria-busy', String(busy))
  for (const button of document.querySelectorAll('button')) button.disabled = busy
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    method: options.method || 'GET',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    body: options.body ? JSON.stringify(options.body) : undefined,
  })
  const body = await response.json().catch(() => ({ ok: false, error: 'invalid_server_response' }))
  if (!response.ok) {
    const error = new Error(body.error || `request_failed_${response.status}`)
    error.status = response.status
    throw error
  }
  return body
}

function evidenceLabel(result) {
  const evidence = result.evidence || {}
  if (evidence.kind === 'moneypenny_public_github_readback') return 'Live public GitHub readback'
  if (evidence.kind === 'moneypenny_synthetic_git_snapshot') return 'Bundled synthetic snapshot'
  if (evidence.kind === 'moneypenny_git_readback') return 'Direct Git readback'
  if (evidence.independently_verified) return 'Trusted signed proof'
  if (evidence.cryptographically_verified && evidence.signer_trusted === false) return 'Valid signature, unknown signer'
  if (evidence.tamper_detected || evidence.invalid) return 'Verification failed'
  if (evidence.supplied) return 'Supplied but unverified'
  return 'No independent evidence'
}

function completionLabel(result) {
  if (result.completion?.reviewed_action_verified) return 'Claimed action supported'
  if (result.completion?.review_completed) return 'Review only; action unverified'
  return 'Not established'
}

function securityLabel(result) {
  const security = result.security || {}
  if ((security.finding_ids || []).length || (security.sensitive_value_findings || []).length) return 'Untrusted content blocked'
  if (result.completion?.review_completed !== true) return 'Not checked'
  return 'Input isolated safely'
}

function renderClaims(claims = []) {
  const fragment = document.createDocumentFragment()
  for (const claim of claims) {
    const item = document.createElement('li')
    item.dataset.assessment = String(claim.assessment || 'unknown')

    const status = document.createElement('strong')
    status.textContent = String(claim.assessment || 'unknown').replaceAll('_', ' ')
    const text = document.createElement('p')
    text.textContent = claim.text || 'Claim text withheld.'
    const reason = document.createElement('small')
    reason.textContent = claim.reason || 'No reason supplied.'
    item.append(status, text, reason)
    fragment.append(item)
  }
  elements.claims.replaceChildren(fragment)
  elements.claimCount.textContent = String(claims.length)
}

function renderResult(result) {
  const verdict = result.verdict || {
    code: 'error',
    label: 'Review unavailable',
    decision: 'blocked',
    summary: result.error || 'The request failed safely.',
    next_action: 'Check the local runtime and try again.',
  }

  elements.resultEmpty.hidden = true
  elements.result.hidden = false
  elements.result.dataset.verdict = verdict.code || 'error'
  elements.verdictLabel.textContent = verdict.label || 'Review complete'
  elements.verdictDecision.textContent = verdict.decision || 'review'
  elements.verdictSummary.textContent = verdict.summary || result.reply || 'No summary returned.'
  elements.factEvidence.textContent = evidenceLabel(result)
  elements.factAuthority.textContent = result.authority?.review_grants_new_authority === false ? 'No new authority' : 'Not established'
  elements.factCompletion.textContent = completionLabel(result)
  elements.factSecurity.textContent = securityLabel(result)
  renderClaims(Array.isArray(result.claims) ? result.claims : [])
  elements.nextAction.textContent = verdict.next_action || 'Review the result before taking any action.'
  elements.receipt.textContent = result.completion?.review_completed !== true
    ? 'Review did not complete. Nothing changed.'
    : result.write_action_performed === false && result.external_action_performed === false
      ? 'Review completed. Nothing changed.'
      : 'Review completed. Inspect the technical record before relying on the change status.'
  elements.technicalRecord.textContent = JSON.stringify(result, null, 2)
  requestAnimationFrame(() => {
    elements.verdictLabel.focus({ preventScroll: true })
    if (window.matchMedia('(max-width: 960px)').matches) {
      const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
      elements.resultPane.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' })
    }
  })
}

function renderError(error) {
  if (!Number.isInteger(error.status)) {
    elements.runtime.dataset.runtimeState = 'error'
    elements.runtimeLabel.textContent = 'Runtime unavailable'
  }
  const knownErrors = {
    github_repository_invalid: {
      summary: 'The repository address is not in a supported GitHub format.',
      next: 'Enter owner/repository or a public https://github.com/owner/repository URL.',
    },
    github_repository_must_be_public_github: {
      summary: 'Only public repositories on github.com can be checked.',
      next: 'Choose a public github.com repository. Private repositories and other hosts are refused.',
    },
    github_repository_not_found_or_private: {
      summary: 'GitHub did not expose that repository as a public source.',
      next: 'Check the spelling and confirm the repository is public.',
    },
    github_repository_not_public: {
      summary: 'The selected repository is not publicly readable.',
      next: 'Choose a public GitHub repository.',
    },
    github_repository_has_no_default_branch_head: {
      summary: 'The repository has no readable default-branch revision yet.',
      next: 'Choose a non-empty public repository.',
    },
    github_read_limit_reached: {
      summary: 'GitHub has temporarily limited anonymous public reads from this demo.',
      next: 'Wait for GitHub’s read window to reset, then try again. No fallback evidence was invented.',
    },
  }
  const message = knownErrors[error.message]
  renderResult({
    error: error.message,
    verdict: {
      code: 'error',
      label: 'Failed safely',
      decision: 'blocked',
      summary: message?.summary || 'The review could not complete.',
      next_action: message?.next || 'Refresh the runtime, then try again.',
    },
    authority: { review_grants_new_authority: false },
    completion: { review_completed: false, reviewed_action_verified: false },
    security: {},
    claims: [],
    write_action_performed: false,
    external_action_performed: false,
  })
}

async function run(path, body) {
  setBusy(true)
  try {
    const result = await requestJson(path, { method: 'POST', body })
    renderResult(result)
    return result
  } catch (error) {
    renderError(error)
    return null
  } finally {
    setBusy(false)
  }
}

async function loadStatus() {
  try {
    const status = await requestJson('/api/status')
    const hosted = status.deployment_mode === 'hosted_public_demo'
    const snapshot = status.git_connector?.source_mode === 'bundled_synthetic_snapshot'
    const publicGithub = hosted && status.github_connector?.ui_enabled === true
    elements.runtime.dataset.runtimeState = 'ready'
    elements.runtimeLabel.textContent = hosted ? 'Public demo ready' : 'Local runtime ready'
    elements.runtimeScope.textContent = hosted ? 'Public demo' : 'Local'
    elements.editionLabel.textContent = hosted ? 'Isolated public competition demo' : 'Local-only competition edition'
    elements.reviewBoundary.textContent = hosted
      ? 'Public demo: use synthetic content only. Do not paste personal or secret data.'
      : 'Local review only. Raw input is not persisted.'
    elements.gitSource.textContent = publicGithub
      ? 'Live public source'
      : snapshot
        ? 'Synthetic snapshot'
        : status.git_connector?.synthetic ? 'Synthetic Git' : 'Live clone'
    if (publicGithub) {
      hostedGithubMode = true
      elements.githubControls.hidden = false
      elements.gitTab.textContent = 'Public GitHub'
      elements.gitHeading.textContent = 'Live public repository check'
      elements.gitConfirmLabel.textContent = 'Confirm current facts'
      elements.gitConfirmNote.textContent = 'Generate a report and verify it against GitHub now'
      elements.gitContradictNote.textContent = 'Generate a false revision and watch Money Penny block it'
      elements.gitFieldNote.textContent = 'The report is untrusted. Money Penny checks only public metadata and the default-branch reference.'
      elements.gitSubmit.textContent = 'Check against live GitHub'
      elements.gitReport.value = 'GitHub repository is openai/openai-node. The default branch is main. The repository is public.'
      elements.contractCommands.textContent = 'None'
      elements.contractNetwork.textContent = 'api.github.com only'
      elements.contractFiles.textContent = 'Never requested'
      gitReviewTask = 'Check this repository claim against live public GitHub.'
    } else if (snapshot) {
      elements.gitTab.textContent = 'Git Proof Lab'
      elements.gitHeading.textContent = 'Git snapshot check'
      elements.gitConfirmLabel.textContent = 'Confirm snapshot facts'
      elements.gitConfirmNote.textContent = 'Generate a claim that matches the bundled fixture'
      elements.gitFieldNote.textContent = 'Public demo fixture only. The report cannot supply a command or repository path.'
      elements.gitSubmit.textContent = 'Check against snapshot'
      gitReviewTask = 'Check this repository claim against the bundled synthetic Git snapshot.'
    }
  } catch {
    elements.runtime.dataset.runtimeState = 'error'
    elements.runtimeLabel.textContent = 'Runtime unavailable'
    elements.gitSource.textContent = 'Unavailable'
  }
}

for (const tab of elements.tabs) {
  tab.addEventListener('click', () => setTab(tab.dataset.tab))
  tab.addEventListener('keydown', handleTabKeydown)
}

for (const button of elements.scenarios) {
  button.setAttribute('aria-pressed', 'false')
  button.addEventListener('click', async () => {
    for (const candidate of elements.scenarios) candidate.setAttribute('aria-pressed', String(candidate === button))
    await run('/api/scenario', { id: button.dataset.scenario })
  })
}

for (const button of elements.gitDemos) {
  button.addEventListener('click', async () => {
    if (hostedGithubMode && !elements.githubRepository.reportValidity()) return
    const result = await run(hostedGithubMode ? '/api/github-demo' : '/api/git-demo', {
      mode: button.dataset.gitDemo,
      repository: hostedGithubMode ? elements.githubRepository.value : undefined,
    })
    if (result?.demo?.agent_output) elements.gitReport.value = result.demo.agent_output
  })
}

elements.gitForm.addEventListener('submit', (event) => {
  event.preventDefault()
  const data = new FormData(elements.gitForm)
  run(hostedGithubMode ? '/api/github-review' : '/api/git-review', {
    source_label: 'Outside coding agent',
    task: gitReviewTask,
    agent_output: data.get('agent_output'),
    repository: hostedGithubMode ? data.get('repository') : undefined,
  })
})

elements.reviewForm.addEventListener('submit', (event) => {
  event.preventDefault()
  const data = new FormData(elements.reviewForm)
  const evidenceText = String(data.get('evidence') || '').trim()
  let evidence = evidenceText
  if (evidenceText.startsWith('{')) {
    try {
      evidence = JSON.parse(evidenceText)
    } catch {
      evidence = evidenceText
    }
  }
  run('/api/review', {
    source_label: data.get('source_label'),
    task: data.get('task'),
    agent_output: data.get('agent_output'),
    evidence,
    prior_approval: data.get('prior_approval') === 'on',
  })
})

elements.reviewForm.addEventListener('reset', () => {
  resetResult()
})

loadStatus()
