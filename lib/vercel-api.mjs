import { reviewMoneypennyAgentOutput } from '../foundry/moneypenny-agent-review.mjs'
import {
  observeMoneypennyGitRepository,
  reviewMoneypennyGitClaim,
} from '../foundry/moneypenny-git-reality-check.mjs'
import {
  reviewMoneypennyPublicGitHubClaim,
  runMoneypennyPublicGitHubDemo,
} from '../foundry/moneypenny-public-github-reality-check.mjs'
import {
  competitionPublicStatus,
  createCompetitionRuntime,
  safeReviewInput,
} from '../server.mjs'
import { gitScenarioClaim } from './git-demo.mjs'

const MAX_BODY_BYTES = 96 * 1024
const SCENARIO_IDS = new Set(['unproven', 'verified', 'unknown_signer', 'tampered', 'prompt_attack'])
const GIT_DEMO_MODES = new Set(['confirmed', 'contradicted'])
const SECURITY_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow',
})

let runtime

function competitionRuntime() {
  if (!runtime) runtime = createCompetitionRuntime({ gitMode: 'synthetic_snapshot' })
  return runtime
}

function applySecurityHeaders(response) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(name, value)
}

function sendJson(response, statusCode, value) {
  applySecurityHeaders(response)
  response.statusCode = statusCode
  response.setHeader('Content-Type', 'application/json; charset=utf-8')
  response.end(`${JSON.stringify(value)}\n`)
}

function requestOriginAllowed(request) {
  const origin = String(request.headers.origin || '').trim().toLowerCase()
  if (!origin) return true
  try {
    const parsed = new URL(origin)
    const host = String(request.headers.host || '').trim().toLowerCase()
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && parsed.host === host
  } catch {
    return false
  }
}

function objectBody(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Buffer.isBuffer(value)) {
    throw Object.assign(new Error('json_body_invalid'), { statusCode: 400 })
  }
  if (Buffer.byteLength(JSON.stringify(value), 'utf8') > MAX_BODY_BYTES) {
    throw Object.assign(new Error('request_body_too_large'), { statusCode: 413 })
  }
  return value
}

async function readJsonBody(request) {
  const contentType = String(request.headers['content-type'] || '').toLowerCase()
  if (!contentType.startsWith('application/json')) {
    throw Object.assign(new Error('json_content_type_required'), { statusCode: 415 })
  }

  let parsedBody
  try {
    parsedBody = request.body
  } catch {
    throw Object.assign(new Error('json_body_invalid'), { statusCode: 400 })
  }
  if (parsedBody !== undefined) {
    if (Buffer.isBuffer(parsedBody)) parsedBody = parsedBody.toString('utf8')
    if (typeof parsedBody === 'string') {
      if (Buffer.byteLength(parsedBody, 'utf8') > MAX_BODY_BYTES) {
        throw Object.assign(new Error('request_body_too_large'), { statusCode: 413 })
      }
      try {
        parsedBody = JSON.parse(parsedBody)
      } catch {
        throw Object.assign(new Error('json_body_invalid'), { statusCode: 400 })
      }
    }
    return objectBody(parsedBody)
  }

  const chunks = []
  let bytes = 0
  for await (const chunk of request) {
    bytes += chunk.length
    if (bytes > MAX_BODY_BYTES) {
      throw Object.assign(new Error('request_body_too_large'), { statusCode: 413 })
    }
    chunks.push(chunk)
  }
  try {
    return objectBody(JSON.parse(Buffer.concat(chunks).toString('utf8')))
  } catch (error) {
    if (error?.statusCode) throw error
    throw Object.assign(new Error('json_body_invalid'), { statusCode: 400 })
  }
}

function requireMethod(request, expected) {
  if (request.method !== expected) {
    throw Object.assign(new Error('method_not_allowed'), { statusCode: 405, allow: expected })
  }
}

function gitOptions(currentRuntime) {
  return {
    repoRoot: currentRuntime.git.repoRoot,
    runGit: currentRuntime.git.runGit,
    directProgramUsed: currentRuntime.git.directProgramUsed,
    observationSource: currentRuntime.git.observationSource,
    sourceScope: currentRuntime.git.sourceScope,
    observationLabel: currentRuntime.git.observationLabel,
  }
}

function publicGitHubOptions(currentRuntime, repository) {
  return {
    ...currentRuntime.github,
    repository,
  }
}

async function routeRequest(route, request) {
  const currentRuntime = competitionRuntime()

  if (route === 'health') {
    requireMethod(request, 'GET')
    return {
      statusCode: 200,
      body: {
        ok: true,
        status: 'ready',
        trust_lab_synthetic_only: true,
        public_github_readback: true,
        personal_data_used: false,
      },
    }
  }
  if (route === 'status') {
    requireMethod(request, 'GET')
    return {
      statusCode: 200,
      body: competitionPublicStatus(currentRuntime, { deploymentMode: 'hosted_public_demo' }),
    }
  }

  requireMethod(request, 'POST')
  const body = await readJsonBody(request)

  if (route === 'scenario') {
    const id = String(body.id || '')
    if (!SCENARIO_IDS.has(id)) throw Object.assign(new Error('trust_lab_scenario_unknown'), { statusCode: 400 })
    const input = currentRuntime.lab.inputFor(id)
    const result = reviewMoneypennyAgentOutput(input, {
      trustedKeyFingerprints: [currentRuntime.lab.trustedSignerFingerprint],
    })
    return { statusCode: 200, body: { ...result, demo: { synthetic_only: true, scenario_id: id } } }
  }

  if (route === 'review') {
    const result = reviewMoneypennyAgentOutput(safeReviewInput(body), {
      trustedKeyFingerprints: [currentRuntime.lab.trustedSignerFingerprint],
    })
    return { statusCode: result.ok ? 200 : 400, body: result }
  }

  if (route === 'git-review') {
    const result = await reviewMoneypennyGitClaim(safeReviewInput(body), gitOptions(currentRuntime))
    return { statusCode: result.ok ? 200 : 400, body: result }
  }

  if (route === 'git-demo') {
    const mode = String(body.mode || '')
    if (!GIT_DEMO_MODES.has(mode)) throw Object.assign(new Error('git_demo_mode_unknown'), { statusCode: 400 })
    const observation = await observeMoneypennyGitRepository(gitOptions(currentRuntime))
    const agentOutput = gitScenarioClaim(observation, mode)
    const result = await reviewMoneypennyGitClaim({
      source_label: 'Synthetic outside coding agent',
      task: 'Check the coding agent report against a bundled synthetic Git snapshot.',
      agent_output: agentOutput,
    }, gitOptions(currentRuntime))
    return {
      statusCode: 200,
      body: {
        ...result,
        demo: {
          synthetic_claim: true,
          agent_output: agentOutput,
          mode,
          source_mode: currentRuntime.git.sourceMode,
        },
      },
    }
  }


  if (route === 'github-review') {
    const result = await reviewMoneypennyPublicGitHubClaim(
      safeReviewInput(body),
      publicGitHubOptions(currentRuntime, body.repository),
    )
    return { statusCode: result.ok ? 200 : 400, body: result }
  }

  if (route === 'github-demo') {
    const mode = String(body.mode || '')
    if (!GIT_DEMO_MODES.has(mode)) throw Object.assign(new Error('github_demo_mode_unknown'), { statusCode: 400 })
    const result = await runMoneypennyPublicGitHubDemo({
      repository: body.repository,
      mode,
    }, publicGitHubOptions(currentRuntime, body.repository))
    return { statusCode: 200, body: result }
  }

  return { statusCode: 404, body: { ok: false, error: 'not_found' } }
}

export function createVercelHandler(route) {
  return async function handler(request, response) {
    try {
      if (!requestOriginAllowed(request)) {
        sendJson(response, 403, { ok: false, error: 'cross_origin_request_blocked' })
        return
      }
      const result = await routeRequest(route, request)
      sendJson(response, result.statusCode, result.body)
    } catch (error) {
      const knownStatus = Number(error?.statusCode)
      const statusCode = Number.isInteger(knownStatus) && knownStatus >= 400 && knownStatus <= 499 ? knownStatus : 500
      if (error?.allow) response.setHeader('Allow', error.allow)
      const publicError = statusCode < 500 ? String(error.message || 'request_rejected') : 'request_failed_safely'
      sendJson(response, statusCode, { ok: false, error: publicError, writes_performed: false })
    }
  }
}
