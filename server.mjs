#!/usr/bin/env node

import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import {
  moneypennyAgentReviewRuntimeStatus,
  reviewMoneypennyAgentOutput,
} from './foundry/moneypenny-agent-review.mjs'
import {
  moneypennyGitRealityCheckRuntimeStatus,
  observeMoneypennyGitRepository,
  reviewMoneypennyGitClaim,
} from './foundry/moneypenny-git-reality-check.mjs'
import {
  moneypennyPublicGitHubRuntimeStatus,
  reviewMoneypennyPublicGitHubClaim,
  runMoneypennyPublicGitHubDemo,
} from './foundry/moneypenny-public-github-reality-check.mjs'
import { prepareGitDemoRepository, gitScenarioClaim } from './lib/git-demo.mjs'
import { createTrustLab } from './lib/trust-lab.mjs'

const RELEASE_ROOT = path.dirname(fileURLToPath(import.meta.url))
const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 4574
const MAX_BODY_BYTES = 96 * 1024

const STATIC_FILES = Object.freeze({
  '/': ['public/index.html', 'text/html; charset=utf-8'],
  '/index.html': ['public/index.html', 'text/html; charset=utf-8'],
  '/app.js': ['public/app.js', 'text/javascript; charset=utf-8'],
  '/styles.css': ['public/styles.css', 'text/css; charset=utf-8'],
})

const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
})

function send(response, statusCode, body, headers = {}) {
  response.writeHead(statusCode, { ...SECURITY_HEADERS, 'Cache-Control': 'no-store', ...headers })
  response.end(body)
}

function sendJson(response, statusCode, value) {
  send(response, statusCode, `${JSON.stringify(value)}\n`, { 'Content-Type': 'application/json; charset=utf-8' })
}

function requestHostAllowed(request) {
  const host = String(request.headers.host || '').toLowerCase()
  return /^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(host)
}

function requestOriginAllowed(request) {
  const origin = String(request.headers.origin || '').trim().toLowerCase()
  if (!origin) return true
  try {
    const parsed = new URL(origin)
    return parsed.protocol === 'http:' && parsed.host === String(request.headers.host || '').toLowerCase()
  } catch {
    return false
  }
}

async function readJsonBody(request) {
  const contentType = String(request.headers['content-type'] || '').toLowerCase()
  if (!contentType.startsWith('application/json')) throw Object.assign(new Error('json_content_type_required'), { statusCode: 415 })
  const chunks = []
  let bytes = 0
  for await (const chunk of request) {
    bytes += chunk.length
    if (bytes > MAX_BODY_BYTES) throw Object.assign(new Error('request_body_too_large'), { statusCode: 413 })
    chunks.push(chunk)
  }
  if (!chunks.length) return {}
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid')
    return value
  } catch {
    throw Object.assign(new Error('json_body_invalid'), { statusCode: 400 })
  }
}

export function competitionPublicStatus(runtime, options = {}) {
  const deploymentMode = options.deploymentMode || 'local_competition_edition'
  const hostedPublicDemo = deploymentMode === 'hosted_public_demo'
  return {
    ok: true,
    product: 'Money Penny Readback',
    release: 'openai-build-week-2026',
    deployment_mode: deploymentMode,
    local_only: !hostedPublicDemo,
    public_demo: hostedPublicDemo,
    synthetic_data_only: false,
    trust_lab_synthetic_only: true,
    public_repository_data_enabled: true,
    private_service_connected: false,
    cloud_model_used: false,
    personal_data_used: false,
    writes_enabled: false,
    trusted_runner_count: 1,
    trust_lab_scenarios: runtime.lab.scenarios,
    git_connector: {
      ...moneypennyGitRealityCheckRuntimeStatus(),
      program: runtime.git.directProgramUsed ? 'git' : 'synthetic_git_snapshot',
      source_scope: runtime.git.sourceScope,
      operation_scope: runtime.git.directProgramUsed ? 'fixed_read_only' : 'fixed_synthetic_fixture',
      source_mode: runtime.git.sourceMode,
      source_label: runtime.git.label,
      synthetic: runtime.git.synthetic,
      direct_program_used: runtime.git.directProgramUsed,
      ui_enabled: !hostedPublicDemo,
    },
    github_connector: {
      ...moneypennyPublicGitHubRuntimeStatus(),
      ui_enabled: hostedPublicDemo,
    },
    honesty_filter: moneypennyAgentReviewRuntimeStatus({
      trustedKeyFingerprints: [runtime.lab.trustedSignerFingerprint],
    }),
  }
}

export function safeReviewInput(body) {
  return {
    source_label: body.source_label,
    task: body.task,
    agent_output: body.agent_output,
    evidence: body.evidence,
    prior_approval: body.prior_approval === true,
  }
}

export function createCompetitionRuntime(options = {}) {
  const lab = createTrustLab(options)
  const git = prepareGitDemoRepository({
    releaseRoot: path.resolve(options.repoRoot || RELEASE_ROOT),
    runtimeRoot: lab.root,
    mode: options.gitMode || 'auto',
  })
  const github = {
    fetchImpl: options.githubFetch,
    now: options.githubNow || options.now,
    timeoutMs: options.githubTimeoutMs,
    cacheTtlMs: options.githubCacheTtlMs,
    cache: new Map(),
  }
  return {
    lab,
    git,
    github,
    cleanup() {
      github.cache.clear()
      lab.cleanup()
    },
  }
}

function gitReviewOptions(runtime) {
  return {
    repoRoot: runtime.git.repoRoot,
    runGit: runtime.git.runGit,
    directProgramUsed: runtime.git.directProgramUsed,
    observationSource: runtime.git.observationSource,
    sourceScope: runtime.git.sourceScope,
    observationLabel: runtime.git.observationLabel,
  }
}

function publicGitHubOptions(runtime, repository) {
  return {
    ...runtime.github,
    repository,
  }
}

export function createCompetitionServer(options = {}) {
  const runtime = options.runtime || createCompetitionRuntime(options)
  const ownsRuntime = !options.runtime

  const server = createServer(async (request, response) => {
    try {
      if (!requestHostAllowed(request)) {
        sendJson(response, 421, { ok: false, error: 'local_host_required' })
        return
      }
      if (!requestOriginAllowed(request)) {
        sendJson(response, 403, { ok: false, error: 'cross_origin_request_blocked' })
        return
      }

      const url = new URL(request.url || '/', 'http://127.0.0.1')
      if (request.method === 'GET' && url.pathname === '/api/health') {
        sendJson(response, 200, { ok: true, status: 'ready' })
        return
      }
      if (request.method === 'GET' && url.pathname === '/api/status') {
        sendJson(response, 200, competitionPublicStatus(runtime))
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/scenario') {
        const body = await readJsonBody(request)
        const input = runtime.lab.inputFor(String(body.id || ''))
        const result = reviewMoneypennyAgentOutput(input, {
          trustedKeyFingerprints: [runtime.lab.trustedSignerFingerprint],
        })
        sendJson(response, 200, { ...result, demo: { synthetic_only: true, scenario_id: body.id } })
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/review') {
        const body = await readJsonBody(request)
        const result = reviewMoneypennyAgentOutput(safeReviewInput(body), {
          trustedKeyFingerprints: [runtime.lab.trustedSignerFingerprint],
        })
        sendJson(response, result.ok ? 200 : 400, result)
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/git-review') {
        const body = await readJsonBody(request)
        const result = await reviewMoneypennyGitClaim(safeReviewInput(body), gitReviewOptions(runtime))
        sendJson(response, result.ok ? 200 : 400, result)
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/github-review') {
        const body = await readJsonBody(request)
        const result = await reviewMoneypennyPublicGitHubClaim(
          safeReviewInput(body),
          publicGitHubOptions(runtime, body.repository),
        )
        sendJson(response, result.ok ? 200 : 400, result)
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/github-demo') {
        const body = await readJsonBody(request)
        const result = await runMoneypennyPublicGitHubDemo({
          repository: body.repository,
          mode: body.mode,
        }, publicGitHubOptions(runtime, body.repository))
        sendJson(response, 200, result)
        return
      }

      if (request.method === 'POST' && url.pathname === '/api/git-demo') {
        const body = await readJsonBody(request)
        const mode = String(body.mode || '')
        const observation = await observeMoneypennyGitRepository(gitReviewOptions(runtime))
        const agentOutput = gitScenarioClaim(observation, mode)
        const result = await reviewMoneypennyGitClaim({
          source_label: 'Synthetic outside coding agent',
          task: 'Check the coding agent report against live Git.',
          agent_output: agentOutput,
        }, gitReviewOptions(runtime))
        sendJson(response, 200, {
          ...result,
          demo: {
            synthetic_claim: true,
            agent_output: agentOutput,
            mode,
            source_mode: runtime.git.sourceMode,
          },
        })
        return
      }

      if (request.method === 'GET' && STATIC_FILES[url.pathname]) {
        const [relativePath, contentType] = STATIC_FILES[url.pathname]
        send(response, 200, readFileSync(path.join(RELEASE_ROOT, relativePath)), { 'Content-Type': contentType })
        return
      }

      sendJson(response, 404, { ok: false, error: 'not_found' })
    } catch (error) {
      const knownStatus = Number(error?.statusCode)
      const statusCode = Number.isInteger(knownStatus) && knownStatus >= 400 && knownStatus <= 499 ? knownStatus : 500
      const publicError = statusCode < 500 ? String(error.message || 'request_rejected') : 'request_failed_safely'
      sendJson(response, statusCode, { ok: false, error: publicError, writes_performed: false })
    }
  })

  server.requestTimeout = 10_000
  server.headersTimeout = 5_000
  server.keepAliveTimeout = 5_000
  server.on('close', () => {
    if (ownsRuntime) runtime.cleanup()
  })
  return { server, runtime }
}

export async function startCompetitionServer(options = {}) {
  const host = options.host || DEFAULT_HOST
  const port = Number.isInteger(Number(options.port)) ? Number(options.port) : DEFAULT_PORT
  if (host !== '127.0.0.1') throw new Error('competition_server_must_bind_loopback')
  const created = createCompetitionServer(options)
  await new Promise((resolve, reject) => {
    created.server.once('error', reject)
    created.server.listen(port, host, resolve)
  })
  return created
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : ''
if (invokedPath === import.meta.url) {
  const started = await startCompetitionServer({
    host: process.env.MONEYPENNY_DEMO_HOST || DEFAULT_HOST,
    port: process.env.MONEYPENNY_DEMO_PORT || DEFAULT_PORT,
  })
  const address = started.server.address()
  console.log(`Money Penny Readback is ready at http://${address.address}:${address.port}`)
  console.log('Local-only demo. No cloud model, personal account, or write-capable connector is enabled.')

  const close = () => started.server.close(() => process.exit(0))
  process.once('SIGINT', close)
  process.once('SIGTERM', close)
}
