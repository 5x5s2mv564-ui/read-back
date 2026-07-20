#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const REQUIRED_FILES = Object.freeze([
  '.github/workflows/ci.yml',
  'api/github-demo.mjs',
  'api/github-review.mjs',
  'api/git-demo.mjs',
  'api/git-review.mjs',
  'api/health.mjs',
  'api/review.mjs',
  'api/scenario.mjs',
  'api/status.mjs',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'docs/ARCHITECTURE.md',
  'foundry/moneypenny-action-policy.mjs',
  'foundry/moneypenny-agent-review.mjs',
  'foundry/moneypenny-completion-receipt.mjs',
  'foundry/moneypenny-git-reality-check.mjs',
  'foundry/moneypenny-public-github-reality-check.mjs',
  'foundry/moneypenny-prompt-security.mjs',
  'lib/git-demo.mjs',
  'lib/trust-lab.mjs',
  'lib/vercel-api.mjs',
  'package-lock.json',
  'package.json',
  'packages/readback/package.json',
  'public/app.js',
  'public/index.html',
  'public/styles.css',
  'server.mjs',
  'test/release.test.mjs',
  'test/public-github.test.mjs',
  'vercel.json',
])
const SKIP_DIRECTORIES = new Set(['.git', '.vercel', 'node_modules', 'coverage'])
const FORBIDDEN_PATH_PARTS = new Set(['credentials', 'memory', 'oauth', 'secrets', 'stores', 'tokens'])
const TEXT_EXTENSIONS = new Set(['', '.css', '.html', '.js', '.json', '.md', '.mjs', '.txt', '.yml', '.yaml'])
const SECRET_PATTERNS = Object.freeze([
  { id: 'absolute_private_path', pattern: /\/Users\// },
  { id: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { id: 'openai_key_like', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { id: 'google_key_like', pattern: /\bAIza[0-9A-Za-z_-]{20,}\b/ },
  { id: 'google_token_like', pattern: /\bya29\.[A-Za-z0-9._-]+\b/ },
  { id: 'github_token_like', pattern: /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}\b/ },
  { id: 'credential_value', pattern: /["']?(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|password)["']?\s*[:=]\s*["'][^"'\n]{8,}["']/i },
])
const DEPLOYED_RUNTIME_PREFIXES = Object.freeze([
  'api/',
  'foundry/',
  'lib/',
  'packages/readback/src/',
  'public/',
])
const DEPLOYED_RUNTIME_FILES = new Set(['server.mjs', 'vercel.json'])
const PRIVATE_RUNTIME_MARKERS = Object.freeze([
  { id: 'owner_name', pattern: /\b(?:kevin|morris)\b/i },
  { id: 'personal_domain', pattern: /\bmoneypenny\.co\.nz\b/i },
])

function walk(root) {
  const output = []
  for (const entry of readdirSync(root)) {
    if (SKIP_DIRECTORIES.has(entry)) continue
    const fullPath = path.join(root, entry)
    const stats = lstatSync(fullPath)
    if (stats.isSymbolicLink()) throw new Error(`symbolic_link_rejected:${path.relative(ROOT, fullPath)}`)
    if (stats.isDirectory()) output.push(...walk(fullPath))
    else output.push(fullPath)
  }
  return output.sort()
}

function hashFile(filePath) {
  return `sha256:${createHash('sha256').update(readFileSync(filePath)).digest('hex')}`
}

function verifyManifest() {
  const manifestPath = path.join(ROOT, 'EXPORT-MANIFEST.json')
  if (!existsSync(manifestPath)) return { present: false, files_verified: 0 }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  if (manifest.manifest_version !== 'money-penny-build-week-release.v0.1') throw new Error('export_manifest_version_invalid')
  const entries = Array.isArray(manifest.files) ? manifest.files : []
  if (manifest.file_count !== entries.length) throw new Error('export_manifest_file_count_invalid')
  const listedPaths = entries.map((entry) => String(entry.path || '')).sort()
  if (new Set(listedPaths).size !== listedPaths.length) throw new Error('export_manifest_duplicate_path')
  const actualPaths = walk(ROOT)
    .map((filePath) => path.relative(ROOT, filePath).replaceAll(path.sep, '/'))
    .filter((relativePath) => relativePath !== 'EXPORT-MANIFEST.json')
    .sort()
  if (JSON.stringify(listedPaths) !== JSON.stringify(actualPaths)) throw new Error('export_manifest_file_set_mismatch')
  for (const entry of entries) {
    const relativePath = String(entry.path || '')
    const fullPath = path.resolve(ROOT, relativePath)
    if (!relativePath || (!fullPath.startsWith(`${ROOT}${path.sep}`) && fullPath !== ROOT)) throw new Error('export_manifest_path_invalid')
    if (!existsSync(fullPath) || hashFile(fullPath) !== entry.sha256) throw new Error(`export_manifest_hash_mismatch:${relativePath}`)
  }
  return { present: true, files_verified: entries.length }
}

function main() {
  const failures = []
  for (const relativePath of REQUIRED_FILES) {
    if (!existsSync(path.join(ROOT, relativePath))) failures.push(`required_file_missing:${relativePath}`)
  }

  const packageJson = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
  if (Object.keys(packageJson.dependencies || {}).length > 0) failures.push('runtime_dependencies_must_be_empty')
  if (Object.keys(packageJson.devDependencies || {}).length > 0) failures.push('dev_dependencies_must_be_empty')
  if (packageJson.private !== true) failures.push('package_must_not_be_publishable')

  const files = walk(ROOT)
  for (const filePath of files) {
    const relativePath = path.relative(ROOT, filePath).replaceAll(path.sep, '/')
    const parts = relativePath.toLowerCase().split('/')
    if (parts.some((part) => FORBIDDEN_PATH_PARTS.has(part))) failures.push(`forbidden_path:${relativePath}`)
    if (!TEXT_EXTENSIONS.has(path.extname(filePath).toLowerCase())) continue
    const text = readFileSync(filePath, 'utf8')
    for (const rule of SECRET_PATTERNS) {
      if (rule.pattern.test(text)) failures.push(`${rule.id}:${relativePath}`)
    }
    const deployedRuntimeFile = DEPLOYED_RUNTIME_FILES.has(relativePath)
      || DEPLOYED_RUNTIME_PREFIXES.some((prefix) => relativePath.startsWith(prefix))
    if (deployedRuntimeFile) {
      for (const rule of PRIVATE_RUNTIME_MARKERS) {
        if (rule.pattern.test(text)) failures.push(`${rule.id}:${relativePath}`)
      }
    }
  }

  let manifest = { present: false, files_verified: 0 }
  try {
    manifest = verifyManifest()
  } catch (error) {
    failures.push(error.message)
  }

  if (failures.length) {
    console.error(JSON.stringify({ ok: false, failures }, null, 2))
    process.exit(1)
  }
  console.log(JSON.stringify({
    ok: true,
    checker: 'money-penny-build-week-release',
    files_scanned: files.length,
    runtime_dependencies: 0,
    dev_dependencies: 0,
    manifest,
  }, null, 2))
}

main()
