import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const SYNTHETIC_SNAPSHOT_HEAD = createHash('sha1')
  .update('money-penny-build-week-public-demo-v1', 'utf8')
  .digest('hex')

function gitEnvironment() {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')))
  return {
    ...env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    GIT_AUTHOR_NAME: 'Money Penny Demo',
    GIT_AUTHOR_EMAIL: 'money-penny@example.invalid',
    GIT_COMMITTER_NAME: 'Money Penny Demo',
    GIT_COMMITTER_EMAIL: 'money-penny@example.invalid',
    LC_ALL: 'C',
  }
}

function runGit(cwd, args) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    env: gitEnvironment(),
    maxBuffer: 512_000,
    timeout: 5_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function isUsableRepository(root) {
  if (!root || !existsSync(root)) return false
  try {
    return runGit(root, ['rev-parse', '--is-inside-work-tree']) === 'true'
      && runGit(root, ['rev-parse', '--is-bare-repository']) === 'false'
  } catch {
    return false
  }
}

function createSyntheticRepository(root) {
  mkdirSync(root, { recursive: true, mode: 0o700 })
  writeFileSync(path.join(root, 'synthetic-agent-result.txt'), 'Synthetic result for the Money Penny Git connector.\n', 'utf8')
  runGit(root, ['init'])
  runGit(root, ['add', 'synthetic-agent-result.txt'])
  runGit(root, ['commit', '-m', 'Create synthetic connector fixture'])
}

function createSyntheticSnapshot(root) {
  mkdirSync(root, { recursive: true, mode: 0o700 })
  const canonicalRoot = realpathSync(root)
  return {
    repoRoot: canonicalRoot,
    sourceMode: 'bundled_synthetic_snapshot',
    label: 'Bundled synthetic Git snapshot',
    synthetic: true,
    directProgramUsed: false,
    observationSource: 'synthetic_git_snapshot',
    sourceScope: 'bundled_fixture_only',
    observationLabel: 'Bundled snapshot',
    runGit({ operation, repoRoot }) {
      const currentRoot = path.resolve(repoRoot)
      if (currentRoot !== canonicalRoot) throw new Error('synthetic_git_repository_scope_mismatch')
      if (operation === 'inside_worktree') return 'true'
      if (operation === 'bare_repository') return 'false'
      if (operation === 'top_level') return canonicalRoot
      if (operation === 'head') return SYNTHETIC_SNAPSHOT_HEAD
      if (operation === 'status') return ''
      throw new Error('git_operation_not_allowlisted')
    },
  }
}

export function prepareGitDemoRepository({ releaseRoot, runtimeRoot, mode = 'auto' }) {
  if (mode === 'synthetic_snapshot') {
    return createSyntheticSnapshot(path.join(runtimeRoot, 'synthetic-git-snapshot'))
  }
  if (mode !== 'auto') throw new Error('git_demo_mode_invalid')

  if (isUsableRepository(releaseRoot)) {
    return {
      repoRoot: releaseRoot,
      sourceMode: 'release_repository',
      label: 'This cloned release repository',
      synthetic: false,
      directProgramUsed: true,
      observationSource: 'git',
      sourceScope: 'canonical_repository_only',
      observationLabel: 'Live Git',
    }
  }

  const fixtureRoot = path.join(runtimeRoot, 'synthetic-git-repository')
  createSyntheticRepository(fixtureRoot)
  if (!isUsableRepository(fixtureRoot)) throw new Error('synthetic_git_repository_unavailable')
  return {
    repoRoot: fixtureRoot,
    sourceMode: 'temporary_synthetic_repository',
    label: 'Temporary synthetic Git repository',
    synthetic: true,
    directProgramUsed: true,
    observationSource: 'git',
    sourceScope: 'canonical_repository_only',
    observationLabel: 'Live Git',
  }
}

export function gitScenarioClaim(observation, mode = 'confirmed') {
  if (mode === 'confirmed') {
    return `Git HEAD is ${observation.head_short}. The worktree is ${observation.worktree_state}. Git reports ${observation.changed_entry_count} changed items.`
  }
  if (mode === 'contradicted') {
    const falseState = observation.worktree_state === 'clean' ? 'dirty' : 'clean'
    return `The Git worktree is ${falseState}.`
  }
  throw new Error('git_demo_mode_unknown')
}
