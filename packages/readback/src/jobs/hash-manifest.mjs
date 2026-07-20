export const HASH_MANIFEST_JOB_TYPE = 'hash_manifest_v0'

export function runHashManifestJob({ spec, inputs, ledgerHeadAtStart, runnerVersion }) {
  const manifest = {
    job_id: spec.job_id,
    job_type: HASH_MANIFEST_JOB_TYPE,
    spec_hash: spec.spec_hash,
    input_path: inputs[0]?.declared_path || '',
    input_hash: inputs[0]?.sha256 || '',
    started_at: spec.parameters?.fixed_timestamp,
    completed_at: spec.parameters?.fixed_timestamp,
    runner_version: runnerVersion,
    ledger_head_at_start: ledgerHeadAtStart,
  }
  return JSON.stringify(manifest, null, 2)
}
