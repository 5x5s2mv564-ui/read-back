export const NOOP_JOB_TYPE = 'noop_v0'

export function runNoopJob({ spec }) {
  return JSON.stringify({
    job_type: NOOP_JOB_TYPE,
    job_id: spec.job_id,
    message: 'no operation',
  }, null, 2)
}
