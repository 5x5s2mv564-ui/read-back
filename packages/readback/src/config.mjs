export const PACKAGE_NAME = 'readback'
export const PACKAGE_VERSION = '0.2.1'
export const EVENT_SCHEMA_VERSION = 1
export const DEFAULT_APPROVAL_EXPIRY_HOURS = 24
export const ENABLE_VALUE = 'true'

export const EVENT_TYPES = Object.freeze([
  'proposal_recorded',
  'proposal_rejected',
  'sidecar_job_approved',
  'sidecar_job_refused',
  'sidecar_job_executed',
  'ledger_schema_migrated',
  'proposal_store_migrated',
  'ledger_head_snapshot',
])

export const REFUSAL_REASONS = Object.freeze([
  'approval_expired',
  'approval_consumed',
  'proposal_tampered',
  'spec_tampered',
  'input_drift',
  'proposal_rejected',
  'approval_missing',
  'unapproved',
  'timeout',
  'output_path_refused',
  'job_failed',
  'single_use_violated',
  'orphan_execution',
  'expired_at_execution',
  'absent_proposal',
  'fake_success_without_evidence',
])
