import { ENABLE_VALUE } from './config.mjs'

export function isGateEnabled(valueOrEnv = '', key = '') {
  const raw = key && valueOrEnv && typeof valueOrEnv === 'object'
    ? valueOrEnv[key]
    : valueOrEnv
  return String(raw ?? '') === ENABLE_VALUE
}
