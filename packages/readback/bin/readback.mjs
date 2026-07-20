#!/usr/bin/env node
import { mkdirSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { approve } from '../src/approvals.mjs'
import { execute } from '../src/execute.mjs'
import { exportProofBundle, generateEphemeralKeypair, readLedgerEntries, verifyLedger, verifyProofBundle } from '../src/ledger.mjs'
import { propose, reject } from '../src/proposals.mjs'
import { interrogate } from '../src/readback.mjs'

function parseArgs(argv = process.argv.slice(2)) {
  const [command = 'help', ...rest] = argv
  const opts = {}
  for (let i = 0; i < rest.length; i += 1) {
    const item = rest[i]
    if (!item.startsWith('--')) continue
    const key = item.slice(2)
    const next = rest[i + 1]
    if (!next || next.startsWith('--')) opts[key] = true
    else {
      opts[key] = next
      i += 1
    }
  }
  return { command, opts }
}

function jsonOut(value) {
  console.log(JSON.stringify(value, null, 2))
}

function keys(opts) {
  if (opts['private-key'] && opts['public-key']) {
    return {
      privateKeyPem: readFileSync(opts['private-key'], 'utf8'),
      publicKeyPem: readFileSync(opts['public-key'], 'utf8'),
    }
  }
  return generateEphemeralKeypair()
}

async function main() {
  const { command, opts } = parseArgs()
  const ledgerPath = opts.ledger || 'readback-ledger.jsonl'
  if (command === 'verify') {
    if (opts['proof-bundle']) return jsonOut(verifyProofBundle(opts['proof-bundle']))
    const publicKeyPem = opts['public-key-pem'] || (opts['public-key'] ? readFileSync(opts['public-key'], 'utf8') : '')
    return jsonOut(verifyLedger({ ledgerPath, publicKeyPem }))
  }
  if (command === 'export-proof') {
    if (!opts['public-key'] || !opts['private-key']) throw new Error('export_proof_requires_public_and_private_keys')
    const publicKeyPem = readFileSync(opts['public-key'], 'utf8')
    const privateKeyPem = readFileSync(opts['private-key'], 'utf8')
    const outPath = opts.out || 'readback-proof-bundle.json'
    mkdirSync(dirname(resolve(outPath)), { recursive: true })
    exportProofBundle({ ledgerPath, publicKeyPem, privateKeyPem, outPath })
    return jsonOut({ ok: true, proof_bundle: outPath })
  }
  if (command === 'interrogate') return jsonOut(interrogate(opts.claim || opts.query || 'manifest_job_ran', { ledgerPath }))
  const keypair = keys(opts)
  if (command === 'propose') return jsonOut(propose({ ledgerPath, ...keypair, specPath: opts.spec, inputPaths: String(opts.inputs || '').split(',').filter(Boolean) }))
  if (command === 'reject') return jsonOut(reject({ ledgerPath, ...keypair, proposalId: opts.id }))
  if (command === 'approve') return jsonOut(approve({ ledgerPath, ...keypair, proposalId: opts.id }))
  if (command === 'execute') return jsonOut(execute({ ledgerPath, ...keypair, proposalId: opts.id, outputDir: opts.output || 'runner-output' }))
  if (command === 'tamper-check') {
    const entries = readLedgerEntries(ledgerPath)
    return jsonOut({ ok: entries.length > 0, entries: entries.length })
  }
  jsonOut({ ok: false, usage: 'readback propose|reject|approve|execute|interrogate|verify|tamper-check|export-proof' })
  process.exitCode = 1
}

main().catch((error) => {
  jsonOut({ ok: false, error: error.message })
  process.exitCode = 1
})
