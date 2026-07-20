# Security

## Runtime Boundary

The local competition edition binds to `127.0.0.1`; the hosted edition exposes same-origin serverless APIs. Both use temporary synthetic proof stores and make no cloud-model or AI-provider call. No write-capable connector is enabled.

The Git connector has a fixed command allowlist:

- `git rev-parse --is-inside-work-tree`
- `git rev-parse --is-bare-repository`
- `git rev-parse --show-toplevel`
- `git rev-parse --verify HEAD`
- `git status --porcelain=v1 -z --untracked-files=normal --no-renames`

Reviewed content cannot provide arguments, a repository path, environment configuration, a signing key, or a trusted-key fingerprint. Git runs without the shell, hooks, global configuration, system configuration, terminal prompts, optional locks, filesystem monitors, or network use.

## Public GitHub Boundary

The hosted `Public GitHub` workflow performs a real source check without cloning or running Git. User source selection must parse as `owner/repository` or an HTTPS `github.com/owner/repository` URL. Ports, credentials, query strings, fragments, encoded paths, extra path segments, other protocols, other hosts, and private or missing repositories are rejected.

The connector constructs only these read operations under the fixed `https://api.github.com` origin:

- `GET /repos/{owner}/{repository}` for public repository metadata and its default-branch name.
- `GET /repos/{owner}/{repository}/git/ref/heads/{default_branch}` for the exact branch reference and commit SHA.

It sends no authorization header, body, cookie, user-controlled header, write method, or arbitrary URL. Redirects are rejected. Each response has a 192 KiB limit and each request has a 3.5-second timeout. The code does not request commit, tree, content, patch, issue, pull-request, workflow, or file endpoints. Only canonical repository identity, default branch, short HEAD, public visibility, and archive state are returned. All other response fields are discarded.

Outside-agent text passes prompt-attack and sensitive-value checks before the public source connector can run. A 30-second, 32-entry process-memory cache stores only the five public safe facts. GitHub's anonymous API limit still applies; a limit or source failure returns an explicit refusal and never falls back to invented evidence.

## Data Handling

Raw reviewed output and evidence are held only for the request. They are fingerprinted for the result but are not written to disk or logged by Money Penny. Prompt-attack and secret-shaped inputs are redacted from claim output. The hosting platform may retain normal infrastructure request logs, so the public interface warns against entering personal or secret data.

Trust Lab private keys exist only in process memory. Temporary ledgers and public proof bundles are removed when the server closes normally and remain under the operating system temporary directory if the process is forcibly terminated.

## Threat Model

The release defends its demonstrated boundary against unsupported completion, self-issued trust, proof mutation, event deletion and reordering, wrong-key substitution, replay, expired or reused approval, orphan execution, schema downgrade, prompt injection, secret-shaped input, claimant-supplied Git commands and paths, SSRF-shaped public-source input, alternate-host redirects, oversized source responses, and accidental return of unneeded GitHub metadata.

It does not defend a compromised host, stolen trusted private key, malicious Node.js or Git binary, operating-system compromise, GitHub API compromise, platform-level traffic abuse, anonymous GitHub rate exhaustion, or claims outside an implemented source connector.

Read the package threat model at [packages/readback/docs/THREAT-MODEL.md](packages/readback/docs/THREAT-MODEL.md).

## Reporting

Do not include credentials, tokens, personal account content, or private payloads in a report. Describe the smallest synthetic reproduction and the affected boundary.
