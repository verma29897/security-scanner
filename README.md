# CodeAudit

Repository: `github.com/verma29897/security-scanner`

Author: **KRISHNA VERMA**

CodeAudit is a defensive, deterministic repository security review CLI. Give it one Git URL; it clones the default branch without submodules, resolves that snapshot to a commit SHA, inventories supported source files, runs narrow security rules, and writes JSON and escaped HTML reports.

This repository delivers milestone 1 plus a small deterministic rule set. It does **not** claim that a clean result proves security, and it does not infer whether a human or AI wrote code.

## Install and run

Requires Go 1.22+ and Git.

```sh
go test ./...
go install ./cmd/code-audit
code-audit scan https://github.com/company/project.git
code-audit scan --out review git@github.com:company/private-project.git
```

The only required scan input is the repository URL. Outputs default to `codeaudit-report.json` and `codeaudit-report.html`, both created with owner-only permissions.

## Optional AI review

AI is disabled by default and deterministic scanning works without an API key. OpenAI/ChatGPT, Anthropic/Claude, and OpenAI-compatible HTTPS APIs are supported. CodeAudit automatically reads `.env` from the directory where it is launched, then falls back to `$XDG_CONFIG_HOME/codeaudit/ai.env` (normally `~/.config/codeaudit/ai.env`). It never reads `.env` from the temporary repository clone.

```sh
# One-time setup; edit .env and add the selected provider key.
cp .env.example .env

# With AI when .env enables it; without AI otherwise.
code-audit scan REPOSITORY_URL
```

Set `CODEAUDIT_AI_MODE=external` in `.env` to explicitly enable AI for the same command. Use `CODEAUDIT_AI_MODE=off` for deterministic-only scanning. Configure `CODEAUDIT_AI_PROVIDER`, `CODEAUDIT_AI_MODEL`, and the generic `CODEAUDIT_AI_API_KEY`. The older `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `CODEAUDIT_AI_EXTERNAL_TRANSMISSION` names remain supported. The API key cannot be supplied as a command-line flag. Only redacted finding metadata is sent, and provider errors never erase deterministic results.

## Private repository authentication

CodeAudit never accepts credentials in URLs. For HTTPS, configure Git's credential manager before scanning. For SSH, load an approved key in `ssh-agent` and use `git@host:owner/repository.git`. CodeAudit sets `GIT_TERMINAL_PROMPT=0`, so missing or unauthorized credentials fail clearly rather than hanging. Use a read-only deploy key or provider token scoped only to selected repositories. Hosted deployments should set `AllowedHosts`, run scans as an isolated unprivileged user, and perform authorization before invoking the scanner.

## Current guarantees

- HTTPS and conventional `git@host:path` input only; embedded URL credentials, local/file/ext protocols, loopback/private literal IPs, and leading option-like input are rejected.
- Git is invoked with argument arrays, restricted protocols, shallow history, no tags, and no submodules.
- Temporary clones are removed after success or failure.
- File count, repository size, and per-file size are bounded; symlinks, binary files, vendored directories, and repository metadata are not scanned.
- Evidence is length-limited, credential values are redacted, and HTML is generated through contextual escaping.
- Finding IDs and order are stable for the same path, line, ruleset, and commit.
- Credential-like values in test paths and obvious placeholder values remain visible but are classified as informational and low-confidence; unknown or production-context candidates remain critical.
- Framework detection requires recognized manifests or exact imports rather than arbitrary word matches.

See [docs/architecture.md](docs/architecture.md), [docs/capabilities.md](docs/capabilities.md), and [docs/rules.md](docs/rules.md). Example output is under `samples/`.

## License

Copyright © 2026 KRISHNA VERMA. Released under the [MIT License](LICENSE).

## Known limitations and expansion plan

The current adapters provide language inventory, framework hints, a narrow deterministic ruleset, and optional AI explanation. They do not yet provide AST parsing, route extraction, call graphs, interprocedural data flow, dependency advisory lookup, or hosted APIs. Unknown controls are reported as unknown—not missing or secure. The next milestone should add versioned AST adapters for Go, Python, Java, JavaScript, and TypeScript, then route/control tracing and an offline-capable advisory scanner adapter.
