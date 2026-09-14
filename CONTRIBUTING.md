# Contributing to Cyprob

Thank you for your interest in contributing to Cyprob! This guide explains how to set up your environment, propose changes, and keep contributions consistent and easy to review.

## Quick Start

- Use feature branches for any non-trivial change: `feat/<short-name>` or `fix/<short-name>`.
- Keep changes small and focused; prefer multiple small PRs over one large PR.
- Before opening a PR, run locally:
  - `make fmt`
  - `make lint`
  - `make test`
  - Optional smoke build: `go build -o cyprob ./cmd`

## Project Layout

- CLI entrypoint: `cmd/cyprob/commands/`
  - `scan.go` - Scan commands
  - `server/` - Server commands
  - `plugin/` - Plugin management commands
  - `storage/` - Storage commands
- Core packages under `pkg/`:
  - `pkg/engine/` - DAG-based execution engine and orchestrator
  - `pkg/modules/` - Scan phases (discovery, scan, parse, evaluation, reporting)
  - `pkg/plugin/` - YAML plugin system (15+ embedded, 200+ downloadable)
  - `pkg/storage/` - Storage abstraction (Local JSONL, PostgreSQL+S3)
  - `pkg/server/` - HTTP server (API + UI + background workers)
  - `pkg/fingerprint/` - Service fingerprinting with confidence scoring
  - `pkg/config/` - Koanf-backed configuration
- UI: `ui/` - React SPA (shadcn-admin)
- Tests live next to code as `*_test.go`
- CI/CD: `.github/workflows/` and `.github/scripts/`

**Target Go version**: Go 1.25 (required)

## Branching and PR Workflow

1. **Sync with upstream**

   ```bash
   git checkout main
   git fetch upstream main
   git merge --ff-only upstream/main
   git push origin main
   ```

2. **Create a feature branch**

   ```bash
   git checkout -b feat/<short-name>
   # Or: fix/, test/, refactor/, docs/, chore/
   ```

3. **Develop incrementally**

   - Commit in small, meaningful slices using Conventional Commits (see below)
   - Write tests for all new/modified code
   - Keep your branch up to date with main

4. **MANDATORY: Run quality checks before commit**

   ```bash
   make test      # MUST PASS
   make validate  # MUST PASS (lint + format + spell check + shell scripts)
   ```

   **Never skip these checks!** CI will fail if they don't pass locally first.

5. **Push and create PR**

   ```bash
   git push origin feat/<short-name>
   gh pr create --repo cyprob/cyprob --web
   ```

   **PR description should include**:

   - **Problem**: What's broken or missing
   - **Changes**: Key changes (not file-by-file diffs)
   - **Testing**: What tests added, how verified
   - **Related**: `Resolves #<issue-number>`

6. **Review cycle**

   - Wait for review from maintainers (weissarc, jonaserflow)
   - Address feedback
   - Push updates (PR updates automatically)
   - CI must pass (all checks green)

7. **After merge**
   ```bash
   git checkout main
   git fetch upstream main && git merge --ff-only upstream/main
   git push origin main
   git branch -D feat/<short-name>
   ```

## Commit Messages (Conventional Commits)

Use Conventional Commit prefixes to keep history consistent and searchable:

- `feat:` new feature
- `fix:` bug fix
- `refactor:` code change that neither fixes a bug nor adds a feature
- `docs:` documentation only changes
- `test:` add or fix tests
- `chore:` tooling, build, or maintenance

Examples:

- `feat: add TCP banner capture module`
- `fix(scanner): handle empty target list`
- `refactor(engine): simplify DAG node scheduling`

## Coding Style

- Go code must be `gofmt -s` clean; run `make fmt`.
- Lint with `make lint` (uses `golangci-lint`).
- Keep package names lowercase and meaningful.
- Exported APIs use PascalCase; unexported helpers use camelCase.
- Prefer structured logging via `pkg/logging` (Zerolog) with a `component` field.

## CLI Error Output Standards

CLI commands must provide consistent, user-friendly error output. This ensures a uniform experience and prevents fragmented error formats across different commands.

### Standard Pattern

**Main error paths** (command-level failures) must use:

```go
return formatter.PrintTotalFailureSummary(operation, err, plugin.ErrorCode(err))
```

**DO NOT use** `formatter.PrintError()` in main error paths. This bypasses the standardized error summary format.

### Why This Matters

✅ **Consistency**: Users see the same error format across all commands
✅ **Machine-readable**: Error codes and structured output for automation
✅ **Actionable**: Clear suggestions and next steps
✅ **Maintainability**: Single source of truth for error presentation

### Examples

❌ **BAD** (inconsistent, no error code):

```go
if err != nil {
    return formatter.PrintError(err)
}
```

✅ **GOOD** (standardized, includes error code and summary):

```go
if err != nil {
    return formatter.PrintTotalFailureSummary("install", err, plugin.ErrorCode(err))
}
```

### Enforcement

CI automatically checks for violations using `.github/scripts/check-error-handling.sh`. The check currently enforces this standard for:

- ✅ Plugin commands (`cmd/cyprob/commands/plugin`)

Future command families (scan, storage, server) will be added as their standards are defined.

### Extending the Standard

When adding new command families:

1. Define the error handling pattern for that family
2. Add a matrix entry to `.github/workflows/validate.yaml`
3. Set `required: false` initially (warning only)
4. Update documentation in this section
5. Once team reviews and approves, set `required: true` to enforce

## Testing

- Write table-driven unit tests next to the code (`*_test.go`).
- Use `testify/require` for assertions to match existing style.
- Run `make test` or `go test ./pkg/... ./cmd/...` before pushing.
- For integration-like coverage of flows, add orchestrator exercises under `pkg/engine/orchestrator_test.go` or adjacent relevant tests.

## Configuration and Security

- Wire new configuration keys through Koanf in `pkg/config` with sensible defaults.
- Document all new/changed flags and config keys in PRs and relevant READMEs.
- Use helpers in `pkg/safe` and `pkg/utils` to validate user input before network calls.
- Mask real targets or secrets in fixtures, tests, and examples.

## Build, Lint, and Validate

**Preferred**: Run without building (faster development):

```bash
go run ./cmd <command>
# Example: go run ./cmd scan --targets 192.168.1.1
```

**Build to dist/** (if needed):

```bash
make binary  # Outputs to dist/<GOOS>/<GOARCH>/cyprob
```

**Quality checks** (MANDATORY before commit):

```bash
make fmt       # Auto-format code
make test      # Run unit tests - MUST PASS
make validate  # Lint + format + spell + shell checks - MUST PASS
```

### Formatter installation (gofumpt)

The project uses `gofumpt` (stricter `gofmt`) via `make fmt`:

```bash
# Install gofumpt if it's not already in your PATH
go install mvdan.cc/gofumpt@latest

# Ensure GOPATH/bin is on your PATH
export PATH="$(go env GOPATH)/bin:$PATH"

# Run formatting locally
make fmt
```

**Integration tests** (optional, recommended before PR):

```bash
make test-integration  # Run with -tags=integration
make test-all          # Run both unit + integration tests
```

## Backward Compatibility

Interfaces in `pkg/api` and `pkg/server` are evolving. Treat them as experimental, but avoid breaking changes when feasible. If a breaking change is unavoidable, call it out plainly in the PR description and related docs.

## Release Notes and Docs

- When runtime behavior, flags, or config keys change, update README or module docs within the same PR.
- Include example CLI output or logs in the PR description to illustrate new behavior.

## Questions and Reviews

- Single maintainer workflows are welcome: self-review via PR is encouraged for structure and history.
- If a review task was interrupted in the CLI, re-initiate with `/review` and wait for it to complete.

Thanks for contributing and keeping Cyprob healthy and reliable!
