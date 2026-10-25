# Contributing to hodor

Thanks for considering a contribution. hodor is a small, deliberately narrow
project — please open an issue to discuss larger changes before writing code.

## Dev setup

Requirements: Go 1.27+, no CGO, no extra tools beyond the standard toolchain.

```sh
git clone https://github.com/saezro/hodor.git
cd hodor
go build ./...
go test ./...
```

## Dependencies

hodor is stdlib-first. The only allowed third-party dependency is
`gopkg.in/yaml.v3`. Do not add new dependencies without discussing it in an
issue first — PRs that add dependencies without prior discussion will be
closed.

## Code style

- `gofmt`-formatted, `go vet ./...` clean.
- `golangci-lint run` must pass (see `.golangci.yml`). Install via
  [golangci-lint](https://golangci-lint.run/usage/install/).
- English for code, comments and commit messages.
- Structured logging via `log/slog`, never `fmt.Println`/`log.Print` in
  library code.
- No secrets, tokens or PINs in log output.

## Tests

- Table-driven tests (`t.Run` subtests) are the convention across the
  codebase — follow the existing style in `internal/*/*_test.go`.
- Use a fake clock for anything timer-related (state expiry, PIN expiry,
  pass TTL) instead of real `time.Sleep`.
- Run the full suite with the race detector before opening a PR:

  ```sh
  go test -race ./...
  ```

## Pull requests

1. Fork and branch from `main`.
2. Keep PRs focused — one logical change per PR.
3. Add/update tests for any behavior change.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Make sure CI (vet, test, lint, build) is green.

## Reporting bugs

Open a GitHub issue with steps to reproduce, your `hodor.yaml` (redact
secrets/hosts if needed), and the hodor version (`hodor version`).

## Reporting security issues

Do not open a public issue — see [SECURITY.md](SECURITY.md).
