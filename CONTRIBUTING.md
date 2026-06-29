# Contributing to Sentari Agent

Thank you for your interest in contributing to the Sentari agent.

## How to contribute

1. **Fork** this repository
2. **Create a branch** for your change (`git checkout -b fix/scanner-symlink-handling`)
3. **Write tests** for your change
4. **Ensure all tests pass** (`go test ./... && go vet ./...`)
5. **Submit a pull request** with a clear description of the change

## What we accept

- Bug fixes with a test that reproduces the issue
- New scanner types (e.g., additional Python environment managers)
- Performance improvements with benchmark evidence
- Documentation improvements

## What we don't accept

- Changes to the enterprise build tag features without prior discussion
- Dependencies on external binaries (the agent must remain a single static binary)
- Features that require network access during scanning

## Development setup

```bash
# Clone
git clone https://github.com/sentari-dev/sentari-agent.git
cd sentari-agent

# Build
go build ./...

# Test
go test ./... -v

# Lint
go vet ./...
```

Requires Go 1.23+.

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Table-driven tests preferred
- No global mutable state
- Error messages should be lowercase and not end with punctuation

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
