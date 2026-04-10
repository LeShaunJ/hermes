# Contributing

## Git Workflow

- **Commits:** Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- **PRs:** Group related changes into single, logical commits.

## Development

- Adhere to [Go Proverbs](https://go-proverbs.github.io).
- Always run `gofmt -s -w` on all `.go` files before committing.
- Be sure to line (_ie: `golangci-lint run`_).
- Ensure appropriate tests exist for all `.go` files.
- Ensure `README.md` and `doc/*` are up-to-date.
