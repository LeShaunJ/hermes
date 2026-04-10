# Contributing

## Quick-Start

The `dev/` directory contains a ready-to-use Compose stack with hermes,
PostgreSQL, and nginx:

```bash
docker compose -f dev/compose.yaml up
```

Edit `dev/hermes.yaml` to customise settings before starting.

The nginx proxy listens on `http://localhost:8888`. Configure your container
runtime to use hermes as its registry endpoint:

```bash
# Pull via hermes gateway directly:
DOCKER_HOST=tcp://localhost:8888 docker pull registry.example.com/myapp:v1.2.3
```

## Git Workflow

- **Pull Requests:** Group related changes into single, logical commits.
- **Commits:** Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
  - Plan your [changes](https://github.com/angular/angular/blob/22b96b9/CONTRIBUTING.md#type):
    | type | purpose |
    | ---: | :------ |
    | `build` | Changes that affect the build system or external dependencies. |
    | `ci` | Changes to our CI configuration files and scripts. |
    | `docs` | Documentation only changes. |
    | `feat` | A new feature. |
    | `fix` | A bug fix. |
    | `perf` | A code change that improves performance. |
    | `refactor` | A code change that neither fixes a bug nor adds a feature. |
    | `style` | Changes that do not affect the meaning of the code. |
    | `test` | Adding missing tests or correcting existing tests. |
  - Scope changes where appropriate (ie: `refactor(cmd/approve): ...`)

## Development

- Adhere to [Go Proverbs](https://go-proverbs.github.io).
- Always run `gofmt -s -w` on all `.go` files before committing.
- Be sure to line (_ie: `golangci-lint run`_).
- Ensure appropriate tests exist for all `.go` files.
- Ensure `README.md` and `doc/*` are up-to-date.
