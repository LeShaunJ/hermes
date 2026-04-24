# Contributing

> [!TIP]
> _This project defines some [`ops`] actions for development convenience._
> _Installing it is optional, but any `ops.yaml` files defined are representative_
> _of the expected development environment._

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
  - Title is a concise summary of main feature or fix.
  - Description formatted as:
    ```markdown
    ### Changelog

    <!-- list of commit titles only; nest breaking changes if needed -->
    ```
    > [!TIP]
    > _If you're using [`ops`], run `ops changelog` to auto-generate a description. If not,_
    > _see [`ops.yaml#/actions/changelog/command`](ops.yaml) for the direct command._
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
  - Add commit bodies if more context is needed; but keep them short, we don't need novels.

## Development

- Adhere to [Go Proverbs](https://go-proverbs.github.io).
- Always run `gofmt -s -w` on all `.go` files before committing.
  > [!TIP]
  > _If you're using [`ops`], you can run `ops format`._
- Be sure to lint before committing.
  > [!TIP]
  > _If you're using [`ops`], you can run `ops lint`._
- Ensure appropriate tests exist for all `.go` files and major e2e scenarios.
  - Ensure unit tests pass.
    > [!TIP]
    > _If you're using [`ops`], you can run `ops test-units`._
  - Ensure end-to-end tests pass.
    > [!TIP]
    > _If you're using [`ops`], you can run `ops test-e2e`._
- Ensure `README.md` and `docs/*` are up-to-date.

[`ops`]: https://github.com/nickthecook/crops
