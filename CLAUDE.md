# Project Memory

## Overview
- See @README.md for high-level context.
- See [Future](#future) release plan.

## Rules & Standards
- See @CONTRIBUTING.md for guidelines.
- Must achieve **80%** test coverage for **any** `go` package created in this project.
- Use `mermaid` for any diagrams in @README.md

## Considerations

- This is pre-alpha!
  - `hermes` is "live" once a release is created in GitHub.
  - Until we go "live", the "base" DB schema is whatever we decide it is.
- End user documention should be written in context of [release](#future) plan.
- @dev directory is for developer-use only; it's not intended for the end user.

## Future
Plan for _eventual_ release:
- Semantic versioning via git tags:
  - Build official image and push _immutable_ tag to `ghcr.io`.
  - Build official binaries and create release:
    - `linux_amd64`
    - `linux_arm64`
    - `darwin_arm64`
    - `darwin_amd64` (maybe)
- Expected usage is with either:
  - Official image via `docker`, `podman`, `k8s`, etc.
  - Official binary.
