# Project Memory

## Overview
- See @README.md for high-level context.
- See [Future](#future) release plan.

## Rules & Standards
- See @CONTRIBUTING.md for guidelines.
- Must achieve **80%** test coverage for **any** `go` package created in this project.
- Use `mermaid` for any diagrams in @README.md.
- Be terse/concise with responses, code comments, and commit message bodies.

### Compact Instructions
When compacting, always preserve:
- The full list of modified files and their exact paths.
- Current architectural decisions.
- Any unresolved error messages or active debugging steps.
- Do not stop tasks early due to token budget concerns; save state to memory before the context refreshes.

### Large File & Context Strategy
- **Split Writes**: Break up large write tasks into smaller tasks.
- **Search First**: For file with >300 lines, use `grep` to locate specific symbols.
- **Chunked Reading**: Never read more than 500 lines of a file at once. Ensure offsets/limits to read only relevant functions.
- **Map Subsystems**: For large directories, create temporary "index" contents before deep dive.
- **Compaction Priorities**: During `/compact`, always preserve active file paths, architectural decisions, and current stack traces.
- **Subagents**: Use specialized subagents for isolated investigations of large modules to keep the main context window lean.

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
