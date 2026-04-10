# hermes

**hermes** is an OCI image approval system that acts as a full OCI Distribution
gateway. It combines [trivy](https://aquasecurity.github.io/trivy) vulnerability
scanning with a human-in-the-loop approval workflow, enforcing image policy
before forwarding client requests to upstream registries.

---

## Table of Contents

- [How it works](#how-it-works)
- [Image states](#image-states)
- [Installation](#installation)
  - [Binary](#binary)
  - [Container](#container)
  - [Dev stack (Docker Compose)](#dev-stack-docker-compose)
- [Configuration](#configuration)
- [CLI usage](#cli-usage)
  - [scan](#scan)
  - [approve](#approve)
  - [rescind](#rescind)
  - [reject](#reject)
  - [view](#view)
  - [list](#list)
  - [report](#report)
  - [serve](#serve)
- [Gateway API](#gateway-api)
  - [GET /v2/](#get-v2)
  - [ANY /v2/\<registry\>/…](#any-v2registry)
  - [ANY /ident/\<registry\>/…](#any-identregistry)
  - [GET /healthz](#get-healthz)
- [Database](#database)

---

## How it works

```
  docker pull ──► hermes (/v2/<registry>/…)
                     │
                     ├── approved  ──► proxy/redirect ──► upstream registry
                     ├── rejected  ──► 403 DENIED
                     └── unknown   ──► 401 UNAUTHORIZED
                                          │
                                          ├── stub-registers tag in DB
                                          └── WWW-Authenticate realm rewritten
                                              through /ident/ for token fetch
```

1. A container runtime targets hermes as its registry endpoint.
2. hermes receives the OCI Distribution request.
3. For manifest requests, hermes checks PostgreSQL:
   - **Approved** → proxies or redirects the request to the upstream registry.
   - **Rejected** → returns `403 DENIED`.
   - **Unknown / not yet approved** → stub-registers the tag and returns
     `401 UNAUTHORIZED` with a `WWW-Authenticate` challenge routed through
     the `/ident/` token proxy.
4. For non-manifest paths (blobs, tag lists, etc.), requests are forwarded
   unconditionally to the upstream registry.
5. An operator uses the CLI to `scan`, `approve`, or `reject` queued images.

---

## Image states

| State       | Group      | Description |
|:-----------:|:----------:|:------------|
| `queued`    | `pending`  | Metadata saved; not yet scanned. |
| `scanned`   | `pending`  | Scan performed and stored. |
| `approved`  | `verified` | Operator approved after reviewing the scan. |
| `rescinded` | `pending`  | Approval withdrawn; effectively back to scanned. |
| `rejected`  | `verified` | Operator deemed the image unusable. |
| `error`     |            | An error occurred during scanning or cache push. |

State transitions:

```
queued ──scan──► scanned ──approve──► approved ──rescind──► rescinded
  │                 │                     │
  ├──reject──►      └──reject──►          └──reject──► rejected
  │           rejected
  └──► (re-scan on next approve)
```

---

## Installation

### Binary

```bash
git clone https://github.com/leshaunj/hermes
cd hermes
go build -o hermes .
sudo mv hermes /usr/local/bin/
```

### Container

Build the image from the `Containerfile`:

```bash
podman build -t hermes -f Containerfile .
# or
docker build -t hermes -f Containerfile .
```

Run (mounting the config and Docker socket for trivy):

```bash
docker run -d \
  --name hermes \
  -v /etc/hermes.yaml:/etc/hermes.yaml:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -p 8080:8080 \
  hermes
```

### Dev stack (Docker Compose)

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

---

## Configuration

hermes reads `/etc/hermes.yaml` on startup (override with `--config`).

```yaml
server:
  addr: ":8080"          # listen address
  url:  ""               # public base URL (default: http://<hostname>:<port>)
  redirect: false        # 307-redirect blobs instead of proxying

db:
  host:     localhost
  port:     5432
  user:     hermes
  password: secret
  name:     hermes
  sslmode:  disable      # disable | require | verify-ca | verify-full

trivy:
  image:        aquasec/trivy:latest   # Docker image for trivy
  args:         []                     # extra args for `trivy image`
  convert_args: []                     # extra args for `trivy convert`

cache_url: ""            # default registry for `hermes approve --cache`
```

`server.url` is used to rewrite `WWW-Authenticate` realm headers so Docker
clients obtain bearer tokens through the `/ident/` proxy. It defaults to
`http://<hostname>:<port>` if not explicitly set.

`server.redirect` controls how non-manifest upstream paths (blobs, tag lists)
are forwarded. When `false` (default), hermes reverse-proxies the request.
When `true`, hermes sends an HTTP 307 redirect to the upstream URL — useful when
clients have direct access to the upstream registry.

A JSON Schema is provided at [`docs/hermes.schema.json`](docs/hermes.schema.json).

Environment variables prefixed with `HERMES_` override file values (e.g.
`HERMES_DB_PASSWORD`).

---

## CLI usage

All CLI commands accept `--config <path>` (default: `/etc/hermes.yaml`).

### scan

```
hermes scan [--force] [--platform OS/ARCH] IMAGE
```

Queues `IMAGE` if it does not already exist, fetches its manifest, runs a trivy
scan, saves the report, and prints the JSON to stdout.

If the image already has a scan report, the existing report is printed unless
`--force` is given.

```bash
hermes scan registry.example.com/myapp:v1.2.3
hermes scan --force registry.example.com/myapp:v1.2.3
hermes scan --platform linux/amd64 registry.example.com/myapp:v1.2.3
```

### approve

```
hermes approve [--platform OS/ARCH] [--cache [URL]] IMAGE
```

Shows the trivy scan report (scanning first if needed) and prompts:

```
Approve this image? [YES / NO / REJECT] (default: NO):
```

- **YES** — sets state to `approved`.
- **NO** — no change; exits 0.
- **REJECT** — sets state to `rejected`; exits non-zero.

If `--cache` is provided, the image is pushed to `URL` (or `cache_url` from the
config if no URL is given) upon `YES`. A successful push records the cache
registry in the database. A failed push sets the state to `error`.

```bash
hermes approve registry.example.com/myapp:v1.2.3
hermes approve --cache registry.example.com/myapp:v1.2.3
hermes approve --cache cache.internal.example.com registry.example.com/myapp:v1.2.3
```

### rescind

```
hermes rescind IMAGE
```

Sets an `approved` image to `rescinded`, immediately blocking it from passing
the gateway check. The image can be re-approved with `hermes approve`.

```bash
hermes rescind registry.example.com/myapp:v1.2.3
```

### reject

```
hermes reject IMAGE
```

Prompts for confirmation then sets the image to `rejected`. Rejected images
return `403 DENIED` at the gateway.

```bash
hermes reject registry.example.com/myapp:v1.2.3
```

### view

```
hermes view [--platform OS/ARCH] IMAGE
```

Prints all stored information for an image — state, digest, cache registry,
timestamps, a vulnerability summary, and the full scan report.

```bash
hermes view registry.example.com/myapp:v1.2.3
hermes view --platform linux/amd64 registry.example.com/myapp:v1.2.3
```

### list

```
hermes list [--state STATE[,...]] [--json] [REF ...]
```

Lists tracked images in a table. `--state` accepts individual states
(`queued`, `scanned`, `approved`, `rescinded`, `rejected`, `error`) or group
names (`pending`, `verified`). Multiple values can be comma-separated or given
as repeated flags. `REF` arguments filter by `[namespace/]name[:tag]`.

Images that have been stub-registered (seen at the gateway but not yet scanned)
show `-` for OS, arch, and digest.

```bash
hermes list
hermes list --state approved
hermes list --state pending,verified --json
hermes list myapp:v1.2.3 otherapp
```

### report

```
hermes report [--format FORMAT] [--output FILE] [--platform OS/ARCH] IMAGE
```

Retrieves the stored trivy JSON report and converts it using `trivy convert`.
Supported formats: `table`, `json`, `sarif`, `cyclonedx`, `spdx`, `spdx-json`,
`github`, `cosign-vuln`. Output goes to stdout or `FILE`.

```bash
hermes report registry.example.com/myapp:v1.2.3
hermes report --format sarif --output report.sarif registry.example.com/myapp:v1.2.3
hermes report --format cyclonedx registry.example.com/myapp:v1.2.3 | jq .
```

### serve

```
hermes serve [--addr ADDR]
```

Starts the OCI gateway server (default address from config, overridden by
`--addr`).

```bash
hermes serve
hermes serve --addr 0.0.0.0:9090
```

---

## Gateway API

hermes implements the OCI Distribution v2 API as a gateway. Configure your
container runtime or mirror tool to use hermes as its registry endpoint.

### GET /v2/

Returns `401 UNAUTHORIZED` with a `WWW-Authenticate: Bearer` challenge pointing
to `/ident/` and sets `Docker-Distribution-API-Version: registry/2.0`.

This is the standard OCI v2 capability ping — all clients hit this first to
negotiate auth.

### ANY /v2/\<registry\>/…

All OCI Distribution sub-paths rooted at `/v2/<registry>/` are handled:

**Manifest paths** (`/v2/<registry>/<repo>/manifests/<ref>`):

| Image state | Response |
|-------------|----------|
| `approved`  | `200` proxied/redirected from upstream |
| `rejected`  | `403 DENIED` (CNCF JSON error body) |
| unknown / not approved | `401 UNAUTHORIZED` + `WWW-Authenticate` challenge; tag stub-registered |

**Non-manifest paths** (blobs, tag lists, uploads, etc.):

Forwarded unconditionally to `https://<registry>/v2/<repo>/…` via proxy or
307 redirect (controlled by `server.redirect`).

### ANY /ident/\<registry\>/…

Token-acquisition proxy. The Docker client sends its bearer-token request here;
hermes proxies it verbatim to `https://<registry>/…`.

The realm URL in upstream `WWW-Authenticate` headers is automatically rewritten
to route through `/ident/` so clients never need direct access to the upstream
auth endpoint.

### GET /healthz

Returns `ok\n` with status `200`. Used as a container liveness probe.

---

## Database

hermes uses PostgreSQL and creates its tables automatically on first run via
`hermes serve`.

### `registries`

| Column       | Type          | Description |
|--------------|---------------|-------------|
| `id`         | `bigserial`   | Primary key |
| `url`        | `text`        | Registry base URL (e.g. `registry.example.com`) |
| `created_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | |

### `tags`

| Column       | Type          | Description |
|--------------|---------------|-------------|
| `id`         | `bigserial`   | Primary key |
| `registry`   | `bigint`      | FK → `registries.id` |
| `repository` | `text`        | e.g. `myorg/myapp` |
| `name`       | `text`        | e.g. `v1.2.3` |
| `digest`     | `text`        | Top-level manifest digest (`sha256:…`); NULL until first scan/approve |
| `created_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | |

### `images`

One row per tracked OCI platform image. Stub-registered images (seen at the
gateway but not yet scanned) have a single placeholder row with NULL digest,
arch, and os.

| Column           | Type          | Description |
|------------------|---------------|-------------|
| `id`             | `bigserial`   | Primary key |
| `tag`            | `bigint`      | FK → `tags.id` |
| `cache_registry` | `bigint`      | FK → `registries.id`; set after a successful cache push |
| `digest`         | `text`        | Platform-specific manifest digest; NULL for placeholders |
| `arch`           | `text`        | e.g. `amd64`, `arm64` |
| `os`             | `text`        | e.g. `linux`, `windows` |
| `manifest`       | `jsonb`       | Raw platform manifest |
| `scan_report`    | `jsonb`       | Raw trivy JSON report |
| `state`          | `state`       | Current state (see [Image states](#image-states)) |
| `created_at`     | `timestamptz` | |
| `updated_at`     | `timestamptz` | |

### `events`

Append-only audit log of every CLI and API action.

| Column       | Type          | Description |
|--------------|---------------|-------------|
| `id`         | `bigserial`   | Primary key |
| `image_id`   | `bigint`      | FK → `images.id` (nullable) |
| `source`     | `text`        | `cli` or `api` |
| `event_type` | `text`        | e.g. `scan`, `approve`, `validate_approved` |
| `details`    | `text`        | JSON with context-specific fields |
| `created_at` | `timestamptz` | |
