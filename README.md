# hermes

**hermes** is an OCI image approval system that gatekeeps OCI Distribution
registries. It combines [trivy](https://aquasecurity.github.io/trivy) vulnerability
scanning with a human-in-the-loop approval workflow and exposes a REST API
designed to be used as an nginx `auth_request` middleware.

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
- [API](#api)
  - [GET /validate/…](#get-validate)
  - [GET /healthz](#get-healthz)
- [nginx integration](#nginx-integration)
- [Database](#database)

---

## How it works

```
                  ┌──────────┐  auth_request  ┌──────────┐
  docker pull ──► │  nginx   │ ─────────────► │  hermes  │
                  └──────────┘                └──────────┘
                       │ 200 + X-Hermes-Image-Uri    │
                       │                             │ (checks PostgreSQL)
                       ▼                             │
                  upstream registry ◄────────────────┘
```

1. A container runtime issues a pull request through nginx.
2. nginx sends an `auth_request` sub-request to hermes.
3. hermes looks up the image in PostgreSQL.
   - **Approved** → returns `200` with `X-Hermes-Image-Uri` pointing at the pinned digest; nginx proxies to the registry.
   - **Not found** → queues the image for review and returns `401`.
   - **Any other state** → returns `401`.
4. An operator uses the CLI to `scan`, `approve`, or `reject` queued images.

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
  ├──reject──►      └──reject──►          └──reject──► rejected ──approve──► queued
  │           rejected
  └──────────────────────────────────────────────────────────────────────────►
                                                                    (re-scan on approve)
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

Run (mounting the config and Docker socket):

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

The nginx proxy listens on `http://localhost:8888`. Pulls routed through it
look like:

```bash
DOCKER_HOST=tcp://localhost:8888 docker pull registry.example.com/myapp:v1.2.3
```

---

## Configuration

hermes reads `/etc/hermes.yaml` on startup (override with `--config`).

```yaml
server:
  addr: ":8080"          # listen address

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

A JSON Schema is provided at [`hermes.schema.json`](hermes.schema.json).

---

## CLI usage

All CLI commands accept `--config <path>` (default: `/etc/hermes.yaml`).

### scan

```
hermes scan [--force] IMAGE
```

Queues `IMAGE` if it does not already exist, fetches its manifest, runs a trivy
scan, saves the report, and prints the JSON to stdout.

If the image already has a scan report, the existing report is printed unless
`--force` is given.

```bash
hermes scan registry.example.com/myapp:v1.2.3
hermes scan --force registry.example.com/myapp:v1.2.3
```

### approve

```
hermes approve [--cache [URL]] IMAGE
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
the API check. The image can be re-approved with `hermes approve`.

```bash
hermes rescind registry.example.com/myapp:v1.2.3
```

### reject

```
hermes reject IMAGE
```

Prompts for confirmation then sets the image to `rejected`.

```bash
hermes reject registry.example.com/myapp:v1.2.3
```

### view

```
hermes view IMAGE
```

Prints all stored information for an image — state, digest, cache registry,
timestamps, a vulnerability summary, and the full scan report.

```bash
hermes view registry.example.com/myapp:v1.2.3
```

### list

```
hermes list [--state STATE[,...]] [--json] [REF ...]
```

Lists tracked images in a table. `--state` accepts individual states
(`queued`, `scanned`, `approved`, `rescinded`, `rejected`, `error`) or group
names (`pending`, `verified`). Multiple values can be comma-separated or given
as repeated flags. `REF` arguments filter by `[namespace/]name[:tag]`.

```bash
hermes list
hermes list --state approved
hermes list --state pending,verified --json
hermes list myapp:v1.2.3 otherapp
```

### report

```
hermes report [--format FORMAT] [--output FILE] IMAGE
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

Starts the HTTP API server (default address from config, overridden by
`--addr`).

```bash
hermes serve
hermes serve --addr 0.0.0.0:9090
```

---

## API

### GET /validate/…

**Purpose:** nginx `auth_request` target.

**URL format:**
```
GET /validate/<registry>/v2/<repository>/manifests/<tag>
```

**Responses:**

| Status | Meaning | Headers set |
|--------|---------|-------------|
| `200`  | Image is approved | `X-Hermes-Image-Uri: <registry>/v2/<repo>/manifests/<digest>` |
| `401`  | Not approved (image queued if new) | — |
| `400`  | Malformed path | — |
| `500`  | Internal error | — |

On `200`, nginx uses the `X-Hermes-Image-Uri` value to `proxy_pass` to the
upstream registry, resolving to the pinned digest.

### GET /healthz

Returns `ok\n` with status `200`. Used as a container liveness probe.

---

## nginx integration

See [`dev/nginx.conf`](dev/nginx.conf) for a complete working example.

The key pattern:

```nginx
location ~ ^/(?<registry>[^/]+)/(?<distpath>v2/.+)$ {
    auth_request     /hermes-validate/$registry/$distpath;
    auth_request_set $hermes_image_uri $upstream_http_x_hermes_image_uri;

    resolver   127.0.0.11 valid=10s;
    proxy_pass https://$hermes_image_uri;

    proxy_ssl_server_name on;
    proxy_set_header Host $registry;
}

location /hermes-validate/ {
    internal;
    rewrite ^/hermes-validate/(.*)$ /validate/$1 break;
    proxy_pass              http://hermes:8080;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
}
```

---

## Database

hermes uses PostgreSQL and creates its tables automatically on first run.

**`images`** — one row per tracked OCI image tag.

| Column           | Type          | Description |
|------------------|---------------|-------------|
| `id`             | `bigserial`   | Primary key |
| `registry`       | `text`        | e.g. `registry.example.com` |
| `repository`     | `text`        | e.g. `myorg/myapp` |
| `tag`            | `text`        | e.g. `v1.2.3` |
| `digest`         | `text`        | `sha256:…` |
| `manifest`       | `text`        | Raw manifest JSON |
| `scan_report`    | `text`        | Raw trivy JSON report |
| `state`          | `text`        | Current state |
| `cache_registry` | `text`        | Set after a successful cache push |
| `created_at`     | `timestamptz` | |
| `updated_at`     | `timestamptz` | |

**`events`** — append-only log of every CLI and API action.

| Column       | Type          | Description |
|--------------|---------------|-------------|
| `id`         | `bigserial`   | Primary key |
| `image_id`   | `bigint`      | FK → `images.id` (nullable) |
| `source`     | `text`        | `cli` or `api` |
| `event_type` | `text`        | e.g. `scan`, `approve`, `validate_approved` |
| `details`    | `text`        | JSON with context-specific fields |
| `created_at` | `timestamptz` | |
