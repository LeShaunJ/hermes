# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /hermes .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

# Docker CLI is needed to spin up ephemeral trivy containers.
RUN apk add --no-cache docker-cli ca-certificates

COPY --from=builder /hermes /usr/local/bin/hermes

# The Docker socket is mounted at runtime so hermes can create trivy containers.
VOLUME [ "/var/run/docker.sock" ]

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD ["hermes", "health"]

ENTRYPOINT ["hermes"]
CMD ["serve"]
