# syntax=docker/dockerfile:1.7

# 1. Pin to an immutable SHR256 digest to prevent supply chain attacks
FROM golang:1.25-alpine@sha256:45df378b20d3f2b604b7db8a01f60975e5da48dcbebffe130cd32fe09d58eb62 AS builder

# 2. Install certificates, tzdata, and create a non-root user
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates tzdata && update-ca-certificates \
    && adduser -D -g '' -s /sbin/nologin -u 65532 nonroot

WORKDIR /src

# 3. Only copy dependency files first for optimal layer caching
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# 4. Use a bind mount for source code to avoid unnecessary layer creation
#    Compile explicitly for linux to ensure cross-compilation reproducibility
RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /mantle ./cmd/mantle/

# 5. Final Stage
FROM scratch

# 6. Apply OCI Standard Metadata Labels
LABEL org.opencontainers.image.title="mantle"
LABEL org.opencontainers.image.description="Wolfi Frontend Mantle CLI"
LABEL org.opencontainers.image.source="https://github.com/wolfi-dev/wolfi-frontend"

# 7. Copy necessary OS dependencies from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# 8. Copy the unprivileged user definition from the builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# 9. Copy the compiled binary
COPY --from=builder /mantle /bin/mantle

# 10. CRITICAL: Drop privileges. Never run as root.
USER 65532:65532

ENTRYPOINT ["/bin/mantle"]
