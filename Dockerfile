# ENCLAVE in a container.
#
#   docker build -t enclave:latest .
#   docker run -p 127.0.0.1:8080:8080 -v enclave-data:/data enclave:latest
#
# Or, far more likely, use the compose file next to this one:
#
#   docker compose up -d
#
# The build needs no network access beyond the base images: ENCLAVE has no
# third-party Go dependencies, so there are no modules to download.

# --- build -------------------------------------------------------------------

ARG GO_VERSION=1.24
ARG ALPINE_VERSION=3

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# go.mod on its own first, so editing source does not invalidate this layer.
# There is no go.sum, because there is nothing to depend on.
COPY go.mod ./
RUN go mod download

COPY . .

# VERSION is stamped into the binary and shown in the interface footer, so a
# screenshot in a report identifies which build produced it. Pass the git SHA
# or a release tag; "docker" is only a placeholder.
ARG VERSION=docker
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/enclave ./cmd/enclave

# --- test --------------------------------------------------------------------
# Not on the path to the runtime image, so an ordinary build does not pay for
# it. Run it deliberately:  docker build --target test .

FROM build AS test
RUN set -eu; \
    unformatted="$(gofmt -l .)"; \
    if [ -n "$unformatted" ]; then echo "not gofmt clean:"; echo "$unformatted"; exit 1; fi
RUN go vet ./...
RUN go test ./...

# --- runtime -----------------------------------------------------------------

FROM alpine:${ALPINE_VERSION} AS runtime

# Alpine rather than scratch on purpose. The image is around 20 MB either way
# once the binary is in it, and having a shell means an operator can get at
# "enclave backup" and look at the data directory on a box where something has
# gone wrong. Nothing is installed but the certificate bundle, which is what
# verifies a Security Center's certificate on an outbound connection. The zone
# database is compiled into the binary, so TZ works without tzdata here.
# su-exec is how the entry point drops out of root once it has made the data
# directory usable. It is 10 KB and is the whole reason nobody has to prepare
# anything before starting this container.
RUN apk add --no-cache ca-certificates su-exec \
 && addgroup -g 65532 -S enclave \
 && adduser -u 65532 -S -G enclave -H -s /sbin/nologin enclave \
 && mkdir -p /data \
 && chown enclave:enclave /data \
 && chmod 0750 /data

COPY --from=build /out/enclave /usr/local/bin/enclave
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint
RUN chmod 0755 /usr/local/bin/docker-entrypoint

# Every serve option is read from the environment, so the image is configured
# the way a container is configured rather than by rewriting a command line.
ENV ENCLAVE_DATA=/data \
    ENCLAVE_ADDR=0.0.0.0:8080 \
    ENCLAVE_NO_BROWSER=1 \
    ENCLAVE_IN_CONTAINER=1 \
    TZ=UTC

# Deliberately not "USER 65532". The container starts as root so that it can
# take ownership of a directory bind-mounted from a host, which arrives owned
# by whoever created it; the entry point then drops to PUID:PGID (65532 by
# default) and the server itself never runs as root. Setting "user:" in a
# compose file still works and skips all of that — then the directory has to
# be owned correctly beforehand, which is the trade.
WORKDIR /data
EXPOSE 8080

# Declared so that a "docker run" with no volume still keeps its records in a
# volume rather than in a container layer that disappears with the container.
VOLUME ["/data"]

# The binary is its own health check, which keeps curl and wget out of the
# picture and works the same if this image is ever rebased onto scratch.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/enclave", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["serve"]
