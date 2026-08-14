# Builds every meshp server-side binary. Clients ship as signed native
# packages, not containers.
# Pinned rather than floating on a major version, and the default is kept in step with
# .go-version by `make image`, which passes it. A floating tag means the binary that ships
# is built by whatever toolchain the registry resolved that day — which is not the one CI
# tested with, and not reproducible from the same commit a month later.
ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Dependency layer first so source edits do not invalidate the module cache.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w \
        -X github.com/meshpnet/meshp/internal/version.version=${VERSION} \
        -X github.com/meshpnet/meshp/internal/version.commit=${COMMIT}" \
      -o /out/meshp-control ./cmd/meshp-control \
 && CGO_ENABLED=0 go build \
      -ldflags "-s -w \
        -X github.com/meshpnet/meshp/internal/version.version=${VERSION} \
        -X github.com/meshpnet/meshp/internal/version.commit=${COMMIT}" \
      -o /out/meshp-relay ./cmd/meshp-relay

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 65532 meshp

COPY --from=build /out/meshp-control /usr/local/bin/meshp-control
COPY --from=build /out/meshp-relay   /usr/local/bin/meshp-relay
COPY migrations /usr/share/meshp/migrations

USER meshp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/meshp-control"]
