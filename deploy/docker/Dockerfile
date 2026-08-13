# Builds every meshp server-side binary. Clients ship as signed native
# packages, not containers.
FROM golang:1.26-alpine AS build

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
