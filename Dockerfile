# syntax=docker/dockerfile:1
ARG VERSION

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG MTLS_CERT_B64
ARG MTLS_KEY_B64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/edge/ ./cmd/edge/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.mtlsCertB64=${MTLS_CERT_B64} -X main.mtlsKeyB64=${MTLS_KEY_B64}" \
    -o /edge ./cmd/edge

FROM alpine:3.21 AS runtime
LABEL org.opencontainers.image.version=${VERSION}
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /edge /usr/bin/mscope-edge
COPY docker-entrypoint.sh /docker-entrypoint.sh
EXPOSE 443/udp 8443/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
