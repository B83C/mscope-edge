# syntax=docker/dockerfile:1
# Multi-arch builder: amd64, arm64, arm/v7

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /edge \
    ./cmd/edge

# ─────────────────────────────────────────────

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /edge /usr/bin/mscope-edge

RUN mkdir -p /etc/mscope

EXPOSE 443/udp 8443/udp

ENTRYPOINT ["mscope-edge"]
CMD ["-central-addr", "central:38472", "-data-listen", "0.0.0.0:443", "-central-pub", "/etc/mscope/central.pub"]
