# syntax=docker/dockerfile:1
ARG CENTRAL_PUB_B64=

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG CENTRAL_PUB_B64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/edge/ ./cmd/edge/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X main.centralPubB64=${CENTRAL_PUB_B64}" \
    -o /edge ./cmd/edge

FROM alpine:3.21 AS runtime
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /edge /usr/bin/mscope-edge
EXPOSE 443/udp 8443/udp
ENTRYPOINT ["mscope-edge"]
CMD ["-central-addr", "central:38472", "-data-listen", "0.0.0.0:443"]
