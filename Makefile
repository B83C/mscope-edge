HY_VERSION := $(shell grep 'apernet/hysteria/core' go.mod | awk '{print $$2}' | sed 's/^v//')
VERSION := v$(HY_VERSION)-mscope

.PHONY: build build-arm64 docker

build:
	go build -ldflags="-X main.version=$(VERSION)" -o edge ./cmd/edge

build-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="-X main.version=$(VERSION)" -o edge-arm64 ./cmd/edge

docker:
	docker build --build-arg VERSION=$(VERSION) -t mscope-edge .
