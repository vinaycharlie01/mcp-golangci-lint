.PHONY: all build test lint tidy clean run-stdio run-sse docker-build help

BINARY     := mcp-golangci-lint
CMD        := ./cmd/server
DOCKER_IMG := ghcr.io/vinaycharlie01/mcp-golangci-lint
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.Version=$(VERSION) \
	-X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.Commit=$(COMMIT) \
	-X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.BuildDate=$(BUILD_DATE)"

all: tidy build test lint

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

test-coverage: test
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/ coverage.out coverage.html

run-stdio: build
	./bin/$(BINARY) --transport stdio

run-sse: build
	./bin/$(BINARY) --transport sse --addr :8080

docker-build:
	docker build -t $(DOCKER_IMG):$(VERSION) .

docker-push:
	docker push $(DOCKER_IMG):$(VERSION)

help:
	@echo "Available targets:"
	@echo "  build          Build the binary"
	@echo "  test           Run tests with race detector"
	@echo "  lint           Run golangci-lint"
	@echo "  tidy           Run go mod tidy"
	@echo "  run-stdio      Run with STDIO transport (Claude/Cursor/VSCode)"
	@echo "  run-sse        Run with SSE transport"
	@echo "  docker-build   Build Docker image"
