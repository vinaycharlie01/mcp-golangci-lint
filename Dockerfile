FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make

# Download dependencies first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w \
      -X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.Version=${VERSION} \
      -X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.Commit=${COMMIT} \
      -X github.com/vinaycharlie01/mcp-golangci-lint/pkg/version.BuildDate=${BUILD_DATE}" \
    -o mcp-golangci-lint ./cmd/server

# Install golangci-lint, staticcheck, gosec in the builder
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest

# Final minimal image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata git

WORKDIR /app

# Copy the server binary
COPY --from=builder /build/mcp-golangci-lint /usr/local/bin/mcp-golangci-lint

# Copy analysis tools
COPY --from=builder /go/bin/golangci-lint /usr/local/bin/golangci-lint
COPY --from=builder /go/bin/staticcheck /usr/local/bin/staticcheck
COPY --from=builder /go/bin/gosec /usr/local/bin/gosec

# Non-root user
RUN addgroup -S mcpuser && adduser -S mcpuser -G mcpuser
USER mcpuser

EXPOSE 8080 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/healthz || exit 1

ENTRYPOINT ["mcp-golangci-lint"]
