# MCP Client Configuration

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "go-static-analysis": {
      "command": "mcp-golangci-lint",
      "args": ["--transport", "stdio"],
      "env": {
        "MCP_LOG_LEVEL": "warn"
      }
    }
  }
}
```

Or if using Docker:

```json
{
  "mcpServers": {
    "go-static-analysis": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/your/go/projects:/workspace:ro",
        "ghcr.io/vinaycharlie01/mcp-golangci-lint:latest",
        "--transport", "stdio"
      ]
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json` in your home directory or project root:

```json
{
  "mcpServers": {
    "go-static-analysis": {
      "command": "mcp-golangci-lint",
      "args": ["--transport", "stdio"]
    }
  }
}
```

## VS Code (Copilot MCP)

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "go-static-analysis": {
      "type": "stdio",
      "command": "mcp-golangci-lint",
      "args": ["--transport", "stdio"]
    }
  }
}
```

For SSE transport (remote server):

```json
{
  "servers": {
    "go-static-analysis": {
      "type": "sse",
      "url": "http://localhost:8081/sse"
    }
  }
}
```

## SSE Transport (Remote / Docker Compose)

Start the server in SSE mode:

```bash
docker compose up mcp-server
# or
mcp-golangci-lint --transport sse
```

Connect via SSE at `http://localhost:8081/sse`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `MCP_LOG_FORMAT` | `json` | Log format: json, text |
| `MCP_MCP_TRANSPORT` | `stdio` | MCP transport: stdio, sse |
| `MCP_MCP_SSE_ADDR` | `0.0.0.0:8081` | SSE listen address |
| `MCP_SERVER_ADDR` | `0.0.0.0:8080` | HTTP health/metrics listen address |
| `MCP_OBSERVABILITY_TRACING_ENABLED` | `false` | Enable OTel tracing |
| `MCP_OBSERVABILITY_OTLP_ENDPOINT` | `localhost:4318` | OTLP exporter endpoint |
| `MCP_CACHE_ENABLED` | `true` | Enable in-memory result cache |
