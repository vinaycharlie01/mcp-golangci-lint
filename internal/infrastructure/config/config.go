// Package config provides structured configuration using viper.
package config

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

// Config is the top-level configuration for the MCP server.
type Config struct {
	Log           LogConfig           `mapstructure:"log"`
	Server        ServerConfig        `mapstructure:"server"`
	MCP           MCPConfig           `mapstructure:"mcp"`
	Observability ObservabilityConfig `mapstructure:"observability"`
	Cache         CacheConfig         `mapstructure:"cache"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"` // "json" or "text"
}

// SlogLevel parses the configured level string into a slog.Level.
func (l LogConfig) SlogLevel() slog.Level {
	switch strings.ToLower(l.Level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ServerConfig controls the HTTP metrics/health server.
type ServerConfig struct {
	Addr string `mapstructure:"addr"`
}

// MCPConfig controls MCP server behaviour.
type MCPConfig struct {
	Name      string `mapstructure:"name"`
	Version   string `mapstructure:"version"`
	Transport string `mapstructure:"transport"` // "stdio" or "sse"
	SSEAddr   string `mapstructure:"sse_addr"`
}

// ObservabilityConfig controls metrics and tracing.
type ObservabilityConfig struct {
	ServiceName    string  `mapstructure:"service_name"`
	TracingEnabled bool    `mapstructure:"tracing_enabled"`
	OTLPEndpoint   string  `mapstructure:"otlp_endpoint"`
	SamplingRate   float64 `mapstructure:"sampling_rate"`
}

// CacheConfig controls result caching.
type CacheConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Load reads configuration from file and environment variables.
// Environment variables take precedence: MCP_LOG_LEVEL, MCP_TRANSPORT, etc.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("server.addr", "0.0.0.0:8080")
	v.SetDefault("mcp.name", "go-static-analysis")
	v.SetDefault("mcp.version", "1.0.0")
	v.SetDefault("mcp.transport", "stdio")
	v.SetDefault("mcp.sse_addr", "0.0.0.0:8081")
	v.SetDefault("observability.service_name", "mcp-golangci-lint")
	v.SetDefault("observability.tracing_enabled", false)
	v.SetDefault("observability.otlp_endpoint", "localhost:4318")
	v.SetDefault("observability.sampling_rate", 1.0)
	v.SetDefault("cache.enabled", true)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./configs")
		v.AddConfigPath("/etc/mcp-golangci-lint")
	}

	v.SetEnvPrefix("MCP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}
	return &cfg, nil
}
