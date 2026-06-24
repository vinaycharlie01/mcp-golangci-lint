// Package logger provides slog-based structured logging helpers.
// The design principle: loggers are NEVER stored in structs.
// All code receives *slog.Logger via logger.FromContext(ctx, slog.Default()).
package logger

import (
	"context"
	"log/slog"
	"os"
)

type contextKey string

const (
	correlationIDKey contextKey = "correlation_id"
	requestIDKey     contextKey = "request_id"
	traceIDKey       contextKey = "trace_id"
)

// New creates a JSON structured logger writing to stdout.
func New(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}))
}

// NewText creates a text structured logger writing to stdout.
func NewText(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}))
}

// WithCorrelationID attaches a correlation ID to the context.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// WithRequestID attaches a request ID to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// WithTraceID attaches a trace ID to the context.
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDKey, id)
}

// FromContext returns the base logger enriched with IDs extracted from ctx.
// No logger is ever stored in a struct; callers always derive from slog.Default().
func FromContext(ctx context.Context, base *slog.Logger) *slog.Logger {
	attrs := make([]any, 0, 6)
	if v, ok := ctx.Value(correlationIDKey).(string); ok && v != "" {
		attrs = append(attrs, slog.String("correlation_id", v))
	}
	if v, ok := ctx.Value(requestIDKey).(string); ok && v != "" {
		attrs = append(attrs, slog.String("request_id", v))
	}
	if v, ok := ctx.Value(traceIDKey).(string); ok && v != "" {
		attrs = append(attrs, slog.String("trace_id", v))
	}
	if len(attrs) == 0 {
		return base
	}
	return base.With(attrs...)
}

// CorrelationID returns the correlation ID stored in context.
func CorrelationID(ctx context.Context) string {
	v, _ := ctx.Value(correlationIDKey).(string)
	return v
}

// RequestID returns the request ID stored in context.
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// TraceID returns the trace ID stored in context.
func TraceID(ctx context.Context) string {
	v, _ := ctx.Value(traceIDKey).(string)
	return v
}
